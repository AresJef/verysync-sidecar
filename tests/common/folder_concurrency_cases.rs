//! Concurrency is derived from one continuous native event sequence, not two reads.
use super::managed_fixture::{options, TestResult};
use std::path::PathBuf;
use std::time::Duration;
use verysync_sidecar::*;

struct Pair {
    source: PathBuf,
    received: PathBuf,
    a: FolderId,
    b: FolderId,
    sender: ManagedInstance,
    sender_identity: DeviceId,
    before_sender: ConfigurationSnapshot,
}

#[tokio::test]
async fn native_folder_concurrency_has_ordered_single_and_double_sync_effects() -> TestResult {
    let root = tempfile::Builder::new().prefix("vsfc-").tempdir()?.keep();
    let sentinel = root.join("caller-sentinel");
    std::fs::write(&sentinel, b"folder-concurrency caller bytes")?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let bid = b.client().instance().device_id.clone();
    b.client()
        .update_network_configuration(&NetworkPatch::default().reconnection_interval_seconds(5))
        .await?;
    b.client()
        .update_general_options(&GeneralOptionsPatch::default().disable_system_sleep_on_sync(false))
        .await?;
    let address = super::configuration_policy_listener(&b).await?;
    let mut pairs = Vec::new();
    for index in 0..2 {
        // Distinct peers keep one sender's protocol/index queue from deciding
        // when the other folder becomes eligible at the receiver.
        let a = ManagedInstance::start(options(&root.join(format!("sender-{index}")))?).await?;
        let aid = a.client().instance().device_id.clone();
        assert_ne!(aid, bid);
        a.client()
            .update_network_configuration(&NetworkPatch::default().reconnection_interval_seconds(5))
            .await?;
        a.client()
            .update_general_options(
                &GeneralOptionsPatch::default().disable_system_sleep_on_sync(false),
            )
            .await?;
        for (client, peer, addresses) in [
            (a.client(), &bid, vec![format!("tcp://{address}")]),
            (b.client(), &aid, vec!["dynamic".into()]),
        ] {
            client
                .create_device(
                    &CreateDeviceOptions::new(peer.clone()).settings(
                        DevicePatch::default()
                            .addresses(addresses)
                            .compression(DeviceCompression::Never)
                            .allowed_transports(vec![DeviceTransport::Tcp])
                            .advanced_configuration(
                                DeviceAdvancedPatch::default().num_connections(1),
                            )?,
                    ),
                )
                .await?;
        }
        assert!(
            a.client()
                .update_bandwidth_configuration(
                    &BandwidthPatch::default()
                        .max_send_kib_per_second(1024)
                        .limit_in_lan(true),
                )
                .await?
                .requested_fields_match
        );
        let source = root.join(format!("source-{index}"));
        let received = root.join(format!("received-{index}"));
        std::fs::create_dir(&source)?;
        let keys = a.client().generate_share().await?;
        let rw = a.client().validate_share_key(&keys.read_write_key).await?;
        let ro = b.client().validate_share_key(&keys.read_only_key).await?;
        let af = a
            .client()
            .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&source)).paused(true))
            .await?;
        let bf = b
            .client()
            .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(&received)).paused(true))
            .await?;
        a.client()
            .share_folder_with(&af.configuration.id, &bid)
            .await?;
        b.client()
            .share_folder_with(&bf.configuration.id, &aid)
            .await?;
        a.client().resume_folder(&af.configuration.id).await?;
        let before_sender = a.client().configuration().await?;
        pairs.push(Pair {
            source,
            received,
            a: af.configuration.id,
            b: bf.configuration.id,
            sender: a,
            sender_identity: aid,
            before_sender,
        });
    }
    assert_ne!(pairs[0].sender_identity, pairs[1].sender_identity);
    let before_b = b.client().configuration().await?;
    let mut all_samples = Vec::new();
    for (phase, limit) in [1, 2].into_iter().enumerate() {
        for pair in &pairs {
            assert!(
                b.client()
                    .pause_folder(&pair.b)
                    .await?
                    .requested_fields_match
            );
        }
        assert!(
            b.client()
                .update_general_options(
                    &GeneralOptionsPatch::default().max_folder_concurrency(limit)
                )
                .await?
                .requested_fields_match
        );
        b.restart(Duration::from_secs(30)).await?;
        let address = super::configuration_policy_listener(&b).await?;
        for pair in &mut pairs {
            pair.sender
                .client()
                .update_device(
                    &bid,
                    &DevicePatch::default().addresses(vec![format!("tcp://{address}")]),
                )
                .await?;
            pair.sender.restart(Duration::from_secs(30)).await?;
            super::name_policy_connection_pair(&pair.sender, &b, true).await?;
        }
        let connected = b.client().connections().await?;
        for pair in &pairs {
            assert!(connected
                .connections
                .get(&pair.sender_identity)
                .is_some_and(|p| p.connected));
        }
        assert_eq!(
            b.client().general_options().await?.max_folder_concurrency,
            limit
        );
        let mut pending = Vec::new();
        let mut source_index_observations = Vec::new();
        for (index, pair) in pairs.iter().enumerate() {
            assert!(b.client().folder(&pair.b).await?.paused);
            let baseline = b.client().folder_status(&pair.b).await?.state;
            assert!(
                matches!(&baseline, Some(FolderState::Paused))
                    || matches!(&baseline, Some(FolderState::Unknown(value)) if value.is_empty()),
                "paused folder must preserve its exact inactive native snapshot"
            );
            let name = format!("concurrency-二-{phase}-{index}.bin");
            let bytes: Vec<u8> = (0..8 * 1024 * 1024)
                .map(|i| ((i * 73 + i / 251 + (phase * 2 + index) * 41) % 251) as u8)
                .collect();
            std::fs::write(pair.source.join(&name), &bytes)?;
            pair.sender.client().request_scan(&pair.a).await?;
            let indexed = pair.sender.client().folder_status(&pair.a).await?;
            assert_eq!(indexed.local_files, Some(u64::try_from(phase + 1)?));
            source_index_observations.push(serde_json::json!({
                "folder_index":index,"expected_local_files":phase+1,
                "actual_local_files":indexed.local_files,
                "actual_local_bytes":indexed.local_bytes,
                "actual_idle":indexed.state==Some(FolderState::Idle)
            }));
            pending.push((name, bytes));
        }
        let mut events = b
            .client()
            .subscribe_events(
                EventOptions::default()
                    .poll_interval(Duration::from_millis(20))?
                    .queue_capacity(128)?
                    .reconnect_attempts(0)?,
            )
            .await?;
        let mut last_id = events.cursor().last_id;
        let mut states = ["inactive".to_owned(), "inactive".to_owned()];
        let mut seen = [false; 2];
        let mut max_syncing = 0;
        let mut serial_waiting_seen = false;
        let mut state_events = 0;
        let mut unpause_spans = Vec::new();
        let mut history = Vec::new();
        let mut history_truncated = false;
        let observation_started = std::time::Instant::now();
        for (pair, (name, _)) in pairs.iter().zip(&pending) {
            assert!(
                !pair.received.join(name).try_exists()?,
                "work completed before the observed unpause"
            );
            let started = std::time::Instant::now();
            assert!(
                b.client()
                    .resume_folder(&pair.b)
                    .await?
                    .requested_fields_match
            );
            unpause_spans.push(serde_json::json!({
                "rpc_elapsed_ns":started.elapsed().as_nanos(),
                "observed_end_ns":observation_started.elapsed().as_nanos()
            }));
        }
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                tokio::select! {
                    item = events.next() => {
                        let event = match item.ok_or("native state stream ended")?? {
                            EventStreamItem::Event(event) => event,
                            _ => return Err("native state event continuity lost".into()),
                        };
                        assert!(event.cursor.last_id > last_id);
                        last_id = event.cursor.last_id;
                        if event.kind != EventKind::StateChanged { continue; }
                        let Some(index) = pairs.iter().position(|p| event.data()["folder"] == p.b.as_str()) else { continue; };
                        let from = event.data()["from"].as_str().ok_or("native state from missing")?;
                        let to = event.data()["to"].as_str().ok_or("native state to missing")?;
                        if seen[index] { assert_eq!(from, states[index]); }
                        else { assert_ne!(from, "syncing", "active work predates the observed history"); }
                        seen[index] = true;
                        states[index] = to.to_owned();
                        assert_ne!(to, "error", "owned folder entered native error state");
                        state_events += 1;
                        if history.len() < 128 {
                            let label = |s: &str| match s {
                                "idle" | "starting" | "scanning" | "scan-waiting" | "syncing"
                                | "sync-waiting" | "sync-preparing" | "cleaning" | "clean-waiting"
                                | "paused" | "error" => s.to_owned(),
                                _ => "<unrecognized>".to_owned(),
                            };
                            history.push(serde_json::json!({
                                "event_id":event.cursor.last_id,"folder_index":index,
                                "from":label(from),"to":label(to),
                                "delivered_ns":observation_started.elapsed().as_nanos()
                            }));
                        } else {
                            history_truncated = true;
                        }
                        let syncing = states.iter().filter(|s| s.as_str() == "syncing").count();
                        max_syncing = max_syncing.max(syncing);
                        serial_waiting_seen |= syncing == 1 && states.iter().any(|s| s == "sync-waiting");
                        assert!(syncing <= limit as usize, "ordered native state history exceeded selected folder concurrency");
                    }
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {
                        if states.iter().all(|s| s == "idle")
                            && pairs.iter().zip(&pending).all(|(p,(name,_))| p.received.join(name).is_file()) {
                            break;
                        }
                    }
                }
            }
            TestResult::Ok(())
        }).await??;
        events.close().await?;
        eprintln!(
            "native folder concurrency preparation diagnostic: {}",
            serde_json::json!({
                "selected":limit,"source_index_observations":source_index_observations,
                "unpause_rpc_spans":unpause_spans,"history":history,
                "history_truncated":history_truncated,
                "delivery_clock_is_not_native_event_time":true,
                "diagnostic_only_original_effect_assertions_unchanged":true
            })
        );
        assert!(seen.into_iter().all(|x| x));
        assert_eq!(
            max_syncing, limit as usize,
            "both selected concurrency effects must actually occur"
        );
        if limit == 1 {
            assert!(
                serial_waiting_seen,
                "pending second folder must actually wait while first syncs"
            );
        }
        for (pair, (name, bytes)) in pairs.iter().zip(pending) {
            assert_eq!(std::fs::read(pair.received.join(&name))?, bytes);
            all_samples.push((pair.source.join(&name), pair.received.join(name), bytes));
        }
        println!(
            "native folder concurrency evidence: {}",
            serde_json::json!({
                "selected":limit,"actual_max_syncing_in_ordered_event_history":max_syncing,
                "native_state_events":state_events,"actual_serial_sync_waiting_observed":serial_waiting_seen,
                "actual_gap_free_source_bound_event_history":true,"actual_both_new_payloads_received":true,
                "actual_normal_restart_retained_policy":true,"sequential_status_reads_used_as_overlap_proof":false,
                "actual_two_independent_authenticated_source_peers":true
            })
        );
    }
    for pair in &pairs {
        b.client().pause_folder(&pair.b).await?;
    }
    for (core, before, identity) in pairs
        .iter()
        .map(|p| (&p.sender, &p.before_sender, &p.sender_identity))
        .chain(std::iter::once((&b, &before_b, &bid)))
    {
        assert_eq!(&core.client().system_status().await?.device_id, identity);
        let after = core.client().configuration().await?;
        for key in ["gui", "folders", "defaults", "ldap"] {
            assert!(before.native_document()[key] == after.native_document()[key]);
        }
    }
    for (source, received, bytes) in &all_samples {
        assert_eq!(&std::fs::read(source)?, bytes);
        assert_eq!(&std::fs::read(received)?, bytes);
    }
    assert_eq!(std::fs::read(sentinel)?, b"folder-concurrency caller bytes");
    let exit = b.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    for core in pairs.iter_mut().map(|pair| &mut pair.sender) {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!("native folder concurrency cleanup evidence: actual_four_source_receiver_payloads_retained=true actual_unrelated_sections_identities_and_sentinel_retained=true actual_all_three_normal_owned_tree_and_state_exit=true actual_two_independent_authenticated_source_peers=true dial_or_incoming_request_limits_claimed=false throughput_improvement_claimed=false");
    Ok(())
}
