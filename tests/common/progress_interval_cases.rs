//! Native progress reporting is observed during real incomplete transfers.
use super::managed_fixture::{options, TestResult};
use std::{collections::BTreeMap, time::Duration};
use verysync_sidecar::*;

async fn received_bytes(client: &Client, peer: &DeviceId) -> TestResult<u64> {
    client
        .connections()
        .await?
        .connections
        .get(peer)
        .filter(|p| p.connected)
        .and_then(|p| p.in_bytes_total)
        .ok_or_else(|| "actual connected peer byte counter missing".into())
}

#[tokio::test]
async fn native_progress_interval_enables_disables_and_restores_actual_transfer_events(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-progress-interval-")
        .tempdir()?
        .keep();
    let sentinel = root.join("caller-sentinel");
    std::fs::write(&sentinel, b"progress setting preserves caller bytes")?;
    let source = root.join("source");
    let received = root.join("received");
    std::fs::create_dir(&source)?;
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let aid = a.client().instance().device_id.clone();
    let bid = b.client().instance().device_id.clone();
    for core in [&a, &b] {
        let transport = core.client().transport_configuration().await?;
        assert!(
            !transport.tracker_enabled
                && !transport.nat_enabled
                && !transport.udp_enabled
                && !transport.relays_enabled
        );
        assert!(
            core.client()
                .update_general_options(
                    &GeneralOptionsPatch::default()
                        .overwrite_remote_device_names_on_connect(false)
                        .disable_system_sleep_on_sync(false)
                )
                .await?
                .requested_fields_match
        );
        core.client()
            .update_network_configuration(&NetworkPatch::default().reconnection_interval_seconds(5))
            .await?;
    }
    let address = super::configuration_policy_listener(&b).await?;
    for (client, peer, addresses) in [
        (a.client(), &bid, vec![format!("tcp://{address}")]),
        (b.client(), &aid, vec!["dynamic".to_owned()]),
    ] {
        client
            .create_device(
                &CreateDeviceOptions::new(peer.clone()).settings(
                    DevicePatch::default()
                        .name("controlled progress peer")
                        .addresses(addresses)
                        .compression(DeviceCompression::Never)
                        .allowed_transports(vec![DeviceTransport::Tcp]),
                ),
            )
            .await?;
    }
    assert!(
        b.client()
            .update_bandwidth_configuration(
                &BandwidthPatch::default()
                    .max_receive_kib_per_second(256)
                    .limit_in_lan(true)
            )
            .await?
            .requested_fields_match
    );
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&source)))
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
    let protected = ["key.pem", "cert.pem"];
    let a_keys = protected
        .iter()
        .map(|p| std::fs::read(a.state_directory().join(p)))
        .collect::<std::io::Result<Vec<_>>>()?;
    let b_keys = protected
        .iter()
        .map(|p| std::fs::read(b.state_directory().join(p)))
        .collect::<std::io::Result<Vec<_>>>()?;
    let before_a = a.client().configuration().await?;
    let before_b = b.client().configuration().await?;
    let mut payloads = Vec::new();
    let mut receipts = Vec::new();
    for (phase, selected) in [1_i64, -1, 1].into_iter().enumerate() {
        assert!(
            b.client()
                .pause_folder(&bf.configuration.id)
                .await?
                .requested_fields_match
        );
        assert!(
            b.client()
                .update_general_options(
                    &GeneralOptionsPatch::default().progress_update_interval_seconds(selected)
                )
                .await?
                .requested_fields_match
        );
        b.restart(Duration::from_secs(30)).await?;
        assert_eq!(b.client().instance().device_id, bid);
        assert_eq!(
            b.client()
                .general_options()
                .await?
                .progress_update_interval_seconds,
            selected
        );
        let address = super::configuration_policy_listener(&b).await?;
        a.client()
            .update_device(
                &bid,
                &DevicePatch::default().addresses(vec![format!("tcp://{address}")]),
            )
            .await?;
        super::name_policy_connection_pair(&a, &b, true).await?;
        let name = format!("progress-二-{phase}.bin");
        // Distinct deterministic nonrepeating bytes avoid cross-file block reuse.
        let mut state = 0xd1342543de82ef95_u64 ^ (phase as u64 + 1);
        let bytes: Vec<u8> = (0..8 * 1024 * 1024)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect();
        std::fs::write(source.join(&name), &bytes)?;
        a.client().request_scan(&af.configuration.id).await?;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let status = a.client().folder_status(&af.configuration.id).await?;
                if status.local_files == Some(phase as u64 + 1)
                    && status.state == Some(FolderState::Idle)
                {
                    return Ok::<_, Error>(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await??;
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
        assert!(!received.join(&name).try_exists()?);
        b.client().resume_folder(&bf.configuration.id).await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
        let mut active = None;
        let mut initial_bytes = 0;
        let mut active_reads = 0;
        let mut progress_events = Vec::new();
        let mut kinds = BTreeMap::<String, usize>::new();
        let final_bytes = loop {
            if tokio::time::Instant::now() >= deadline {
                return Err("actual incomplete progress observation deadline expired".into());
            }
            tokio::select! {
                item = events.next() => {
                    let event = match item.ok_or("native event stream ended")?? {
                        EventStreamItem::Event(event) => event,
                        _ => return Err("native progress event continuity lost".into()),
                    };
                    assert!(event.cursor.last_id > last_id);
                    last_id = event.cursor.last_id;
                    if let EventKind::Unknown(kind) = &event.kind {
                        *kinds.entry(kind.clone()).or_default() += 1;
                        if kind == "DownloadProgress" {
                            if let Some(progress) = event.data().get(bf.configuration.id.as_str())
                                .and_then(|p| p.get(&name)) {
                                if active.is_some() {
                                    assert!(progress.is_object(), "matching native progress omitted fields");
                                    let native: FileDownloadProgress = serde_json::from_value(progress.clone())?;
                                    assert!(native.total_blocks > 0 && native.bytes_total > 0);
                                    progress_events.push(serde_json::json!({"event_id":last_id,
                                        "time":event.time,"fields":progress}));
                                }
                            }
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    let status = b.client().folder_status(&bf.configuration.id).await?;
                    let incomplete = status.state == Some(FolderState::Syncing) && status.need_bytes.is_some_and(|n| n > 0);
                    if active.is_none() {
                        if incomplete {
                            initial_bytes = received_bytes(b.client(), &aid).await?;
                            active = Some(tokio::time::Instant::now());
                        }
                    } else {
                        assert!(incomplete, "transfer completed before the full active progress window");
                        active_reads += 1;
                        let actual_bytes = received_bytes(b.client(), &aid).await?;
                        if active.is_some_and(|s| s.elapsed() >= Duration::from_secs(6)) { break actual_bytes; }
                    }
                }
            }
        };
        events.close().await?;
        assert!(active_reads >= 3 && final_bytes.saturating_sub(initial_bytes) >= 128 * 1024);
        println!(
            "native progress interval observation: {}",
            serde_json::json!({
            "selected":selected,"active_reads":active_reads,"actual_inbound_bytes_delta":final_bytes-initial_bytes,
            "observed_unknown_event_kinds":kinds,"matching_progress_events":progress_events,
            "actual_incomplete_active_window_seconds":6,"gap_free_stream":true})
        );
        if selected > 0 {
            assert!(
                progress_events.len() >= 3,
                "enabled native progress events missing"
            );
        } else {
            assert!(
                progress_events.is_empty(),
                "disabled native progress still emitted matching events"
            );
        }
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                if std::fs::read(received.join(&name)).is_ok_and(|actual| actual == bytes) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await?;
        receipts.push(
            serde_json::json!({"selected":selected,"matching_events":progress_events.len(),
            "actual_inbound_bytes_delta":final_bytes-initial_bytes,"active_reads":active_reads}),
        );
        payloads.push((name, bytes));
    }
    b.client().pause_folder(&bf.configuration.id).await?;
    assert_eq!(a.client().system_status().await?.device_id, aid);
    assert_eq!(b.client().system_status().await?.device_id, bid);
    let after_b = b.client().configuration().await?;
    for key in ["gui", "folders", "devices", "defaults", "ldap"] {
        assert!(before_b.native_document()[key] == after_b.native_document()[key]);
    }
    let mut original_options = before_b.native_document()["options"].clone();
    let mut final_options = after_b.native_document()["options"].clone();
    for value in [&mut original_options, &mut final_options] {
        value
            .as_object_mut()
            .ok_or("native options object missing")?
            .remove("progressUpdateIntervalS");
    }
    assert!(
        original_options == final_options,
        "unrelated receiver options changed"
    );
    let after_a = a.client().configuration().await?;
    for key in ["gui", "folders", "defaults", "ldap", "options"] {
        assert!(before_a.native_document()[key] == after_a.native_document()[key]);
    }
    let mut original_devices = before_a.native_document()["devices"].clone();
    let mut final_devices = after_a.native_document()["devices"].clone();
    for value in [&mut original_devices, &mut final_devices] {
        for device in value.as_array_mut().ok_or("native device array missing")? {
            if device["deviceID"] == bid.as_str() {
                device
                    .as_object_mut()
                    .ok_or("native device object missing")?
                    .remove("addresses");
            }
        }
    }
    assert!(
        original_devices == final_devices,
        "unrelated sender peer settings changed"
    );
    for (name, bytes) in &payloads {
        assert_eq!(&std::fs::read(source.join(name))?, bytes);
        assert_eq!(&std::fs::read(received.join(name))?, bytes);
    }
    for (core, original) in [(&a, &a_keys), (&b, &b_keys)] {
        for (name, bytes) in protected.iter().zip(original) {
            assert_eq!(&std::fs::read(core.state_directory().join(name))?, bytes);
        }
    }
    assert_eq!(
        std::fs::read(sentinel)?,
        b"progress setting preserves caller bytes"
    );
    for core in [&mut b, &mut a] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    println!(
        "native progress interval effects: {}",
        serde_json::json!({
        "phases":receipts,"actual_three_distinct_8_mib_payloads_retained":true,
        "actual_original_identities_keys_unrelated_configuration_and_sentinel_retained":true,
        "both_final_normal_owned_tree_and_state_exits":true,"precise_reporting_latency_claimed":false})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
