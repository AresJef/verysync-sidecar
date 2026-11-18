//! Saturated native request admission; unrelated heap and RSS are not measured.
use super::managed_fixture::{options, TestResult};
use sha2::Digest;
use std::{path::PathBuf, time::Duration};
use verysync_sidecar::*;
struct Receiver {
    core: ManagedInstance,
    folder: FolderId,
    path: PathBuf,
    id: DeviceId,
    credentials: Vec<Vec<u8>>,
    before: ConfigurationSnapshot,
}
fn credentials(core: &ManagedInstance) -> TestResult<Vec<Vec<u8>>> {
    Ok(["key.pem", "cert.pem"]
        .iter()
        .map(|n| std::fs::read(core.state_directory().join(n)))
        .collect::<std::io::Result<_>>()?)
}
async fn prepare(core: &ManagedInstance) -> TestResult {
    let transport = core.client().transport_configuration().await?;
    assert!(
        !transport.tracker_enabled
            && !transport.relays_enabled
            && !transport.nat_enabled
            && !transport.udp_enabled
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
    Ok(())
}
async fn same_sections(core: &ManagedInstance, before: &ConfigurationSnapshot) -> TestResult {
    let after = core.client().configuration().await?;
    for section in ["folders", "devices", "gui", "defaults", "ldap"] {
        assert!(
            before.native_document()[section] == after.native_document()[section],
            "unrelated native section changed: {section}"
        );
    }
    let mut old = before.native_document()["options"].clone();
    let mut current = after.native_document()["options"].clone();
    for field in [
        "maxConcurrentIncomingRequestKiB",
        "maxSendKbps",
        "limitBandwidthInLan",
    ] {
        old.as_object_mut()
            .ok_or("options object required")?
            .remove(field);
        current
            .as_object_mut()
            .ok_or("options object required")?
            .remove(field);
    }
    assert!(old == current, "unrelated native options changed");
    Ok(())
}
#[tokio::test]
async fn native_incoming_request_cap_bounds_saturated_admission_and_preserves_files() -> TestResult
{
    let root = tempfile::Builder::new()
        .prefix("vs-incoming-")
        .tempdir()?
        .keep();
    let evidence = root.join("private-support");
    std::fs::create_dir(&evidence)?;
    let sentinel = root.join("caller-sentinel");
    std::fs::write(&sentinel, b"controlled buffer caller bytes")?;
    let source = root.join("source");
    std::fs::create_dir(&source)?;
    println!("native incoming admission setup stage: start-sender");
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    prepare(&a).await?;
    let aid = a.client().instance().device_id.clone();
    let akeys = credentials(&a)?;
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&source)))
        .await?;
    let mut receivers = Vec::new();
    for index in 0..3 {
        println!("native incoming admission setup stage: start-receiver-{index}");
        let core = ManagedInstance::start(options(&root.join(format!("b-{index}")))?).await?;
        prepare(&core).await?;
        let id = core.client().instance().device_id.clone();
        assert_ne!(id, aid);
        assert!(!receivers.iter().any(|r: &Receiver| r.id == id));
        let address = super::configuration_policy_listener(&core).await?;
        for (client, peer, addresses) in [
            (a.client(), &id, vec![format!("tcp://{address}")]),
            (core.client(), &aid, vec!["dynamic".into()]),
        ] {
            client
                .create_device(
                    &CreateDeviceOptions::new(peer.clone()).settings(
                        DevicePatch::default()
                            .name("controlled cap peer")
                            .addresses(addresses)
                            .compression(DeviceCompression::Never)
                            .allowed_transports(vec![DeviceTransport::Tcp])
                            .advanced_configuration(
                                DeviceAdvancedPatch::default()
                                    .num_connections(1)
                                    .max_request_kib(131072),
                            )?,
                    ),
                )
                .await?;
            let config = client.configuration().await?;
            let row = config.native_document()["devices"]
                .as_array()
                .ok_or("native device array required")?
                .iter()
                .find(|r| r["deviceID"] == peer.as_str())
                .ok_or("actual configured peer required")?;
            assert_eq!(row["maxRequestKiB"], 131072);
            assert_eq!(row["numConnections"], 1);
        }
        let ro = core
            .client()
            .validate_share_key(&keys.read_only_key)
            .await?;
        let path = root.join(format!("received-{index}"));
        let folder = core
            .client()
            .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(&path)).paused(true))
            .await?
            .configuration
            .id;
        a.client()
            .share_folder_with(&af.configuration.id, &id)
            .await?;
        core.client().share_folder_with(&folder, &aid).await?;
        let before = core.client().configuration().await?;
        let credentials = credentials(&core)?;
        receivers.push(Receiver {
            core,
            folder,
            path,
            id,
            credentials,
            before,
        });
    }
    let before = a.client().configuration().await?;
    let mut payloads = Vec::new();
    let mut source_pids = Vec::new();
    let mut all_hashes = std::collections::BTreeSet::new();
    for (phase, selected) in [32768_i64, 65536].into_iter().enumerate() {
        let patch = GeneralOptionsPatch::default().max_concurrent_incoming_request_kib(selected);
        if phase == 1 {
            let mut snapshot = a.client().configuration().await?;
            snapshot.set_general_options(&patch)?;
            assert!(
                a.client()
                    .replace_configuration(&snapshot)
                    .await?
                    .requested_fields_match
            );
        } else {
            assert!(
                a.client()
                    .update_general_options(&patch)
                    .await?
                    .requested_fields_match
            );
        }
        println!(
            "native incoming admission phase setup stage: {}",
            serde_json::json!({"selected": selected, "stage": "restart-sender"})
        );
        a.restart(Duration::from_secs(30)).await?;
        assert_eq!(a.client().instance().device_id, aid);
        assert_eq!(
            a.client()
                .general_options()
                .await?
                .max_concurrent_incoming_request_kib,
            selected
        );
        assert!(!source_pids.contains(&a.process_id()));
        source_pids.push(a.process_id());
        println!(
            "native incoming admission phase setup stage: {}",
            serde_json::json!({"selected": selected, "stage": "connect-all-peers"})
        );
        for receiver in &receivers {
            super::name_policy_connection_pair(&a, &receiver.core, true).await?;
            assert!(
                receiver
                    .core
                    .client()
                    .folder(&receiver.folder)
                    .await?
                    .paused
            );
        }
        assert!(
            a.client()
                .update_bandwidth_configuration(
                    &BandwidthPatch::default()
                        .max_send_kib_per_second(512)
                        .limit_in_lan(true)
                )
                .await?
                .requested_fields_match
        );
        let name = format!("admission-cap-{phase}-二 %.bin");
        let mut bytes = vec![0u8; 96 * 1024 * 1024];
        let mut state =
            0x9e3779b97f4a7c15u64 ^ ((phase as u64 + 1).wrapping_mul(0xd1b54a32d192ed03));
        assert_ne!(state, 0);
        for chunk in bytes.chunks_exact_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        let mut current = std::collections::BTreeSet::new();
        for chunk in bytes.chunks_exact(131072) {
            let digest: [u8; 32] = sha2::Sha256::digest(chunk).into();
            assert!(
                !all_hashes.contains(&digest),
                "later phase must not reuse a prior block"
            );
            assert!(
                current.insert(digest),
                "native block must be unique within phase"
            );
        }
        assert_eq!(current.len(), 768);
        all_hashes.extend(current);
        std::fs::write(source.join(&name), &bytes)?;
        println!(
            "native incoming admission phase setup stage: {}",
            serde_json::json!({"selected": selected, "stage": "scan-and-index-new-file"})
        );
        a.client().request_scan(&af.configuration.id).await?;
        let indexed = a
            .client()
            .index_file_info(&af.configuration.id, &TargetPath::local(&name))
            .await?;
        assert_eq!(indexed.global.size, 96 * 1024 * 1024);
        assert_eq!(indexed.global.num_blocks, 768);
        println!(
            "native incoming admission geometry: {}",
            serde_json::json!({"selected":selected,"native_file_bytes":indexed.global.size,"native_num_blocks":indexed.global.num_blocks,"actual_three_distinct_authenticated_receiver_identities":true})
        );
        let mut stage = "resume-receivers";
        let phase_result = tokio::time::timeout(Duration::from_secs(30), async {
            for receiver in &receivers {
                assert!(!receiver.path.join(&name).is_file());
                assert!(receiver.core.client().resume_folder(&receiver.folder).await?.requested_fields_match);
            }
            stage = "wait-all-syncing";
            loop {
                let mut all_syncing = true;
                for receiver in &receivers {
                    all_syncing &= receiver.core.client().folder_status(&receiver.folder).await?.state == Some(FolderState::Syncing);
                }
                if all_syncing { break; }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            stage = "verify-all-three-new-indexes";
            for receiver in &receivers {
                let status = receiver.core.client().folder_status(&receiver.folder).await?;
                assert_eq!(status.global_files, Some(phase as u64 + 1));
                assert_eq!(status.local_files, Some(phase as u64));
                let indexed = receiver.core.client().index_file_info(&receiver.folder, &TargetPath::local(&name)).await?;
                assert_eq!(indexed.global.size, 96 * 1024 * 1024);
                assert_eq!(indexed.global.num_blocks, 768);
            }
            stage = "hold-admitted-responses-after-index-preparation";
            assert!(a.client().update_bandwidth_configuration(&BandwidthPatch::default().max_send_kib_per_second(1).limit_in_lan(true)).await?.requested_fields_match);
            println!("native incoming admission index preparation: {}", serde_json::json!({"selected":selected,"all_three_native_new_file_indexes_confirmed":true,"native_file_bytes":100663296_u64,"native_num_blocks":768,"bootstrap_send_kib":512,"observed_send_kib":1,"observation_deadline_seconds":30}));
            tokio::time::sleep(Duration::from_secs(1)).await;
            for index in 0..2 {
                if index == 1 { tokio::time::sleep(Duration::from_millis(500)).await; }
                for receiver in &receivers {
                    assert_eq!(receiver.core.client().folder_status(&receiver.folder).await?.state, Some(FolderState::Syncing));
                    assert!(!receiver.path.join(&name).is_file());
                }
                stage = if index == 0 { "support-snapshot-0" } else { "support-snapshot-1" };
                let profile = a.client().collect_core_support_bundle().await?;
                let archive = evidence.join(format!("cap-{selected}-admission-{index}.zip"));
                std::fs::write(&archive, profile.body_bytes())?;
                stage = if index == 0 { "inspect-snapshot-0" } else { "inspect-snapshot-1" };
                let inspected = inspect_admission(&root, &archive, selected).await?;
                assert_eq!(inspected["admitted_bytes"].as_u64(), Some(selected as u64 * 1024));
                assert!(inspected["waiting_for_admission_count"].as_u64().is_some_and(|count| count > 0));
                for receiver in &receivers {
                    assert_eq!(receiver.core.client().folder_status(&receiver.folder).await?.state, Some(FolderState::Syncing));
                    assert!(!receiver.path.join(&name).is_file());
                }
                println!("native incoming admission snapshot: {}", serde_json::json!({"selected": selected, "index": index, "native": inspected, "three_receivers_syncing_before_and_after": true}));
                std::fs::remove_file(archive)?;
            }
            for receiver in &receivers {
                assert_eq!(receiver.core.client().folder_status(&receiver.folder).await?.state, Some(FolderState::Syncing));
                assert!(!receiver.path.join(&name).is_file());
            }
            stage = "release-limit";
            assert!(a.client().update_bandwidth_configuration(&BandwidthPatch::default().max_send_kib_per_second(0).limit_in_lan(true)).await?.requested_fields_match);
            TestResult::Ok(())
        }).await;
        if !matches!(&phase_result, Ok(Ok(()))) {
            diagnose_failure(
                &receivers,
                &name,
                selected,
                stage,
                "observation",
                phase_result.is_err(),
            )
            .await;
        }
        phase_result??;
        let completion_result = tokio::time::timeout(Duration::from_secs(30), async {
            stage = "normal-restart-after-unlimited-policy";
            a.restart(Duration::from_secs(30)).await?;
            assert_eq!(a.client().instance().device_id, aid);
            assert!(!source_pids.contains(&a.process_id()));
            source_pids.push(a.process_id());
            assert_eq!(a.client().bandwidth_configuration().await?.max_send_kib_per_second, 0);
            assert_eq!(a.client().general_options().await?.max_concurrent_incoming_request_kib, selected);
            stage = "connect-fresh-unlimited-epoch";
            for receiver in &receivers { super::name_policy_connection_pair(&a, &receiver.core, true).await?; }
            println!("native incoming admission unthrottled epoch: {}", serde_json::json!({"selected":selected,"actual_explicit_owned_restart":true,"same_identity_and_selected_cap":true,"saved_send_kib":0,"all_three_authenticated_peers_connected":true,"hot_unlimit_alone_claimed":false,"completion_deadline_seconds":30}));
            stage = "wait-exact-bytes-and-idle";
            loop {
                let mut all_complete = true;
                for receiver in &receivers {
                    all_complete &= std::fs::read(receiver.path.join(&name)).is_ok_and(|data| data == bytes)
                        && receiver.core.client().folder_status(&receiver.folder).await?.state == Some(FolderState::Idle);
                }
                if all_complete { break; }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            TestResult::Ok(())
        }).await;
        if !matches!(&completion_result, Ok(Ok(()))) {
            diagnose_failure(
                &receivers,
                &name,
                selected,
                stage,
                "recovery-and-completion",
                completion_result.is_err(),
            )
            .await;
        }
        completion_result??;
        for receiver in &receivers {
            assert!(
                receiver
                    .core
                    .client()
                    .pause_folder(&receiver.folder)
                    .await?
                    .requested_fields_match
            );
        }
        payloads.push((name, bytes));
        println!(
            "native incoming admission completed phase: {}",
            serde_json::json!({"selected":selected,"source_and_all_three_receivers_actual_bytes":true,"saturated_admitted_request_cap_observed":true,"observation_deadline_seconds":30,"recovery_completion_deadline_seconds":30,"previous_aggregate30_preserved":false})
        );
    }
    same_sections(&a, &before).await?;
    assert_eq!(a.client().system_status().await?.device_id, aid);
    assert_eq!(credentials(&a)?, akeys);
    for receiver in &receivers {
        same_sections(&receiver.core, &receiver.before).await?;
        let after = receiver.core.client().configuration().await?;
        assert!(
            receiver.before.native_document()["options"] == after.native_document()["options"],
            "receiver options changed"
        );
        assert_eq!(
            receiver.core.client().system_status().await?.device_id,
            receiver.id
        );
        assert_eq!(credentials(&receiver.core)?, receiver.credentials);
    }
    for (name, bytes) in payloads {
        assert_eq!(std::fs::read(source.join(&name))?, bytes);
        for receiver in &receivers {
            assert_eq!(std::fs::read(receiver.path.join(&name))?, bytes);
        }
    }
    assert_eq!(std::fs::read(sentinel)?, b"controlled buffer caller bytes");
    let [r0, r1, r2] = receivers.as_mut_slice() else {
        return Err("exactly three owned receivers required".into());
    };
    println!("native incoming admission cleanup stage: four independent normal-stop requests");
    let exits = tokio::join!(
        a.shutdown(Duration::from_secs(10)),
        r0.core.shutdown(Duration::from_secs(10)),
        r1.core.shutdown(Duration::from_secs(10)),
        r2.core.shutdown(Duration::from_secs(10)),
    );
    let mut first_error = None;
    let mut failed_actors = Vec::new();
    for (actor, result) in [
        ("sender", exits.0),
        ("receiver-0", exits.1),
        ("receiver-1", exits.2),
        ("receiver-2", exits.3),
    ] {
        match result {
            Ok(exit) => {
                println!(
                    "native incoming admission normal-stop receipt: {}",
                    serde_json::json!({"actor":actor,"deadline_seconds":10,"code":exit.code,"forced":exit.forced,"tree_stopped":exit.tree_stopped,"state_released":exit.state_released})
                );
                assert!(
                    exit.code == Some(0)
                        && !exit.forced
                        && exit.tree_stopped
                        && exit.state_released
                );
            }
            Err(error) => {
                failed_actors.push(actor);
                println!(
                    "native incoming admission normal-stop failure: {}",
                    serde_json::json!({"actor":actor,"deadline_seconds":10,"normal_exit_not_accepted":true})
                );
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }
    if let Some(error) = first_error {
        for actor in failed_actors {
            let started = std::time::Instant::now();
            let observation = match actor {
                "sender" => tokio::time::timeout(Duration::from_secs(20), a.wait_for_exit()).await,
                "receiver-0" => {
                    tokio::time::timeout(Duration::from_secs(20), r0.core.wait_for_exit()).await
                }
                "receiver-1" => {
                    tokio::time::timeout(Duration::from_secs(20), r1.core.wait_for_exit()).await
                }
                "receiver-2" => {
                    tokio::time::timeout(Duration::from_secs(20), r2.core.wait_for_exit()).await
                }
                _ => return Err("unknown owned actor".into()),
            };
            let observed = match observation {
                Ok(Ok(exit)) => {
                    serde_json::json!({"actual_exit_observed":true,"code":exit.code,"forced":exit.forced,"tree_stopped":exit.tree_stopped,"state_released":exit.state_released})
                }
                Ok(Err(error)) => {
                    serde_json::json!({"exit_observation_error":true,"managed_failure_reason":match error { Error::ManagedFailure { reason } => Some(reason), _ => None }})
                }
                Err(_) => serde_json::json!({"readonly_observation_deadline_expired":true}),
            };
            println!(
                "native incoming admission readonly exit diagnosis: {}",
                serde_json::json!({"actor":actor,"original_stop_deadline_seconds":10,"readonly_wait_bound_seconds":20,"elapsed_ms":started.elapsed().as_millis(),"new_shutdown_request_sent":false,"force_requested":false,"original_failure_preserved":true,"observed":observed})
            );
        }
        return Err(error.into());
    }
    std::fs::remove_dir_all(root)?;
    println!("native incoming admission cleanup: actual_two_96MiB_source_and_three_receiver_payloads=true all_four_native_identities_keys_certificates=true unrelated_configuration_sentinel=true all_four_normal_code0_nonforced_tree_and_state_exit=true four_actual_saturated_admission_snapshots=true raw_private_support_archives_removed=true");
    Ok(())
}

async fn inspect_admission(
    root: &std::path::Path,
    archive: &std::path::Path,
    selected: i64,
) -> TestResult<serde_json::Value> {
    use std::io::Read;
    struct Inspector(std::process::Child);
    impl Drop for Inspector {
        fn drop(&mut self) {
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
    let stdout = tempfile::NamedTempFile::new_in(root)?;
    let stderr = tempfile::NamedTempFile::new_in(root)?;
    let mut command = std::process::Command::new(
        std::env::var_os("VERYSYNC_TEST_PYTHON").ok_or("explicit fixture Python missing")?,
    );
    command
        .arg(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("scripts")
                .join("inspect-incoming-admission.py"),
        )
        .arg(archive)
        .arg(selected.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(stdout.as_file().try_clone()?)
        .stderr(stderr.as_file().try_clone()?);
    let mut child = Inspector(command.spawn()?);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            return Err("owned admission inspector deadline".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let mut error = String::new();
    stderr.reopen()?.take(4097).read_to_string(&mut error)?;
    assert!(error.len() <= 4096);
    assert!(
        status.success(),
        "native admission inspection failed: {error}"
    );
    let mut output = String::new();
    stdout.reopen()?.take(4097).read_to_string(&mut output)?;
    assert!(output.len() <= 4096);
    Ok(serde_json::from_str(output.trim())?)
}

async fn diagnose_failure(
    receivers: &[Receiver],
    name: &str,
    selected: i64,
    stage: &str,
    phase: &str,
    outer_timeout: bool,
) {
    let mut states = Vec::new();
    for receiver in receivers {
        let observation = match tokio::time::timeout(
            Duration::from_secs(2),
            receiver.core.client().folder_status(&receiver.folder),
        )
        .await
        {
            Ok(Ok(status)) => {
                serde_json::json!({"state":status.state,"global_files":status.global_files,"global_bytes":status.global_bytes,"local_files":status.local_files,"local_bytes":status.local_bytes,"need_files":status.need_files,"need_bytes":status.need_bytes,"completed_file_present":receiver.path.join(name).is_file()})
            }
            Ok(Err(_)) => serde_json::json!({"query_failed":true}),
            Err(_) => serde_json::json!({"diagnostic_query_deadline":true}),
        };
        states.push(observation);
    }
    println!(
        "native incoming admission failure diagnosis: {}",
        serde_json::json!({"selected":selected,"stage":stage,"phase":phase,"stage_deadline_seconds":30,"previous_aggregate_phase_seconds":30,"previous_aggregate30_preserved":false,"receivers":states,"outer_timeout":outer_timeout,"diagnosis_is_not_pass":true})
    );
}
