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
                        .max_send_kib_per_second(1)
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
        tokio::time::timeout(Duration::from_secs(30), async {
            for receiver in &receivers {
                assert!(!receiver.path.join(&name).is_file());
                assert!(receiver.core.client().resume_folder(&receiver.folder).await?.requested_fields_match);
            }
            loop {
                let mut all_syncing = true;
                for receiver in &receivers {
                    all_syncing &= receiver.core.client().folder_status(&receiver.folder).await?.state == Some(FolderState::Syncing);
                }
                if all_syncing { break; }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            for index in 0..2 {
                if index == 1 { tokio::time::sleep(Duration::from_millis(500)).await; }
                for receiver in &receivers {
                    assert_eq!(receiver.core.client().folder_status(&receiver.folder).await?.state, Some(FolderState::Syncing));
                    assert!(!receiver.path.join(&name).is_file());
                }
                let profile = a.client().collect_core_support_bundle().await?;
                let archive = evidence.join(format!("cap-{selected}-admission-{index}.zip"));
                std::fs::write(&archive, profile.body_bytes())?;
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
            assert!(a.client().update_bandwidth_configuration(&BandwidthPatch::default().max_send_kib_per_second(0).limit_in_lan(true)).await?.requested_fields_match);
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
        }).await??;
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
            serde_json::json!({"selected":selected,"source_and_all_three_receivers_actual_bytes":true,"saturated_admitted_request_cap_observed":true})
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
    let exit = a.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.code == Some(0) && !exit.forced && exit.tree_stopped && exit.state_released);
    for receiver in &mut receivers {
        let exit = receiver.core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.code == Some(0) && !exit.forced && exit.tree_stopped && exit.state_released);
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
