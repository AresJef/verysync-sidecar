//! Observe permissions on files transferred by two owned VerySync instances.
use super::{configuration_policy_listener, options, TestResult};
use std::{fs, os::unix::fs::PermissionsExt, time::Duration};
use verysync_sidecar::*;

#[tokio::test]
async fn native_receiver_permission_selection_controls_actual_file_modes() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-receive-permissions-")
        .tempdir()?
        .keep();
    let sentinel = root.join("caller-sentinel");
    fs::write(&sentinel, b"caller data")?;
    let mut sender = ManagedInstance::start(options(&root.join("sender"))?).await?;
    let mut receiver = ManagedInstance::start(options(&root.join("receiver"))?).await?;
    let sender_id = sender.client().instance().device_id.clone();
    let receiver_id = receiver.client().instance().device_id.clone();
    assert_ne!(sender_id, receiver_id);
    let address = configuration_policy_listener(&receiver).await?;
    for (client, peer, endpoint) in [
        (sender.client(), &receiver_id, format!("tcp://{address}")),
        (receiver.client(), &sender_id, "dynamic".into()),
    ] {
        let settings = DevicePatch::default()
            .addresses(vec![endpoint])
            .allowed_transports(vec![DeviceTransport::Tcp]);
        client
            .create_device(&CreateDeviceOptions::new(peer.clone()).settings(settings))
            .await?;
    }
    let samples = [
        (
            "owner-execute.bin",
            0o700,
            b"executable synthetic bytes".repeat(256),
        ),
        (
            "owner-data.bin",
            0o600,
            b"ordinary synthetic bytes".repeat(256),
        ),
    ];
    let mut observed = Vec::new();
    for ignore in [false, true] {
        let from = root.join(format!("source-{ignore}"));
        let to = root.join(format!("received-{ignore}"));
        fs::create_dir(&from)?;
        fs::create_dir(&to)?;
        for (name, mode, bytes) in &samples {
            let source = from.join(name);
            fs::write(&source, bytes)?;
            fs::set_permissions(&source, fs::Permissions::from_mode(*mode))?;
            assert_eq!(fs::metadata(source)?.permissions().mode() & 0o777, *mode);
        }
        let keys = sender.client().generate_share().await?;
        let rw = sender
            .client()
            .validate_share_key(&keys.read_write_key)
            .await?;
        let receiver_key = receiver
            .client()
            .validate_share_key(&keys.read_write_key)
            .await?;
        let src = sender
            .client()
            .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&from)).paused(true))
            .await?
            .configuration
            .id;
        let dst = receiver
            .client()
            .join_folder(&JoinFolderOptions::new(receiver_key, TargetPath::local(&to)).paused(true))
            .await?
            .configuration
            .id;
        for (role, client, folder, ignore) in [
            ("sender", sender.client(), &src, false),
            ("receiver", receiver.client(), &dst, ignore),
        ] {
            let previous = client
                .folder_advanced_configuration(folder)
                .await?
                .ignore_permissions;
            let reply = client
                .update_folder_advanced_configuration(
                    folder,
                    &FolderAdvancedPatch::default().ignore_permissions(ignore),
                )
                .await?;
            assert!(
                reply.requested_fields_match,
                "{role} ignore_permissions requested={ignore} previous={previous:?} actual={:?}",
                reply.configuration.ignore_permissions
            );
            assert_eq!(reply.configuration.ignore_permissions, Some(ignore));
        }
        sender
            .client()
            .share_folder_with(&src, &receiver_id)
            .await?;
        receiver
            .client()
            .share_folder_with(&dst, &sender_id)
            .await?;
        sender.client().resume_folder(&src).await?;
        receiver.client().resume_folder(&dst).await?;
        tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                let first = to.join(samples[0].0);
                let second = to.join(samples[1].0);
                if first.is_file()
                    && second.is_file()
                    && fs::read(first)? == samples[0].2
                    && fs::read(second)? == samples[1].2
                    && receiver.client().folder_status(&dst).await?.state == Some(FolderState::Idle)
                {
                    return TestResult::Ok(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await??;
        let mut modes = Vec::new();
        for (name, mode, bytes) in &samples {
            let source = from.join(name);
            assert_eq!(fs::read(&source)?, *bytes);
            assert_eq!(fs::metadata(source)?.permissions().mode() & 0o777, *mode);
            modes.push(fs::metadata(to.join(name))?.permissions().mode() & 0o777);
        }
        observed.push((ignore, modes));
    }
    assert_eq!(fs::read(sentinel)?, b"caller data");
    assert_eq!(sender.client().system_status().await?.device_id, sender_id);
    assert_eq!(
        receiver.client().system_status().await?.device_id,
        receiver_id
    );
    for core in [&mut sender, &mut receiver] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    fs::remove_dir_all(root)?;
    println!(
        "native file permission effects: {}",
        serde_json::json!({
            "ignore_permissions_and_received_modes": observed,
            "all_four_received_files_match_and_preserve_source_files": true,
            "caller_sentinel_and_distinct_identities_retained": true,
            "both_normal_owned_exits": true,
        })
    );
    assert_eq!(observed[0], (false, vec![0o700, 0o600]));
    assert_eq!(observed[1].1[0], observed[1].1[1]);
    assert_eq!(observed[1].1[0] & 0o100, 0);
    Ok(())
}
