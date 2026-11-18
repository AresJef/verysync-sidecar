//! Distinguish the receiver's default group from the group's parent on Linux.
use super::{configuration_policy_listener, options, TestResult};
use std::{fs, os::unix::fs::MetadataExt, path::Path, process::Command, time::Duration};
use verysync_sidecar::*;

fn verify_group_oracle(parent: &Path) -> TestResult<(u32, u32)> {
    let executable =
        std::env::var_os("VERYSYNC_TEST_PYTHON").ok_or("explicit fixture Python required")?;
    assert!(Path::new(&executable).is_absolute());
    let result = Command::new(executable)
        .args([
            "-c",
            r"
import os, pathlib, sys
parent = pathlib.Path(sys.argv[1])
default = os.getegid()
if os.geteuid() == 0:
    raise SystemExit('the fixture requires an ordinary non-root process')
for group in sorted(set(os.getgroups()) - {default, 0}):
    try:
        os.chown(parent, -1, group)
    except PermissionError:
        continue
    break
else:
    raise SystemExit('fixture has no writable alternate supplementary group')
parent.chmod(0o700)
probe = parent / 'ordinary-creation-oracle'
try:
    probe.write_bytes(b'independent group oracle')
    if probe.stat().st_gid != default or parent.stat().st_gid != group:
        raise SystemExit('ordinary creation did not give an independent group contrast')
    os.chown(probe, os.geteuid(), group)
    if probe.stat().st_gid != group:
        raise SystemExit('same-user group assignment did not take effect')
finally:
    probe.unlink()
print(default, group)
",
        ])
        .arg(parent)
        .output()?;
    if !result.status.success() {
        return Err(format!(
            "ownership oracle failed: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    let output = std::str::from_utf8(&result.stdout)?;
    let (default, parent) = output.trim().split_once(' ').ok_or("group oracle output")?;
    Ok((default.parse()?, parent.parse()?))
}

#[tokio::test]
async fn native_copy_ownership_from_parent_changes_received_group_and_preserves_data() -> TestResult
{
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    let root = tempfile::Builder::new()
        .prefix("vs-parent-group-")
        .tempdir()?
        .keep();
    let sentinel = root.join("private-caller-sentinel");
    fs::write(&sentinel, b"owned caller bytes")?;
    let mut sender = ManagedInstance::start(options(&root.join("sender"))?).await?;
    let mut receiver = ManagedInstance::start(options(&root.join("receiver"))?).await?;
    let sender_id = sender.client().instance().device_id.clone();
    let receiver_id = receiver.client().instance().device_id.clone();
    let address = configuration_policy_listener(&receiver).await?;
    for (client, peer, address) in [
        (sender.client(), &receiver_id, format!("tcp://{address}")),
        (receiver.client(), &sender_id, "dynamic".into()),
    ] {
        client
            .create_device(
                &CreateDeviceOptions::new(peer.clone()).settings(
                    DevicePatch::default()
                        .addresses(vec![address])
                        .allowed_transports(vec![DeviceTransport::Tcp]),
                ),
            )
            .await?;
    }
    let mut observations = Vec::new();
    for enabled in [false, true] {
        let from = root.join(format!("source-{enabled}"));
        let to = root.join(format!("received-{enabled}"));
        fs::create_dir(&from)?;
        fs::create_dir(&to)?;
        let (default, parent) = verify_group_oracle(&to)?;
        let payload = format!("synthetic parent group {enabled}").repeat(2048);
        let name = "native-payload.bin";
        let source_file = from.join(name);
        let received_file = to.join(name);
        fs::write(&source_file, payload.as_bytes())?;
        let share = sender.client().generate_share().await?;
        let rw = sender
            .client()
            .validate_share_key(&share.read_write_key)
            .await?;
        let ro = receiver
            .client()
            .validate_share_key(&share.read_only_key)
            .await?;
        let send_folder = sender
            .client()
            .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&from)).paused(true))
            .await?
            .configuration
            .id;
        let recv_folder = receiver
            .client()
            .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(&to)).paused(true))
            .await?
            .configuration
            .id;
        assert!(
            sender
                .client()
                .update_folder_advanced_configuration(
                    &send_folder,
                    &FolderAdvancedPatch::default().send_ownership(false),
                )
                .await?
                .requested_fields_match
        );
        assert!(
            receiver
                .client()
                .update_folder_advanced_configuration(
                    &recv_folder,
                    &FolderAdvancedPatch::default()
                        .sync_ownership(false)
                        .copy_ownership_from_parent(enabled),
                )
                .await?
                .requested_fields_match
        );
        sender
            .client()
            .share_folder_with(&send_folder, &receiver_id)
            .await?;
        receiver
            .client()
            .share_folder_with(&recv_folder, &sender_id)
            .await?;
        sender.client().resume_folder(&send_folder).await?;
        receiver.client().resume_folder(&recv_folder).await?;
        tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                if received_file.is_file()
                    && fs::read(&received_file)? == payload.as_bytes()
                    && receiver.client().folder_status(&recv_folder).await?.state
                        == Some(FolderState::Idle)
                {
                    return TestResult::Ok(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await??;
        let received = fs::metadata(&received_file)?;
        assert_eq!(fs::read(&source_file)?, payload.as_bytes());
        assert_eq!(received.uid(), fs::metadata(&to)?.uid());
        assert!(fs::metadata(&to)?.gid() == parent);
        observations.push((enabled, received.gid() == default, received.gid() == parent));
    }
    assert_eq!(fs::read(sentinel)?, b"owned caller bytes");
    assert_eq!(sender.client().system_status().await?.device_id, sender_id);
    assert_eq!(
        receiver.client().system_status().await?.device_id,
        receiver_id
    );
    for core in [&mut sender, &mut receiver] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    println!(
        "native parent group effects: {}",
        serde_json::json!({
            "ordinary_creation_distinguished_from_parent": true,
            "same_user_group_assignment_passed": true,
            "enabled_received_default_received_parent": observations,
            "actual_both_file_copies_and_caller_bytes": true,
            "both_normal_owned_exits": true
        })
    );
    fs::remove_dir_all(root)?;
    assert_eq!(
        observations,
        vec![(false, true, false), (true, false, true)]
    );
    Ok(())
}
