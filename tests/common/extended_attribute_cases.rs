//! Read the actual filesystem attributes on both sides of an owned transfer.
use super::{configuration_policy_listener, options, TestResult};
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use verysync_sidecar::*;

const KEEP: &str = "user.verysync-sidecar.keep";
const EXCLUDE: &str = "user.verysync-sidecar.exclude";
const KEEP_HEX: &str = "7065726d6974746564008f";
const EXCLUDE_HEX: &str = "6578636c7564656400f0";

fn oracle_output(command: &mut Command) -> TestResult<String> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!(
            "extended attribute oracle failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

#[cfg(target_os = "linux")]
fn python_oracle() -> TestResult<Command> {
    let path = std::env::var_os("VERYSYNC_TEST_PYTHON").ok_or("explicit test Python required")?;
    assert!(Path::new(&path).is_absolute());
    Ok(Command::new(path))
}

fn set_attribute(file: &Path, name: &str, hex: &str) -> TestResult {
    #[cfg(target_os = "macos")]
    oracle_output(
        Command::new("/usr/bin/xattr")
            .args(["-wx", name, hex])
            .arg(file),
    )?;
    #[cfg(target_os = "linux")]
    oracle_output(
        python_oracle()?
            .args([
                "-c",
                "import os, sys; os.setxattr(sys.argv[1], sys.argv[2], bytes.fromhex(sys.argv[3]))",
            ])
            .arg(file)
            .args([name, hex]),
    )?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn attribute(file: &Path, name: &str) -> TestResult<Option<String>> {
    let names = oracle_output(Command::new("/usr/bin/xattr").arg(file))?;
    if !names.lines().any(|line| line == name) {
        return Ok(None);
    }
    let raw = oracle_output(Command::new("/usr/bin/xattr").args(["-px", name]).arg(file))?;
    let hex = raw
        .split_ascii_whitespace()
        .collect::<String>()
        .to_ascii_lowercase();
    Ok(Some(hex))
}

#[cfg(target_os = "linux")]
fn attribute(file: &Path, name: &str) -> TestResult<Option<String>> {
    let hex = oracle_output(
        python_oracle()?
            .args([
                "-c",
                r"
import errno, os, sys
try:
    print(os.getxattr(sys.argv[1], sys.argv[2]).hex())
except OSError as error:
    if error.errno != errno.ENODATA:
        raise
    print('absent')
",
            ])
            .arg(file)
            .arg(name),
    )?;
    let hex = hex.trim_end();
    Ok((hex != "absent").then(|| hex.to_owned()))
}

#[tokio::test]
async fn native_extended_attribute_filter_uses_first_rule_and_preserves_files() -> TestResult {
    transfer_with_filter(true).await?;
    transfer_with_filter(false).await
}

async fn transfer_with_filter(exclude_first: bool) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-xattr-")
        .tempdir()?
        .keep();
    let from = root.join("source");
    let to = root.join("received");
    std::fs::create_dir(&from)?;
    std::fs::create_dir(&to)?;
    let sentinel = root.join("private-caller-sentinel");
    std::fs::write(&sentinel, b"caller-owned bytes")?;
    // Verify the receiver-side filesystem independently before starting either core.
    set_attribute(&sentinel, KEEP, KEEP_HEX)?;
    assert_eq!(attribute(&sentinel, KEEP)?.as_deref(), Some(KEEP_HEX));
    assert_eq!(attribute(&sentinel, EXCLUDE)?, None);
    let name = "synthetic-xattr.bin";
    let body = b"Rust native xattr transfer fixture".repeat(1024);
    let source_file = from.join(name);
    std::fs::write(&source_file, &body)?;
    set_attribute(&source_file, KEEP, KEEP_HEX)?;
    set_attribute(&source_file, EXCLUDE, EXCLUDE_HEX)?;
    assert_eq!(attribute(&source_file, KEEP)?.as_deref(), Some(KEEP_HEX));
    assert_eq!(
        attribute(&source_file, EXCLUDE)?.as_deref(),
        Some(EXCLUDE_HEX)
    );

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
    // Both phases use the same attribute names and values. Their rule order differs.
    let mut rules = vec![
        ExtendedAttributeRule::new(EXCLUDE, false)?,
        ExtendedAttributeRule::new("user.verysync-sidecar.*", true)?,
    ];
    if !exclude_first {
        rules.reverse();
    }
    let filter = ExtendedAttributeFilter::new(rules, 2048, 8192)?;
    let sent = sender
        .client()
        .update_folder_advanced_configuration(
            &send_folder,
            &FolderAdvancedPatch::default()
                .send_extended_attributes(true)
                .extended_attribute_filter(filter),
        )
        .await?;
    assert!(sent.requested_fields_match);
    let applied = receiver
        .client()
        .update_folder_advanced_configuration(
            &recv_folder,
            &FolderAdvancedPatch::default().sync_extended_attributes(true),
        )
        .await?;
    assert!(applied.requested_fields_match);

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
    let received = to.join(name);
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            if received.is_file()
                && std::fs::read(&received)? == body
                && receiver.client().folder_status(&recv_folder).await?.state
                    == Some(FolderState::Idle)
            {
                return TestResult::Ok(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    println!("native extended attribute transfer: actual_file_bytes=true; sender_oracle=true");
    let actual_keep = attribute(&received, KEEP)?;
    let actual_excluded = attribute(&received, EXCLUDE)?;
    assert_eq!(std::fs::read(from.join(name))?, body);
    assert_eq!(attribute(&source_file, KEEP)?.as_deref(), Some(KEEP_HEX));
    assert_eq!(
        attribute(&source_file, EXCLUDE)?.as_deref(),
        Some(EXCLUDE_HEX)
    );
    assert_eq!(std::fs::read(&sentinel)?, b"caller-owned bytes");
    assert_eq!(attribute(&sentinel, KEEP)?.as_deref(), Some(KEEP_HEX));
    assert_eq!(sender.client().system_status().await?.device_id, sender_id);
    assert_eq!(
        receiver.client().system_status().await?.device_id,
        receiver_id
    );
    for core in [&mut sender, &mut receiver] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    assert_eq!(
        actual_keep.as_deref(),
        Some(KEEP_HEX),
        "receiver applied attribute"
    );
    assert_eq!(
        actual_excluded.as_deref(),
        (!exclude_first).then_some(EXCLUDE_HEX),
        "receiver honors the first matching rule"
    );
    std::fs::remove_dir_all(root)?;
    println!(
        "native_extended_attribute_effects: {}",
        serde_json::json!({
            "exclude_first": exclude_first,
            "actual_overlapping_attribute_present": actual_excluded.is_some(),
            "actual_allowed_attribute_bytes": true,
            "actual_file_and_caller_data_preserved": true,
            "actual_both_normal_owned_exits": true
        })
    );
    Ok(())
}
