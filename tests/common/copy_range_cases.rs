//! Observe actual reuse of a previously transferred regular file.
use super::{configuration_policy_listener, name_policy_connection_pair, options, TestResult};
use std::{
    fs::{self, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::Path,
    time::Duration,
};
use verysync_sidecar::*;

const FILE_LEN: usize = 8 * 1024 * 1024;
const CHANGED_LEN: usize = 128 * 1024;
const PAYLOAD: &str = "copy-range-fixture.bin";

fn sample(mut value: u64) -> Vec<u8> {
    // Different deterministic blocks make both the full transfer and partial reuse observable.
    let mut data = Vec::with_capacity(FILE_LEN);
    for _ in 0..FILE_LEN / 8 {
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        data.extend_from_slice(&value.to_le_bytes());
    }
    data
}

async fn peer_counter(client: &Client, peer: &DeviceId) -> TestResult<(String, u64)> {
    let mut snapshot = client.connections().await?;
    let live = snapshot
        .connections
        .remove(peer)
        .filter(|peer| peer.connected)
        .ok_or("the expected direct peer is not connected")?;
    Ok((
        live.started_at.ok_or("peer connection time is missing")?,
        live.in_bytes_total.ok_or("peer receive count is missing")?,
    ))
}

async fn receive_exact(
    client: &Client,
    folder: &FolderId,
    path: &Path,
    expected: &[u8],
) -> TestResult {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if path.is_file()
                && fs::read(path)? == expected
                && client.folder_status(folder).await?.state == Some(FolderState::Idle)
            {
                return TestResult::Ok(());
            }
            tokio::time::sleep(Duration::from_millis(75)).await;
        }
    })
    .await?
}

#[tokio::test]
async fn native_copy_range_methods_reuse_old_blocks_and_preserve_bytes() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-native-copy-range-")
        .tempdir()?
        .keep()
        .canonicalize()?;
    let sentinel = root.join("caller-sentinel.bin");
    fs::write(&sentinel, b"owned caller bytes")?;
    let mut sender = ManagedInstance::start(options(&root.join("sender"))?).await?;
    let mut receiver = ManagedInstance::start(options(&root.join("receiver"))?).await?;
    let receiver_pid = receiver.process_id();
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
    name_policy_connection_pair(&sender, &receiver, true).await?;

    let mut receipts = Vec::new();
    for (name, method, seed) in [
        ("standard", CopyRangeMethod::Standard, 5_814_137),
        (
            "copy-file-range",
            CopyRangeMethod::CopyFileRange,
            581_983_123,
        ),
    ] {
        let from = root.join(format!("sender-{name}"));
        let to = root.join(format!("receiver-{name}"));
        fs::create_dir(&from)?;
        fs::create_dir(&to)?;
        let source = from.join(PAYLOAD);
        let destination = to.join(PAYLOAD);
        let keys = sender.client().generate_share().await?;
        let left = sender
            .client()
            .validate_share_key(&keys.read_write_key)
            .await?;
        let right = receiver
            .client()
            .validate_share_key(&keys.read_write_key)
            .await?;
        let source_folder = sender
            .client()
            .join_folder(&JoinFolderOptions::new(left, TargetPath::local(&from)).paused(true))
            .await?
            .configuration
            .id;
        let destination_folder = receiver
            .client()
            .join_folder(&JoinFolderOptions::new(right, TargetPath::local(&to)).paused(true))
            .await?
            .configuration
            .id;
        assert!(
            sender
                .client()
                .update_folder_scan_configuration(
                    &source_folder,
                    &FolderScanPatch::default()
                        .watcher(false)
                        .rescan_interval_seconds(0),
                )
                .await?
                .requested_fields_match
        );
        let update = receiver
            .client()
            .update_folder_advanced_configuration(
                &destination_folder,
                &FolderAdvancedPatch::default()
                    .copy_range_method(method.clone())
                    .block_indexing(true),
            )
            .await?;
        assert!(update.requested_fields_match);
        assert_eq!(update.configuration.copy_range_method, Some(method));
        sender
            .client()
            .share_folder_with(&source_folder, &receiver_id)
            .await?;
        receiver
            .client()
            .share_folder_with(&destination_folder, &sender_id)
            .await?;
        sender.client().resume_folder(&source_folder).await?;
        receiver.client().resume_folder(&destination_folder).await?;

        let before = peer_counter(receiver.client(), &sender_id).await?;
        let mut data = sample(seed);
        fs::write(&source, &data)?;
        sender
            .client()
            .request_scan_subpaths(&source_folder, &[TargetPath::local(PAYLOAD)])
            .await?;
        receive_exact(receiver.client(), &destination_folder, &destination, &data).await?;
        let first = peer_counter(receiver.client(), &sender_id).await?;

        let change = FILE_LEN - CHANGED_LEN;
        for byte in &mut data[change..] {
            *byte ^= 0xff;
        }
        {
            let mut file = OpenOptions::new().write(true).open(&source)?;
            file.seek(SeekFrom::Start(change as u64))?;
            file.write_all(&data[change..])?;
        }
        sender
            .client()
            .request_scan_subpaths(&source_folder, &[TargetPath::local(PAYLOAD)])
            .await?;
        receive_exact(receiver.client(), &destination_folder, &destination, &data).await?;
        let second = peer_counter(receiver.client(), &sender_id).await?;
        assert_eq!(
            before.0, first.0,
            "peer reconnected during initial transfer"
        );
        assert_eq!(
            first.0, second.0,
            "peer reconnected during changed-block transfer"
        );
        let fresh_bytes = first
            .1
            .checked_sub(before.1)
            .ok_or("peer counter regressed")?;
        let changed_bytes = second
            .1
            .checked_sub(first.1)
            .ok_or("peer counter regressed")?;
        assert_eq!(fs::read(&source)?, data);
        receipts.push((name, fresh_bytes, changed_bytes));
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
    fs::remove_dir_all(&root)?;
    println!(
        "native copy range transfer effects: {}",
        serde_json::json!({
            "receiver_pid": receiver_pid,
            "fixture_root": root,
            "file_bytes": FILE_LEN,
            "changed_bytes": CHANGED_LEN,
            "fresh_and_changed_network_bytes": receipts,
            "all_versions_match_and_both_normal_owned_exits": true,
        })
    );
    for (method, fresh_bytes, changed_bytes) in receipts {
        assert!(
            fresh_bytes >= (FILE_LEN * 3 / 4) as u64 && changed_bytes < (FILE_LEN / 4) as u64,
            "no measurable reuse for {method}: fresh={fresh_bytes} changed={changed_bytes}"
        );
    }
    Ok(())
}
