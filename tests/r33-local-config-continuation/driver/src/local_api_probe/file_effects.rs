//! File and index evidence from the owned Local-API instance.

use crate::{check_authorization, device_alias, Stage};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, time::Duration};
use verysync_sidecar::{
    Client, CreateFolderOptions, DeviceId, Error, FolderId, FolderPatch, FolderScanPatch,
    FolderState, LocalApiClient, LocalApiConnectOptions, ManagedInstance, ManagementEndpoint,
    SelectiveScope, SelectiveTree, TargetPath,
};

const FOLDER_ID: &str = "r33-local-api-index";
const BASE: &[u8] = b"R33 file present before the explicit Local-API scan";
const CONTROL: &[u8] = b"R33 file outside the requested scan subpath";
const OUTSIDE: &[u8] = b"R33 file outside the registered folder";
const POLL: Duration = Duration::from_millis(40);
const WINDOW: Duration = Duration::from_secs(14);

pub(super) fn unavailable(error: &Error) -> Value {
    match error {
        Error::LicenseRequired { code, response } => {
            json!({"state":"license-required","code":code,"http":response.status()})
        }
        Error::Http { response } | Error::AccessDenied { response } => {
            json!({"state":"http-failure","http":response.status()})
        }
        _ => json!({"state":"unconfirmed"}),
    }
}

fn optional_fingerprint(path: &Path, expected: &[u8]) -> Stage<Option<Value>> {
    let actual = match fs::read(path) {
        Ok(actual) => actual,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("local-api-index-owned-sample-unavailable"),
    };
    if actual != expected {
        return Err("local-api-index-owned-sample-changed");
    }
    Ok(Some(
        json!({"bytes":actual.len(),"sha256":format!("{:x}", Sha256::digest(&actual))}),
    ))
}

fn file_fingerprint(path: &Path, expected: &[u8]) -> Stage<Value> {
    optional_fingerprint(path, expected)?.ok_or("local-api-index-owned-sample-unavailable")
}

async fn index_absent(managed: &Client, id: &FolderId, relative: &TargetPath) -> Stage<bool> {
    match managed.index_file_info(id, relative).await {
        Ok(info) => Ok(info.local.name.is_empty()),
        Err(Error::Http { response }) if response.status() == 404 => Ok(true),
        Err(_) => Err("local-api-index-missing-file-lookup-unconfirmed"),
    }
}

fn browse_entry(tree: &SelectiveTree, name: &str, directory: bool, size: Option<u64>) -> bool {
    tree.entries.get(name).is_some_and(|entry| {
        entry.name == name
            && entry.is_directory == directory
            && (size.is_none() || entry.size == size)
    })
}

async fn browse(local: &LocalApiClient, id: &FolderId, nested: &Path, size: u64) -> Value {
    match local.browse_folder(id, &SelectiveScope::FolderRoot).await {
        Ok(root) if browse_entry(&root, "nested", true, None) => {}
        Ok(_) => return json!({"state":"fixture-directory-not-observed"}),
        Err(error) => return unavailable(&error),
    }
    let scope = SelectiveScope::Path(TargetPath::local(nested));
    match local.browse_folder(id, &scope).await {
        Ok(tree) if browse_entry(&tree, "sample.bin", false, Some(size)) => {
            json!({"state":"observed","directory":true,"file_bytes":size})
        }
        Ok(_) => json!({"state":"fixture-file-not-observed"}),
        Err(error) => unavailable(&error),
    }
}

async fn measure(
    root: &Path,
    managed: &Client,
    local: &LocalApiClient,
    id: &FolderId,
    directory: &Path,
    payload: &[u8],
) -> Stage<Value> {
    check_authorization(root)?;
    let configured = managed
        .update_folder_scan_configuration(
            id,
            &FolderScanPatch::default()
                .watcher(false)
                .rescan_interval_seconds(0),
        )
        .await
        .map_err(|_| "local-api-index-fixture-scan-settings-unconfirmed")?;
    if !configured.requested_fields_match {
        return Err("local-api-index-fixture-scan-settings-mismatch");
    }
    check_authorization(root)?;
    let enabled = managed
        .update_folder(id, &FolderPatch::default().paused(false))
        .await
        .map_err(|_| "local-api-index-fixture-start-unconfirmed")?;
    if !enabled.requested_fields_match {
        return Err("local-api-index-fixture-start-mismatch");
    }
    tokio::time::timeout(WINDOW, async {
        loop {
            check_authorization(root)?;
            let status = managed
                .folder_status(id)
                .await
                .map_err(|_| "local-api-index-baseline-unavailable")?;
            if status.state == Some(FolderState::Idle) && status.local_files == Some(1) {
                return Ok::<(), &'static str>(());
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .map_err(|_| "local-api-index-baseline-timed-out")??;

    let nested = Path::new("nested");
    let relative = nested.join("sample.bin");
    let sample = directory.join(&relative);
    let outside_scan = Path::new("untouched-while-scanning.bin");
    let control = directory.join(outside_scan);
    let native_relative = TargetPath::local(&relative);
    let native_control = TargetPath::local(outside_scan);
    let relative_string = native_relative
        .to_protocol()
        .map_err(|_| "local-api-index-relative-path-invalid")?;
    let bytes = payload.len() as u64;
    check_authorization(root)?;
    fs::write(&sample, payload)
        .and_then(|()| fs::write(&control, CONTROL))
        .map_err(|_| "local-api-index-synthetic-write-unavailable")?;
    if !index_absent(managed, id, &native_relative).await?
        || !index_absent(managed, id, &native_control).await?
    {
        return Err("local-api-index-fixture-already-scanned");
    }
    check_authorization(root)?;
    let request = local
        .request_scan(id, &SelectiveScope::Path(native_relative.clone()))
        .await
        .map_err(|_| "local-api-index-one-scan-unconfirmed")?;
    let observed = tokio::time::timeout(WINDOW, async {
        loop {
            check_authorization(root)?;
            match managed.index_file_info(id, &native_relative).await {
                Ok(info) if info.local.name == relative_string && info.local.size == bytes => {
                    return Ok(())
                }
                Ok(_) => {}
                Err(Error::Http { response }) if response.status() == 404 => {}
                Err(_) => return Err("local-api-index-effect-lookup-unconfirmed"),
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await;
    observed.map_err(|_| "local-api-index-effect-timed-out")??;
    if !index_absent(managed, id, &native_control).await? {
        return Err("local-api-index-scan-expanded-beyond-selected-path");
    }
    let expected_index_bytes = (BASE.len() + payload.len()) as u64;
    let summary = match local.folder_summaries().await {
        Ok(rows)
            if rows.get(id).is_some_and(|value| {
                value.local_files == Some(2) && value.local_bytes == Some(expected_index_bytes)
            }) =>
        {
            json!({"state":"observed","local_files":2,"local_bytes":expected_index_bytes})
        }
        Ok(_) => json!({"state":"indexed-file-set-not-observed"}),
        Err(error) => unavailable(&error),
    };
    let management_stats = managed.folder_statistics().await.ok();
    let management_scan = management_stats
        .as_ref()
        .and_then(|rows| rows.get(id))
        .and_then(|stats| stats.last_scan.as_deref());
    let stats = match local.folder_statistics().await {
        Ok(rows)
            if rows
                .get(id)
                .and_then(|stats| stats.last_scan.as_deref())
                .is_some_and(|timestamp| {
                    !timestamp.is_empty()
                        && !timestamp.starts_with("0001-")
                        && Some(timestamp) == management_scan
                }) =>
        {
            json!({"state":"observed","matches_management_last_scan":true})
        }
        Ok(_) => json!({"state":"folder-scan-statistic-not-observed"}),
        Err(error) => unavailable(&error),
    };
    Ok(json!({
        "SYM-090":{"state":"observed","http":request.response.status(),"indexed_bytes":bytes,
                   "previously_absent":true,"outside_subpath_still_unindexed":true},
        "SYM-048":browse(local, id, nested, bytes).await,
        "LA-008":summary,
        "LA-018":stats,
    }))
}

pub(super) async fn verify(
    root: &Path,
    core: &ManagedInstance,
    endpoint: ManagementEndpoint,
    device: &DeviceId,
    run: &str,
) -> Stage<Value> {
    check_authorization(root)?;
    let managed = core.client();
    if &managed.instance().device_id != device {
        return Err("local-api-file-device-mismatch");
    }
    let local = LocalApiClient::connect(
        LocalApiConnectOptions::new(endpoint)
            .map_err(|_| "local-api-file-options-unavailable")?
            .expected_device_id(device.clone()),
    )
    .await
    .map_err(|_| "local-api-file-handshake-unconfirmed")?;
    let prior = managed
        .folders()
        .await
        .map_err(|_| "local-api-file-registry-unavailable")?;
    let id = FolderId::parse(FOLDER_ID).map_err(|_| "local-api-file-folder-id-invalid")?;
    let parent = root.join("local-api-file-check");
    fs::create_dir(&parent).map_err(|_| "local-api-file-test-root-unavailable")?;
    let directory = parent.join("indexed");
    let nested = directory.join("nested");
    let outside = parent.join("untouched.bin");
    fs::create_dir(&directory)
        .and_then(|()| fs::create_dir(&nested))
        .and_then(|()| fs::write(directory.join("before.bin"), BASE))
        .and_then(|()| fs::write(&outside, OUTSIDE))
        .map_err(|_| "local-api-file-fixture-unavailable")?;
    let path = TargetPath::local(&directory);
    let expected_path = path
        .to_protocol()
        .map_err(|_| "local-api-file-fixture-path-invalid")?;
    check_authorization(root)?;
    let created = managed
        .create_folder(&CreateFolderOptions::new(id.clone(), path.clone()).paused(true))
        .await
        .map_err(|_| "local-api-file-fixture-create-unconfirmed")?;
    if created.id != id || !created.paused || created.path.to_protocol().ok() != Some(expected_path)
    {
        return Err("local-api-file-fixture-configuration-mismatch");
    }
    let payload = format!("R33 Local-API indexed sample {run}\n");
    let measured = measure(root, managed, &local, &id, &directory, payload.as_bytes()).await;

    // If permission was withdrawn, the wrapper stops the instance and removes the owned root.
    check_authorization(root)?;
    let sample_path = nested.join("sample.bin");
    let control_path = directory.join("untouched-while-scanning.bin");
    let before_sample = optional_fingerprint(&sample_path, payload.as_bytes())?;
    let before_control = optional_fingerprint(&control_path, CONTROL)?;
    let current = managed
        .folder(&id)
        .await
        .map_err(|_| "local-api-file-cleanup-target-unconfirmed")?;
    if current.id != id || current.path.to_protocol().ok() != Some(expected_path) {
        return Err("local-api-file-cleanup-target-mismatch");
    }
    check_authorization(root)?;
    managed
        .remove_folder_keep_files(&id)
        .await
        .map_err(|_| "local-api-file-cleanup-unconfirmed")?;
    let remaining = managed
        .folders()
        .await
        .map_err(|_| "local-api-file-cleanup-registry-unconfirmed")?;
    if remaining.len() != prior.len()
        || prior.iter().any(|expected| {
            !remaining
                .iter()
                .any(|actual| super::configuration::same_configuration(actual, expected))
        })
    {
        return Err("local-api-file-cleanup-registry-mismatch");
    }
    let outside = file_fingerprint(&outside, OUTSIDE)?;
    let sample = optional_fingerprint(&sample_path, payload.as_bytes())?;
    let control = optional_fingerprint(&control_path, CONTROL)?;
    file_fingerprint(&directory.join("before.bin"), BASE)?;
    if sample != before_sample
        || control != before_control
        || (measured.is_ok() && (sample.is_none() || control.is_none()))
    {
        return Err("local-api-index-unregistration-changed-owned-data");
    }
    let mut receipt = json!({"ok":measured.is_ok(),"device":device_alias(core, run),"fixture_unregistered":true,
                            "sample_after_unregistration":sample,"outside_file":outside});
    match measured {
        Ok(checks) => receipt["checks"] = checks,
        Err(reason) => receipt["reason"] = json!(reason),
    }
    Ok(receipt)
}
