//! File and index evidence from the owned Local-API instance.

use crate::{check_authorization, device_alias, Stage};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::Path, time::Duration};
use verysync_sidecar::{
    AuditHistorySettings, Client, CreateFolderOptions, DeviceId, Error, EventFilter, EventKind,
    EventOptions, EventStreamItem, EventSubscription, FolderId, FolderPatch, FolderScanPatch,
    FolderState, ListPage, LocalApiClient, LocalApiConnectOptions, LocalApiHistoryFilter,
    ManagedInstance, ManagementEndpoint, SelectiveScope, SelectiveTree, SharePermission,
    TargetPath,
};

const FOLDER_ID: &str = "r33-local-api-index";
const BASE: &[u8] = b"R33 file present before the explicit Local-API scan";
const CONTROL: &[u8] = b"R33 file outside the requested scan subpath";
const OUTSIDE: &[u8] = b"R33 file outside the registered folder";
const POLL: Duration = Duration::from_millis(40);
const WINDOW: Duration = Duration::from_secs(14);
const INDEX_EVENT: &str = "LocalIndexUpdated";

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

async fn sharing_receipts(
    root: &Path,
    managed: &Client,
    local: &LocalApiClient,
) -> Stage<(Value, Value)> {
    check_authorization(root)?;
    let (keys, generation_refusal) = match local.generate_share().await {
        Ok(keys) => (keys, None),
        Err(error @ Error::LicenseRequired { code: 3001, .. }) => {
            check_authorization(root)?;
            let owned = managed
                .generate_share()
                .await
                .map_err(|_| "local-api-test-share-control-unavailable")?;
            (owned, Some(unavailable(&error)))
        }
        Err(error) => return Ok((unavailable(&error), json!({"state":"test-key-unavailable"}))),
    };
    check_authorization(root)?;
    let write = local.validate_share_key(&keys.read_write_key).await;
    check_authorization(root)?;
    let read = local.validate_share_key(&keys.read_only_key).await;
    let valid = match (write, read) {
        (Ok(write), Ok(read))
            if write.permission() == &SharePermission::ReadWrite
                && read.permission() == &SharePermission::ReadOnly
                && write.read_write_key() == Some(&keys.read_write_key)
                && read.read_write_key().is_none()
                && write.read_only_key() == &keys.read_only_key
                && read.read_only_key() == &keys.read_only_key
                && write.device_id() == &managed.instance().device_id
                && read.device_id() == &managed.instance().device_id =>
        {
            json!({"state":"observed","separate_read_only_and_read_write":true,
                   "read_only_key_does_not_match_write_scope":true})
        }
        (Err(write), Err(read)) => {
            let mut result = unavailable(&write);
            result["read_only_control"] = unavailable(&read);
            result
        }
        (Err(error), _) | (_, Err(error)) => unavailable(&error),
        (Ok(_), Ok(_)) => json!({"state":"share-identity-or-permission-mismatch"}),
    };
    let generation = generation_refusal.unwrap_or_else(|| {
        if keys.read_only_key != keys.read_write_key && valid["state"] == "observed" {
            json!({"state":"observed","generated_distinct_scopes":true})
        } else {
            json!({"state":"generated-scope-unconfirmed"})
        }
    });
    Ok((generation, valid))
}

async fn cleanup_owned_temporary(
    root: &Path,
    local: &LocalApiClient,
    id: &FolderId,
    folder: &Path,
) -> Stage<Value> {
    const KEEP: &[u8] = b"Owned ordinary file within the native temporary directory";
    check_authorization(root)?;
    let parent = folder.join(".verysync");
    if fs::symlink_metadata(&parent).is_ok_and(|metadata| !metadata.is_dir()) {
        return Err("local-api-owned-temporary-directory-is-not-regular");
    }
    let session = parent.join("r33-owned.sess");
    let temporary = parent.join("r33-owned.tmp");
    let ordinary = parent.join("r33-keep.dat");
    fs::create_dir_all(&parent)
        .and_then(|()| fs::create_dir(&session))
        .map_err(|_| "local-api-owned-temporary-fixture-unavailable")?;
    for (path, bytes) in [
        (
            session.join("nested.bin"),
            b"Owned session payload".as_slice(),
        ),
        (temporary.clone(), b"Owned temporary payload".as_slice()),
        (ordinary.clone(), KEEP),
    ] {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut file| file.write_all(bytes))
            .map_err(|_| "local-api-owned-temporary-sample-unavailable")?;
    }
    check_authorization(root)?;
    let request = local.request_folder_temporary_cleanup(id).await;
    let retained = file_fingerprint(&ordinary, KEEP)?;
    let gone = |path: &Path| matches!(fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound);
    let placeholders_removed = gone(&temporary) && gone(&session);
    match request {
        Ok(_) if placeholders_removed => Ok(json!({
            "state":"observed","temporary_file_removed":true,"session_directory_removed":true,
            "ordinary_file":retained,
        })),
        Ok(_) => Ok(json!({"state":"temporary-objects-still-present","ordinary_file":retained})),
        Err(error) => {
            let mut result = unavailable(&error);
            result["physical_placeholders_removed"] = json!(placeholders_removed);
            result["ordinary_file"] = retained;
            Ok(result)
        }
    }
}

async fn audit_matches(local: &LocalApiClient, id: &FolderId, relative: &str) -> Stage<Value> {
    let page = ListPage::new(1, 100).map_err(|_| "local-api-audit-page-invalid")?;
    let filter = LocalApiHistoryFilter {
        folder: Some(id.clone()),
        ..Default::default()
    };
    Ok(match local.folder_history(page, &filter).await {
        Ok(snapshot) => {
            let matches = snapshot
                .records
                .iter()
                .flatten()
                .filter(|row| {
                    row.folder_id.as_deref() == Some(id.as_str())
                        && row.name.as_deref() == Some(relative)
                        && row.action.as_ref().is_some_and(|value| !value.is_empty())
                        && row.event_time.is_some()
                })
                .count();
            json!({"state":"read","total":snapshot.total,"matching_records":matches})
        }
        Err(error) => unavailable(&error),
    })
}

async fn observe_index(
    root: &Path,
    source: Result<EventSubscription, Error>,
    id: &FolderId,
) -> Value {
    let mut stream = match source {
        Ok(stream) => stream,
        Err(error) => return unavailable(&error),
    };
    let baseline = stream.cursor().last_id;
    let result = tokio::time::timeout(Duration::from_secs(6), async {
        while check_authorization(root).is_ok() {
            match stream.next().await {
                Some(Ok(EventStreamItem::Event(event)))
                    if event.cursor.last_id > baseline
                        && event.kind == EventKind::Unknown(INDEX_EVENT.into())
                        && event.data().get("folder").and_then(Value::as_str)
                            == Some(id.as_str())
                        && event
                            .data()
                            .get("items")
                            .and_then(Value::as_u64)
                            .is_some_and(|count| count > 0) =>
                {
                    return json!({"state":"observed","cursor_before_scan":baseline,
                                  "cursor_at_index_update":event.cursor.last_id,
                                  "same_test_folder":true,"nonempty_index_update":true});
                }
                Some(Ok(EventStreamItem::Gap(_))) => {
                    return json!({"state":"event-continuity-unconfirmed"});
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => return unavailable(&error),
                None => return json!({"state":"index-stream-ended"}),
            }
        }
        json!({"state":"authorization-withdrawn"})
    })
    .await
    .unwrap_or_else(|_| json!({"state":"owned-index-event-not-observed"}));
    if stream.close().await.is_err() {
        return json!({"state":"index-stream-close-unconfirmed","observation":result});
    }
    result
}

async fn measure(
    root: &Path,
    managed: &Client,
    local: &LocalApiClient,
    id: &FolderId,
    directory: &Path,
    payload: &[u8],
    recording_enabled: bool,
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
    let before_history = audit_matches(local, id, &relative_string).await?;
    let default_events = local.subscribe_index_events(EventOptions::default()).await;
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
    let default_event = observe_index(root, default_events, id).await;
    let history = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            check_authorization(root)?;
            let after = audit_matches(local, id, &relative_string).await?;
            if before_history["matching_records"] == 0
                && after["matching_records"]
                    .as_u64()
                    .is_some_and(|count| count > 0)
            {
                return Ok::<Value, &'static str>(
                    json!({"state":"observed","before":before_history,"after":after,
                                 "same_folder_and_indexed_path":true}),
                );
            }
            if !recording_enabled || after["state"] != "read" {
                return Ok(json!({"state":"record-unconfirmed","before":before_history,
                                 "after":after,"recording_enabled":recording_enabled}));
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        Ok(json!({"state":"owned-audit-record-not-observed","before":before_history}))
    })?;
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
    let filter = EventFilter::new([EventKind::Unknown(INDEX_EVENT.into())])
        .map_err(|_| "local-api-index-event-filter-invalid")?;
    let filtered_event = match local
        .subscribe_filtered_index_events(filter, EventOptions::default())
        .await
    {
        Ok(stream) => {
            check_authorization(root)?;
            if !index_absent(managed, id, &native_control).await? {
                return Err("local-api-filtered-index-control-already-present");
            }
            check_authorization(root)?;
            managed
                .request_scan_subpaths(id, std::slice::from_ref(&native_control))
                .await
                .map_err(|_| "local-api-filtered-index-control-scan-unconfirmed")?;
            let mut event = observe_index(root, Ok(stream), id).await;
            let control_indexed = managed
                .index_file_info(id, &native_control)
                .await
                .is_ok_and(|file| {
                    native_control
                        .to_protocol()
                        .as_ref()
                        .is_ok_and(|name| *name == file.local.name)
                        && file.local.size == CONTROL.len() as u64
                });
            event["separate_control_file_indexed"] = json!(control_indexed);
            if !control_indexed && event["state"] == "observed" {
                event["state"] = json!("filtered-index-file-effect-unconfirmed");
            }
            event
        }
        Err(error) => unavailable(&error),
    };
    let hardware = match local.hardware().await {
        Ok(snapshot) if snapshot.cpu.total_threads > 0 && snapshot.cpu.total_cores > 0 => json!({
            "state":"observed","processor_counts_present":true,
            "physical_memory_reported":snapshot.memory.total_physical_bytes > 0,
            "network_inventory_reported":snapshot.network.nics.is_some(),
        }),
        Ok(_) => json!({"state":"native-hardware-snapshot-has-no-processor-count"}),
        Err(Error::Api { response, .. }) => {
            json!({"state":"native-hardware-snapshot-incomplete","http":response.status()})
        }
        Err(error) => unavailable(&error),
    };
    let (generation, validation) = sharing_receipts(root, managed, local).await?;
    let temp_cleanup = cleanup_owned_temporary(root, local, id, directory).await?;
    Ok(json!({
        "SYM-090":{"state":"observed","http":request.response.status(),"indexed_bytes":bytes,
                   "previously_absent":true,"outside_subpath_still_unindexed":true},
        "SYM-048":browse(local, id, nested, bytes).await,
        "LA-008":summary,
        "LA-009":history,
        "LA-018":stats,
        "LA-003":hardware,
        "LA-025":{"default":default_event,"filtered":filtered_event},
        "LA-026":generation,
        "LA-027":validation,
        "LA-028":temp_cleanup,
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
    let initial_audit = managed.audit_history_settings().await.ok();
    check_authorization(root)?;
    if let Some(previous) = initial_audit.filter(|settings| !settings.enabled) {
        let _ = managed
            .set_audit_history_settings(AuditHistorySettings {
                enabled: true,
                ..previous
            })
            .await;
    }
    let recording_enabled = managed
        .audit_history_settings()
        .await
        .is_ok_and(|state| state.enabled);
    let measured = measure(
        root,
        managed,
        &local,
        &id,
        &directory,
        payload.as_bytes(),
        recording_enabled,
    )
    .await;

    // If permission was withdrawn, the wrapper stops the instance and removes the owned root.
    check_authorization(root)?;
    let audit_restored = if let Some(previous) = initial_audit {
        let current = managed.audit_history_settings().await;
        if current.as_ref().is_ok_and(|settings| *settings != previous) {
            check_authorization(root)?;
            let _ = managed.set_audit_history_settings(previous).await;
        }
        managed
            .audit_history_settings()
            .await
            .is_ok_and(|settings| settings == previous)
    } else {
        true
    };
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
    let mut receipt = json!({"ok":measured.is_ok() && audit_restored,"device":device_alias(core, run),"fixture_unregistered":true,
                            "audit_settings_restored":audit_restored,
                            "sample_after_unregistration":sample,"outside_file":outside});
    match measured {
        Ok(checks) => receipt["checks"] = checks,
        Err(reason) => receipt["reason"] = json!(reason),
    }
    Ok(receipt)
}
