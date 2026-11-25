//! Verify the configuration routes on the already qualified isolated device.

use crate::{check_authorization, paid_native_permission, Stage, RESTART};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use verysync_sidecar::{
    CreateFolderOptions, DeviceId, FolderConfig, FolderDefaults, FolderId, FolderPatch,
    LocalApiClient, LocalApiConnectOptions, LocalApiExitAction, ManagedInstance,
    ManagementEndpoint, TargetPath,
};

pub(super) const FIRST_ID: &str = "r33-local-api-read-qualification";
const SECOND_ID: &str = "r33-local-api-config-second";
const CREATED: &str = "R33 Created";
const PATCHED: &str = "R33 Patched";
const REPLACED: &str = "R33 Replaced";
const COLLECTION: &str = "R33 Collection";

struct FolderTarget {
    id: FolderId,
    path: PathBuf,
}

impl FolderTarget {
    fn new(id: &str, path: PathBuf) -> Stage<Self> {
        Ok(Self {
            id: FolderId::parse(id).map_err(|_| "local-api-fixture-folder-id-invalid")?,
            path,
        })
    }

    fn matches(&self, config: &FolderConfig) -> bool {
        config.id == self.id
            && matches!(
                (config.path.to_protocol(), self.path.to_str()),
                (Ok(observed), Some(expected)) if observed == expected
            )
    }
}

async fn open(endpoint: ManagementEndpoint, device: &DeviceId) -> Stage<LocalApiClient> {
    let options = LocalApiConnectOptions::new(endpoint)
        .map_err(|_| "local-api-config-options-unavailable")?
        .expected_device_id(device.clone());
    LocalApiClient::connect(options)
        .await
        .map_err(|_| "local-api-config-handshake-unavailable")
}

async fn configured(local: &LocalApiClient, target: &FolderTarget) -> Stage<FolderConfig> {
    let config = local
        .folder_configuration(&target.id)
        .await
        .map_err(|_| "local-api-exact-configuration-read-unconfirmed")?;
    if !target.matches(&config) {
        return Err("local-api-exact-configuration-target-mismatch");
    }
    Ok(config)
}

async fn require_inventory(local: &LocalApiClient, targets: &[&FolderTarget]) -> Stage<()> {
    let projection = local
        .folders()
        .await
        .map_err(|_| "local-api-configuration-inventory-unavailable")?;
    if projection.len() != targets.len()
        || targets
            .iter()
            .any(|target| !projection.iter().any(|folder| folder.id == target.id))
    {
        return Err("local-api-configuration-inventory-outside-fixture");
    }
    for target in targets {
        configured(local, target).await?;
    }
    Ok(())
}

fn label_applied(folder: &FolderConfig, label: &str) -> Stage<()> {
    if folder.label != label || !folder.paused {
        return Err("local-api-configuration-label-or-pause-unconfirmed");
    }
    Ok(())
}

fn same_configuration(observed: &FolderConfig, expected: &FolderConfig) -> bool {
    observed.id == expected.id
        && matches!(
            (observed.path.to_protocol(), expected.path.to_protocol()),
            (Ok(actual), Ok(desired)) if actual == desired
        )
        && observed.label == expected.label
        && observed.paused == expected.paused
        && observed.extra == expected.extra
}

async fn change_configurations(
    root: &Path,
    local: &LocalApiClient,
    first: &FolderTarget,
    second: &FolderTarget,
    template: &FolderDefaults,
) -> Stage<BTreeMap<&'static str, bool>> {
    require_inventory(local, &[first]).await?;
    let original = configured(local, first).await?;
    check_authorization(root)?;
    let options = CreateFolderOptions::new(second.id.clone(), TargetPath::local(&second.path))
        .label(CREATED)
        .paused(true);
    let created = local
        .create_folder(template, &options)
        .await
        .is_ok_and(|config| second.matches(&config) && config.label == CREATED && config.paused);
    // Each request is submitted once. A separate exact read observes the
    // effect even when the write acknowledgement could not be confirmed.
    require_inventory(local, &[first, second]).await?;
    let mut selected = configured(local, second).await?;
    label_applied(&selected, CREATED)?;

    selected.label = PATCHED.to_owned();
    check_authorization(root)?;
    let patched = local
        .update_folder(&second.id, &FolderPatch::default().label(PATCHED))
        .await
        .is_ok_and(|reply| reply.requested_fields_match && second.matches(&reply.configuration));
    if !same_configuration(&configured(local, second).await?, &selected) {
        return Err("local-api-patch-readback-unconfirmed");
    }

    selected.label = REPLACED.to_owned();
    check_authorization(root)?;
    let replaced = local
        .replace_folder_configuration(&selected)
        .await
        .is_ok_and(|reply| reply.requested_fields_match && second.matches(&reply.configuration));
    let observed = configured(local, second).await?;
    if !same_configuration(&observed, &selected) {
        return Err("local-api-item-replacement-readback-unconfirmed");
    }

    require_inventory(local, &[first, second]).await?;
    if !same_configuration(&configured(local, first).await?, &original) {
        return Err("local-api-unrelated-configuration-changed");
    }
    selected.label = COLLECTION.to_owned();
    check_authorization(root)?;
    let collection = local
        .replace_folder_configurations(&[original.clone(), selected.clone()])
        .await
        .is_ok_and(|reply| reply.configuration_ids_match && reply.requested_fields_match);
    require_inventory(local, &[first, second]).await?;
    if !same_configuration(&configured(local, first).await?, &original)
        || !same_configuration(&configured(local, second).await?, &selected)
    {
        return Err("local-api-collection-replacement-readback-unconfirmed");
    }

    Ok(BTreeMap::from([
        ("LA-010", created),
        ("LA-011", collection),
        ("LA-013", replaced),
        ("LA-014", patched),
    ]))
}

fn snapshot(paths: &[PathBuf]) -> Stage<Vec<Value>> {
    paths
        .iter()
        .map(|path| {
            let kind = fs::symlink_metadata(path)
                .map_err(|_| "local-api-configuration-sample-missing")?
                .file_type();
            if !kind.is_file() {
                return Err("local-api-configuration-sample-must-be-a-regular-file");
            }
            let bytes = fs::read(path).map_err(|_| "local-api-configuration-sample-unavailable")?;
            Ok(json!({"bytes":bytes.len(),"sha256":format!("{:x}", Sha256::digest(&bytes))}))
        })
        .collect()
}

async fn unregister_second(
    root: &Path,
    local: &LocalApiClient,
    first: &FolderTarget,
    second: &FolderTarget,
) -> Stage<bool> {
    require_inventory(local, &[first, second]).await?;
    let previous = configured(local, first).await?;
    check_authorization(root)?;
    let removed = local
        .remove_folder_keep_files(&second.id)
        .await
        .is_ok_and(|reply| {
            reply.configuration_absent && second.matches(&reply.previous_configuration)
        });
    require_inventory(local, &[first]).await?;
    if !same_configuration(&configured(local, first).await?, &previous) {
        return Err("local-api-remove-changed-the-other-configuration");
    }
    Ok(removed)
}

pub(super) async fn verify(
    root: &Path,
    core: &mut ManagedInstance,
    endpoint: ManagementEndpoint,
    run: &str,
    device: &DeviceId,
) -> Stage<Value> {
    check_authorization(root)?;
    if &core.client().instance().device_id != device {
        return Err("local-api-qualified-device-identity-changed");
    }
    let paid = paid_native_permission(core, run).await?;
    let first = FolderTarget::new(FIRST_ID, root.join("synthetic"))?;
    let second = FolderTarget::new(SECOND_ID, root.join("synthetic-configuration"))?;
    fs::create_dir(&second.path).map_err(|_| "local-api-configuration-fixture-unavailable")?;
    let sample = second.path.join("configuration-sample.txt");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&sample)
        .and_then(|mut file| writeln!(file, "R33 owned configuration sample {run}"))
        .map_err(|_| "local-api-configuration-fixture-unavailable")?;
    let files = [
        first.path.join("read-qualification.bin"),
        sample,
        root.join("untouched-control.bin"),
    ];
    let before = snapshot(&files)?;
    let template = core
        .client()
        .folder_defaults()
        .await
        .map_err(|_| "local-api-native-defaults-unavailable")?;
    let local = open(endpoint.clone(), device).await?;
    let mut writes = change_configurations(root, &local, &first, &second, &template).await?;
    let first_before_restart = configured(&local, &first).await?;
    let second_before_restart = configured(&local, &second).await?;

    check_authorization(root)?;
    let restart_request_confirmed = local
        .request_restart()
        .await
        .is_ok_and(|reply| reply.action == LocalApiExitAction::Restart);
    let exited = tokio::time::timeout(Duration::from_secs(15), core.wait_for_exit())
        .await
        .map_err(|_| "local-api-restart-exit-timed-out")?
        .map_err(|_| "local-api-restart-exit-unconfirmed")?;
    if exited.code != Some(3) || exited.forced || !exited.tree_stopped || !exited.state_released {
        return Err("local-api-restart-native-exit-unconfirmed");
    }
    check_authorization(root)?;
    core.restart(RESTART)
        .await
        .map_err(|_| "local-api-restart-startup-unconfirmed")?;
    let after_restart = paid_native_permission(core, run).await?;
    if &core.client().instance().device_id != device || after_restart["device"] != paid["device"] {
        return Err("local-api-restart-device-or-license-unconfirmed");
    }
    let local = open(endpoint, device).await?;
    require_inventory(&local, &[&first, &second]).await?;
    if !same_configuration(&configured(&local, &first).await?, &first_before_restart)
        || !same_configuration(&configured(&local, &second).await?, &second_before_restart)
        || snapshot(&files)? != before
    {
        return Err("local-api-restart-did-not-preserve-owned-configuration-and-data");
    }

    let removed = unregister_second(root, &local, &first, &second).await?;
    let after = snapshot(&files)?;
    if after != before
        || !same_configuration(&configured(&local, &first).await?, &first_before_restart)
    {
        return Err("local-api-remove-did-not-preserve-owned-data");
    }
    writes.insert("LA-015", removed);
    Ok(json!({
        "ok":true,"device":paid["device"],"native_write_acknowledged":writes,
        "independent_exact_readback":["LA-010","LA-011","LA-012","LA-013","LA-014","LA-015"],
        "restart":{"route":"LA-022","request_acknowledged":restart_request_confirmed,
                   "native_exit_code":3,"same_device":true,"same_full_configuration":true},
        "sample_fingerprints_before":before,"sample_fingerprints_after":after,
        "second_folder_unregistered":true,"other_folder_preserved":true
    }))
}

#[cfg(test)]
#[path = "configuration_fixture.rs"]
mod fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use verysync_sidecar::PathStyle;

    fn folder(id: &str, path: &str) -> FolderConfig {
        FolderConfig {
            id: FolderId::parse(id).expect("test folder id"),
            label: "owned fixture".to_owned(),
            path: TargetPath::remote(PathStyle::Unix, path).expect("test path"),
            paused: true,
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn exact_configuration_requires_both_the_owned_identifier_and_the_path() {
        let expected = FolderTarget {
            id: FolderId::parse("owned-local-api").expect("test folder id"),
            path: PathBuf::from("/fixture/folder"),
        };
        assert!(expected.matches(&folder("owned-local-api", "/fixture/folder")));
        assert!(!expected.matches(&folder("another-folder", "/fixture/folder")));
        assert!(!expected.matches(&folder("owned-local-api", "/fixture/another")));
    }
}
