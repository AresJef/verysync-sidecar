//! Owned two-core selective sync acceptance, with independently read data.

use crate::{audit_files, device_alias, end, inspect, record, schedule, start, Stage};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use verysync_sidecar::{
    Client, DeviceId, Error, FolderId, ManagedInstance, SelectiveAction, SelectiveBrowseOptions,
    SelectiveEntry, SelectiveScope, SelectiveTree, TargetPath,
};

const FILE: &str = "select-one.bin";
const CHILD: &str = "nested-sample.bin";
const DIRECTORY: &str = "nested";
const REMOVE: &str = "all-peers-sample.bin";
const CONTROL: &str = "unselected-control.bin";
const SAMPLES: [&str; 4] = [FILE, CHILD, REMOVE, CONTROL];
const SENTINELS: [&str; 2] = ["source-outside-share", "target-outside-share"];
const WAIT: Duration = Duration::from_secs(25);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct SampleState {
    sample: &'static str,
    selected: Option<bool>,
    native_local_presence: Option<bool>,
    source: Option<Value>,
    target: Option<Value>,
}

fn sample_path(name: &str) -> PathBuf {
    match name {
        CHILD => Path::new(DIRECTORY).join(CHILD),
        _ => PathBuf::from(name),
    }
}

fn project_entry<'a>(tree: &'a SelectiveTree, name: &str) -> Option<&'a SelectiveEntry> {
    let entry = if name == CHILD {
        tree.entries
            .get(DIRECTORY)?
            .children
            .as_ref()?
            .entries
            .get(CHILD)?
    } else {
        tree.entries.get(name)?
    };
    (entry.name == name && !entry.is_directory).then_some(entry)
}

fn read_fingerprint(path: &Path) -> Stage<Option<Value>> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => {
            let bytes = fs::read(path).map_err(|_| "selective-sample-read-failed")?;
            Ok(Some(
                json!({"bytes":bytes.len(),"sha256":format!("{:x}", Sha256::digest(&bytes))}),
            ))
        }
        Ok(_) => Err("selective-owned-sample-not-a-regular-file"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("selective-sample-existence-unverified"),
    }
}

struct Registration {
    sender_folder: FolderId,
    receiver_folder: FolderId,
    source: PathBuf,
    target: PathBuf,
}

async fn configure(
    root: &Path,
    sender: &ManagedInstance,
    receiver: &ManagedInstance,
    run: &str,
    revoke: &Path,
) -> Stage<Registration> {
    let (source_port, target_port) = audit_files::fixture_ports()?;
    let destination = audit_files::fixed_listener(receiver.client(), target_port, revoke).await?;
    audit_files::fixed_listener(sender.client(), source_port, revoke).await?;
    schedule::check_authorization(revoke)?;
    let source = root.join("source");
    let target = root.join("target");
    fs::create_dir(&source).map_err(|_| "selective-source-directory-failed")?;
    fs::create_dir(&target).map_err(|_| "selective-target-directory-failed")?;
    fs::create_dir(source.join(DIRECTORY)).map_err(|_| "selective-source-subdirectory-failed")?;
    for name in SENTINELS {
        schedule::check_authorization(revoke)?;
        fs::write(
            root.join(name),
            format!("isolated selective sentinel {run}\n"),
        )
        .map_err(|_| "selective-unrelated-sentinel-write-failed")?;
    }
    for name in SAMPLES {
        schedule::check_authorization(revoke)?;
        fs::write(
            source.join(sample_path(name)),
            format!("isolated selective sample {run} {name}\n"),
        )
        .map_err(|_| "selective-source-seed-write-failed")?;
    }
    let (sender_folder, receiver_folder) = audit_files::register(
        sender.client(),
        receiver.client(),
        &source,
        &target,
        destination,
        revoke,
    )
    .await?;
    schedule::check_authorization(revoke)?;
    let mode = receiver
        .client()
        .set_folder_selective_enabled(&receiver_folder, true)
        .await
        .map_err(|_| "selective-mode-write-failed")?;
    if !mode.requested_mode_match || !mode.configuration.enabled {
        return Err("selective-mode-did-not-read-back-as-enabled");
    }
    for (client, folder) in [
        (sender.client(), &sender_folder),
        (receiver.client(), &receiver_folder),
    ] {
        schedule::check_authorization(revoke)?;
        client
            .resume_folder(folder)
            .await
            .map_err(|_| "selective-owned-folder-resume-failed")?;
    }
    schedule::check_authorization(revoke)?;
    sender
        .client()
        .request_scan(&sender_folder)
        .await
        .map_err(|_| "selective-source-scan-failed")?;
    Ok(Registration {
        sender_folder,
        receiver_folder,
        source,
        target,
    })
}

async fn census(client: &Client, fixture: &Registration) -> Stage<Vec<SampleState>> {
    let tree = client
        .browse_selective(
            &fixture.receiver_folder,
            &SelectiveBrowseOptions::new(SelectiveScope::FolderRoot).levels(3),
        )
        .await
        .map_err(|_| "selective-target-index-unavailable")?;
    SAMPLES
        .iter()
        .map(|&name| {
            let projected = project_entry(&tree, name);
            let relative = sample_path(name);
            Ok(SampleState {
                sample: name,
                selected: projected.map(|entry| entry.selected),
                native_local_presence: projected.map(|entry| entry.exists_locally),
                source: read_fingerprint(&fixture.source.join(&relative))?,
                target: read_fingerprint(&fixture.target.join(&relative))?,
            })
        })
        .collect()
}

async fn wait_baseline(client: &Client, fixture: &Registration) -> Stage<Vec<SampleState>> {
    tokio::time::timeout(WAIT, async {
        loop {
            let current = census(client, fixture).await?;
            if current.iter().any(|sample| {
                sample.source.is_none()
                    || sample.target.is_some()
                    || sample.selected == Some(true)
                    || sample.native_local_presence == Some(true)
            }) {
                return Err("selective-fixture-has-an-unexpected-initial-selection-or-file");
            }
            if current.iter().all(|sample| {
                sample.selected == Some(false) && sample.native_local_presence == Some(false)
            }) {
                return Ok(current);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| "selective-native-index-did-not-receive-owned-samples")?
}

fn sentinels(root: &Path) -> Stage<[Option<Value>; 2]> {
    let [source, target] = SENTINELS;
    Ok([
        read_fingerprint(&root.join(source))?,
        read_fingerprint(&root.join(target))?,
    ])
}

async fn clear_owned_receiver_registration(
    receiver: &Client,
    owned: &Registration,
    peer: &DeviceId,
    case_root: &Path,
) -> Stage<()> {
    let census = || -> Stage<Vec<Option<Value>>> {
        SAMPLES
            .iter()
            .flat_map(|name| {
                let path = sample_path(name);
                [&owned.source, &owned.target].map(|root| read_fingerprint(&root.join(&path)))
            })
            .collect()
    };
    let before = census()?;
    let control = sentinels(case_root)?;
    let folder = receiver
        .remove_folder_keep_files(&owned.receiver_folder)
        .await
        .map_err(|_| "selective-owned-folder-removal-unconfirmed")?;
    if !folder.configuration_absent || folder.previous_configuration.id != owned.receiver_folder {
        return Err("selective-owned-folder-still-registered");
    }
    let device = receiver
        .remove_device(peer)
        .await
        .map_err(|_| "selective-owned-peer-removal-unconfirmed")?;
    if !device.configuration_absent
        || device.previous_configuration.device_id != *peer
        || !device.remaining_folder_associations.is_empty()
    {
        return Err("selective-owned-peer-still-registered");
    }
    if before != census()? || control != sentinels(case_root)? {
        return Err("selective-unregister-affected-synthetic-data");
    }
    Ok(())
}

async fn pause_pair(sender: &Client, receiver: &Client) -> Stage<()> {
    let dest = &receiver.instance().device_id;
    let source = &sender.instance().device_id;
    sender
        .pause_device(dest)
        .await
        .map_err(|_| "selective-source-pause-failed")?;
    receiver
        .pause_device(source)
        .await
        .map_err(|_| "selective-target-pause-failed")?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let a = sender
                .connections()
                .await
                .map_err(|_| "selective-source-connection-unavailable")?;
            let b = receiver
                .connections()
                .await
                .map_err(|_| "selective-target-connection-unavailable")?;
            if !a.connections.get(dest).is_some_and(|peer| peer.connected)
                && !b.connections.get(source).is_some_and(|peer| peer.connected)
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| "selective-owned-peers-did-not-quiesce")?
}

async fn check_free(
    root: &Path,
    sender: &ManagedInstance,
    receiver: &ManagedInstance,
    run: &str,
) -> Stage<(Registration, Value)> {
    let a = inspect(sender, run).await?;
    let b = inspect(receiver, run).await?;
    if a["account"] != "logged-out"
        || b["account"] != "logged-out"
        || a["pro_observations"] != json!([])
        || b["pro_observations"] != json!([])
        || a["device"] == b["device"]
    {
        return Err("selective-free-control-needs-two-distinct-unlicensed-identities");
    }
    let owned = configure(
        root,
        sender,
        receiver,
        run,
        &root.join(schedule::GRANT_REVOKED),
    )
    .await?;
    verify_pair(&owned, sender.client(), receiver.client()).await?;
    let api = receiver.client();
    let baseline = wait_baseline(api, &owned).await?;
    let before = sentinels(root)?;
    let file = SelectiveScope::Path(TargetPath::local(sample_path(FILE)));
    let all = SelectiveScope::Path(TargetPath::local(sample_path(REMOVE)));
    let wrong =
        FolderId::parse("synthetic-unregistered").map_err(|_| "selective-wrong-target-invalid")?;
    let wrong_target = api
        .request_selection(&wrong, &all, SelectiveAction::RemoveFromAll)
        .await;
    if !matches!(wrong_target, Err(Error::FolderNotFound { .. })) {
        return Err("selective-unknown-owned-target-was-not-rejected");
    }
    let mut refused = Vec::new();
    for (name, scope, action) in [
        ("file-select", file.clone(), SelectiveAction::Select),
        ("file-deselect", file, SelectiveAction::Deselect),
        (
            "directory-select",
            SelectiveScope::Path(TargetPath::local(DIRECTORY)),
            SelectiveAction::Select,
        ),
        (
            "root-select",
            SelectiveScope::FolderRoot,
            SelectiveAction::Select,
        ),
        ("file-remove-from-all", all, SelectiveAction::RemoveFromAll),
    ] {
        let reply = api
            .request_selection(&owned.receiver_folder, &scope, action)
            .await;
        let Err(Error::LicenseRequired {
            code: 3000,
            response,
        }) = reply
        else {
            return Err("selective-expected-free-license-refusal-missing");
        };
        if response.status() != 200 {
            return Err("selective-free-license-status-unexpected");
        }
        if census(api, &owned).await? != baseline
            || sentinels(root)? != before
            || before.iter().any(Option::is_none)
        {
            return Err("selective-free-refusal-changed-selection-or-bytes");
        }
        refused.push(json!({"operation":name,"code":3000,"http":200,
                            "files_and_selection_unchanged":true}));
    }
    let folder_exists = sender.client().folder(&owned.sender_folder).await.is_ok();
    if !folder_exists {
        return Err("selective-owned-source-registration-unverified");
    }
    pause_pair(sender.client(), receiver.client()).await?;
    let after = census(api, &owned).await?;
    let after_sentinels = sentinels(root)?;
    if after != baseline || before != after_sentinels {
        return Err("selective-free-contents-changed-before-clean-shutdown");
    }
    Ok((
        owned,
        json!({
            "sender":a,"receiver":b,"before":baseline,"after":after,
            "sentinels_before":before,"sentinels_after":after_sentinels,
            "wrong_target_rejected":true,"refused":refused,"observed_peer_disconnect":true,
        }),
    ))
}

pub(crate) async fn free_native_control(
    engine: &Path,
    root: &Path,
    run: &str,
    verify_audit_transition: bool,
) -> Stage<()> {
    let send_root = root.join("s");
    let receive_root = root.join("r");
    fs::create_dir(&send_root).map_err(|_| "selective-owned-source-state-unavailable")?;
    fs::create_dir(&receive_root).map_err(|_| "selective-owned-target-state-unavailable")?;
    let mut sender = start(engine.to_path_buf(), &send_root).await?;
    let mut receiver = match start(engine.to_path_buf(), &receive_root).await {
        Ok(core) => core,
        Err(reason) => {
            if !end(&mut sender).await {
                return Err("selective-source-exit-unconfirmed-after-start-failed");
            }
            return Err(reason);
        }
    };
    let mut observation = check_free(root, &sender, &receiver, run).await;
    let source_device = sender.client().instance().device_id.clone();
    let source_stopped = end(&mut sender).await;
    let mut registry_clean = false;
    if source_stopped {
        if let Ok((registered, _)) = &observation {
            match clear_owned_receiver_registration(
                receiver.client(),
                registered,
                &source_device,
                root,
            )
            .await
            {
                Ok(()) => registry_clean = true,
                Err(code) => observation = Err(code),
            }
        }
    }
    if verify_audit_transition && registry_clean {
        if let Ok((registered, receipt)) = &mut observation {
            match audit_transition(engine, root, &receiver, registered, run).await {
                Ok(observed) => receipt["audit_transition"] = observed,
                Err(code) => observation = Err(code),
            }
        }
    }
    let target_stopped = end(&mut receiver).await;
    if let Ok((_, value)) = &mut observation {
        value["sender_normal_exit"] = json!(source_stopped);
        value["receiver_normal_exit"] = json!(target_stopped);
        value["only_test_registrations_removed_preserving_bytes"] = json!(registry_clean);
        value["ok"] = json!(source_stopped && target_stopped && registry_clean);
        record(value.clone())?;
    }
    if source_stopped && target_stopped {
        observation.map(|_| ())
    } else {
        Err("selective-owned-normal-process-exits-unconfirmed")
    }
}

async fn audit_transition(
    engine: &Path,
    root: &Path,
    receiver: &ManagedInstance,
    selection: &Registration,
    run: &str,
) -> Stage<Value> {
    let api = receiver.client();
    if !api
        .folders()
        .await
        .map_err(|_| "transition-folder-census-unavailable")?
        .is_empty()
    {
        return Err("transition-has-stale-selection-folders");
    }
    let before = SAMPLES
        .iter()
        .map(|name| read_fingerprint(&selection.source.join(sample_path(name))))
        .collect::<Stage<Vec<_>>>()?;
    let scope = root.join("audit-after-selective");
    fs::create_dir(&scope).map_err(|_| "transition-synthetic-directory-unavailable")?;
    let mut witness = audit_files::ArchiveWitness::prepare(engine, &scope, receiver, run).await?;
    let evidence = async {
        let files = witness.archive_revisions(api).await?;
        witness.quiesce(api).await?;
        if witness.snapshot(api).await? != files {
            return Err("transition-audit-witness-unconfirmed-after-peer-exit");
        }
        let after = SAMPLES
            .iter()
            .map(|name| read_fingerprint(&selection.source.join(sample_path(name))))
            .collect::<Stage<Vec<_>>>()?;
        if after != before {
            return Err("transition-affected-earlier-selection-scope");
        }
        Ok(
            json!({"same_receiver_process":receiver.process_id(),"new_audit_peer_stopped":true,
                  "earlier_selection_bytes_preserved":true,"owned_archive_census":files}),
        )
    }
    .await;
    witness.stop_source().await?;
    evidence
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Step {
    Prepare,
    SelectFile,
    DeselectFile,
    SelectDirectory,
    SelectRoot,
    RemoveFromAll,
    Finish,
}

const ORDER: [Step; 5] = [
    Step::SelectFile,
    Step::DeselectFile,
    Step::SelectDirectory,
    Step::SelectRoot,
    Step::RemoveFromAll,
];

impl Step {
    fn operation(self) -> Stage<(SelectiveScope, SelectiveAction)> {
        let single = |name| SelectiveScope::Path(TargetPath::local(sample_path(name)));
        match self {
            Self::SelectFile => Ok((single(FILE), SelectiveAction::Select)),
            Self::DeselectFile => Ok((single(FILE), SelectiveAction::Deselect)),
            Self::SelectDirectory => Ok((
                SelectiveScope::Path(TargetPath::local(DIRECTORY)),
                SelectiveAction::Select,
            )),
            Self::SelectRoot => Ok((SelectiveScope::FolderRoot, SelectiveAction::Select)),
            Self::RemoveFromAll => Ok((single(REMOVE), SelectiveAction::RemoveFromAll)),
            _ => Err("selective-operation-has-no-native-selection"),
        }
    }
}

pub(crate) struct LicensedCase {
    engine: PathBuf,
    root: PathBuf,
    revoke: PathBuf,
    source: Option<ManagedInstance>,
    owned: Option<Registration>,
    previous: Vec<SampleState>,
    control: [Option<Value>; 2],
    next: usize,
    unsettled: bool,
    cleanup_error: Option<&'static str>,
}

impl LicensedCase {
    pub(crate) fn new(engine: &Path, owned_session: &Path) -> Self {
        Self {
            engine: engine.to_owned(),
            root: owned_session.join("selective-case"),
            revoke: owned_session.join(schedule::GRANT_REVOKED),
            source: None,
            owned: None,
            previous: Vec::new(),
            control: [None, None],
            next: 0,
            unsettled: false,
            cleanup_error: None,
        }
    }

    pub(crate) async fn apply(
        &mut self,
        step: Step,
        receiver: &ManagedInstance,
        run: &str,
    ) -> Stage<Value> {
        match step {
            Step::Finish => {
                self.cleanup(receiver.client()).await?;
                Ok(
                    json!({"ok":true,"owned_source_stopped":true,"isolation_preserved":true,
                          "owned_registrations_absent":self.owned.is_none()}),
                )
            }
            Step::Prepare => self.prepare(receiver, run).await,
            _ => self.select(step, receiver).await,
        }
    }

    async fn prepare(&mut self, receiver: &ManagedInstance, run: &str) -> Stage<Value> {
        schedule::check_authorization(&self.revoke)?;
        if self.root.exists()
            || !receiver
                .client()
                .folders()
                .await
                .map_err(|_| "selective-receiver-folder-census-unavailable")?
                .is_empty()
        {
            return Err("selective-requires-an-exclusive-new-receiver");
        }
        fs::create_dir(&self.root).map_err(|_| "selective-licensed-scope-not-created")?;
        let source_state = self
            .root
            .parent()
            .ok_or("selective-owned-session-parent-unavailable")?
            .join("sp");
        fs::create_dir(&source_state).map_err(|_| "selective-licensed-source-state-not-created")?;
        schedule::check_authorization(&self.revoke)?;
        let source = start(self.engine.clone(), &source_state).await?;
        self.source = Some(source);
        let source = self
            .source
            .as_ref()
            .ok_or("selective-owned-source-unavailable")?;
        let a = inspect(source, run).await?;
        if a["account"] != "logged-out" || a["device"] == device_alias(receiver, run) {
            return Err("selective-source-is-not-an-independent-signed-out-test-core");
        }
        let owned = configure(&self.root, source, receiver, run, &self.revoke).await?;
        verify_pair(&owned, source.client(), receiver.client()).await?;
        let baseline = wait_baseline(receiver.client(), &owned).await?;
        self.control = sentinels(&self.root)?;
        if self.control.iter().any(Option::is_none) {
            return Err("selective-owned-sentinels-not-confirmed");
        }
        self.owned = Some(owned);
        self.previous = baseline;
        Ok(
            json!({"ok":true,"source":a,"destination":device_alias(receiver, run),
                  "source_process":source.process_id(),"destination_process":receiver.process_id(),
                  "one_exclusive_peer_on_each_node":true,"before":self.previous,"outside_sentinels":self.control}),
        )
    }

    async fn select(&mut self, step: Step, receiver: &ManagedInstance) -> Stage<Value> {
        if self.unsettled || ORDER.get(self.next) != Some(&step) {
            return Err("selective-step-is-out-of-order-or-an-effect-is-unconfirmed");
        }
        schedule::check_authorization(&self.revoke)?;
        let source = self
            .source
            .as_ref()
            .ok_or("selective-owned-source-unavailable")?;
        let owned = self
            .owned
            .as_ref()
            .ok_or("selective-owned-registration-unavailable")?;
        let api = receiver.client();
        verify_pair(owned, source.client(), api).await?;
        let before = census(api, owned).await?;
        let controls = sentinels(&self.root)?;
        if before != self.previous || controls != self.control {
            return Err("selective-data-changed-before-the-next-operation");
        }
        if step == Step::RemoveFromAll
            && !before.iter().any(|item| {
                item.sample == REMOVE
                    && item.source.is_some()
                    && item.source == item.target
                    && item.native_local_presence == Some(true)
            })
        {
            return Err("selective-removal-target-must-exist-with-matching-bytes-on-both-nodes");
        }
        let (scope, action) = step.operation()?;
        schedule::check_authorization(&self.revoke)?;
        self.unsettled = true;
        let result = api
            .request_selection(&owned.receiver_folder, &scope, action)
            .await;
        let acknowledgement = match result {
            Ok(value) => json!({"http":value.response.status(),"acknowledged":true}),
            Err(Error::LicenseRequired { code, response }) => {
                json!({"http":response.status(),"native_license_code":code,"acknowledged":false})
            }
            Err(_) => json!({"acknowledged":false,"outcome":"requires-native-readback"}),
        };
        let stop = Instant::now() + WAIT;
        let settle = if step == Step::DeselectFile {
            Duration::from_secs(2)
        } else {
            Duration::from_millis(300)
        };
        let mut stable_since = None;
        let mut stable_state: Option<Vec<SampleState>> = None;
        let (observed, final_controls, confirmed) = loop {
            let observed = census(api, owned).await?;
            let final_controls = sentinels(&self.root)?;
            let matches = selection_effect(step, &before, &observed) && final_controls == controls;
            if matches && stable_state.as_ref() == Some(&observed) {
                if stable_since.is_some_and(|moment: Instant| moment.elapsed() >= settle) {
                    break (observed, final_controls, true);
                }
            } else if matches {
                stable_since = Some(Instant::now());
                stable_state = Some(observed.clone());
            } else {
                stable_since = None;
                stable_state = None;
            }
            if Instant::now() >= stop || acknowledgement["acknowledged"] == false {
                break (observed, final_controls, false);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        if confirmed {
            self.unsettled = false;
            self.next += 1;
            self.previous.clone_from(&observed);
        }
        Ok(
            json!({"ok":confirmed,"selection_request":acknowledgement,"before":before,"after":observed,
                  "sentinels_before":controls,"sentinels_after":final_controls,
                  "one_request_submitted":true,"all_peers_exclusive":true}),
        )
    }

    pub(crate) async fn cleanup(&mut self, receiver: &Client) -> Stage<()> {
        if let Some(error) = self.cleanup_error {
            return Err(error);
        }
        let Some(mut source) = self.source.take() else {
            return Ok(());
        };
        let peer = source.client().instance().device_id.clone();
        let outcome = async {
            let disconnected = if let Some(owned) = self.owned.as_ref() {
                match verify_pair(owned, source.client(), receiver).await {
                    Ok(()) => pause_pair(source.client(), receiver).await,
                    Err(code) => Err(code),
                }
            } else {
                Ok(())
            };
            if !end(&mut source).await {
                return Err("selective-licensed-source-normal-exit-unconfirmed");
            }
            disconnected?;
            if let Some(owned) = self.owned.as_ref() {
                clear_owned_receiver_registration(receiver, owned, &peer, &self.root).await?;
                self.owned = None;
            }
            Ok(())
        }
        .await;
        if let Err(code) = outcome {
            self.cleanup_error = Some(code);
        }
        outcome
    }
}

async fn verify_pair(fixture: &Registration, source: &Client, target: &Client) -> Stage<()> {
    for (client, counterpart, folder, root) in [
        (source, target, &fixture.sender_folder, &fixture.source),
        (target, source, &fixture.receiver_folder, &fixture.target),
    ] {
        let local = &client.instance().device_id;
        let remote = &counterpart.instance().device_id;
        if client
            .system_status()
            .await
            .map_err(|_| "selective-fresh-device-identity-unavailable")?
            .device_id
            != *local
        {
            return Err("selective-fresh-device-identity-changed");
        }
        let configurations = client
            .folders()
            .await
            .map_err(|_| "selective-registered-scope-unavailable")?;
        let [registered] = configurations.as_slice() else {
            return Err("selective-owned-configuration-is-not-exclusive");
        };
        let target_path = TargetPath::local(root);
        let expected = target_path
            .to_protocol()
            .map_err(|_| "selective-owned-path-encoding-unverified")?;
        if registered.id != *folder
            || !registered
                .path
                .to_protocol()
                .is_ok_and(|actual| actual == expected)
        {
            return Err("selective-registered-path-or-folder-identity-changed");
        }
        let devices = registered
            .extra
            .get("devices")
            .and_then(Value::as_array)
            .ok_or("selective-configured-peers-unavailable")?;
        let identities = devices
            .iter()
            .map(|entry| {
                let id = entry
                    .get("deviceID")
                    .and_then(Value::as_str)
                    .ok_or("selective-configured-peer-identity-unavailable")?;
                DeviceId::parse(id).map_err(|_| "selective-configured-peer-identity-invalid")
            })
            .collect::<Stage<BTreeSet<_>>>()?;
        if identities.len() != devices.len()
            || !identities.contains(remote)
            || identities.iter().any(|id| id != local && id != remote)
        {
            return Err("selective-has-an-unregistered-or-unconfirmed-peer");
        }
    }
    Ok(())
}

fn selection_effect(step: Step, before: &[SampleState], after: &[SampleState]) -> bool {
    before.len() == SAMPLES.len()
        && after.len() == before.len()
        && before.iter().zip(after).all(|(old, new)| {
            if old.sample != new.sample {
                return false;
            }
            let downloaded = new.selected == Some(true)
                && new.native_local_presence == Some(true)
                && old.source.is_some()
                && new.source == old.source
                && new.target == old.source;
            match (step, new.sample) {
                (Step::SelectFile, FILE)
                | (Step::SelectDirectory, CHILD)
                | (Step::SelectRoot, _) => downloaded,
                (Step::DeselectFile, FILE) => {
                    new.selected == Some(false)
                        && new.source == old.source
                        && new.native_local_presence == Some(new.target.is_some())
                        && (new.target.is_none() || new.target == old.target)
                }
                (Step::RemoveFromAll, REMOVE) => {
                    new.selected != Some(true)
                        && new.native_local_presence != Some(true)
                        && new.source.is_none()
                        && new.target.is_none()
                }
                _ => new == old,
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original() -> Vec<SampleState> {
        SAMPLES
            .iter()
            .map(|&name| SampleState {
                sample: name,
                selected: Some(false),
                native_local_presence: Some(false),
                source: Some(json!({"bytes":3,"sha256":format!("synthetic-{name}")})),
                target: None,
            })
            .collect()
    }

    #[test]
    fn positive_selection_needs_native_flags_matching_bytes_and_unselected_controls() {
        let before = original();
        let mut after = before.clone();
        after[0].selected = Some(true);
        after[0].native_local_presence = Some(true);
        assert!(!selection_effect(Step::SelectFile, &before, &after));
        after[0].target = after[0].source.clone();
        assert!(selection_effect(Step::SelectFile, &before, &after));
        after[1].target = after[1].source.clone();
        assert!(!selection_effect(Step::SelectFile, &before, &after));
    }

    #[test]
    fn deselection_records_both_possible_local_dispositions_without_source_change() {
        let mut before = original();
        before[0].selected = Some(true);
        before[0].native_local_presence = Some(true);
        before[0].target = before[0].source.clone();
        let mut after = before.clone();
        after[0].selected = Some(false);
        assert!(selection_effect(Step::DeselectFile, &before, &after));
        after[0].target = None;
        assert!(!selection_effect(Step::DeselectFile, &before, &after));
        after[0].native_local_presence = Some(false);
        assert!(selection_effect(Step::DeselectFile, &before, &after));
        after[0].source = None;
        assert!(!selection_effect(Step::DeselectFile, &before, &after));
    }

    #[test]
    fn removal_requires_absence_on_both_nodes_and_preservation_of_unrelated_bytes() {
        let mut before = original();
        for row in &mut before {
            row.selected = Some(true);
            row.native_local_presence = Some(true);
            row.target = row.source.clone();
        }
        let mut after = before.clone();
        let row = after.iter_mut().find(|row| row.sample == REMOVE).unwrap();
        row.selected = None;
        row.native_local_presence = None;
        row.target = None;
        assert!(!selection_effect(Step::RemoveFromAll, &before, &after));
        after[2].source = None;
        assert!(selection_effect(Step::RemoveFromAll, &before, &after));
        after[1].target = None;
        assert!(!selection_effect(Step::RemoveFromAll, &before, &after));
    }
}
