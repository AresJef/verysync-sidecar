use crate::{end, schedule, start, Stage};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};
use verysync_sidecar::{
    Client, CreateDeviceOptions, DeviceId, DevicePatch, DeviceTransport, FolderId,
    FolderVersioningPolicy, JoinFolderOptions, ManagedInstance, NetworkPatch, TargetPath,
};

const DATA_FILES: [&str; 3] = ["audit-alpha.bin", "audit-beta.bin", "audit-gamma.bin"];
const DATA_TIMEOUT: Duration = Duration::from_secs(25);
const SENTINEL: &[u8] = b"R33 fixture control outside the shared folder";

pub(crate) struct ArchiveWitness {
    root: PathBuf,
    source: PathBuf,
    received: PathBuf,
    receiver_folder: FolderId,
    receiver_peer: DeviceId,
    sender: Option<ManagedInstance>,
    sender_folder: FolderId,
    sample_tag: String,
    revoke_marker: PathBuf,
}

impl ArchiveWitness {
    pub(crate) fn named_samples(&self) -> &'static [&'static str] {
        &DATA_FILES
    }

    pub(crate) fn folder_id(&self) -> &str {
        self.receiver_folder.as_str()
    }

    fn bytes(&self, name: &str, current: bool) -> Vec<u8> {
        let generation = if current {
            "current revision with more bytes"
        } else {
            "first revision"
        };
        format!("R33 {} {} {}\n", self.sample_tag, name, generation).into_bytes()
    }

    pub(crate) async fn prepare(
        engine: &Path,
        parent: &Path,
        receiver: &ManagedInstance,
        sample_tag: &str,
    ) -> Stage<Self> {
        let revoke_marker = parent.join(schedule::GRANT_REVOKED);
        schedule::check_authorization(&revoke_marker)?;
        let root = parent.join("audit-file-witness");
        let source = root.join("src");
        let received = root.join("rx");
        fs::create_dir(&root).map_err(|_| "audit-file-fixture-already-present")?;
        fs::create_dir(&source).map_err(|_| "audit-source-folder-unavailable")?;
        fs::create_dir(&received).map_err(|_| "audit-receive-folder-unavailable")?;
        fs::write(root.join("outside-shared-folder"), SENTINEL)
            .map_err(|_| "audit-unrelated-sentinel-unavailable")?;
        let peer_root = parent.join("ap");
        fs::create_dir(&peer_root).map_err(|_| "audit-source-state-folder-unavailable")?;
        let sender = start(engine.to_path_buf(), &peer_root)
            .await
            .map_err(|_| "audit-source-core-start-failed")?;
        let mut sender = sender;
        let registered = async {
            let (send, receive) = fixture_ports()?;
            let expected_destination =
                fixed_listener(receiver.client(), receive, &revoke_marker).await?;
            fixed_listener(sender.client(), send, &revoke_marker).await?;
            register(
                sender.client(),
                receiver.client(),
                &source,
                &received,
                expected_destination,
                &revoke_marker,
            )
            .await
        }
        .await;
        let (sender_folder, receiver_folder) = match registered {
            Ok(ids) => ids,
            Err(code) => {
                if !end(&mut sender).await {
                    return Err("audit-source-normal-exit-unverified-after-registration");
                }
                return Err(code);
            }
        };
        let receiver_peer = sender.client().instance().device_id.clone();
        let mut case = Self {
            root,
            source,
            received,
            receiver_folder,
            receiver_peer,
            sender: Some(sender),
            sender_folder,
            sample_tag: sample_tag.to_string(),
            revoke_marker,
        };
        let result = case.seed(receiver.client()).await;
        if let Err(code) = result {
            let _ = case.stop_source().await;
            return Err(code);
        }
        Ok(case)
    }

    async fn seed(&self, receiver: &Client) -> Stage<()> {
        let sender = self.sender()?.client();
        schedule::check_authorization(&self.revoke_marker)?;
        let configuration = receiver
            .set_folder_versioning(
                &self.receiver_folder,
                FolderVersioningPolicy::Simple {
                    keep: 2,
                    cleanout_days: 0,
                    cleanup_interval_seconds: 3600,
                },
            )
            .await
            .map_err(|_| "audit-archive-configuration-failed")?;
        if !configuration.requested_fields_match {
            return Err("audit-versioner-not-confirmed");
        }
        for name in DATA_FILES {
            schedule::check_authorization(&self.revoke_marker)?;
            fs::write(self.source.join(name), self.bytes(name, false))
                .map_err(|_| "audit-initial-sample-write-failed")?;
        }
        schedule::check_authorization(&self.revoke_marker)?;
        let _ = sender
            .resume_folder(&self.sender_folder)
            .await
            .map_err(|_| "audit-source-resume-failed")?;
        schedule::check_authorization(&self.revoke_marker)?;
        let _ = receiver
            .resume_folder(&self.receiver_folder)
            .await
            .map_err(|_| "audit-receiver-resume-failed")?;
        self.scan(sender).await?;
        self.confirm_received(false).await?;
        let empty = receiver
            .folder_version_inventory(&self.receiver_folder)
            .await
            .map_err(|_| "audit-initial-version-inventory-unavailable")?;
        if !empty.0.is_empty() {
            return Err("audit-unexpected-initial-versions");
        }
        Ok(())
    }

    async fn scan(&self, sender: &Client) -> Stage<()> {
        schedule::check_authorization(&self.revoke_marker)?;
        sender
            .request_scan(&self.sender_folder)
            .await
            .map_err(|_| "audit-registered-source-scan-failed")?;
        Ok(())
    }

    fn sender(&self) -> Stage<&ManagedInstance> {
        self.sender
            .as_ref()
            .ok_or("audit-fixture-source-already-stopped")
    }

    async fn confirm_received(&self, current: bool) -> Stage<()> {
        tokio::time::timeout(DATA_TIMEOUT, async {
            loop {
                if DATA_FILES.iter().all(|name| {
                    let expected = self.bytes(name, current);
                    fs::read(self.received.join(name)).is_ok_and(|value| value == expected)
                        && fs::read(self.source.join(name)).is_ok_and(|value| value == expected)
                }) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(|_| "audit-actual-file-transfer-not-confirmed")
    }

    pub(crate) async fn archive_revisions(&self, receiver: &Client) -> Stage<Value> {
        let sender = self.sender()?.client();
        for name in DATA_FILES {
            schedule::check_authorization(&self.revoke_marker)?;
            fs::write(self.source.join(name), self.bytes(name, true))
                .map_err(|_| "audit-owned-revision-write-failed")?;
            self.scan(sender).await?;
            let expected = self.bytes(name, true);
            tokio::time::timeout(DATA_TIMEOUT, async {
                loop {
                    if fs::read(self.received.join(name)).is_ok_and(|data| data == expected) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .map_err(|_| "audit-revised-file-transfer-not-confirmed")?;
        }
        self.confirm_received(true).await?;
        self.snapshot(receiver).await
    }

    pub(crate) async fn snapshot(&self, receiver: &Client) -> Stage<Value> {
        let listed = receiver
            .folder_version_inventory(&self.receiver_folder)
            .await
            .map_err(|_| "audit-archive-list-unavailable")?;
        if listed.0.len() != DATA_FILES.len() {
            return Err("audit-archive-inventory-unexpected");
        }
        let vault = self.received.join(".verysync").join("Archive");
        let mut archives = Vec::new();
        for item in fs::read_dir(vault).map_err(|_| "audit-archive-directory-unavailable")? {
            let item = item.map_err(|_| "audit-archive-directory-unavailable")?;
            if !item
                .file_type()
                .map_err(|_| "audit-archive-mode-unavailable")?
                .is_file()
            {
                return Err("audit-archive-unexpected-entry");
            }
            let file =
                fs::read(item.path()).map_err(|_| "audit-independent-archive-read-failed")?;
            let name = DATA_FILES
                .into_iter()
                .find(|name| file == self.bytes(name, false))
                .ok_or("audit-unregistered-archive")?;
            if archives.iter().any(|(existing, _)| existing == &name) {
                return Err("audit-duplicate-old-version");
            }
            let versions = listed
                .0
                .get(name)
                .ok_or("audit-native-version-entry-missing")?;
            let [version] = versions.as_slice() else {
                return Err("audit-version-count-unexpected");
            };
            if version.size != file.len() as u64 {
                return Err("audit-native-archive-length-mismatch");
            }
            archives.push((name, fingerprint(name, &file)));
        }
        if archives.len() != DATA_FILES.len() {
            return Err("audit-independent-archived-bytes-not-confirmed");
        }
        archives.sort_by_key(|(name, _)| *name);
        let mut current = Vec::new();
        for name in DATA_FILES {
            let bytes = fs::read(self.received.join(name))
                .map_err(|_| "audit-destination-file-read-failed")?;
            let independent_source =
                fs::read(self.source.join(name)).map_err(|_| "audit-source-file-read-failed")?;
            if bytes != independent_source || bytes != self.bytes(name, true) {
                return Err("audit-ordinary-file-changed");
            }
            current.push(fingerprint(name, &bytes));
        }
        let sentinel = fs::read(self.root.join("outside-shared-folder"))
            .map_err(|_| "audit-sentinel-still-unreadable")?;
        if sentinel != SENTINEL {
            return Err("audit-unrelated-sentinel-changed");
        }
        Ok(json!({
            "current_data": current,
            "prior_versions": archives.into_iter().map(|(_, proof)| proof).collect::<Vec<_>>(),
            "sentinels": [fingerprint("outside-shared-folder", &sentinel)]
        }))
    }

    pub(crate) async fn quiesce(&mut self, receiver: &Client) -> Stage<()> {
        let sender = self.sender()?.client();
        let target = receiver.instance().device_id.clone();
        sender
            .pause_device(&target)
            .await
            .map_err(|_| "audit-pause-source-peer-failed")?;
        receiver
            .pause_device(&self.receiver_peer)
            .await
            .map_err(|_| "audit-pause-destination-peer-failed")?;
        let peer = self.receiver_peer.clone();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let source_state = sender
                    .connections()
                    .await
                    .map_err(|_| "audit-source-peer-state-unavailable")?;
                let receiver_state = receiver
                    .connections()
                    .await
                    .map_err(|_| "audit-receiver-peer-state-unavailable")?;
                if !source_state
                    .connections
                    .get(&target)
                    .is_some_and(|value| value.connected)
                    && !receiver_state
                        .connections
                        .get(&peer)
                        .is_some_and(|value| value.connected)
                {
                    return Ok::<(), &'static str>(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(|_| "audit-peer-disconnection-not-confirmed")??;
        self.stop_source().await
    }

    pub(crate) async fn stop_source(&mut self) -> Stage<()> {
        let Some(mut sender) = self.sender.take() else {
            return Ok(());
        };
        if !end(&mut sender).await {
            return Err("audit-archive-peer-normal-exit-not-confirmed");
        }
        Ok(())
    }
}

pub(super) fn fixture_ports() -> Stage<(u16, u16)> {
    let configured =
        env::var("R33_AUDIT_P2P_PORTS").map_err(|_| "audit-exact-loopback-ports-missing")?;
    let (first, second) = configured
        .split_once(',')
        .ok_or("audit-exact-loopback-ports-invalid")?;
    let pair = (first.parse::<u16>(), second.parse::<u16>());
    match pair {
        (Ok(first), Ok(second))
            if [first, second].iter().all(|p| *p >= 1024 && *p != 18886) && first != second =>
        {
            Ok((first, second))
        }
        _ => Err("audit-exact-loopback-ports-invalid"),
    }
}

pub(super) async fn fixed_listener(
    client: &Client,
    port: u16,
    revoke_marker: &Path,
) -> Stage<String> {
    let address = format!("tcp://{}", SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    schedule::check_authorization(revoke_marker)?;
    let response = client
        .update_network_configuration(
            &NetworkPatch::default()
                .listen_addresses(vec![address.clone()])
                .global_discovery(false)
                .local_discovery(false)
                .reconnection_interval_seconds(5),
        )
        .await
        .map_err(|_| "audit-exact-loopback-address-update-unverified")?;
    if !response.requested_fields_match
        || response.configuration.listen_addresses != [address.as_str()]
    {
        return Err("audit-exact-loopback-address-readback-unverified");
    }
    tokio::time::timeout(Duration::from_secs(9), async {
        loop {
            let active = client
                .listener_status()
                .await
                .map_err(|_| "audit-peer-listener-unavailable")?;
            let live: Vec<_> = active
                .into_values()
                .flat_map(|state| state.lan_addresses)
                .collect();
            if live == [address.as_str()] {
                return Ok(address);
            }
            if live.iter().any(|existing| existing != &address) {
                return Err("audit-unexpected-active-listener");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| "audit-explicit-loopback-listener-not-confirmed")?
}

pub(super) async fn register(
    sender: &Client,
    receiver: &Client,
    source: &Path,
    destination: &Path,
    destination_address: String,
    revoke_marker: &Path,
) -> Stage<(FolderId, FolderId)> {
    let keys = sender
        .generate_share()
        .await
        .map_err(|_| "audit-ephemeral-share-failed")?;
    let source_key = sender
        .validate_share_key(&keys.read_write_key)
        .await
        .map_err(|_| "audit-owned-source-key-unverified")?;
    let dest_key = receiver
        .validate_share_key(&keys.read_write_key)
        .await
        .map_err(|_| "audit-owned-destination-key-unverified")?;
    schedule::check_authorization(revoke_marker)?;
    let source_folder = sender
        .join_folder(&JoinFolderOptions::new(source_key, TargetPath::local(source)).paused(true))
        .await
        .map_err(|_| "audit-source-folder-registration-failed")?
        .configuration
        .id;
    schedule::check_authorization(revoke_marker)?;
    let dest_folder = receiver
        .join_folder(&JoinFolderOptions::new(dest_key, TargetPath::local(destination)).paused(true))
        .await
        .map_err(|_| "audit-destination-folder-registration-failed")?
        .configuration
        .id;
    for (client, folder, id, address) in [
        (
            sender,
            &source_folder,
            &receiver.instance().device_id,
            destination_address,
        ),
        (
            receiver,
            &dest_folder,
            &sender.instance().device_id,
            "dynamic".to_owned(),
        ),
    ] {
        let config = DevicePatch::default()
            .addresses(vec![address])
            .allowed_transports(vec![DeviceTransport::Tcp]);
        schedule::check_authorization(revoke_marker)?;
        client
            .create_device(&CreateDeviceOptions::new(id.clone()).settings(config))
            .await
            .map_err(|_| "audit-owned-device-register-failed")?;
        schedule::check_authorization(revoke_marker)?;
        client
            .share_folder_with(folder, id)
            .await
            .map_err(|_| "audit-owned-share-registration-failed")?;
    }
    Ok((source_folder, dest_folder))
}

fn fingerprint(name: &str, bytes: &[u8]) -> Value {
    json!({"sample":name, "bytes":bytes.len(), "sha256":format!("{:x}", Sha256::digest(bytes))})
}
