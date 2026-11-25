//! Native two-way file receipt and the corresponding Local-API observations.

use super::{file_effects::unavailable, loopback_endpoint, start_at};
use crate::{check_authorization, device_alias, end, Stage};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    time::Duration,
};
use verysync_sidecar::{
    BandwidthPatch, Client, CompletionSnapshot, CreateDeviceOptions, DeviceId, DevicePatch,
    DeviceTransport, Error, FileDownloadProgress, FolderAdvancedPatch, FolderId, JoinFolderOptions,
    ListPage, LocalApiClient, LocalApiConnectOptions, ManagedInstance, ManagementEndpoint,
    NeedPage, NetworkPatch, SelectiveAction, SelectiveBrowseOptions, SelectiveScope, SyncFileKind,
    TargetPath,
};

const INCOMING: &str = "incoming.bin";
const OUTGOING: &str = "outgoing.bin";
const LENGTH: usize = 4 * 1024 * 1024;
const WAIT: Duration = Duration::from_secs(24);
const POLL: Duration = Duration::from_millis(65);

fn ports() -> Stage<[u16; 3]> {
    let selected = if let Ok(value) = env::var("R33_LOCAL_API_PAIR_PORTS") {
        value
            .split(',')
            .map(str::parse::<u16>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "local-api-pair-test-ports-invalid")?
    } else {
        let listeners = (0..3)
            .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "local-api-pair-loopback-ports-unavailable")?;
        listeners
            .iter()
            .map(|stream| stream.local_addr().map(|address| address.port()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "local-api-pair-loopback-ports-unavailable")?
    };
    let [gui, primary, peer] = selected
        .try_into()
        .map_err(|_| "local-api-pair-test-ports-invalid")?;
    let main = env::var("R33_LOCAL_API_PORT")
        .ok()
        .and_then(|port| port.parse().ok());
    if [gui, primary, peer]
        .iter()
        .any(|&port| port < 1024 || port == 18886 || Some(port) == main)
        || gui == primary
        || gui == peer
        || primary == peer
    {
        return Err("local-api-pair-test-ports-invalid");
    }
    Ok([gui, primary, peer])
}

fn data(seed: u64) -> Vec<u8> {
    let mut seed = seed;
    (0..LENGTH)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect()
}

fn fingerprint(path: &Path) -> Stage<Value> {
    let bytes = fs::read(path).map_err(|_| "local-api-pair-sample-read-unavailable")?;
    Ok(json!({"bytes":bytes.len(),"sha256":format!("{:x}", Sha256::digest(bytes))}))
}

async fn listen(root: &Path, node: &Client, port: u16) -> Stage<String> {
    check_authorization(root)?;
    let address = format!("tcp://{}", SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    let observed = node
        .update_network_configuration(
            &NetworkPatch::default()
                .listen_addresses(vec![address.clone()])
                .global_discovery(false)
                .local_discovery(false)
                .reconnection_interval_seconds(5),
        )
        .await
        .map_err(|_| "local-api-pair-listener-configuration-unavailable")?;
    if !observed.requested_fields_match {
        return Err("local-api-pair-listener-configuration-mismatch");
    }
    tokio::time::timeout(Duration::from_secs(9), async {
        loop {
            check_authorization(root)?;
            let active = node
                .listener_status()
                .await
                .map_err(|_| "local-api-pair-listener-unknown")?;
            let addresses = active
                .into_values()
                .flat_map(|v| v.lan_addresses)
                .collect::<Vec<_>>();
            if addresses == [address.as_str()] {
                return Ok(address);
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .map_err(|_| "local-api-pair-listener-timed-out")?
}

async fn bandwidth(root: &Path, node: &Client, patch: BandwidthPatch) -> Stage<()> {
    check_authorization(root)?;
    let observed = node
        .update_bandwidth_configuration(&patch)
        .await
        .map_err(|_| "local-api-pair-bandwidth-update-unconfirmed")?;
    if !observed.requested_fields_match {
        return Err("local-api-pair-bandwidth-readback-mismatch");
    }
    Ok(())
}

struct Pair {
    primary_files: PathBuf,
    secondary_files: PathBuf,
    primary_folder: FolderId,
    secondary_folder: FolderId,
}

async fn register(
    root: &Path,
    directory: &Path,
    primary: &Client,
    secondary: &Client,
    addresses: [String; 2],
) -> Stage<Pair> {
    check_authorization(root)?;
    let keys = primary
        .generate_share()
        .await
        .map_err(|_| "local-api-pair-share-unavailable")?;
    let primary_key = primary
        .validate_share_key(&keys.read_write_key)
        .await
        .map_err(|_| "local-api-pair-primary-share-unconfirmed")?;
    let secondary_key = secondary
        .validate_share_key(&keys.read_write_key)
        .await
        .map_err(|_| "local-api-pair-secondary-share-unconfirmed")?;
    let primary_files = directory.join("primary-files");
    let secondary_files = directory.join("secondary-files");
    let mut folders = Vec::with_capacity(2);
    let [primary_address, secondary_address] = addresses;
    for (node, peer, key, path, other_address) in [
        (
            primary,
            secondary,
            primary_key,
            &primary_files,
            secondary_address,
        ),
        (
            secondary,
            primary,
            secondary_key,
            &secondary_files,
            primary_address,
        ),
    ] {
        check_authorization(root)?;
        let path = TargetPath::local(path);
        let created = node
            .join_folder(&JoinFolderOptions::new(key, path.clone()).paused(true))
            .await
            .map_err(|_| "local-api-pair-folder-registration-unconfirmed")?
            .configuration;
        if !created.paused || created.path.to_protocol().ok() != path.to_protocol().ok() {
            return Err("local-api-pair-folder-readback-mismatch");
        }
        check_authorization(root)?;
        let advanced = node
            .update_folder_advanced_configuration(
                &created.id,
                &FolderAdvancedPatch::default()
                    .ants_puller_enabled(false)
                    .puller_session_enabled(false),
            )
            .await
            .map_err(|_| "local-api-pair-folder-transfer-mode-unconfirmed")?;
        if !advanced.requested_fields_match {
            return Err("local-api-pair-folder-transfer-mode-mismatch");
        }
        let peer = &peer.instance().device_id;
        check_authorization(root)?;
        node.create_device(
            &CreateDeviceOptions::new(peer.clone()).settings(
                DevicePatch::default()
                    .addresses(vec![other_address])
                    .allowed_transports(vec![DeviceTransport::Tcp]),
            ),
        )
        .await
        .map_err(|_| "local-api-pair-device-registration-unconfirmed")?;
        check_authorization(root)?;
        node.share_folder_with(&created.id, peer)
            .await
            .map_err(|_| "local-api-pair-sharing-unconfirmed")?;
        folders.push(created.id);
    }
    let [primary_folder, secondary_folder] = folders
        .try_into()
        .map_err(|_| "local-api-pair-folder-count-mismatch")?;
    Ok(Pair {
        primary_files,
        secondary_files,
        primary_folder,
        secondary_folder,
    })
}

fn pending(page: &NeedPage, name: &str) -> bool {
    page.progress
        .iter()
        .chain(&page.queued)
        .chain(&page.rest)
        .any(|entry| {
            entry.name == name
                && entry.kind == SyncFileKind::File
                && entry.size == Some(LENGTH as u64)
        })
}

fn is_partial(progress: &FileDownloadProgress) -> bool {
    progress.total_blocks > 0
        && progress.pulled_blocks > 0
        && progress.pulling_blocks > 0
        && progress.bytes_done > 0
        && progress.bytes_done < progress.bytes_total
        && progress.bytes_total <= LENGTH as i64
}

async fn wait_pending(
    root: &Path,
    node: &Client,
    folder: &FolderId,
    peer: &DeviceId,
    name: &str,
    path: &Path,
    page: ListPage,
) -> Stage<()> {
    let relative = TargetPath::local(name);
    tokio::time::timeout(WAIT, async {
        loop {
            check_authorization(root)?;
            if path.exists() {
                return Err("local-api-pair-sample-arrived-before-pending-observation");
            }
            let available = match node.index_file_info(folder, &relative).await {
                Ok(index) => {
                    index.global.name == name
                        && index.global.size == LENGTH as u64
                        && index.local.name.is_empty()
                        && index.availability.as_ref().is_some_and(|items| {
                            items
                                .iter()
                                .any(|item| &item.device_id == peer && !item.from_temporary)
                        })
                }
                Err(Error::Http { response }) if response.status() == 404 => false,
                Err(_) => return Err("local-api-pair-index-unconfirmed"),
            };
            if available {
                let need = node
                    .folder_need(folder, page)
                    .await
                    .map_err(|_| "local-api-pair-need-unavailable")?;
                if pending(&need, name) {
                    return Ok(());
                }
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .map_err(|_| "local-api-pair-pending-timed-out")?
}

async fn wait_partial(root: &Path, node: &Client, folder: &FolderId) -> Stage<Value> {
    tokio::time::timeout(WAIT, async {
        loop {
            check_authorization(root)?;
            match node.folder_download_progress(folder).await {
                Ok(seen) => {
                    if let Some(transfer) = seen.files.get(INCOMING).filter(|progress| is_partial(progress)) {
                        return Ok(json!({"bytes_done":transfer.bytes_done,"bytes_total":transfer.bytes_total,
                                         "pulled_blocks":transfer.pulled_blocks,"pulling_blocks":transfer.pulling_blocks}));
                    }
                }
                Err(Error::Http { response }) if response.status() == 500 => {}
                Err(_) => return Err("local-api-pair-partial-progress-unconfirmed"),
            }
            tokio::time::sleep(POLL).await;
        }
    }).await.map_err(|_| "local-api-pair-partial-progress-timed-out")?
}

async fn wait_file(root: &Path, path: &Path, expected: &Value) -> Stage<Value> {
    tokio::time::timeout(WAIT, async {
        loop {
            check_authorization(root)?;
            if path.exists() {
                let actual = fingerprint(path)?;
                if &actual == expected {
                    return Ok(actual);
                }
                return Err("local-api-pair-received-file-digest-mismatch");
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .map_err(|_| "local-api-pair-file-receive-timed-out")?
}

fn incomplete(state: &CompletionSnapshot) -> bool {
    state.completion_percent < 100.0
        && state.need_bytes.is_some_and(|bytes| bytes > 0)
        && state.global_bytes == Some(2 * LENGTH as u64)
}

fn complete(state: &CompletionSnapshot) -> bool {
    state.completion_percent == 100.0
        && state.need_bytes == Some(0)
        && state.global_bytes == Some(2 * LENGTH as u64)
}

async fn wait_completion(
    root: &Path,
    node: &Client,
    folder: &FolderId,
    peer: &DeviceId,
    expectation: fn(&CompletionSnapshot) -> bool,
) -> Stage<Value> {
    tokio::time::timeout(WAIT, async {
        loop {
            check_authorization(root)?;
            let state = node
                .folder_completion(folder, peer)
                .await
                .map_err(|_| "local-api-pair-completion-query-unavailable")?;
            if expectation(&state) {
                return Ok(json!({
                    "percent":state.completion_percent,"need_bytes":state.need_bytes,
                    "global_bytes":state.global_bytes,
                }));
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .map_err(|_| "local-api-pair-completion-timed-out")?
}

async fn selection(
    root: &Path,
    pair: &Pair,
    primary: &Client,
    secondary: &Client,
    local: &LocalApiClient,
    seed: u64,
) -> Stage<Value> {
    const SAMPLE: &str = "selection-sample.bin";
    const WITNESS: &str = "selection-witness.bin";
    check_authorization(root)?;
    let mode = primary
        .set_folder_selective_enabled(&pair.primary_folder, true)
        .await
        .map_err(|_| "local-api-selective-mode-unconfirmed")?;
    if !mode.requested_mode_match {
        return Err("local-api-selective-mode-mismatch");
    }
    let source = pair.secondary_files.join(SAMPLE);
    let witness = pair.secondary_files.join(WITNESS);
    let target = pair.primary_files.join(SAMPLE);
    let unselected = pair.primary_files.join(WITNESS);
    check_authorization(root)?;
    fs::write(&source, format!("R33 selected sample {seed:016x}\n"))
        .and_then(|()| fs::write(&witness, b"R33 independently unselected file"))
        .map_err(|_| "local-api-selective-source-write-unavailable")?;
    let sent = fingerprint(&source)?;
    let preserved = fingerprint(&witness)?;
    check_authorization(root)?;
    secondary
        .request_scan(&pair.secondary_folder)
        .await
        .map_err(|_| "local-api-selective-source-scan-unconfirmed")?;
    let browse = SelectiveBrowseOptions::new(SelectiveScope::FolderRoot);
    tokio::time::timeout(WAIT, async {
        loop {
            check_authorization(root)?;
            let tree = primary
                .browse_selective(&pair.primary_folder, &browse)
                .await
                .map_err(|_| "local-api-selective-published-tree-unavailable")?;
            if [SAMPLE, WITNESS].iter().all(|name| {
                tree.entries
                    .get(*name)
                    .is_some_and(|entry| !entry.selected && !entry.exists_locally)
            }) {
                return Ok::<(), &'static str>(());
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .map_err(|_| "local-api-selective-unselected-tree-timed-out")??;
    if target.exists() || unselected.exists() {
        return Err("local-api-selective-file-present-before-selection");
    }
    let scope = SelectiveScope::Path(TargetPath::local(SAMPLE));
    check_authorization(root)?;
    if let Err(error) = local
        .request_selection(&pair.primary_folder, &scope, SelectiveAction::Select)
        .await
    {
        let mut result = unavailable(&error);
        result["target_file_present_after_error"] = json!(target.exists());
        result["unselected_witness_absent"] = json!(!unselected.exists());
        result["source_file_unchanged"] = json!(fingerprint(&source)? == sent);
        return Ok(result);
    }
    let received = wait_file(root, &target, &sent).await?;
    if unselected.exists() || fingerprint(&witness)? != preserved {
        return Err("local-api-selective-witness-changed");
    }
    check_authorization(root)?;
    if let Err(error) = local
        .request_selection(&pair.primary_folder, &scope, SelectiveAction::Deselect)
        .await
    {
        let mut result = unavailable(&error);
        result["received_file"] = received;
        result["deselection_target_still_present"] = json!(target.exists());
        return Ok(result);
    }
    tokio::time::timeout(WAIT, async {
        while target.exists() {
            check_authorization(root)?;
            tokio::time::sleep(POLL).await;
        }
        Ok::<(), &'static str>(())
    })
    .await
    .map_err(|_| "local-api-selective-receiving-file-still-present")??;
    if fingerprint(&source)? != sent || fingerprint(&witness)? != preserved || unselected.exists() {
        return Err("local-api-selective-source-or-witness-changed");
    }
    Ok(
        json!({"state":"observed","received_file":received,"receiving_file_removed":true,
              "source_file_preserved":true,"unselected_witness_preserved_on_source_only":true}),
    )
}

async fn measure(
    root: &Path,
    pair: &Pair,
    primary: &Client,
    secondary: &Client,
    local: &LocalApiClient,
    seed: u64,
) -> Stage<Value> {
    let peer = &secondary.instance().device_id;
    let page = ListPage::new(1, 10).map_err(|_| "local-api-pair-need-page-invalid")?;
    let receive = |limit| {
        BandwidthPatch::default()
            .max_receive_kib_per_second(limit)
            .limit_in_lan(true)
    };
    bandwidth(root, primary, receive(1)).await?;
    let from = pair.secondary_files.join(INCOMING);
    let to = pair.primary_files.join(INCOMING);
    check_authorization(root)?;
    fs::write(&from, data(seed)).map_err(|_| "local-api-pair-source-write-unavailable")?;
    let sent_in = fingerprint(&from)?;
    for (node, folder) in [
        (primary, &pair.primary_folder),
        (secondary, &pair.secondary_folder),
    ] {
        check_authorization(root)?;
        node.resume_folder(folder)
            .await
            .map_err(|_| "local-api-pair-folder-resume-unconfirmed")?;
    }
    check_authorization(root)?;
    secondary
        .request_scan(&pair.secondary_folder)
        .await
        .map_err(|_| "local-api-pair-sender-scan-unconfirmed")?;
    wait_pending(
        root,
        primary,
        &pair.primary_folder,
        peer,
        INCOMING,
        &to,
        page,
    )
    .await?;
    let need_before = local.folder_need(&pair.primary_folder, page).await;
    let partial = wait_partial(root, primary, &pair.primary_folder).await?;
    if to.exists() {
        return Err("local-api-pair-sample-arrived-before-partial-observation");
    }
    let protected_progress = match local.folder_download_progress(&pair.primary_folder).await {
        Ok(state) if state.files.get(INCOMING).is_some_and(is_partial) => {
            json!({"state":"observed"})
        }
        Ok(_) => json!({"state":"partial-file-not-observed"}),
        Err(error) => unavailable(&error),
    };
    let sessions = primary
        .connections()
        .await
        .map_err(|_| "local-api-pair-connection-unavailable")?;
    if !sessions
        .connections
        .get(peer)
        .is_some_and(|item| item.connected)
    {
        return Err("local-api-pair-selected-peer-not-connected");
    }
    let device_inventory = match local.devices().await {
        Ok(state)
            if state.iter().any(|item| &item.device_id == peer)
                && state
                    .iter()
                    .any(|item| item.device_id == primary.instance().device_id) =>
        {
            json!({"state":"observed","matches_both_owned_identities":true})
        }
        Ok(_) => json!({"state":"owned-device-identity-not-observed"}),
        Err(error) => unavailable(&error),
    };
    let primary_transport = match local.connections().await {
        Ok(state)
            if state
                .connections
                .get(peer)
                .is_some_and(|item| item.connected) =>
        {
            json!({"state":"observed"})
        }
        Ok(_) => json!({"state":"selected-peer-not-observed"}),
        Err(error) => unavailable(&error),
    };
    bandwidth(root, primary, receive(0)).await?;
    let incoming = wait_file(root, &to, &sent_in).await?;
    let need_after = primary
        .folder_need(&pair.primary_folder, page)
        .await
        .map_err(|_| "local-api-pair-post-transfer-need-unavailable")?;
    if pending(&need_after, INCOMING) {
        return Err("local-api-pair-file-still-needed-after-receive");
    }
    let protected_need = match need_before {
        Ok(before) if pending(&before, INCOMING) => {
            match local.folder_need(&pair.primary_folder, page).await {
                Ok(after) if !pending(&after, INCOMING) => {
                    json!({"state":"observed","pending_then_absent":true})
                }
                Ok(_) => json!({"state":"file-still-needed-after-receive"}),
                Err(error) => unavailable(&error),
            }
        }
        Ok(_) => json!({"state":"pending-file-not-observed"}),
        Err(error) => unavailable(&error),
    };

    bandwidth(root, secondary, receive(1)).await?;
    let from = pair.primary_files.join(OUTGOING);
    let to = pair.secondary_files.join(OUTGOING);
    check_authorization(root)?;
    fs::write(&from, data(seed.rotate_left(13) ^ 0xd372_65f8_5417_e20b))
        .map_err(|_| "local-api-pair-source-write-unavailable")?;
    let sent_out = fingerprint(&from)?;
    if sent_in == sent_out {
        return Err("local-api-pair-independent-payloads-mismatch");
    }
    check_authorization(root)?;
    primary
        .request_scan(&pair.primary_folder)
        .await
        .map_err(|_| "local-api-pair-sender-scan-unconfirmed")?;
    wait_pending(
        root,
        secondary,
        &pair.secondary_folder,
        &primary.instance().device_id,
        OUTGOING,
        &to,
        page,
    )
    .await?;
    let before = wait_completion(root, primary, &pair.primary_folder, peer, incomplete).await?;
    let completion_before = local.folder_completions(&pair.primary_folder).await;
    bandwidth(root, secondary, receive(0)).await?;
    let outgoing = wait_file(root, &to, &sent_out).await?;
    let after = wait_completion(root, primary, &pair.primary_folder, peer, complete).await?;
    let protected_completion = match completion_before {
        Ok(before) if before.get(peer).is_some_and(incomplete) => {
            match local.folder_completions(&pair.primary_folder).await {
                Ok(after) if after.get(peer).is_some_and(complete) => {
                    json!({"state":"observed","same_peer_and_indexed_file_set":true})
                }
                Ok(_) => json!({"state":"complete-peer-not-observed"}),
                Err(error) => unavailable(&error),
            }
        }
        Ok(_) => json!({"state":"incomplete-peer-not-observed"}),
        Err(error) => unavailable(&error),
    };
    let selective = selection(root, pair, primary, secondary, local, seed).await?;
    Ok(json!({
        "actual_pending_file":true, "actual_partial_block_progress":true,
        "actual_incomplete_then_completed_peer":true, "ordinary_partial":partial,
        "ordinary_completion":{"before":before,"after":after},
        "files":{"incoming":incoming,"outgoing":outgoing},
        "local_api":{"LA-002":device_inventory,"SYM-049":protected_need,"SYM-091":selective,"LA-016":protected_progress,
                     "LA-017":protected_completion,"LA-019":primary_transport},
    }))
}

pub(super) async fn verify(
    root: &Path,
    engine: &Path,
    core: &ManagedInstance,
    endpoint: ManagementEndpoint,
    device: &DeviceId,
    run: &str,
) -> Stage<Value> {
    check_authorization(root)?;
    let primary = core.client();
    if &primary.instance().device_id != device {
        return Err("local-api-pair-primary-device-mismatch");
    }
    let [management, primary_port, peer_port] = ports()?;
    let directory = root.join("local-api-peer-check");
    fs::create_dir(&directory).map_err(|_| "local-api-pair-case-root-unavailable")?;
    for name in ["primary-files", "secondary-files", "secondary-run"] {
        fs::create_dir(directory.join(name))
            .map_err(|_| "local-api-pair-test-directories-unavailable")?;
    }
    let sentinel = directory.join("untouched.txt");
    fs::write(&sentinel, b"Owned sentinel outside both registered folders")
        .map_err(|_| "local-api-pair-sentinel-unavailable")?;
    let sentinel_digest = fingerprint(&sentinel)?;
    let prior_rate = primary
        .bandwidth_configuration()
        .await
        .map_err(|_| "local-api-pair-original-rate-unavailable")?;
    let prior_net = primary
        .network_configuration()
        .await
        .map_err(|_| "local-api-pair-original-listeners-unavailable")?;
    let prior_folders = primary
        .folders()
        .await
        .map_err(|_| "local-api-pair-original-registry-unavailable")?;
    let prior_devices = primary
        .devices()
        .await
        .map_err(|_| "local-api-pair-original-peers-unavailable")?;
    let seed = run
        .get(..16)
        .and_then(|part| u64::from_str_radix(part, 16).ok())
        .filter(|&value| value != 0)
        .ok_or("local-api-pair-test-seed-invalid")?;
    let local = LocalApiClient::connect(
        LocalApiConnectOptions::new(endpoint)
            .map_err(|_| "local-api-pair-client-options-unavailable")?
            .expected_device_id(device.clone()),
    )
    .await
    .map_err(|_| "local-api-pair-client-identity-unconfirmed")?;
    check_authorization(root)?;
    let mut second = start_at(
        engine,
        &directory.join("secondary-run"),
        loopback_endpoint(management)?,
    )
    .await?;
    let transfer = async {
        let secondary = second.client();
        if secondary.instance().device_id == *device {
            return Err("local-api-pair-shared-device-identity");
        }
        let addresses = [
            listen(root, primary, primary_port).await?,
            listen(root, secondary, peer_port).await?,
        ];
        let pair = register(root, &directory, primary, secondary, addresses).await?;
        let receipt = measure(root, &pair, primary, secondary, &local, seed).await;
        Ok((pair, receipt))
    }
    .await;
    let peer_id = second.client().instance().device_id.clone();
    if !end(&mut second).await {
        return Err("local-api-pair-secondary-exit-unconfirmed");
    }
    let (pair, receipt) = transfer?;
    check_authorization(root)?;
    let actual = primary
        .folder(&pair.primary_folder)
        .await
        .map_err(|_| "local-api-pair-cleanup-folder-unavailable")?;
    if actual.id != pair.primary_folder
        || actual.path.to_protocol().ok()
            != TargetPath::local(&pair.primary_files).to_protocol().ok()
    {
        return Err("local-api-pair-cleanup-folder-mismatch");
    }
    primary
        .remove_folder_keep_files(&pair.primary_folder)
        .await
        .map_err(|_| "local-api-pair-unregister-unconfirmed")?;
    check_authorization(root)?;
    primary
        .remove_device(&peer_id)
        .await
        .map_err(|_| "local-api-pair-peer-removal-unconfirmed")?;
    bandwidth(
        root,
        primary,
        BandwidthPatch::default()
            .max_send_kib_per_second(prior_rate.max_send_kib_per_second)
            .max_receive_kib_per_second(prior_rate.max_receive_kib_per_second)
            .limit_in_lan(prior_rate.limit_in_lan),
    )
    .await?;
    check_authorization(root)?;
    let restored_net = primary
        .update_network_configuration(
            &NetworkPatch::default()
                .listen_addresses(prior_net.listen_addresses)
                .global_discovery(prior_net.global_announce_enabled)
                .local_discovery(prior_net.local_announce_enabled)
                .reconnection_interval_seconds(prior_net.reconnection_interval_seconds),
        )
        .await
        .map_err(|_| "local-api-pair-restore-network-unconfirmed")?;
    let folders = primary
        .folders()
        .await
        .map_err(|_| "local-api-pair-restored-registry-unavailable")?;
    let devices = primary
        .devices()
        .await
        .map_err(|_| "local-api-pair-restored-peers-unavailable")?;
    if !restored_net.requested_fields_match
        || folders.len() != prior_folders.len()
        || prior_folders.iter().any(|expected| {
            !folders
                .iter()
                .any(|value| super::configuration::same_configuration(value, expected))
        })
        || devices.len() != prior_devices.len()
        || primary.device(&peer_id).await.is_ok()
        || fingerprint(&sentinel)? != sentinel_digest
    {
        return Err("local-api-pair-restoration-mismatch");
    }
    let mut result = match receipt {
        Ok(observed) => {
            for (name, key) in [(INCOMING, "incoming"), (OUTGOING, "outgoing")] {
                for folder in [&pair.primary_files, &pair.secondary_files] {
                    if fingerprint(&folder.join(name))? != observed["files"][key] {
                        return Err("local-api-pair-cleanup-changed-file");
                    }
                }
            }
            observed
        }
        Err(reason) => json!({"reason":reason}),
    };
    result["ok"] = json!(result.get("reason").is_none());
    result["device"] = json!(device_alias(core, run));
    result["secondary_device"] = json!(device_alias(&second, run));
    result["secondary_normal_owned_exit"] = json!(true);
    result["fixture_unregistered"] = json!(true);
    result["device_restored"] = json!(true);
    result["outside_file"] = sentinel_digest;
    Ok(result)
}
