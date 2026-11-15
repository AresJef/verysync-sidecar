//! Native helper results are checked independently from raw research calls.
use super::managed_fixture::{options, TestResult};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use verysync_sidecar::{Error, ManagedInstance};

#[tokio::test]
async fn actual_native_target_path_completions_preserve_prefixes_selectors_and_owned_data(
) -> TestResult {
    use verysync_sidecar::{TargetPath, TargetPathBrowseOptions};
    let root = tempfile::Builder::new()
        .prefix("vs-path-completion-")
        .tempdir()?
        .keep();
    let paths = root.join("synthetic paths");
    let alpha = paths.join("alpha \u{4e8c} % +");
    let alpine = paths.join("alpine");
    std::fs::create_dir_all(alpha.join("deep"))?;
    std::fs::create_dir(&alpine)?;
    std::fs::create_dir(paths.join("beta"))?;
    std::fs::write(paths.join("alpha.txt"), b"retained native completion bytes")?;
    let mut owner = ManagedInstance::start(options(&root.join("core"))?).await?;
    let id = owner.client().instance().device_id.clone();
    let config = std::fs::read(root.join("core").join("setting.dat"))?;
    let prefix = TargetPath::local(paths.join("al"));
    let options = TargetPathBrowseOptions::default().current(prefix);
    let observed = owner.client().browse_target_paths(&options).await?;
    assert_eq!(observed.paths.len(), 2);
    let actual: std::collections::BTreeSet<_> = observed
        .paths
        .iter()
        .map(|p| {
            assert!(p.local_path().is_none());
            assert_eq!(p.style(), TargetPath::local(&paths).style());
            p.to_protocol().map(std::path::PathBuf::from)
        })
        .collect::<verysync_sidecar::Result<_>>()?;
    assert_eq!(
        actual,
        std::collections::BTreeSet::from([alpha.clone(), alpine])
    );
    assert!(!format!("{options:?} {observed:?}").contains("synthetic paths"));
    let explicit = owner
        .client()
        .browse_target_paths(&options.clone().filesystem("basic"))
        .await?;
    assert_eq!(
        explicit
            .paths
            .iter()
            .map(|p| p.to_protocol().map(str::to_owned))
            .collect::<verysync_sidecar::Result<Vec<_>>>()?,
        observed
            .paths
            .iter()
            .map(|p| p.to_protocol().map(str::to_owned))
            .collect::<verysync_sidecar::Result<Vec<_>>>()?
    );
    let mut trailing = alpha.clone();
    trailing.push("");
    let children = owner
        .client()
        .browse_target_paths(
            &TargetPathBrowseOptions::default().current(TargetPath::local(trailing)),
        )
        .await?;
    assert_eq!(children.paths.len(), 1);
    assert_eq!(
        std::path::Path::new(children.paths[0].to_protocol()?),
        alpha.join("deep")
    );
    for current in [paths.join("absent"), paths.join("alpha.txt")] {
        assert!(owner
            .client()
            .browse_target_paths(
                &TargetPathBrowseOptions::default().current(TargetPath::local(current))
            )
            .await?
            .paths
            .is_empty());
    }
    assert!(owner
        .client()
        .browse_target_paths(
            &options
                .clone()
                .filesystem("synthetic-unavailable-filesystem")
        )
        .await?
        .paths
        .is_empty());
    let roots = owner
        .client()
        .browse_target_paths(&TargetPathBrowseOptions::default())
        .await?;
    assert!(!roots.paths.is_empty());
    assert_eq!(owner.client().system_status().await?.device_id, id);
    assert_eq!(
        std::fs::read(root.join("core").join("setting.dat"))?,
        config
    );
    assert_eq!(
        std::fs::read(paths.join("alpha.txt"))?,
        b"retained native completion bytes"
    );
    assert!(alpha.join("deep").is_dir());
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_target_path_browse_snapshots=7 actual_directory_prefix_and_children=true files_excluded=true explicit_basic_selector_matches=true unknown_selector_empty_not_support=true roots_observed=true target_paths_private_no_controller_lookup=true identity_configuration_and_synthetic_data_retained=true normal_owned_tree_exit=true");
    Ok(())
}

#[tokio::test]
async fn actual_native_index_file_metadata_preserves_native_records_and_missing_objects(
) -> TestResult {
    use verysync_sidecar::{
        CreateFolderOptions, FolderId, FolderScanPatch, FolderState, SyncFileKind, TargetPath,
    };
    let root = tempfile::Builder::new()
        .prefix("vs-index-file-")
        .tempdir()?
        .keep();
    let data = root.join("synthetic data");
    let branch = std::path::Path::new("branch \u{4e8c} % +");
    std::fs::create_dir_all(data.join(branch))?;
    let original = b"synthetic native index bytes";
    std::fs::write(data.join("root.txt"), original)?;
    std::fs::write(data.join(branch).join("child.txt"), b"distinct child bytes")?;
    let mut owner = ManagedInstance::start(options(&root.join("core"))?).await?;
    let id = owner.client().instance().device_id.clone();
    let folder = FolderId::parse("typed-native-index-file")?;
    owner
        .client()
        .create_folder(
            &CreateFolderOptions::new(folder.clone(), TargetPath::local(&data)).paused(true),
        )
        .await?;
    owner
        .client()
        .update_folder_scan_configuration(
            &folder,
            &FolderScanPatch::default()
                .watcher(false)
                .rescan_interval_seconds(0)
                .disable_initial_scan(false),
        )
        .await?;
    owner.client().resume_folder(&folder).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status = owner.client().folder_status(&folder).await?;
            if status.state == Some(FolderState::Idle) && status.local_files == Some(2) {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await??;
    let configuration = std::fs::read(root.join("core").join("setting.dat"))?;
    let file = owner
        .client()
        .index_file_info(&folder, &TargetPath::local("root.txt"))
        .await?;
    assert_eq!(file.global.name, "root.txt");
    assert_eq!(file.local.name, "root.txt");
    assert_eq!(file.global.kind, SyncFileKind::File);
    assert_eq!(file.global.size, original.len() as u64);
    assert_eq!(file.local.size, original.len() as u64);
    assert!(!file.global.version.is_empty());
    assert_eq!(file.global.version, file.local.version);
    assert!(file.availability.is_none());
    assert!(!file.global.deleted && !file.global.ignored && !file.global.invalid);
    assert_eq!(file.global.num_blocks, 1);
    assert!(file
        .global
        .blocks_hash
        .as_ref()
        .is_some_and(|v| !v.is_empty()));
    assert!(file.global.previous_blocks_hash.is_none());
    let child = owner
        .client()
        .index_file_info(&folder, &TargetPath::local(branch.join("child.txt")))
        .await?;
    assert!(child.global.name.ends_with("child.txt"));
    assert_eq!(child.global.size, b"distinct child bytes".len() as u64);
    let directory = owner
        .client()
        .index_file_info(&folder, &TargetPath::local(branch))
        .await?;
    assert_eq!(directory.global.kind, SyncFileKind::Directory);
    assert_eq!(directory.global.size, 0);
    assert_eq!(directory.global.num_blocks, 0);
    assert!(directory.global.blocks_hash.is_none());
    assert!(matches!(
        owner
            .client()
            .index_file_info(&folder, &TargetPath::local("absent.txt"))
            .await,
        Err(Error::Http { response }) if response.status()==404
    ));
    std::fs::write(
        data.join("unscanned.txt"),
        b"caller explicitly scans this later",
    )?;
    assert!(matches!(
        owner
            .client()
            .index_file_info(&folder, &TargetPath::local("unscanned.txt"))
            .await,
        Err(Error::Http { response }) if response.status()==404
    ));
    assert_eq!(
        owner.client().folder_status(&folder).await?.local_files,
        Some(2)
    );
    owner.client().request_scan(&folder).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status = owner.client().folder_status(&folder).await?;
            if status.state == Some(FolderState::Idle) && status.local_files == Some(3) {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await??;
    let scanned = owner
        .client()
        .index_file_info(&folder, &TargetPath::local("unscanned.txt"))
        .await?;
    assert_eq!(
        scanned.global.size,
        b"caller explicitly scans this later".len() as u64
    );
    assert_eq!(owner.client().system_status().await?.device_id, id);
    assert_eq!(
        std::fs::read(root.join("core").join("setting.dat"))?,
        configuration
    );
    assert_eq!(std::fs::read(data.join("root.txt"))?, original);
    assert_eq!(
        std::fs::read(data.join(branch).join("child.txt"))?,
        b"distinct child bytes"
    );
    assert_eq!(
        std::fs::read(data.join("unscanned.txt"))?,
        b"caller explicitly scans this later"
    );
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_index_file_metadata_snapshots=4 native_missing_objects=2 nested_unicode_target_path=true directory_kind_and_null_hash=true null_availability_retained=true unscanned_file_not_fabricated=true explicit_scan_effect_separate=true identity_configuration_and_three_files_retained=true normal_owned_exit=true");
    Ok(())
}

#[tokio::test]
async fn actual_native_index_file_availability_preserves_zero_local_state() -> TestResult {
    use verysync_sidecar::{
        BandwidthPatch, Client, CreateDeviceOptions, DeviceId, DevicePatch, DeviceTransport,
        FolderId, JoinFolderOptions, RawMethod, RawRequest, RequestEffect, TargetPath,
    };
    async fn address(client: &Client) -> TestResult<String> {
        Ok(tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                for status in client.listener_status().await?.into_values() {
                    for address in status.lan_addresses {
                        if address
                            .strip_prefix("tcp://")
                            .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
                            .is_some_and(|a| {
                                a.ip().is_loopback() && a.port() != 0 && a.port() != 18886
                            })
                        {
                            return Ok::<_, Error>(address);
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??)
    }
    async fn associate(
        client: &Client,
        folder: &FolderId,
        peer: &DeviceId,
        address: &str,
    ) -> TestResult {
        assert!(
            client
                .create_device(
                    &CreateDeviceOptions::new(peer.clone()).settings(
                        DevicePatch::default()
                            .addresses(vec![address.to_owned()])
                            .allowed_transports(vec![DeviceTransport::Tcp])
                            .paused(false)
                    )
                )
                .await?
                .requested_fields_match
        );
        client.share_folder_with(folder, peer).await?;
        Ok(())
    }

    let root = tempfile::Builder::new()
        .prefix("vs-index-peer-")
        .tempdir()?
        .keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let aid = a.client().instance().device_id.clone();
    let bid = b.client().instance().device_id.clone();
    assert_ne!(aid, bid);
    let aa = address(a.client()).await?;
    let ba = address(b.client()).await?;
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    let origin = root.join("source files");
    let received = root.join("receiver files");
    std::fs::create_dir_all(&origin)?;
    let mut seed = 0x34abcdef12345678u64;
    let sample: Vec<u8> = (0..131072)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect();
    std::fs::write(origin.join("sample.bin"), &sample)?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&origin)).paused(true))
        .await?;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(&received)).paused(true))
        .await?;
    assert!(
        b.client()
            .update_bandwidth_configuration(
                &BandwidthPatch::default()
                    .max_receive_kib_per_second(1)
                    .limit_in_lan(true)
            )
            .await?
            .requested_fields_match
    );
    let setup = RawRequest::new(
        RawMethod::Patch,
        ["rest", "config", "folders", bf.configuration.id.as_str()],
        RequestEffect::MayModify,
    )?
    .json_body(&serde_json::json!({"antsPullerEnabled":false,"pullerSessionEnabled":false}))?;
    assert_eq!(b.client().raw_request(&setup).await?.status(), 200);
    associate(a.client(), &af.configuration.id, &bid, &ba).await?;
    associate(b.client(), &bf.configuration.id, &aid, &aa).await?;
    a.client().resume_folder(&af.configuration.id).await?;
    b.client().resume_folder(&bf.configuration.id).await?;
    a.client().request_scan(&af.configuration.id).await?;
    let file = TargetPath::local("sample.bin");
    let info = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match b
                .client()
                .index_file_info(&bf.configuration.id, &file)
                .await
            {
                Ok(info)
                    if info
                        .availability
                        .as_ref()
                        .is_some_and(|records| !records.is_empty()) =>
                {
                    return Ok::<_, Error>(info)
                }
                Ok(_) => {}
                Err(Error::Http { response }) if response.status() == 404 => {}
                Err(error) => return Err(error),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    assert_eq!(info.global.name, "sample.bin");
    assert_eq!(info.global.size, sample.len() as u64);
    assert_eq!(info.global.kind, verysync_sidecar::SyncFileKind::File);
    assert!(info.local.name.is_empty());
    assert!(info.local.version.is_empty());
    assert_eq!(info.local.size, 0);
    assert_eq!(info.local.num_blocks, 0);
    assert!(info.local.blocks_hash.is_none());
    assert_eq!(info.local.signature.version, 0);
    assert!(info.local.signature.encoded_signature.is_none());
    assert!(!received.join("sample.bin").exists());
    let available = info
        .availability
        .as_ref()
        .ok_or("nonempty availability required")?;
    assert!(available
        .iter()
        .any(|source| source.device_id == aid && !source.from_temporary));
    assert_eq!(info.global.signature.version, 3);
    let encoded = info
        .global
        .signature
        .encoded_signature
        .as_ref()
        .ok_or("native shared-file signature absent")?;
    assert!(!encoded.is_empty());
    let debug = format!(
        "{info:?} {:?} {:?} {:?} {available:?}",
        info.global, info.local, info.global.signature
    );
    assert!(!debug.contains(encoded));
    assert!(!debug.contains(aid.as_str()));
    assert!(!debug.contains(keys.read_only_key.expose_secret()));
    assert!(!debug.contains(keys.read_write_key.expose_secret()));
    println!("native_index_file_availability=true actual_private_peer_matches=true non_temporary_source_record=true shared_native_signature_version3_preserved_without_verification=true zero_local_record_preserved=true receiver_file_not_complete=true no_wan_or_completion_claim=true caller_fixture_polling_separate_from_single_sdk_reads=true");
    assert_eq!(std::fs::read(origin.join("sample.bin"))?, sample);
    assert_eq!(a.client().system_status().await?.device_id, aid);
    assert_eq!(b.client().system_status().await?.device_id, bid);
    for owner in [&mut b, &mut a] {
        let exit = owner.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn actual_native_index_browse_keeps_depth_filters_and_index_only_observations() -> TestResult
{
    use verysync_sidecar::{
        CreateFolderOptions, FolderId, FolderScanPatch, FolderState, IndexBrowseOptions,
        IndexTreeEntry, SyncFileKind, TargetPath,
    };
    fn node<'a>(entries: &'a [IndexTreeEntry], name: &str) -> TestResult<&'a IndexTreeEntry> {
        entries
            .iter()
            .find(|entry| entry.name == name)
            .ok_or_else(|| "expected indexed entry absent".into())
    }
    let root = tempfile::Builder::new()
        .prefix("vs-index-tree-")
        .tempdir()?
        .keep();
    let data = root.join("synthetic data");
    let branch = std::path::Path::new("branch \u{4e8c} % +");
    let deep = branch.join("deep");
    std::fs::create_dir_all(data.join(&deep))?;
    let payload = b"synthetic indexed browse bytes";
    let files = [
        std::path::PathBuf::from("root.txt"),
        branch.join("child.txt"),
        deep.join("leaf.txt"),
    ];
    for file in &files {
        std::fs::write(data.join(file), payload)?;
    }
    let mut owner = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = owner.client().instance().device_id.clone();
    let folder = FolderId::parse("typed-native-index-browse")?;
    owner
        .client()
        .create_folder(
            &CreateFolderOptions::new(folder.clone(), TargetPath::local(&data)).paused(true),
        )
        .await?;
    owner
        .client()
        .update_folder_scan_configuration(
            &folder,
            &FolderScanPatch::default()
                .watcher(false)
                .rescan_interval_seconds(0)
                .disable_initial_scan(false),
        )
        .await?;
    owner.client().resume_folder(&folder).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status = owner.client().folder_status(&folder).await?;
            if status.state == Some(FolderState::Idle) && status.local_files == Some(3) {
                return Ok::<_, verysync_sidecar::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await??;
    let configuration = std::fs::read(root.join("core").join("setting.dat"))?;
    // A newly created but unscanned file proves that this reads native index
    // knowledge rather than performing a controller or target filesystem listing.
    std::fs::write(data.join("not-indexed.txt"), b"unindexed retained bytes")?;
    let flat = owner
        .client()
        .browse_index(&folder, &IndexBrowseOptions::default())
        .await?;
    assert_eq!(flat.entries.len(), 2);
    assert!(flat.entries.iter().all(|entry| entry.children.is_none()));
    let branch_name = branch.to_str().ok_or("synthetic prefix must be UTF8")?;
    assert_eq!(
        node(&flat.entries, branch_name)?.kind,
        SyncFileKind::Directory
    );
    assert_eq!(node(&flat.entries, "root.txt")?.size, payload.len() as u64);
    assert!(!format!("{flat:?} {:?}", node(&flat.entries, branch_name)?).contains(branch_name));
    let one = owner
        .client()
        .browse_index(&folder, &IndexBrowseOptions::default().levels(Some(1)))
        .await?;
    let first = node(&one.entries, branch_name)?
        .children
        .as_ref()
        .ok_or("first descendant level absent")?;
    assert_eq!(first.len(), 2);
    assert!(node(first, "deep")?.children.is_none());
    let complete = owner
        .client()
        .browse_index(&folder, &IndexBrowseOptions::default().levels(None))
        .await?;
    let first = node(&complete.entries, branch_name)?
        .children
        .as_ref()
        .ok_or("native descendants absent")?;
    let second = node(first, "deep")?
        .children
        .as_ref()
        .ok_or("second descendant level absent")?;
    assert_eq!(node(second, "leaf.txt")?.kind, SyncFileKind::File);
    assert!(!node(second, "leaf.txt")?.modified.is_empty());
    let directories = owner
        .client()
        .browse_index(
            &folder,
            &IndexBrowseOptions::default()
                .levels(None)
                .directories_only(true),
        )
        .await?;
    assert_eq!(directories.entries.len(), 1);
    assert_eq!(directories.entries[0].kind, SyncFileKind::Directory);
    let nested = directories.entries[0]
        .children
        .as_ref()
        .ok_or("nested directory absent")?;
    assert_eq!(nested.len(), 1);
    assert_eq!(nested[0].name, "deep");
    assert_eq!(nested[0].kind, SyncFileKind::Directory);
    assert!(nested[0].children.is_none());
    let all_again = owner
        .client()
        .browse_index(
            &folder,
            &IndexBrowseOptions::default()
                .levels(None)
                .directories_only(false),
        )
        .await?;
    assert_eq!(all_again.entries.len(), 2);
    assert_eq!(
        node(&all_again.entries, "root.txt")?.kind,
        SyncFileKind::File
    );
    let scoped = owner
        .client()
        .browse_index(
            &folder,
            &IndexBrowseOptions::default().prefix(TargetPath::local(branch)),
        )
        .await?;
    assert_eq!(scoped.entries.len(), 2);
    assert_eq!(
        node(&scoped.entries, "child.txt")?.size,
        payload.len() as u64
    );
    assert!(node(&scoped.entries, "deep")?.children.is_none());
    let nested = owner
        .client()
        .browse_index(
            &folder,
            &IndexBrowseOptions::default().prefix(TargetPath::local(&deep)),
        )
        .await?;
    assert_eq!(nested.entries.len(), 1);
    assert_eq!(nested.entries[0].name, "leaf.txt");
    for prefix in [
        std::path::Path::new("absent"),
        std::path::Path::new("root.txt"),
    ] {
        assert!(owner
            .client()
            .browse_index(
                &folder,
                &IndexBrowseOptions::default().prefix(TargetPath::local(prefix))
            )
            .await?
            .entries
            .is_empty());
    }
    assert!(matches!(
        owner
            .client()
            .browse_index(
                &FolderId::parse("not-configured")?,
                &IndexBrowseOptions::default()
            )
            .await,
        Err(Error::FolderNotFound { .. })
    ));
    assert_eq!(
        owner.client().folder_status(&folder).await?.local_files,
        Some(3)
    );
    assert_eq!(owner.client().system_status().await?.device_id, identity);
    assert_eq!(
        std::fs::read(root.join("core").join("setting.dat"))?,
        configuration
    );
    for file in &files {
        assert_eq!(std::fs::read(data.join(file))?, payload);
    }
    assert_eq!(
        std::fs::read(data.join("not-indexed.txt"))?,
        b"unindexed retained bytes"
    );
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_index_browse_snapshots=9 flat_zero_and_native_unlimited_depth=true actual_directory_filter_and_false_omission=true native_relative_unicode_prefix=true empty_missing_or_file_prefix=true index_not_filesystem_observation=true unknown_folder_refused=true identity_configuration_and_four_files_retained=true normal_owned_tree_exit=true");
    Ok(())
}

#[tokio::test]
async fn actual_native_core_log_text_retains_messages_filters_and_owned_state() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vslogtext-")
        .tempdir()?
        .keep();
    let state = root.join("core");
    let sentinel = root.join("retained.txt");
    std::fs::write(&sentinel, b"text log reads retain synthetic bytes")?;
    let mut owner = ManagedInstance::start(options(&state)?).await?;
    let identity = owner.client().instance().device_id.clone();
    let configuration = std::fs::read(state.join("setting.dat"))?;
    let nonce = "synthetic-private-text-log-message 二 %";
    owner.client().record_core_error(nonce).await?;
    let all = owner.client().core_log_text(None).await?;
    assert!(all.text.contains(nonce));
    assert!(!format!("{all:?}").contains(nonce));
    assert!(owner
        .client()
        .core_log_text(Some("1970-01-01T00:00:00Z"))
        .await?
        .text
        .contains(nonce));
    assert!(owner
        .client()
        .core_log_text(Some("2100-01-01T00:00:00Z"))
        .await?
        .text
        .is_empty());
    assert!(owner
        .client()
        .core_log_text(None)
        .await?
        .text
        .contains(nonce));
    assert_eq!(owner.client().system_status().await?.device_id, identity);
    assert_eq!(std::fs::read(state.join("setting.dat"))?, configuration);
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"text log reads retain synthetic bytes"
    );
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_core_log_text_snapshots=4 actual_explicit_synthetic_message=true native_past_filter=true empty_future_filter=true repeated_read_retains_message=true private_debug=true identity_configuration_sentinel_retained=true normal_owned_tree_exit=true no_controller_logger=true");
    Ok(())
}

#[tokio::test]
async fn actual_native_random_strings_preserve_requested_lengths_and_owned_state() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vsrandom-")
        .tempdir()?
        .keep();
    let state = root.join("core");
    let sentinel = root.join("retained.txt");
    std::fs::write(&sentinel, b"native generation retains synthetic data")?;
    let mut owner = ManagedInstance::start(options(&state)?).await?;
    let identity = owner.client().instance().device_id.clone();
    let configuration = std::fs::read(state.join("setting.dat"))?;
    for (length, expected) in [
        (None, 32),
        (Some(0), 32),
        (Some(1), 1),
        (Some(16), 16),
        (Some(u16::MAX), 65535),
    ] {
        let result = owner.client().native_random_string(length).await?;
        assert_eq!(result.value.len(), expected);
        assert!(result.value.bytes().all(|b| b.is_ascii_alphanumeric()));
        if expected >= 16 {
            assert!(!format!("{result:?}").contains(&result.value));
        }
    }
    assert_eq!(owner.client().system_status().await?.device_id, identity);
    assert!(owner.client().folders().await?.is_empty());
    assert_eq!(std::fs::read(state.join("setting.dat"))?, configuration);
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"native generation retains synthetic data"
    );
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_random_string_effects=5 default_and_zero_length_32=true exact_positive_lengths_1_16_65535=true ascii_alphanumeric=true identity_configuration_and_sentinel_retained=true private_debug=true normal_owned_tree_exit=true no_uniqueness_or_cryptographic_claim=true");
    Ok(())
}

#[tokio::test]
async fn actual_native_helpers_normalize_ids_collect_reports_and_preserve_explicit_boundaries(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vshelpers-")
        .tempdir()?
        .keep();
    let mut owner = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = owner.client().instance().device_id.clone();
    for value in [
        identity.to_string(),
        identity.as_str().to_lowercase(),
        identity.as_str().replace('-', ""),
    ] {
        assert_eq!(owner.client().normalize_device_id(&value).await?, identity);
    }
    assert!(matches!(
        owner.client().normalize_device_id("invalid").await,
        Err(Error::Api { .. })
    ));
    let mut checksum = identity.as_str().as_bytes().to_vec();
    let last = checksum.last_mut().ok_or("identity absent")?;
    *last = if *last == b'A' { b'B' } else { b'A' };
    let checksum = String::from_utf8(checksum)?;
    assert!(verysync_sidecar::DeviceId::parse(&checksum).is_ok());
    assert!(matches!(
        owner.client().normalize_device_id(&checksum).await,
        Err(Error::Api { .. })
    ));
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let lookup = owner.client().lookup_target_ip(ip).await?;
        assert_eq!(lookup.ip, ip);
        assert!(
            lookup.province.is_empty() && lookup.city.is_empty() && lookup.description.is_empty()
        );
    }
    let before = owner.client().diagnostics_options().await?;
    let health = owner.client().native_health().await?;
    assert!(matches!(
        health.status,
        verysync_sidecar::NativeHealthStatus::Ok
    ));
    let native_health = owner
        .client()
        .raw_request(&verysync_sidecar::RawRequest::new(
            verysync_sidecar::RawMethod::Get,
            ["rest", "noauth", "health"],
            verysync_sidecar::RequestEffect::ReadOnly,
        )?)
        .await?;
    assert_eq!(native_health.status(), 200);
    let raw_health: serde_json::Value = serde_json::from_slice(native_health.body_bytes())?;
    assert_eq!(raw_health["status"], health.status.native_value());
    let migration = owner.client().native_migration_progress().await?;
    assert!(migration.finished && migration.error_message.is_empty());
    let native_migration = owner
        .client()
        .raw_request(&verysync_sidecar::RawRequest::new(
            verysync_sidecar::RawMethod::Get,
            ["rest", "migrate", "progress"],
            verysync_sidecar::RequestEffect::ReadOnly,
        )?)
        .await?;
    assert_eq!(native_migration.status(), 200);
    let raw_migration: serde_json::Value = serde_json::from_slice(native_migration.body_bytes())?;
    assert!(raw_migration["name"].as_str() == Some(migration.name.as_str()));
    assert_eq!(raw_migration["total"].as_i64(), Some(migration.total));
    assert_eq!(
        raw_migration["completed"].as_i64(),
        Some(migration.completed)
    );
    assert_eq!(raw_migration["percent"].as_f64(), Some(migration.percent));
    assert_eq!(
        raw_migration["finished"].as_bool(),
        Some(migration.finished)
    );
    assert!(raw_migration["error"].as_str() == Some(migration.error_message.as_str()));
    #[cfg(unix)]
    {
        let control = reqwest::Client::builder()
            .unix_socket(root.join("core").join("gui.sock"))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()?;
        let reply = control
            .get("http://localhost/rest/noauth/health")
            .send()
            .await?;
        assert_eq!(reply.status(), reqwest::StatusCode::OK);
        assert!(reply.content_length().is_some_and(|length| length <= 4096));
        let value: serde_json::Value = reply.json().await?;
        assert_eq!(value["status"], "OK");
        println!("native_health_unauthenticated_control=true private_unix_socket_only=true");
    }
    let report = owner.client().collect_native_usage_report().await?;
    assert_eq!(report.version, verysync_sidecar::BASELINE_ENGINE_VERSION);
    let version = &owner.client().instance().version;
    assert_eq!(report.platform, format!("{}-{}", version.os, version.arch));
    assert_eq!(report.device_count, 1);
    assert!(!report.unique_id.as_deref().unwrap_or("").is_empty());
    let after = owner.client().diagnostics_options().await?;
    assert_eq!(before.usage_accepted_version, after.usage_accepted_version);
    assert_eq!(before.usage_seen_version, after.usage_seen_version);
    assert_eq!(before.usage_identifier(), after.usage_identifier());
    assert_eq!(before.usage_report_url(), after.usage_report_url());
    assert_eq!(
        before.crash_reporting_enabled,
        after.crash_reporting_enabled
    );
    for _ in 0..3 {
        let _native_number = owner.client().native_random_number().await?;
    }
    let pending = owner.client().pending_native_link().await?;
    assert!(pending.link().is_none());
    assert!(owner.client().folders().await?.is_empty());
    assert_eq!(owner.client().system_status().await?.device_id, identity);
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_helper_observations native_health_ok=true health_matches_independent_native_response=true migration_completed_baseline_matches_independent_native_response=true migration_not_started=true migration_active_effect_not_observed=true native_id_normalization_and_checksum_rejection=true explicit_loopback_lookup=true report_collection_without_consent_change=true random_quality_not_asserted=true empty_link_only_native_effect=true");
    Ok(())
}
