//! Native helper results are checked independently from raw research calls.
use super::managed_fixture::{options, TestResult};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use verysync_sidecar::{Error, ManagedInstance};
#[cfg(windows)]
#[path = "native_opener_trace.rs"]
mod native_opener_trace;
#[cfg(windows)]
#[path = "windows_cleanup_diagnostic.rs"]
mod windows_cleanup_diagnostic;

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
    let detailed = owner
        .client()
        .index_file_diagnostics(&folder, &TargetPath::local("root.txt"))
        .await?;
    assert_eq!(detailed.global.name, file.global.name);
    assert_eq!(detailed.global.version, file.global.version);
    assert_eq!(detailed.global.blocks_hash, file.global.blocks_hash);
    assert_eq!(detailed.local.size, file.local.size);
    assert!(detailed.availability.is_none());
    let absent = owner
        .client()
        .index_file_diagnostics(&folder, &TargetPath::local("absent.txt"))
        .await?;
    for record in [&absent.global, &absent.local] {
        assert!(record.name.is_empty() && record.version.is_empty());
        assert_eq!(record.size, 0);
        assert_eq!(record.num_blocks, 0);
        assert!(record.blocks_hash.is_none());
        assert_eq!(record.signature.version, 0);
        assert!(record.signature.encoded_signature.is_none());
    }

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
    let detailed_child = owner
        .client()
        .index_file_diagnostics(&folder, &TargetPath::local(branch.join("child.txt")))
        .await?;
    assert_eq!(detailed_child.global.name, child.global.name);
    assert_eq!(detailed_child.global.version, child.global.version);

    let directory = owner
        .client()
        .index_file_info(&folder, &TargetPath::local(branch))
        .await?;
    assert_eq!(directory.global.kind, SyncFileKind::Directory);
    assert_eq!(directory.global.size, 0);
    assert_eq!(directory.global.num_blocks, 0);
    assert!(directory.global.blocks_hash.is_none());
    let detailed_directory = owner
        .client()
        .index_file_diagnostics(&folder, &TargetPath::local(branch))
        .await?;
    assert_eq!(detailed_directory.global.kind, SyncFileKind::Directory);
    assert_eq!(detailed_directory.global.num_blocks, 0);

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
    let unscanned = owner
        .client()
        .index_file_diagnostics(&folder, &TargetPath::local("unscanned.txt"))
        .await?;
    assert!(unscanned.global.name.is_empty() && unscanned.local.name.is_empty());
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
    let scanned_diagnostics = owner
        .client()
        .index_file_diagnostics(&folder, &TargetPath::local("unscanned.txt"))
        .await?;
    assert_eq!(scanned_diagnostics.global.name, "unscanned.txt");
    assert_eq!(scanned_diagnostics.global.size, scanned.global.size);

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
    println!("native_index_file_diagnostic_snapshots=6 native_zero_debug_records_contrast_real_db_404=true native_index_file_metadata_snapshots=4 native_missing_objects=2 nested_unicode_target_path=true directory_kind_and_null_hash=true null_availability_retained=true unscanned_file_not_fabricated=true explicit_scan_effect_separate=true identity_configuration_and_three_files_retained=true normal_owned_exit=true");
    Ok(())
}

#[tokio::test]
async fn actual_native_index_file_availability_preserves_zero_local_state() -> TestResult {
    incomplete_native_peer_observation(false).await
}

#[tokio::test]
async fn actual_native_folder_download_progress_preserves_inflight_block_and_byte_counters(
) -> TestResult {
    incomplete_native_peer_observation(true).await
}

async fn incomplete_native_peer_observation(observe_download: bool) -> TestResult {
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
    let sample: Vec<u8> = (0..if observe_download {
        4 * 1024 * 1024
    } else {
        131072
    })
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
    let diagnostics = b
        .client()
        .index_file_diagnostics(&bf.configuration.id, &file)
        .await?;
    assert_eq!(diagnostics.global.name, info.global.name);
    assert_eq!(diagnostics.global.size, info.global.size);
    assert_eq!(diagnostics.global.signature.version, 3);
    assert!(diagnostics
        .global
        .signature
        .encoded_signature
        .as_ref()
        .is_some_and(|s| !s.is_empty()));
    assert!(diagnostics.local.name.is_empty() && diagnostics.local.version.is_empty());
    assert_eq!(diagnostics.local.size, 0);
    assert!(diagnostics
        .availability
        .as_ref()
        .is_some_and(|sources| sources
            .iter()
            .any(|source| source.device_id == aid && !source.from_temporary)));

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
    println!("native_debug_index_file_actual_peer_availability=true native_index_file_availability=true actual_private_peer_matches=true non_temporary_source_record=true shared_native_signature_version3_preserved_without_verification=true zero_local_record_preserved=true receiver_file_not_complete=true no_wan_or_completion_claim=true caller_fixture_polling_separate_from_single_sdk_reads=true");

    if observe_download {
        let progress = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                match b
                    .client()
                    .folder_download_progress(&bf.configuration.id)
                    .await
                {
                    Ok(progress)
                        if progress
                            .files
                            .get("sample.bin")
                            .is_some_and(|p| p.pulled_blocks > 0 && p.pulling_blocks > 0) =>
                    {
                        return Ok::<_, Error>(progress)
                    }
                    Ok(_) => {}
                    Err(Error::Http { response }) if response.status() == 500 => {}
                    Err(error) => return Err(error),
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        let current = &progress.files["sample.bin"];
        assert_eq!(current.total_blocks, 32);
        assert!(current.bytes_done > 0 && current.bytes_done < current.bytes_total);
        assert!(current.bytes_total > 0 && current.bytes_total <= sample.len() as i64);
        assert!(!received.join("sample.bin").exists());
        assert!(!format!("{progress:?} {current:?}").contains("sample.bin"));
        // The caller explicitly releases the fixture throttle and independently
        // verifies the file. The progress getter neither starts nor waits for it.
        assert!(
            b.client()
                .update_bandwidth_configuration(
                    &BandwidthPatch::default().max_receive_kib_per_second(0)
                )
                .await?
                .requested_fields_match
        );
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                match std::fs::read(received.join("sample.bin")) {
                    Ok(bytes) if bytes == sample => {
                        return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        assert!(b
            .client()
            .folder_download_progress(&bf.configuration.id)
            .await?
            .files
            .is_empty());
        b.client().pause_folder(&bf.configuration.id).await?;
        assert!(
            matches!(b.client().folder_download_progress(&bf.configuration.id).await,Err(Error::Http{response}) if response.status()==500)
        );
        println!("native_folder_download_progress_actual_partial_record=true actual_total_blocks=32 actual_incomplete_receiver_before_explicit_throttle_release=true native_bytes_retained_without_file_length_assumption=true caller_separately_verified_completed_bytes=true completed_native_map_empty=true paused_native_http_500_preserved=true sdk_polling_or_transfer_side_effects_not_claimed=true");
    }
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
    let mut nonempty_public_ip_snapshots = 0;
    for ip in [
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114)),
    ] {
        let lookup = owner.client().lookup_target_ip(ip).await?;
        let native = owner
            .client()
            .raw_request(
                &verysync_sidecar::RawRequest::new(
                    verysync_sidecar::RawMethod::Get,
                    ["rest", "svc", "ip", "lookup"],
                    verysync_sidecar::RequestEffect::ReadOnly,
                )?
                .query("ip", ip.to_string()),
            )
            .await?;
        assert_eq!(native.status(), 200);
        let actual: serde_json::Value = serde_json::from_slice(native.body_bytes())?;
        assert_eq!(lookup.ip, ip);
        assert_eq!(actual["ip"].as_str(), Some(ip.to_string().as_str()));
        assert_eq!(actual["pro"].as_str(), Some(lookup.province.as_str()));
        assert_eq!(actual["city"].as_str(), Some(lookup.city.as_str()));
        assert_eq!(actual["addr"].as_str(), Some(lookup.description.as_str()));
        if !lookup.province.is_empty() || !lookup.city.is_empty() || !lookup.description.is_empty()
        {
            nonempty_public_ip_snapshots += 1;
        }
        assert!(!format!("{lookup:?}").contains(&ip.to_string()));
    }
    println!("native_public_ip_snapshots_requested=2 nonempty_native_snapshots={nonempty_public_ip_snapshots} typed_matches_direct_native=true empty_unknown_locations_preserved=true no_geographic_accuracy_claim=true");
    assert!(
        nonempty_public_ip_snapshots > 0,
        "no nonempty public-IP native snapshot observed"
    );
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

#[tokio::test]
async fn actual_native_support_bundle_contains_valid_private_archive_and_preserves_owned_state(
) -> TestResult {
    use sha2::{Digest, Sha256};
    use verysync_sidecar::{
        ApiKey, Client, ConnectOptions, CreateFolderOptions, FolderId, TargetPath,
    };
    let root = tempfile::Builder::new().prefix("vns-").tempdir()?.keep();
    let state = root.join("core");
    let settings = options(&state)?;
    let endpoint = settings.management_endpoint().clone();
    let mut owner = ManagedInstance::start(settings).await?;
    let id = owner.client().instance().device_id.clone();
    assert!(!owner.client().gui_preferences().await?.debugging);
    let data = root.join("synthetic bundle data");
    std::fs::create_dir(&data)?;
    let sample = b"retained private bundle sentinel";
    std::fs::write(data.join("sentinel.txt"), sample)?;
    let folder = FolderId::parse("typed-native-support-bundle")?;
    owner
        .client()
        .create_folder(&CreateFolderOptions::new(folder, TargetPath::local(&data)).paused(true))
        .await?;
    let config = std::fs::read(state.join("setting.dat"))?;
    let before = Sha256::digest(std::fs::read(data.join("sentinel.txt"))?);
    let hashes = ["key.pem", "cert.pem", ".verysync-sidecar-identity"]
        .into_iter()
        .map(|name| std::fs::read(state.join(name)).map(|v| Sha256::digest(v).to_vec()))
        .collect::<std::io::Result<Vec<_>>>()?;
    let bundle = owner.client().collect_core_support_bundle().await?;
    assert!(bundle.body_bytes().len() > 4096);
    assert!(!format!("{bundle:?}").contains("synthetic bundle data"));
    let archive = root.join("private bundle.debug");
    std::fs::write(&archive, bundle.body_bytes())?;
    let inspect = r#"import gzip,json,sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    entries=z.infolist()
    assert len(entries)<=64 and sum(e.file_size for e in entries)<=8*1024*1024
    assert all(e.file_size<=2*1024*1024 for e in entries)
    assert z.testzip() is None
    names={e.filename for e in entries}
    required={'config.json.txt','log-inmemory.txt','version-platform.json.txt','usage-reporting.json.txt','metrics.txt','connection-stats.json.txt'}
    assert required<=names
    config=json.loads(z.read('config.json.txt'))
    assert config['gui']['apiKey']=='REDACTED'
    assert config['gui']['debugging'] is False and len(config['folders'])==1
    version=json.loads(z.read('version-platform.json.txt'))
    assert version['version']=='v2.33.2'
    profiles=[e for e in entries if e.filename.endswith('.pprof')]
    for entry in profiles:
        assert gzip.decompress(z.read(entry))
    goroutines=[e for e in entries if e.filename.startswith('verysync-goroutine-')]
    for entry in goroutines:
        assert b'goroutine' in z.read(entry)
    print(json.dumps({'zip_entries':len(entries),'native_gzip_profiles':len(profiles),'native_goroutine_reports':len(goroutines),'zip_all_crc_valid':True,'actual_native_config_api_key_redacted':True,'native_redaction_not_complete_privacy_guarantee':True,'native_version_metadata_matches':True}))
"#;
    let validation = {
        use std::io::Read;
        struct Inspector(std::process::Child);
        impl Drop for Inspector {
            fn drop(&mut self) {
                if !matches!(self.0.try_wait(), Ok(Some(_))) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
        }
        let stdout = tempfile::NamedTempFile::new_in(&root)?;
        let stderr = tempfile::NamedTempFile::new_in(&root)?;
        let mut command = std::process::Command::new(
            std::env::var_os("VERYSYNC_TEST_PYTHON").ok_or("explicit fixture Python missing")?,
        );
        command
            .arg("-c")
            .arg(inspect)
            .arg(&archive)
            .stdin(std::process::Stdio::null())
            .stdout(stdout.as_file().try_clone()?)
            .stderr(stderr.as_file().try_clone()?);
        let mut child = Inspector(command.spawn()?);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.0.try_wait()? {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                return Err("owned archive inspector deadline".into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let mut error = String::new();
        stderr.reopen()?.take(4097).read_to_string(&mut error)?;
        assert!(error.len() <= 4096);
        assert!(status.success(), "native ZIP validation failed: {error}");
        let mut output = String::new();
        stdout.reopen()?.take(4097).read_to_string(&mut output)?;
        assert!(output.len() <= 4096);
        output
    };
    println!("native support archive validation: {}", validation.trim());
    let decoded = rmpv::decode::read_value(&mut std::io::Cursor::new(&config))?;
    let key = decoded["4"]["6"]
        .as_str()
        .ok_or("private credential missing")?;
    let small = Client::connect(
        ConnectOptions::new(endpoint, ApiKey::new(key)?)
            .expected_device_id(id.clone())
            .response_limit(4096)?,
    )
    .await?;
    assert!(
        matches!(small.collect_core_support_bundle().await,Err(Error::MutationOutcomeUnknown{source,..}) if matches!(source.as_ref(),Error::ResponseTooLarge{limit:4096}))
    );
    assert_eq!(owner.client().system_status().await?.device_id, id);
    assert!(!owner.client().gui_preferences().await?.debugging);
    assert_eq!(std::fs::read(state.join("setting.dat"))?, config);
    assert_eq!(
        Sha256::digest(std::fs::read(data.join("sentinel.txt"))?),
        before
    );
    for (name, hash) in ["key.pem", "cert.pem", ".verysync-sidecar-identity"]
        .into_iter()
        .zip(hashes)
    {
        assert_eq!(
            Sha256::digest(std::fs::read(state.join(name))?).as_slice(),
            hash
        );
    }
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_support_bundle_typed=true collected_with_debugging_false=true explicit_caller_fixture_storage_only=true actual_compressed_response_limit=true response_limit_keeps_collection_uncertain=true identity_configuration_and_sample_sha_preserved=true normal_owned_tree_exit=true");
    Ok(())
}

#[tokio::test]
async fn actual_native_path_writeability_keeps_native_limit_and_owned_data() -> TestResult {
    use sha2::{Digest, Sha256};
    use verysync_sidecar::TargetPath;
    let root = tempfile::Builder::new()
        .prefix("vs-path-probe-")
        .tempdir()?
        .keep();
    let target = root.join("probe \u{4e8c} % +");
    std::fs::create_dir(&target)?;
    let sample = target.join("sample.txt");
    let contents = b"retained writable native path sample";
    std::fs::write(&sample, contents)?;
    let state = root.join("core");
    let mut owner = ManagedInstance::start(options(&state)?).await?;
    let id = owner.client().instance().device_id.clone();
    let config = std::fs::read(state.join("setting.dat"))?;
    let hashes = ["key.pem", "cert.pem", ".verysync-sidecar-identity"]
        .map(|name| std::fs::read(state.join(name)).map(|b| Sha256::digest(b).to_vec()))
        .into_iter()
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut native_false_errors = 0;
    for (path, ancestors) in [
        (target.clone(), false),
        (target.join("missing").join("deeper"), false),
        (target.join("missing").join("deeper"), true),
        (sample.clone(), false),
    ] {
        let result = owner
            .client()
            .probe_target_path_writeability(&TargetPath::local(&path), ancestors)
            .await?;
        assert_eq!(std::path::Path::new(result.path.to_protocol()?), path);
        assert_eq!(result.attempt, if ancestors { "true" } else { "" });
        assert_eq!(result.last_path.style(), TargetPath::local(&path).style());
        assert!(!format!("{result:?}").contains("probe "));
        if !result.writeable && result.native_error.is_object() {
            native_false_errors += 1;
        }
    }
    assert!(!target.join("missing").exists());
    assert_eq!(std::fs::read(&sample)?, contents);
    let oracle = target.join("caller-write-oracle.txt");
    let oracle_bytes = b"caller explicitly proves this owned directory is writable";
    std::fs::write(&oracle, oracle_bytes)?;
    assert_eq!(std::fs::read(&oracle)?, oracle_bytes);
    std::fs::remove_file(oracle)?;
    assert_eq!(std::fs::read_dir(&target)?.count(), 1);
    assert_eq!(owner.client().system_status().await?.device_id, id);
    assert_eq!(std::fs::read(state.join("setting.dat"))?, config);
    for (name, hash) in ["key.pem", "cert.pem", ".verysync-sidecar-identity"]
        .into_iter()
        .zip(hashes)
    {
        assert_eq!(
            Sha256::digest(std::fs::read(state.join(name))?).as_slice(),
            hash
        );
    }
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_path_writeability_snapshots=4 native_false_with_object_errors={native_false_errors} native_permission_positive_not_claimed=true missing_directory_not_created=true caller_write_oracle_succeeded=true sample_configuration_identity_preserved=true normal_owned_tree_exit=true");
    Ok(())
}

fn native_opener_capture_shapes(
    capture: &std::path::Path,
    wanted: &[u8],
) -> TestResult<serde_json::Value> {
    use std::io::Read;
    let expected = wanted.strip_suffix(&[0]).unwrap_or(wanted);
    let mut records = Vec::new();
    for record in std::fs::read_dir(capture)?.take(32) {
        let record = record?;
        if !record.path().extension().is_some_and(|v| v == "argv") {
            continue;
        }
        let metadata = record.path().symlink_metadata()?;
        if !metadata.is_file() || metadata.len() > 65536 {
            records.push(serde_json::json!({"bounded_regular_capture":false}));
            continue;
        }
        let mut bytes = Vec::new();
        std::fs::File::open(record.path())?
            .take(65537)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            records.push(serde_json::json!({"bounded_regular_capture":false}));
            continue;
        }
        let payload = bytes.strip_suffix(&[0]).unwrap_or(&bytes);
        let args: Vec<&[u8]> = if bytes.is_empty() {
            Vec::new()
        } else {
            payload.split(|b| *b == 0).collect()
        };
        records.push(serde_json::json!({
            "bounded_regular_capture":true, "nul_terminated":bytes.last() == Some(&0),
            "argc":args.len(), "argument_bytes":args.iter().map(|s| s.len()).collect::<Vec<_>>(),
            "exact_expected_argument":args.iter().map(|s| *s == expected).collect::<Vec<_>>(),
            "quoted_expected_argument":args.iter().map(|s| s.strip_prefix(b"\"").and_then(|s| s.strip_suffix(b"\"")).is_some_and(|s| s == expected)).collect::<Vec<_>>(),
            "contains_expected_argument":args.iter().map(|s| !expected.is_empty() && s.windows(expected.len()).any(|w| w == expected)).collect::<Vec<_>>(),
            "file_url_argument":args.iter().map(|s| s.starts_with(b"file:")).collect::<Vec<_>>(),
            "non_utf8_arguments":args.iter().filter(|s| std::str::from_utf8(s).is_err()).count(),
            "known_dispatch_flags":args.iter().filter_map(|s| {
                ["/c", "start", "/e", "/e,", "/select,", "url.dll,FileProtocolHandler"].into_iter().find(|flag| *s == flag.as_bytes())
            }).collect::<Vec<_>>(),
        }));
    }
    Ok(serde_json::json!({"observed_records":records,"record_limit":32,"raw_values_logged":false}))
}

#[test]
fn native_opener_shape_diagnostics_keep_argument_values_private_and_reads_bounded() -> TestResult {
    let root = tempfile::tempdir()?;
    let expected = b"private-target-with-spaces";
    let mut wanted = expected.to_vec();
    wanted.push(0);
    let mut captured = b"/select,\0\"".to_vec();
    captured.extend_from_slice(expected);
    captured.extend_from_slice(b"\"\0");
    std::fs::write(root.path().join("1.argv"), captured)?;
    let shapes = native_opener_capture_shapes(root.path(), &wanted)?;
    let row = &shapes["observed_records"][0];
    assert_eq!(row["argc"], 2);
    assert_eq!(row["quoted_expected_argument"][1], true);
    assert_eq!(row["contains_expected_argument"][1], true);
    assert_eq!(row["known_dispatch_flags"][0], "/select,");
    assert!(!shapes.to_string().contains("private-target-with-spaces"));
    std::fs::write(root.path().join("2.argv"), vec![b'x'; 65537])?;
    let shapes = native_opener_capture_shapes(root.path(), &wanted)?;
    assert_eq!(
        shapes["observed_records"]
            .as_array()
            .ok_or("missing records")?
            .iter()
            .filter(|v| v["bounded_regular_capture"] == false)
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn actual_native_folder_open_requests_capture_exact_owned_target_dispatch() -> TestResult {
    #[cfg(windows)]
    if native_opener_trace::run_owned_capture_child().await? {
        return Ok(());
    }
    use verysync_sidecar::{CreateFolderOptions, FolderId, NativeFolderOpenLocation, TargetPath};
    let root = tempfile::Builder::new()
        .prefix("vs-open-")
        .tempdir()?
        .keep();
    let data = root.join("owned \u{4e8c} % +");
    let archive = data.join(".verysync").join("Archive");
    std::fs::create_dir_all(&archive)?;
    std::fs::write(data.join("sample.txt"), b"retained opener bytes")?;
    let capture = std::path::PathBuf::from(
        std::env::var_os("VERYSYNC_TEST_OPENER_CAPTURE_DIR")
            .ok_or("owned opener fixture required")?,
    );
    let mut owner = ManagedInstance::start(options(&root.join("core"))?).await?;
    let folder = FolderId::parse("owned-open")?;
    owner
        .client()
        .create_folder(
            &CreateFolderOptions::new(folder.clone(), TargetPath::local(&data)).paused(true),
        )
        .await?;
    let identity = owner.client().instance().device_id.clone();
    #[cfg(windows)]
    let _dispatch_trace = native_opener_trace::Trace::maybe_start(owner.process_id(), &capture);
    for (location, expected) in [
        (NativeFolderOpenLocation::Folder, &data),
        (NativeFolderOpenLocation::Trash, &archive),
    ] {
        let receipt = owner
            .client()
            .request_native_folder_open(&folder, location)
            .await?;
        assert_eq!(receipt.folder, folder);
        assert_eq!(receipt.location, location);
        assert!(!format!("{receipt:?}").contains(folder.as_str()));
        let mut wanted = TargetPath::local(expected)
            .to_protocol()?
            .as_bytes()
            .to_vec();
        wanted.push(0);
        // Require the complete platform dispatch, including the Windows DLL
        // entry point. A matching path among unrelated arguments is insufficient.
        #[cfg(windows)]
        let expected_dispatch = [b"url.dll,FileProtocolHandler\0".as_slice(), &wanted].concat();
        #[cfg(not(windows))]
        let expected_dispatch = wanted.clone();
        let dispatched = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                for record in std::fs::read_dir(&capture)? {
                    let record = record?;
                    if record.path().extension().is_some_and(|v| v == "argv")
                        && std::fs::read(record.path())? == expected_dispatch
                    {
                        return Ok::<_, std::io::Error>(());
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        if dispatched.as_ref().is_err() || dispatched.as_ref().is_ok_and(|result| result.is_err()) {
            let locality = match tokio::time::timeout(
                Duration::from_secs(1),
                owner.client().core_log_text(None),
            )
            .await
            {
                Ok(Ok(log)) => {
                    serde_json::json!({"available":true,"known_native_locality_denial_marker":log.text.contains("Open Folder Remote access UI can not open directory"),"raw_text_logged":false})
                }
                _ => serde_json::json!({"available":false,"raw_text_logged":false}),
            };
            eprintln!("native opener locality observation: {locality}");
            eprintln!(
                "native folder opener dispatch diagnostic: {}",
                serde_json::json!({
                    "location":format!("{location:?}"), "platform":std::env::consts::OS,
                    "expected_bytes":wanted.len(), "captures":native_opener_capture_shapes(&capture, &wanted)?,
                    "deadline_unchanged_s":3, "automatic_request_retries":0,
                })
            );
        }
        dispatched??;
    }
    assert_eq!(
        std::fs::read(data.join("sample.txt"))?,
        b"retained opener bytes"
    );
    assert_eq!(owner.client().system_status().await?.device_id, identity);
    assert!(archive.is_dir());
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_folder_open_normal_and_trash_arguments_captured=true caller_desktop_never_opened=true native_ack_not_window_success=true synthetic_bytes_identity_and_archive_preserved=true normal_owned_tree_exit=true");
    Ok(())
}

#[tokio::test]
async fn actual_native_helpers_consume_nonempty_link_inbox_without_following_or_registering(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vslink-").tempdir()?.keep();
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    assert_ne!(address.port(), 18886);
    listener.set_nonblocking(true)?;
    let sentinel = root.join("caller-sentinel");
    std::fs::write(&sentinel, b"native link caller bytes")?;
    let mut owner = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = owner.client().instance().device_id.clone();
    let config = owner
        .client()
        .configuration()
        .await?
        .native_document()
        .clone();
    let inbox = owner.state_directory().join("add-url");
    assert!(!inbox.try_exists()?);
    for value in [
        format!("http://{address}/owned/%E4%BA%8C?private=synthetic-link-secret#untrusted"),
        "verysync://synthetic-二/%2e%2e?private=synthetic-link-secret\nopaque text".into(),
    ] {
        // This creates the fixed core's task-owned input, not a CLI-producer claim.
        std::fs::write(&inbox, value.as_bytes())?;
        let pending = owner.client().pending_native_link().await?;
        assert_eq!(pending.link(), Some(value.as_str()));
        assert!(!format!("{pending:?}").contains("synthetic-link-secret"));
        assert!(!format!("{pending:?}").contains(&value));
        tokio::time::timeout(Duration::from_secs(2), async {
            while inbox.try_exists()? {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<_, std::io::Error>(())
        })
        .await??;
        assert!(owner.client().pending_native_link().await?.link().is_none());
    }
    // A native read error also becomes an empty string; it does not establish
    // that no inbox exists. Preserve the nonempty directory after failed remove.
    std::fs::create_dir(&inbox)?;
    std::fs::write(inbox.join("retained"), b"unreadable-as-file inbox")?;
    assert!(owner.client().pending_native_link().await?.link().is_none());
    assert_eq!(
        std::fs::read(inbox.join("retained"))?,
        b"unreadable-as-file inbox"
    );
    assert!(matches!(listener.accept(),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock));
    assert!(owner.client().folders().await?.is_empty());
    assert_eq!(
        owner.client().configuration().await?.native_document(),
        &config
    );
    assert_eq!(owner.client().system_status().await?.device_id, identity);
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    assert_eq!(std::fs::read(&sentinel)?, b"native link caller bytes");
    assert_eq!(
        std::fs::read(inbox.join("retained"))?,
        b"unreadable-as-file inbox"
    );
    std::fs::remove_dir_all(root)?;
    println!(
        "native pending link evidence: {}",
        serde_json::json!({"actual_nonempty_native_file_inbox_read":true,"actual_percent_unicode_and_opaque_text_retained":true,"actual_native_inbox_consumed_after_read":true,"actual_followup_snapshot_empty":true,"actual_native_read_error_also_returns_empty":true,"actual_nonempty_directory_not_removed":true,"actual_returned_http_link_not_followed":true,"actual_no_folder_auto_registration":true,"actual_private_debug_redacted":true,"actual_configuration_identity_and_caller_bytes_retained":true,"actual_normal_owned_tree_and_state_exit":true,"fixture_producer":"task-owned native input file","native_cli_producer_verified":false})
    );
    Ok(())
}

#[tokio::test]
async fn actual_native_helpers_preserve_uncertainty_after_consuming_link_response_loss(
) -> TestResult {
    use super::engine_fixture::EngineFixture;
    use super::response_proxy::{ResponseFault, ResponseProxy};
    use verysync_sidecar::{ApiKey, Client, ConnectOptions, DeviceId};
    let mut instance = EngineFixture::start().await?;
    let proxy = ResponseProxy::start_native_link(&instance, ResponseFault::DropAfterApply).await?;
    let options = |endpoint| -> verysync_sidecar::Result<ConnectOptions> {
        ConnectOptions::new(endpoint, ApiKey::new(instance.api_key())?)
            .expected_device_id(DeviceId::parse(instance.device_id())?)
            .request_timeout(Duration::from_secs(3))
    };
    let client = Client::connect(options(proxy.endpoint())?).await?;
    let before = client.configuration().await?.native_document().clone();
    let inbox = instance.state_dir().join("add-url");
    let sentinel = instance.state_dir().join("caller-link-sentinel");
    std::fs::write(&sentinel, b"retained after native link response loss")?;
    std::fs::write(&inbox, b"verysync://synthetic-private-response-loss-secret")?;
    let result = client.pending_native_link().await;
    let error = result.err().ok_or("lost native response became success")?;
    assert!(matches!(&error, Error::MutationOutcomeUnknown { .. }));
    let diagnostic = format!("{error:?} {error}");
    assert!(!diagnostic.contains(instance.api_key()));
    assert!(!diagnostic.contains("synthetic-private-response-loss-secret"));
    tokio::time::timeout(Duration::from_secs(2), async {
        while inbox.try_exists()? {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<_, std::io::Error>(())
    })
    .await??;
    assert_eq!(proxy.mutation_count(), 1);
    let direct = Client::connect(options(super::endpoint(&instance)?)?).await?;
    assert!(direct.pending_native_link().await?.link().is_none());
    assert_eq!(direct.configuration().await?.native_document(), &before);
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"retained after native link response loss"
    );
    proxy.finish().await?;
    assert!(instance.shutdown().await?.success());
    println!("native pending link lost-response evidence: actual_native_inbox_consumed_before_response_loss=true mutation_outcome_unknown=true actual_consuming_get_count=1 automatic_retry=false explicit_followup_empty=true actual_error_debug_redacted=true configuration_identity_and_caller_bytes_retained=true native_normal_exit=true");
    Ok(())
}

#[tokio::test]
async fn actual_native_helpers_consume_official_add_url_before_native_start_refusal() -> TestResult
{
    use std::process::{Child, Command, Stdio};
    struct Producer(Child);
    impl Drop for Producer {
        fn drop(&mut self) {
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
    let root = tempfile::Builder::new().prefix("vslcli-").tempdir()?.keep();
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    assert_ne!(address.port(), 18886);
    listener.set_nonblocking(true)?;
    let sentinel = root.join("caller-sentinel");
    std::fs::write(&sentinel, b"official link producer keeps caller bytes")?;
    let mut owner = ManagedInstance::start(options(&root.join("core"))?).await?;
    let id = owner.client().instance().device_id.clone();
    let document = owner
        .client()
        .configuration()
        .await?
        .native_document()
        .clone();
    for (index, link) in [
        format!("http://{address}/owned/%E4%BA%8C?private=native-cli-private-query#untrusted"),
        "verysync://synthetic-二/%2e%2e?private=native-cli-private-query".into(),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(!owner.state_directory().join("add-url").try_exists()?);
        let state = owner.state_directory();
        let stdout = root.join(format!("private-producer-{index}.stdout"));
        let stderr = root.join(format!("private-producer-{index}.stderr"));
        let native_log = root.join(format!("private-producer-{index}.native.log"));
        let mut command = Command::new(owner.selected_program().path());
        command
            .arg("serve")
            .arg("--home")
            .arg(state)
            .arg("--log-file")
            .arg(&native_log)
            .args(["--no-browser", "--no-restart", "--no-upgrade", "--add-url"])
            .arg(&link)
            .current_dir(state)
            .env("VSHOMEDIR", state)
            .env_remove("VSCONFDIR")
            .env_remove("VSDATADIR")
            .env("TMPDIR", state.join("tmp"))
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&stdout)?)
            .stderr(std::fs::File::create(&stderr)?);
        #[cfg(unix)]
        command
            .env("HOME", state.join("profile"))
            .env("XDG_CONFIG_HOME", state.join("roaming"))
            .env("XDG_CACHE_HOME", state.join("local"))
            .env("XDG_DATA_HOME", state.join("profile").join("data"));
        #[cfg(windows)]
        command
            .env("APPDATA", state.join("roaming"))
            .env("LOCALAPPDATA", state.join("local"))
            .env("USERPROFILE", state.join("profile"))
            .env("TEMP", state.join("tmp"))
            .env("TMP", state.join("tmp"));
        let mut producer = Producer(command.spawn()?);
        let status = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = producer.0.try_wait()? {
                    return Ok::<_, std::io::Error>(status);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        // The official command writes its input before its platform-specific
        // startup refusal. Neither observed refusal is CLI start success.
        eprintln!("native official producer stage: input={index} child_exited");
        assert_eq!(status.code(), Some(1));
        assert!(std::fs::metadata(&stdout)?.len() <= 8192);
        assert!(std::fs::metadata(&stderr)?.len() <= 8192);
        let native_output = if native_log.try_exists()? {
            let metadata = native_log.symlink_metadata()?;
            assert!(
                metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 8192
            );
            std::fs::read(&native_log)?
        } else {
            Vec::new()
        };
        let output = [
            std::fs::read(&stdout)?,
            std::fs::read(&stderr)?,
            native_output,
        ]
        .concat();
        let observed = String::from_utf8_lossy(&output);
        #[cfg(not(windows))]
        let exact_refusal = observed
            .contains("Failed to acquire lock: is another Verysync instance already running?");
        #[cfg(windows)]
        let exact_refusal = observed.contains("Failed allocConsole")
            && observed.contains("fixConsole")
            && observed.contains("Access is denied.");
        if !exact_refusal {
            // Only this owned synthetic producer, with URLs/paths and opaque
            // credential-shaped runs removed before publishing CI diagnostics.
            let safe = observed
                .replace(&link, "[SYNTHETIC-LINK]")
                .replace("native-cli-private-query", "[SYNTHETIC-QUERY]")
                .replace(state.to_string_lossy().as_ref(), "[OWNED-STATE]");
            let mut sanitized = String::new();
            let mut token = String::new();
            for ch in safe.chars().chain(std::iter::once(' ')) {
                if ch.is_ascii_alphanumeric() {
                    token.push(ch);
                } else {
                    sanitized.push_str(if token.len() >= 16 {
                        "[OPAQUE]"
                    } else {
                        &token
                    });
                    token.clear();
                    sanitized.push(if ch.is_control() && !matches!(ch, '\n' | '\t') {
                        '?'
                    } else {
                        ch
                    });
                }
            }
            eprintln!(
                "native official producer diagnostic: {}",
                serde_json::json!({
                    "exit_code":status.code(),"stdout_bytes":std::fs::metadata(&stdout)?.len(),
                    "stderr_bytes":std::fs::metadata(&stderr)?.len(),"explicit_native_log_present":native_log.try_exists()?,
                    "native_input_present_before_consumption":state.join("add-url").is_file(),
                    "bounded_owned_diagnostic":sanitized.chars().take(768).collect::<String>()
                })
            );
        }
        assert!(
            exact_refusal,
            "the specific native refusal remains required"
        );
        eprintln!("native official producer stage: input={index} specific_refusal_captured");
        let pending = owner.client().pending_native_link().await?;
        assert_eq!(pending.link(), Some(link.as_str()));
        assert!(!format!("{pending:?}").contains("native-cli-private-query"));
        assert!(!owner.state_directory().join("add-url").try_exists()?);
        assert!(owner.client().pending_native_link().await?.link().is_none());
        eprintln!("native official producer stage: input={index} exact_link_consumed_once");
        assert!(owner.client().folders().await?.is_empty());
        assert_eq!(
            owner.client().configuration().await?.native_document(),
            &document
        );
        assert_eq!(owner.client().system_status().await?.device_id, id);
        assert!(
            matches!(listener.accept(),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock)
        );
    }
    eprintln!("native official producer stage: both_inputs_and_primary_preserved");
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    eprintln!("native official producer stage: normal_owned_tree_and_state_exit");
    assert_eq!(
        std::fs::read(sentinel)?,
        b"official link producer keeps caller bytes"
    );
    if let Err(error) = std::fs::remove_dir_all(&root) {
        #[cfg(windows)]
        eprintln!(
            "native official producer cleanup diagnostic: {}",
            windows_cleanup_diagnostic::snapshot(&root)
        );
        return Err(format!("owned official producer fixture removal: {error}").into());
    }
    println!(
        "native official link producer evidence: {}",
        serde_json::json!({
            "actual_official_add_url_writes_consumable_input":true,
            "actual_http_and_protocol_links_retained":true,
            "actual_native_file_consumed_once_and_followup_empty":true,
            "no_link_follow_or_folder_registration":true,
            "configuration_identity_and_caller_bytes_retained":true,
            "normal_owned_tree_and_state_exit":true,
            "native_cli_producer_verified":true,
        "native_platform_start_refusal_preserved":true,
        "native_existing_instance_lock_refusal_observed":!cfg!(windows),
        "native_windows_console_access_denied_observed":cfg!(windows),
        "native_cli_exit_code":1,"native_cli_start_success_claimed":false
        })
    );
    Ok(())
}
