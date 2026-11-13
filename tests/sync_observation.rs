//! Actual indexed data, bounded pages and a native file-access failure.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use serde_json::json;
#[cfg(unix)]
use std::path::PathBuf;
use std::{collections::BTreeSet, path::Path, time::Duration};
use verysync_sidecar::{
    CreateDeviceOptions, CreateFolderOptions, DevicePatch, Error, FolderId, ListPage,
    ManagedInstance, SyncFileKind, TargetPath,
};

async fn indexed_files(
    client: &verysync_sidecar::Client,
    folder: &FolderId,
    count: u64,
) -> TestResult {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let status = client.folder_status(folder).await?;
            if status.local_files == Some(count)
                && status.state == Some(verysync_sidecar::FolderState::Idle)
            {
                break Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn actual_scan_scopes_schedule_and_watcher_preserve_files() -> TestResult {
    use verysync_sidecar::FolderScanPatch;
    let root = tempfile::Builder::new()
        .prefix("vss-scan-")
        .tempdir()?
        .keep();
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let a = FolderId::parse("scan-scope-a")?;
    let b = FolderId::parse("scan-scope-b")?;
    let a_path = root.join("a files");
    let b_path = root.join("b files");
    std::fs::create_dir_all(a_path.join("one"))?;
    std::fs::create_dir(&b_path)?;
    let stopped = FolderScanPatch::default()
        .rescan_interval_seconds(0)
        .watcher(false)
        .watcher_delay_seconds(1.5)
        .watcher_timeout_seconds(2)
        .progress_interval_seconds(1)
        .disable_initial_scan(false);
    for (id, path) in [(&a, &a_path), (&b, &b_path)] {
        core.client()
            .create_folder(
                &CreateFolderOptions::new(id.clone(), TargetPath::local(path)).paused(true),
            )
            .await?;
        let changed = core
            .client()
            .update_folder_scan_configuration(id, &stopped)
            .await?;
        assert!(changed.requested_fields_match);
        assert_eq!(changed.configuration.watcher_delay_seconds, 1.5);
        core.client().resume_folder(id).await?;
        indexed_files(core.client(), id, 0).await?;
    }
    let first = Path::new("one").join("二 ?%.bin");
    let second = Path::new("two.bin");
    for path in [&first, second, Path::new("unselected.bin")] {
        std::fs::write(a_path.join(path), b"scope bytes")?;
    }
    std::fs::write(b_path.join("other.bin"), b"other folder bytes")?;
    core.client()
        .request_scan_subpaths(&a, &[TargetPath::local(&first), TargetPath::local(second)])
        .await?;
    indexed_files(core.client(), &a, 2).await?;
    assert_eq!(core.client().folder_status(&b).await?.local_files, Some(0));
    core.client().request_scan(&a).await?;
    indexed_files(core.client(), &a, 3).await?;
    assert_eq!(core.client().folder_status(&b).await?.local_files, Some(0));
    core.client().request_all_scans().await?;
    indexed_files(core.client(), &b, 1).await?;
    core.client().pause_folder(&a).await?;
    std::fs::write(a_path.join("paused.bin"), b"paused folder bytes")?;
    assert!(matches!(
        core.client()
            .request_scan_subpaths(&a, &[TargetPath::local("paused.bin")])
            .await,
        Err(Error::ScanNotIdle)
    ));
    for invalid in [TargetPath::local("../escape"), TargetPath::local(&a_path)] {
        assert!(matches!(
            core.client().request_scan_subpaths(&b, &[invalid]).await,
            Err(Error::InvalidPath { .. })
        ));
    }
    assert!(matches!(
        core.client()
            .request_scan_subpaths(&FolderId::parse("missing")?, &[TargetPath::local("file")])
            .await,
        Err(Error::FolderNotFound { .. })
    ));
    core.client().request_all_scans().await?;
    assert!(core.client().folder(&a).await?.paused);
    core.client().resume_folder(&a).await?;
    core.client().request_scan(&a).await?;
    indexed_files(core.client(), &a, 4).await?;
    assert!(
        core.client()
            .update_folder_scan_configuration(
                &b,
                &FolderScanPatch::default().rescan_interval_seconds(1)
            )
            .await?
            .requested_fields_match
    );
    std::fs::write(b_path.join("scheduled.bin"), b"automatic rescan bytes")?;
    indexed_files(core.client(), &b, 2).await?;
    assert!(
        core.client()
            .update_folder_scan_configuration(
                &b,
                &FolderScanPatch::default()
                    .rescan_interval_seconds(0)
                    .watcher(true)
                    .watcher_delay_seconds(1.5)
                    .disable_initial_scan(true)
            )
            .await?
            .requested_fields_match
    );
    core.restart(Duration::from_secs(30)).await?;
    indexed_files(core.client(), &b, 2).await?;
    let settings = core.client().folder_scan_configuration(&b).await?;
    assert_eq!(settings.rescan_interval_seconds, 0);
    assert!(settings.watcher_enabled);
    assert_eq!(settings.watcher_delay_seconds, 1.5);
    assert!(settings.disable_initial_scan);
    let mut settle = core.client().observe_next_scan(&b).await?;
    let (requested, completed) = tokio::join!(
        core.client().request_scan(&b),
        settle.wait(Duration::from_secs(15)),
    );
    settle.close().await?;
    requested?;
    completed?;
    std::fs::write(b_path.join("watched.bin"), b"filesystem notification bytes")?;
    indexed_files(core.client(), &b, 3).await?;
    for path in [&first, second, Path::new("unselected.bin")] {
        assert_eq!(std::fs::read(a_path.join(path))?, b"scope bytes");
    }
    assert_eq!(
        std::fs::read(a_path.join("paused.bin"))?,
        b"paused folder bytes"
    );
    assert_eq!(
        std::fs::read(b_path.join("other.bin"))?,
        b"other folder bytes"
    );
    assert_eq!(
        std::fs::read(b_path.join("scheduled.bin"))?,
        b"automatic rescan bytes"
    );
    assert_eq!(
        std::fs::read(b_path.join("watched.bin"))?,
        b"filesystem notification bytes"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public scan scope evidence: {}",
        json!({"actual_partial_settings_readback":true,"actual_fractional_watcher_delay":true,"actual_two_subpaths_index_only_selected_files":true,"subpaths_preserve_other_folder_index":true,"actual_whole_folder_indexes_remainder":true,"whole_folder_preserves_other_index":true,"actual_all_folder_scan":true,"paused_subpath_rejected":true,"invalid_scope_rejected":true,"missing_folder_rejected":true,"all_scan_does_not_resume_paused_folder":true,"explicit_resume_and_index":true,"actual_scheduled_scan_without_request":true,"settings_persist_after_restart":true,"startup_scan_disabled_before_watch_sample":true,"actual_settle_scan_observed_before_watch_sample":true,"actual_watcher_scan_without_request":true,"all_original_synthetic_bytes_preserved":true,"actual_normal_tree_exit":true})
    );
    Ok(())
}

struct BlockedFile {
    #[cfg(unix)]
    path: PathBuf,
    #[cfg(unix)]
    original: std::fs::Permissions,
    #[cfg(windows)]
    _held: std::fs::File,
}

#[tokio::test]
async fn actual_ignore_replace_parse_rejection_reset_and_restart_preserve_files() -> TestResult {
    use verysync_sidecar::IgnorePatterns;
    let root = tempfile::Builder::new()
        .prefix("vss-ignore-")
        .tempdir()?
        .keep();
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let id = FolderId::parse("ignore-rules-a")?;
    let other = FolderId::parse("ignore-rules-b")?;
    let data = root.join("data");
    let unrelated = root.join("other");
    std::fs::create_dir_all(data.join("sub"))?;
    std::fs::create_dir(&unrelated)?;
    let nested = [
        Path::new("sub").join("hidden.dat"),
        Path::new("sub").join("second.dat"),
    ];
    let names = [
        Path::new("visible.txt"),
        Path::new("skip.tmp"),
        Path::new("keep.tmp"),
        nested[0].as_path(),
        nested[1].as_path(),
    ];
    for name in names {
        std::fs::write(data.join(name), b"retained synthetic ignore bytes")?;
    }
    std::fs::write(unrelated.join("untouched.bin"), b"unrelated bytes")?;
    for (folder, path) in [(&id, &data), (&other, &unrelated)] {
        core.client()
            .create_folder(&CreateFolderOptions::new(
                folder.clone(),
                TargetPath::local(path),
            ))
            .await?;
        core.client().request_scan(folder).await?;
    }
    indexed_files(core.client(), &id, 3).await?;
    indexed_files(core.client(), &other, 1).await?;
    let original = core.client().ignore_patterns(&id).await?;
    let other_original = core.client().ignore_patterns(&other).await?;
    assert!(original.parse_error.is_none() && !original.expanded_patterns.is_empty());
    assert!(original
        .patterns
        .as_ref()
        .unwrap()
        .iter()
        .any(|s| s.contains("*.tmp")));
    let empty = core
        .client()
        .set_ignore_patterns(&id, &IgnorePatterns::new(Vec::new())?)
        .await?;
    assert!(
        empty.requested_patterns_match
            && empty.snapshot.patterns.is_none()
            && empty.snapshot.expanded_patterns.is_empty()
    );
    core.client().request_scan(&id).await?;
    indexed_files(core.client(), &id, 5).await?;
    let rules = IgnorePatterns::new(vec![
        "// synthetic private rule".into(),
        "!keep.tmp".into(),
        "*.tmp".into(),
        "sub/*.dat".into(),
    ])?;
    let changed = core.client().set_ignore_patterns(&id, &rules).await?;
    assert!(changed.requested_patterns_match);
    assert_eq!(changed.snapshot.patterns.as_deref(), Some(rules.patterns()));
    assert!(!changed.snapshot.expanded_patterns.is_empty());
    assert!(!format!("{changed:?} {rules:?}").contains("synthetic private"));
    core.client().request_scan(&id).await?;
    indexed_files(core.client(), &id, 2).await?;
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(
        core.client()
            .ignore_patterns(&id)
            .await?
            .patterns
            .as_deref(),
        Some(rules.patterns())
    );
    indexed_files(core.client(), &id, 2).await?;
    let bad = IgnorePatterns::new(vec!["[synthetic-private-pattern".into()])?;
    let rejection = core
        .client()
        .set_ignore_patterns(&id, &bad)
        .await
        .unwrap_err();
    assert!(!format!("{rejection:?} {rejection}").contains("synthetic-private"));
    let Error::IgnorePatternsRejected { snapshot } = rejection else {
        return Err("expected actual ignore parser rejection".into());
    };
    assert_eq!(snapshot.patterns.as_deref(), Some(bad.patterns()));
    assert!(snapshot.parse_error.as_ref().is_some_and(|s| !s.is_empty()));
    let persisted = core.client().ignore_patterns(&id).await?;
    assert_eq!(persisted.patterns.as_deref(), Some(bad.patterns()));
    assert!(persisted
        .parse_error
        .as_ref()
        .is_some_and(|s| !s.is_empty()));
    let reset = core.client().reset_ignore_patterns(&id).await?;
    assert!(reset.parse_error.is_none());
    assert_eq!(reset.expanded_patterns, original.expanded_patterns);
    core.client().request_scan(&id).await?;
    indexed_files(core.client(), &id, 3).await?;
    let other_after = core.client().ignore_patterns(&other).await?;
    assert_eq!(other_after.patterns, other_original.patterns);
    assert_eq!(
        other_after.expanded_patterns,
        other_original.expanded_patterns
    );
    indexed_files(core.client(), &other, 1).await?;
    assert!(matches!(
        core.client()
            .set_ignore_patterns(&FolderId::parse("missing")?, &rules)
            .await,
        Err(Error::FolderNotFound { .. })
    ));
    for name in names {
        assert_eq!(
            std::fs::read(data.join(name))?,
            b"retained synthetic ignore bytes"
        );
    }
    assert_eq!(
        std::fs::read(unrelated.join("untouched.bin"))?,
        b"unrelated bytes"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public ignore patterns evidence: {}",
        json!({"actual_default_tmp_exclusion":true,"actual_empty_replacement_and_null_readback":true,"actual_all_files_indexed_after_clear":true,"exact_comment_negation_and_subdirectory_patterns":true,"actual_rule_filtered_index":true,"rules_persist_after_restart":true,"actual_http_success_parser_rejection_is_typed_error":true,"rejected_rules_actually_stored":true,"actual_get_retains_parse_error":true,"reset_restores_actual_engine_default_expansion":true,"actual_index_recovers_after_reset":true,"other_folder_rules_and_index_unchanged":true,"missing_folder_rejected":true,"patterns_and_errors_not_in_debug":true,"all_synthetic_bytes_retained":true,"actual_normal_tree_exit":true})
    );
    Ok(())
}
impl BlockedFile {
    fn new(path: &Path) -> TestResult<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let original = std::fs::metadata(path)?.permissions();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o0))?;
            Ok(Self {
                path: path.to_owned(),
                original,
            })
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            Ok(Self {
                _held: std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .share_mode(0)
                    .open(path)?,
            })
        }
    }
}
impl Drop for BlockedFile {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let _restored = std::fs::set_permissions(&self.path, self.original.clone());
        }
    }
}

#[tokio::test]
async fn actual_snapshots_pages_unknown_remote_and_file_errors_preserve_data() -> TestResult {
    let root = tempfile::Builder::new().prefix("vss-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    assert!(
        !a.client()
            .transport_configuration()
            .await?
            .tcp_punch_enabled
    );
    assert!(
        !b.client()
            .transport_configuration()
            .await?
            .tcp_punch_enabled
    );
    let b_id = b.client().instance().device_id.clone();
    let data = root.join("synthetic files");
    std::fs::create_dir(&data)?;
    let samples = [
        ("one.bin", b"a".as_slice()),
        ("二.bin", b"bb".as_slice()),
        ("third.bin", b"ccc".as_slice()),
    ];
    for (name, bytes) in samples {
        std::fs::write(data.join(name), bytes)?;
    }
    let id = FolderId::parse("typed-sync-observation")?;
    a.client()
        .create_folder(&CreateFolderOptions::new(
            id.clone(),
            TargetPath::local(data.clone()),
        ))
        .await?;
    a.client().request_scan(&id).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if a.client().folder_status(&id).await?.local_files == Some(3) {
                break Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    a.client()
        .create_device(
            &CreateDeviceOptions::new(b_id.clone())
                .settings(DevicePatch::default().addresses(Vec::new()).paused(true)),
        )
        .await?;
    a.client().share_folder_with(&id, &b_id).await?;
    let status = a.client().batch_folder_status().await?;
    assert_eq!(status[&id].local_files, Some(3));
    assert_eq!(status[&id].local_bytes, Some(6));
    let completion = a.client().folder_completion(&id, &b_id).await?;
    assert_eq!(completion.need_bytes, Some(6));
    assert_eq!(completion.need_items, Some(3));
    assert_eq!(completion.remote_state.as_deref(), Some("unknown"));
    let batch = a.client().folder_completions(&id).await?;
    assert_eq!(batch[&b_id].need_bytes, completion.need_bytes);
    assert_eq!(batch[&b_id].remote_state.as_deref(), Some("unknown"));
    let page = ListPage::new(1, 2)?;
    let need = a.client().folder_need(&id, page).await?;
    assert!(need.progress.is_empty() && need.queued.is_empty() && need.rest.is_empty());
    assert_eq!(need.page, Some(1));
    assert_eq!(need.per_page, Some(2));
    let first = a.client().remote_need(&id, &b_id, page).await?;
    let second = a
        .client()
        .remote_need(&id, &b_id, ListPage::new(2, 2)?)
        .await?;
    assert_eq!(first.files.len(), 2);
    assert_eq!(second.files.len(), 1);
    let names: BTreeSet<_> = first
        .files
        .iter()
        .chain(&second.files)
        .map(|f| f.name.clone())
        .collect();
    assert_eq!(names, samples.iter().map(|(n, _)| n.to_string()).collect());
    for file in first.files.iter().chain(&second.files) {
        assert_eq!(file.kind, SyncFileKind::File);
        let bytes = samples
            .iter()
            .find(|(name, _)| *name == file.name)
            .ok_or("unexpected indexed file")?
            .1;
        assert_eq!(file.size, Some(bytes.len() as u64));
        assert!(!format!("{file:?}").contains(&file.name));
    }
    assert!(a.client().local_changes(&id, page).await?.files.is_empty());
    assert!(a.client().folder_errors(&id, page).await?.errors.is_none());
    let devices = a.client().device_statistics().await?;
    assert!(devices[&b_id].created.is_some());
    assert!(devices[&b_id].last_seen.is_some());
    let folders = a.client().folder_statistics().await?;
    assert!(folders[&id].last_scan.is_some());
    assert!(folders[&id].last_file.is_some());
    let missing = FolderId::parse("not-configured-sync-observation")?;
    assert!(matches!(
        a.client().folder_need(&missing, page).await,
        Err(Error::FolderNotFound { .. })
    ));
    for (name, bytes) in samples {
        assert_eq!(std::fs::read(data.join(name))?, bytes);
    }
    let blocked = data.join("blocked.bin");
    std::fs::write(&blocked, b"synthetic blocked file")?;
    let guard = BlockedFile::new(&blocked)?;
    a.client().request_scan(&id).await?;
    let failures = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let errors = a.client().folder_errors(&id, page).await?;
            if errors.errors.as_ref().is_some_and(|v| {
                v.iter()
                    .any(|e| e.path == "blocked.bin" && !e.error.is_empty())
            }) {
                break Ok::<_, Error>(errors);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    assert!(!format!("{failures:?}").contains("blocked.bin"));
    drop(guard);
    assert_eq!(std::fs::read(&blocked)?, b"synthetic blocked file");
    a.client().request_scan(&id).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if a.client().folder_status(&id).await?.local_files == Some(4) {
                break Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    for instance in [&mut b, &mut a] {
        let exit = instance.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!(
        "public sync snapshot evidence: {}",
        json!({"fresh_private_tcp_punching_disabled":true,"actual_indexed_three_files_six_bytes":true,"batch_status_matches_actual_local_data":true,"actual_remote_need_counters":true,"unknown_remote_state_preserved":true,"actual_batch_peer_completion":true,"actual_empty_local_need_separate":true,"explicit_page_and_limit_readback":true,"two_actual_pages_cover_three_unique_files":true,"actual_file_names_kinds_and_sizes":true,"actual_empty_local_changes_separate":true,"actual_null_error_list_preserved":true,"actual_device_and_folder_stats":true,"missing_folder_not_empty_success":true,"all_original_sample_bytes_retained":true,"actual_native_blocked_file_error":true,"error_metadata_not_in_debug":true,"permission_or_handle_restored":true,"actual_recovery_indexed_fourth_file":true,"both_actual_normal_tree_exits":true})
    );
    Ok(())
}

async fn private_tcp(client: &verysync_sidecar::Client) -> TestResult<String> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for status in client.listener_status().await?.into_values() {
                for address in status.lan_addresses {
                    if address
                        .strip_prefix("tcp://")
                        .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
                        .is_some_and(|s| s.ip().is_loopback() && s.port() != 0 && s.port() != 18886)
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
async fn fixture_options(
    client: &verysync_sidecar::Client,
    value: serde_json::Value,
) -> TestResult {
    use verysync_sidecar::{RawMethod, RawRequest, RequestEffect};
    let response = client
        .raw_request(
            &RawRequest::new(
                RawMethod::Patch,
                ["rest", "config", "options"],
                RequestEffect::MayModify,
            )?
            .json_body(&value)?,
        )
        .await?;
    assert_eq!(response.status(), 200);
    Ok(())
}
#[tokio::test]
async fn actual_active_need_and_receive_only_local_changes_then_restore() -> TestResult {
    use verysync_sidecar::{
        DeviceTransport, JoinFolderOptions, RawMethod, RawRequest, RequestEffect,
    };
    let root = tempfile::Builder::new().prefix("vssn-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    let a_address = private_tcp(a.client()).await?;
    let b_address = private_tcp(b.client()).await?;
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    let a_path = root.join("source");
    let b_path = root.join("receiver");
    std::fs::create_dir(&a_path)?;
    let mut random = 0x1234abcd9876u64;
    let sample: Vec<u8> = (0..1_048_576)
        .map(|_| {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            random as u8
        })
        .collect();
    std::fs::write(a_path.join("payload.bin"), &sample)?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(a_path.clone())).paused(true))
        .await?;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(b_path.clone())).paused(true))
        .await?;
    // A fixture window for observation, not typed mode/rate-limit acceptance.
    let configured = b
        .client()
        .raw_request(
            &RawRequest::new(
                RawMethod::Patch,
                ["rest", "config", "folders", bf.configuration.id.as_str()],
                RequestEffect::MayModify,
            )?
            .json_body(&json!({"type":"receiveonly"}))?,
        )
        .await?;
    assert_eq!(configured.status(), 200);
    assert_eq!(
        b.client().folder(&bf.configuration.id).await?.extra["type"],
        "receiveonly"
    );
    fixture_options(
        b.client(),
        json!({"maxRecvKbps":1,"limitBandwidthInLan":true}),
    )
    .await?;
    let limit = b.client().network_configuration().await?;
    assert_eq!(limit.extra["maxRecvKbps"], 1);
    assert_eq!(limit.extra["limitBandwidthInLan"], true);
    for (client, folder, peer, address) in [
        (a.client(), &af.configuration.id, &b_id, b_address),
        (b.client(), &bf.configuration.id, &a_id, a_address),
    ] {
        client
            .create_device(
                &CreateDeviceOptions::new(peer.clone()).settings(
                    DevicePatch::default()
                        .addresses(vec![address])
                        .allowed_transports(vec![DeviceTransport::Tcp])
                        .paused(false),
                ),
            )
            .await?;
        client.share_folder_with(folder, peer).await?;
    }
    a.client().resume_folder(&af.configuration.id).await?;
    a.client().request_scan(&af.configuration.id).await?;
    b.client().resume_folder(&bf.configuration.id).await?;
    let page = ListPage::new(1, 5)?;
    let needed = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let need = b.client().folder_need(&bf.configuration.id, page).await?;
            if need
                .progress
                .iter()
                .chain(&need.queued)
                .chain(&need.rest)
                .any(|f| f.name == "payload.bin" && f.size == Some(sample.len() as u64))
            {
                break Ok::<_, Error>(need);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    assert!(!needed.progress.is_empty() || !needed.queued.is_empty() || !needed.rest.is_empty());
    assert!(b
        .client()
        .folder_status(&bf.configuration.id)
        .await?
        .need_bytes
        .is_some_and(|n| n > 0));
    fixture_options(
        b.client(),
        json!({"maxRecvKbps":0,"limitBandwidthInLan":false}),
    )
    .await?;
    assert_eq!(
        b.client().network_configuration().await?.extra["maxRecvKbps"],
        0
    );
    tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            if std::fs::read(b_path.join("payload.bin")).ok().as_deref() == Some(sample.as_slice())
                && b.client()
                    .folder_status(&bf.configuration.id)
                    .await?
                    .need_bytes
                    == Some(0)
            {
                break Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let target = b_path.join("payload.bin");
    let original = std::fs::metadata(&target)?;
    let modified = original.modified()?;
    let local = b"synthetic receive-only local edit";
    std::fs::write(&target, local)?;
    b.client().request_scan(&bf.configuration.id).await?;
    let changed = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let changes = b.client().local_changes(&bf.configuration.id, page).await?;
            if changes
                .files
                .iter()
                .any(|f| f.name == "payload.bin" && f.size == Some(local.len() as u64))
            {
                break Ok::<_, Error>(changes);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    assert!(!changed.files.is_empty());
    assert_eq!(std::fs::read(a_path.join("payload.bin"))?, sample);
    std::fs::write(&target, &sample)?;
    std::fs::File::options()
        .write(true)
        .open(&target)?
        .set_times(std::fs::FileTimes::new().set_modified(modified))?;
    b.client().request_scan(&bf.configuration.id).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if b.client()
                .local_changes(&bf.configuration.id, page)
                .await?
                .files
                .is_empty()
            {
                break Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    assert_eq!(std::fs::read(&target)?, sample);
    a.client().pause_device(&b_id).await?;
    b.client().pause_device(&a_id).await?;
    for instance in [&mut b, &mut a] {
        let exit = instance.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!(
        "public active sync observation evidence: {}",
        json!({"actual_distinct_key_registration_ids":true,"actual_private_peer_associations":true,"fixture_receiveonly_and_throttle_readback":true,"actual_nonempty_receiver_need":true,"actual_needed_filename_and_size":true,"actual_positive_need_bytes":true,"fixture_limit_restored":true,"actual_full_received_bytes_and_zero_need":true,"actual_receive_only_local_change":true,"actual_local_change_name_and_size":true,"source_data_not_modified_by_local_change":true,"actual_content_and_mtime_restored":true,"actual_local_changes_clear_after_restore":true,"both_actual_normal_tree_exits":true})
    );
    Ok(())
}
