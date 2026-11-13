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

#[path = "common/sync_diagnostics.rs"]
mod sync_diagnostics;
use sync_diagnostics::report as sync_stage_diagnostic;

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
    let first = Path::new("one").join("二 空格 %.bin");
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
    let needed_observation = tokio::time::timeout(Duration::from_secs(20), async {
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
    .await;
    if needed_observation.is_err() {
        sync_stage_diagnostic(
            "active-need-before-any-payload",
            &[
                (&a, &af.configuration.id, &b_id),
                (&b, &bf.configuration.id, &a_id),
            ],
        )
        .await;
        let status = b.client().folder_status(&bf.configuration.id).await?;
        let config = b.client().folder(&bf.configuration.id).await?;
        eprintln!(
            "active need preparation diagnostic: {}",
            json!({
                "state":status.state.as_ref().map(|s|s.as_str()),
                "need_bytes":status.need_bytes,
                "local_files":status.local_files,
                "configured_paused":config.paused,
                "fixture_rate":b.client().network_configuration().await?.extra.get("maxRecvKbps"),
                "receiver_payload_exists":b_path.join("payload.bin").exists()
            })
        );
    }
    let needed = needed_observation??;
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

#[tokio::test]
async fn actual_folder_order_and_specific_priority_change_preserve_samples() -> TestResult {
    use verysync_sidecar::{
        BandwidthPatch, DeviceTransport, FolderPullOrder, JoinFolderOptions, RawMethod, RawRequest,
        RequestEffect,
    };
    let root = tempfile::Builder::new().prefix("vssp-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    let a_address = private_tcp(a.client()).await?;
    let b_address = private_tcp(b.client()).await?;
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    let source = root.join("source");
    std::fs::create_dir(&source)?;
    for index in 0..512u64 {
        let name = if index == 511 {
            "zz priority %.bin".to_owned()
        } else {
            format!("file-{index:04}.bin")
        };
        let mut random = 0x1234abcd9876u64 ^ (index + 1);
        let sample: Vec<u8> = (0..8192)
            .map(|_| {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                random as u8
            })
            .collect();
        std::fs::write(source.join(name), sample)?;
    }
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&source)).paused(true))
        .await?;
    let bf = b
        .client()
        .join_folder(
            &JoinFolderOptions::new(ro, TargetPath::local(root.join("receiver"))).paused(true),
        )
        .await?;
    let folder = &bf.configuration.id;
    assert!(matches!(
        b.client()
            .prioritize_file(
                folder,
                &TargetPath::local("zz priority %.bin"),
                ListPage::new(1, 1000)?
            )
            .await,
        Err(Error::FolderPaused { .. })
    ));

    // Select the fixed core's legacy queue only as an explicit fixture. This
    // does not claim typed control of these advanced puller-mode fields.
    let configured = b
        .client()
        .raw_request(
            &RawRequest::new(
                RawMethod::Patch,
                ["rest", "config", "folders", folder.as_str()],
                RequestEffect::MayModify,
            )?
            .json_body(
                &json!({"copiers":1,"antsPullerEnabled":false,"pullerSessionEnabled":false}),
            )?,
        )
        .await?;
    assert_eq!(configured.status(), 200);
    let fixture = b.client().folder(folder).await?;
    assert_eq!(fixture.extra["antsPullerEnabled"], false);
    assert_eq!(fixture.extra["pullerSessionEnabled"], false);
    for order in [
        FolderPullOrder::Random,
        FolderPullOrder::Alphabetic,
        FolderPullOrder::SmallestFirst,
        FolderPullOrder::LargestFirst,
        FolderPullOrder::OldestFirst,
        FolderPullOrder::NewestFirst,
        FolderPullOrder::Alphabetic,
    ] {
        let changed = b.client().set_folder_pull_order(folder, &order).await?;
        assert!(changed.requested_order_match && changed.configuration.pull_order == order);
        assert_eq!(changed.configuration.extra["antsPullerEnabled"], false);
    }
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
    b.client().resume_folder(folder).await?;
    let page = ListPage::new(1, 1000)?;
    let need_result = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let n = b.client().folder_need(folder, page).await?;
            if n.queued.len() >= 2 && n.queued.iter().any(|f| f.name == "zz priority %.bin") {
                break Ok::<_, Error>(n);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if need_result.is_err() {
        sync_stage_diagnostic(
            "legacy-priority-queue-prepare",
            &[(&a, &af.configuration.id, &b_id), (&b, folder, &a_id)],
        )
        .await;
        if let Ok(observed) = b.client().folder_need(folder, page).await {
            eprintln!(
                "private priority queue preparation diagnostic: {}",
                json!({"queued":observed.queued.len(),"progress":observed.progress.len(),"rest":observed.rest.len(),"target_queued":observed.queued.iter().any(|f|f.name=="zz priority %.bin"),"target_progress":observed.progress.iter().any(|f|f.name=="zz priority %.bin"),"target_rest":observed.rest.iter().any(|f|f.name=="zz priority %.bin")})
            );
        }
    }
    let need = need_result??;
    let target = "zz priority %.bin";
    assert!(need
        .queued
        .iter()
        .position(|f| f.name == target)
        .is_some_and(|p| p > 0));
    let prioritized = b
        .client()
        .prioritize_file(folder, &TargetPath::local(target), page)
        .await?;
    assert!(!prioritized.queued.is_empty());
    assert!(
        prioritized.queued.first().is_some_and(|f| f.name == target)
            || prioritized.progress.iter().any(|f| f.name == target)
    );
    assert!(prioritized.queued.iter().any(|f| f.name != target));
    assert_eq!(prioritized.page, Some(1));
    assert_eq!(prioritized.per_page, Some(1000));
    assert!(b
        .client()
        .set_folder_pull_order(folder, &FolderPullOrder::Unknown("unverified".into()))
        .await
        .is_err());
    assert!(matches!(
        b.client()
            .prioritize_file(folder, &TargetPath::local("../escape"), page)
            .await,
        Err(Error::InvalidPath { .. })
    ));
    assert!(
        b.client()
            .update_bandwidth_configuration(
                &BandwidthPatch::default().max_receive_kib_per_second(0)
            )
            .await?
            .requested_fields_match
    );
    tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            let status = b.client().folder_status(folder).await?;
            if status.local_files == Some(512) && status.need_bytes == Some(0) {
                break Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    for index in 0..512u64 {
        let name = if index == 511 {
            target.to_owned()
        } else {
            format!("file-{index:04}.bin")
        };
        assert_eq!(
            std::fs::read(source.join(&name))?,
            std::fs::read(root.join("receiver").join(name))?
        );
    }
    a.client().pause_device(&b_id).await?;
    b.client().pause_device(&a_id).await?;
    for instance in [&mut b, &mut a] {
        let exit = instance.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!(
        "public folder priority evidence: {}",
        json!({"all_six_actual_order_readbacks":true,"paused_scope_rejected":true,"legacy_queue_fixture_fields_read_back":true,"actual_alphabetic_backlog_has_nonfirst_target":true,"actual_target_promoted_while_other_work_still_queued":true,"actual_page_scope_preserved":true,"unrelated_folder_settings_retained":true,"unknown_order_and_invalid_relative_path_rejected":true,"explicit_rate_restoration_read_back":true,"actual_all_512_files_received":true,"all_source_and_destination_contents_match":true,"both_actual_normal_tree_exits":true})
    );
    Ok(())
}

async fn incoming_bytes(
    client: &verysync_sidecar::Client,
    peer: &verysync_sidecar::DeviceId,
) -> TestResult<u64> {
    let snapshot = client.connections().await?;
    let connection = snapshot
        .connections
        .get(peer)
        .ok_or("private receiving peer is absent")?;
    let endpoint = connection
        .address
        .as_deref()
        .and_then(|s| s.parse::<std::net::SocketAddr>().ok());
    if !connection.connected
        || !endpoint.is_some_and(|s| s.ip().is_loopback() && s.port() != 0 && s.port() != 18886)
        || !matches!(
            connection.connection_type,
            Some(
                verysync_sidecar::PeerConnectionType::TcpClient
                    | verysync_sidecar::PeerConnectionType::TcpServer
            )
        )
    {
        return Err("expected an actual connected private loopback TCP peer".into());
    }
    connection
        .in_bytes_total
        .ok_or_else(|| "incoming byte counter is absent".into())
}
async fn clear_bandwidth(a: &ManagedInstance, b: &ManagedInstance) -> TestResult {
    use verysync_sidecar::BandwidthPatch;
    for (client, peer) in [
        (a.client(), &b.client().instance().device_id),
        (b.client(), &a.client().instance().device_id),
    ] {
        assert!(
            client
                .update_bandwidth_configuration(
                    &BandwidthPatch::default()
                        .max_send_kib_per_second(0)
                        .max_receive_kib_per_second(0)
                        .limit_in_lan(true)
                )
                .await?
                .requested_fields_match
        );
        assert!(
            client
                .update_device(
                    peer,
                    &DevicePatch::default()
                        .max_send_kib_per_second(0)
                        .max_receive_kib_per_second(0)
                )
                .await?
                .requested_fields_match
        );
    }
    Ok(())
}
#[tokio::test]
async fn actual_global_and_device_bandwidth_caps_preserve_transferred_bytes() -> TestResult {
    use sha2::{Digest, Sha256};
    use std::time::Instant;
    use verysync_sidecar::{BandwidthPatch, DeviceCompression, DeviceTransport, JoinFolderOptions};
    let mut resolution = u128::MAX;
    let clock_started = Instant::now();
    for _ in 0..10000 {
        let tick = Instant::now();
        let dt = tick.elapsed().as_nanos();
        if dt > 0 {
            resolution = resolution.min(dt);
        }
    }
    assert!(resolution > 0 && resolution <= 1_000_000);
    println!(
        "bandwidth clock preparation: {}",
        json!({"minimum_positive_read_ns":resolution,"read_pairs":10000,"complete_loop_ns":clock_started.elapsed().as_nanos()})
    );
    let root = tempfile::Builder::new()
        .prefix("vss-rates-")
        .tempdir()?
        .keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    let a_address = private_tcp(a.client()).await?;
    let b_address = private_tcp(b.client()).await?;
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    let source = root.join("source");
    let receiver = root.join("receiver");
    std::fs::create_dir(&source)?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&source)).paused(true))
        .await?;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(&receiver)).paused(true))
        .await?;
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
                        .compression(DeviceCompression::Never),
                ),
            )
            .await?;
        client.share_folder_with(folder, peer).await?;
        client.resume_folder(folder).await?;
    }
    let connected_observation = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if b.client()
                .connections()
                .await?
                .connections
                .get(&a_id)
                .is_some_and(|p| p.connected)
            {
                break Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if !matches!(&connected_observation, Ok(Ok(()))) {
        sync_stage_diagnostic(
            "bandwidth-initial-connection",
            &[
                (&a, &af.configuration.id, &b_id),
                (&b, &bf.configuration.id, &a_id),
            ],
        )
        .await;
    }
    connected_observation??;
    let mut samples = Vec::new();
    let mut original = Vec::new();
    let mut payload_hashes = BTreeSet::new();
    for case in 0..4u64 {
        clear_bandwidth(&a, &b).await?;
        match case {
            0 => assert!(
                a.client()
                    .update_bandwidth_configuration(
                        &BandwidthPatch::default().max_send_kib_per_second(64)
                    )
                    .await?
                    .requested_fields_match
            ),
            1 => assert!(
                b.client()
                    .update_bandwidth_configuration(
                        &BandwidthPatch::default().max_receive_kib_per_second(64)
                    )
                    .await?
                    .requested_fields_match
            ),
            2 => assert!(
                a.client()
                    .update_device(&b_id, &DevicePatch::default().max_send_kib_per_second(64))
                    .await?
                    .requested_fields_match
            ),
            _ => assert!(
                b.client()
                    .update_device(
                        &a_id,
                        &DevicePatch::default().max_receive_kib_per_second(64)
                    )
                    .await?
                    .requested_fields_match
            ),
        }
        let name = format!("rate-{case}.bin");
        let mut state = 0x1234abcd9876u64 ^ (case + 1);
        let content: Vec<u8> = (0..2_097_152)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        let digest = format!("{:x}", Sha256::digest(&content));
        assert!(payload_hashes.insert(digest.clone()));
        std::fs::write(source.join(&name), &content)?;
        a.client().request_scan(&af.configuration.id).await?;
        let needed_observation = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let need = b
                    .client()
                    .folder_need(&bf.configuration.id, ListPage::new(1, 100)?)
                    .await?;
                if need
                    .progress
                    .iter()
                    .chain(&need.queued)
                    .chain(&need.rest)
                    .any(|f| f.name == name && f.size == Some(content.len() as u64))
                {
                    break Ok::<_, Error>(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        if !matches!(&needed_observation, Ok(Ok(()))) {
            sync_stage_diagnostic(
                &format!("bandwidth-case-{case}-need"),
                &[
                    (&a, &af.configuration.id, &b_id),
                    (&b, &bf.configuration.id, &a_id),
                ],
            )
            .await;
        }
        needed_observation??;
        let outer_start = Instant::now();
        let before = incoming_bytes(b.client(), &a_id).await?;
        let before_end = outer_start.elapsed();
        tokio::time::sleep(Duration::from_secs(3)).await;
        let after_start = outer_start.elapsed();
        let after = incoming_bytes(b.client(), &a_id).await?;
        let outer_span = outer_start.elapsed();
        let delta = after
            .checked_sub(before)
            .ok_or("counter decreased during the complete measurement window")?;
        if !(3.0..=6.0).contains(&outer_span.as_secs_f64()) {
            return Err("insufficient measurement: counter window outside frozen bounds".into());
        }
        let upper = 1_048_576.0 + 65_536.0 * outer_span.as_secs_f64();
        assert!(
            delta > 0 && (delta as f64) <= upper,
            "functional rate window exceeded the frozen byte bound"
        );
        assert!(b
            .client()
            .folder_status(&bf.configuration.id)
            .await?
            .need_bytes
            .is_some_and(|n| n > 0));
        clear_bandwidth(&a, &b).await?;
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let status = b.client().folder_status(&bf.configuration.id).await?;
                if status.local_files == Some(case + 1) && status.need_bytes == Some(0) {
                    break Ok::<_, Error>(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        assert_eq!(std::fs::read(receiver.join(&name))?, content);
        let sample = json!({"case":case,"payload_bytes":content.len(),"payload_sha256":digest,"configured_kib_per_second":64,"before_bytes":before,"after_bytes":after,"delta_bytes":delta,"first_api_end_ns":before_end.as_nanos(),"second_api_start_ns":after_start.as_nanos(),"outer_span_ns":outer_span.as_nanos(),"upper_bytes":upper,"actual_full_content_after_limit_removed":true});
        println!("public bandwidth functional sample: {}", sample);
        samples.push(sample);
        original.push((name, content));
    }
    for (name, content) in original {
        assert_eq!(std::fs::read(source.join(name))?, content);
    }
    a.client().pause_device(&b_id).await?;
    b.client().pause_device(&a_id).await?;
    for core in [&mut b, &mut a] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    let phase = std::env::var("VERYSYNC_BANDWIDTH_PHASE").unwrap_or_else(|_| "acceptance".into());
    println!(
        "public bandwidth functional trial: {}",
        json!({"phase":phase,"protocol":"VS033-S4-functional-v2","complete_cases":samples,"scope":"absolute functional byte-cap observations; no throughput or speedup claim"})
    );
    println!(
        "public bandwidth functional evidence: {}",
        json!({"actual_global_upload_cap":true,"actual_global_download_cap":true,"actual_device_upload_cap":true,"actual_device_download_cap":true,"all_positive_monotonic_byte_windows":true,"all_complete_windows_within_frozen_bounds":true,"actual_nonempty_need_while_limited":true,"all_selected_settings_read_back":true,"actual_explicit_zero_limit_restoration":true,"all_four_actual_full_received_files":true,"all_distinct_payload_hashes_and_source_bytes_preserved":true,"both_actual_normal_tree_exits":true})
    );
    Ok(())
}

#[tokio::test]
async fn actual_selective_tree_pages_and_license_rejection_preserve_files() -> TestResult {
    use verysync_sidecar::{
        DeviceTransport, JoinFolderOptions, SelectiveAction, SelectiveBrowseOptions,
        SelectiveScope, SelectiveSearchOptions,
    };
    let root = tempfile::Builder::new().prefix("vsssel-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    let a_address = private_tcp(a.client()).await?;
    let b_address = private_tcp(b.client()).await?;
    let keys = a.client().generate_share().await?;
    let ak = a.client().validate_share_key(&keys.read_write_key).await?;
    let bk = b.client().validate_share_key(&keys.read_write_key).await?;
    let source = root.join("source");
    let receiver = root.join("receiver");
    std::fs::create_dir_all(source.join("nested"))?;
    for (name, bytes) in [
        (Path::new("first.bin"), b"first synthetic".as_slice()),
        (Path::new("third.bin"), b"third synthetic".as_slice()),
        (
            Path::new("nested").join("child.bin").as_path(),
            b"nested synthetic".as_slice(),
        ),
    ] {
        std::fs::write(source.join(name), bytes)?;
    }
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(ak, TargetPath::local(&source)).paused(true))
        .await?;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(bk, TargetPath::local(&receiver)).paused(true))
        .await?;
    let configured = b
        .client()
        .set_folder_selective_enabled(&bf.configuration.id, true)
        .await?;
    assert!(configured.requested_mode_match && configured.configuration.enabled);
    for (client, folder, peer, address) in [
        (a.client(), &af.configuration.id, &b_id, b_address),
        (b.client(), &bf.configuration.id, &a_id, a_address),
    ] {
        client
            .create_device(
                &CreateDeviceOptions::new(peer.clone()).settings(
                    DevicePatch::default()
                        .addresses(vec![address])
                        .allowed_transports(vec![DeviceTransport::Tcp]),
                ),
            )
            .await?;
        client.share_folder_with(folder, peer).await?;
        client.resume_folder(folder).await?;
    }
    a.client().request_scan(&af.configuration.id).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if b.client()
                .folder_status(&bf.configuration.id)
                .await?
                .global_files
                == Some(3)
            {
                break Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let folder = &bf.configuration.id;
    let root_options = SelectiveBrowseOptions::new(SelectiveScope::FolderRoot).levels(2);
    let tree = b.client().browse_selective(folder, &root_options).await?;
    assert_eq!(tree.entries.len(), 3);
    assert_eq!(tree.entries["first.bin"].name, "first.bin");
    assert_eq!(tree.entries["first.bin"].size, Some(15));
    assert!(!tree.entries["first.bin"].selected && !tree.entries["first.bin"].exists_locally);
    assert!(tree.entries["nested"].is_directory);
    let child = &tree.entries["nested"]
        .children
        .as_ref()
        .ok_or("expected actual nested tree")?
        .entries["child.bin"];
    assert_eq!(child.size, Some(16));
    assert!(!child.selected && !child.exists_locally);
    assert!(!format!("{tree:?}").contains("first.bin"));
    let prefixed = b
        .client()
        .browse_selective(
            folder,
            &SelectiveBrowseOptions::new(SelectiveScope::Path(TargetPath::local("nested"))),
        )
        .await?;
    assert_eq!(
        prefixed
            .entries
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["child.bin"]
    );
    let dirs = b
        .client()
        .browse_selective(
            folder,
            &SelectiveBrowseOptions::new(SelectiveScope::FolderRoot).directories_only(true),
        )
        .await?;
    assert_eq!(
        dirs.entries.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["nested"]
    );
    let search = SelectiveSearchOptions::new("child")?.limit(1);
    let page = b.client().search_selective(folder, &search).await?;
    assert!(page.search && page.has_more);
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].entry.name, "child.bin");
    assert!(page.items[0].path.ends_with("child.bin"));
    let cursor = page
        .next_cursor
        .clone()
        .ok_or("expected explicit actual next cursor")?;
    let end = b
        .client()
        .search_selective(folder, &search.after_cursor(cursor))
        .await?;
    assert!(end.items.is_empty() && !end.has_more);
    assert!(!format!("{page:?}").contains("child.bin"));
    for (scope, action) in [
        (
            SelectiveScope::Path(TargetPath::local("first.bin")),
            SelectiveAction::Select,
        ),
        (
            SelectiveScope::Path(TargetPath::local("first.bin")),
            SelectiveAction::Deselect,
        ),
        (
            SelectiveScope::Path(TargetPath::local("nested")),
            SelectiveAction::Select,
        ),
        (SelectiveScope::FolderRoot, SelectiveAction::Select),
        (
            SelectiveScope::Path(TargetPath::local("third.bin")),
            SelectiveAction::RemoveFromAll,
        ),
    ] {
        let error = b
            .client()
            .request_selection(folder, &scope, action)
            .await
            .unwrap_err();
        let Error::LicenseRequired { code, response } = error else {
            return Err("expected actual Pro license refusal".into());
        };
        assert_eq!(code, 3000);
        assert_eq!(response.status(), 200);
    }
    let unchanged = b.client().browse_selective(folder, &root_options).await?;
    assert!(unchanged
        .entries
        .values()
        .all(|n| !n.selected && !n.exists_locally));
    assert_eq!(b.client().folder_status(folder).await?.local_files, Some(0));
    assert!(matches!(
        b.client()
            .browse_selective(&FolderId::parse("missing")?, &root_options)
            .await,
        Err(Error::FolderNotFound { .. })
    ));
    assert!(matches!(
        b.client()
            .request_selection(
                folder,
                &SelectiveScope::Path(TargetPath::local("../escape")),
                SelectiveAction::RemoveFromAll
            )
            .await,
        Err(Error::InvalidPath { .. })
    ));
    assert!(b
        .client()
        .search_selective(folder, &SelectiveSearchOptions::new("child")?.limit(0))
        .await
        .is_err());
    assert!(
        b.client()
            .set_folder_selective_enabled(folder, false)
            .await?
            .requested_mode_match
    );
    b.restart(Duration::from_secs(30)).await?;
    assert!(
        !b.client()
            .folder_selective_configuration(folder)
            .await?
            .enabled
    );
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status = b.client().folder_status(folder).await?;
            if status.local_files == Some(3) && status.need_bytes == Some(0) {
                break Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let nested = Path::new("nested").join("child.bin");
    for (name, bytes) in [
        (Path::new("first.bin"), b"first synthetic".as_slice()),
        (Path::new("third.bin"), b"third synthetic".as_slice()),
        (nested.as_path(), b"nested synthetic".as_slice()),
    ] {
        assert_eq!(std::fs::read(source.join(name))?, bytes);
        assert_eq!(std::fs::read(receiver.join(name))?, bytes);
    }
    a.client().pause_device(&b_id).await?;
    b.client().pause_device(&a_id).await?;
    for core in [&mut b, &mut a] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!(
        "public selective browse and license evidence: {}",
        json!({"actual_selective_mode_readback":true,"actual_unselected_remote_tree":true,"actual_nested_child_metadata":true,"actual_file_sizes_and_absence_flags":true,"actual_relative_prefix_scope":true,"actual_directories_only_filter":true,"actual_search_match_and_path":true,"actual_full_last_page_continuation_flag_retained":true,"actual_opaque_cursor_next_page":true,"all_five_mutations_return_typed_license_refusal":true,"http_success_not_selection_success":true,"denied_selection_keeps_all_flags_and_receiver_empty":true,"missing_folder_and_invalid_scope_rejected":true,"tree_names_and_cursor_not_in_debug":true,"explicit_normal_mode_restored_after_restart":true,"actual_free_normal_sync_receives_all_three_files":true,"all_source_and_destination_bytes_match":true,"both_actual_normal_tree_exits":true})
    );
    Ok(())
}

#[tokio::test]
async fn actual_receiveonly_revert_and_marker_repair_restore_owned_data() -> TestResult {
    use verysync_sidecar::{
        DeviceTransport, JoinFolderOptions, RawMethod, RawRequest, RequestEffect,
    };
    let root = tempfile::Builder::new().prefix("vssrec-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    let a_address = private_tcp(a.client()).await?;
    let b_address = private_tcp(b.client()).await?;
    let keys = a.client().generate_share().await?;
    let ak = a.client().validate_share_key(&keys.read_write_key).await?;
    let bk = b.client().validate_share_key(&keys.read_only_key).await?;
    let source = root.join("source");
    let receiver = root.join("receiver");
    std::fs::create_dir(&source)?;
    let original = b"authoritative synthetic revert bytes";
    std::fs::write(source.join("revert.bin"), original)?;
    std::fs::write(
        source.join("deleted.bin"),
        b"original deleted synthetic bytes",
    )?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(ak, TargetPath::local(&source)).paused(true))
        .await?;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(bk, TargetPath::local(&receiver)).paused(true))
        .await?;
    let r = b
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
    assert_eq!(r.status(), 200);
    assert_eq!(
        b.client().folder(&bf.configuration.id).await?.extra["type"],
        "receiveonly"
    );
    for (client, folder, peer, address) in [
        (a.client(), &af.configuration.id, &b_id, b_address),
        (b.client(), &bf.configuration.id, &a_id, a_address),
    ] {
        client
            .create_device(
                &CreateDeviceOptions::new(peer.clone()).settings(
                    DevicePatch::default()
                        .addresses(vec![address])
                        .allowed_transports(vec![DeviceTransport::Tcp]),
                ),
            )
            .await?;
        client.share_folder_with(folder, peer).await?;
        client.resume_folder(folder).await?;
    }
    a.client().request_scan(&af.configuration.id).await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if std::fs::read(receiver.join("revert.bin")).is_ok_and(|v| v == original) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    assert!(matches!(
        b.client()
            .request_override_remote_changes(&bf.configuration.id)
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if std::fs::read(receiver.join("deleted.bin"))
                .is_ok_and(|v| v == b"original deleted synthetic bytes")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    std::fs::remove_file(receiver.join("deleted.bin"))?;
    std::fs::write(
        receiver.join("local-only.bin"),
        b"local addition to be reverted",
    )?;
    std::fs::write(
        receiver.join("revert.bin"),
        b"synthetic local edit to revert",
    )?;
    b.client().request_scan(&bf.configuration.id).await?;
    let change_observation = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let observed = b
                .client()
                .local_changes(&bf.configuration.id, ListPage::new(1, 10)?)
                .await?;
            if observed.files.iter().any(|f| f.name == "revert.bin")
                && !observed.files.iter().any(|f| f.name == "deleted.bin")
                && std::fs::read(receiver.join("deleted.bin"))
                    .is_ok_and(|v| v == b"original deleted synthetic bytes")
            {
                break Ok::<_, Error>(observed);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if change_observation.is_err() {
        let page = b
            .client()
            .local_changes(&bf.configuration.id, ListPage::new(1, 10)?)
            .await?;
        eprintln!(
            "receive-only local change preparation diagnostic: {}",
            json!({
                "edit_in_changes":page.files.iter().any(|f|f.name == "revert.bin"),
                "deletion_in_changes":page.files.iter().any(|f|f.name == "deleted.bin"),
                "addition_in_changes":page.files.iter().any(|f|f.name == "local-only.bin"),
                "receiver_deleted_path_exists":receiver.join("deleted.bin").exists(),
                "receiver_addition_exists":receiver.join("local-only.bin").exists(),
                "receiver_edit_is_original":std::fs::read(receiver.join("revert.bin")).is_ok_and(|v|v==original)
            })
        );
    }
    let observed_changes = change_observation??;
    // The fixed engine derives receive-only mode from the RO key and repairs
    // local deletion itself; establish that separately before explicit revert.
    assert_eq!(
        std::fs::read(receiver.join("deleted.bin"))?,
        b"original deleted synthetic bytes"
    );
    assert!(!observed_changes
        .files
        .iter()
        .any(|f| f.name == "deleted.bin"));
    b.client()
        .request_revert_local_changes(&bf.configuration.id)
        .await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if std::fs::read(receiver.join("revert.bin")).is_ok_and(|v| v == original)
                && b.client()
                    .local_changes(&bf.configuration.id, ListPage::new(1, 10)?)
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
    assert_eq!(std::fs::read(receiver.join("revert.bin"))?, original);
    assert_eq!(
        std::fs::read(receiver.join("deleted.bin"))?,
        b"original deleted synthetic bytes"
    );
    assert_eq!(
        std::fs::read(receiver.join("local-only.bin"))?,
        b"local addition to be reverted"
    );
    assert_eq!(
        std::fs::read(source.join("deleted.bin"))?,
        b"original deleted synthetic bytes"
    );
    assert!(!source.join("local-only.bin").exists());
    assert_eq!(
        b.client().folder(&bf.configuration.id).await?.extra["type"],
        "receiveonly"
    );
    assert_eq!(std::fs::read(source.join("revert.bin"))?, original);
    a.client().pause_device(&b_id).await?;
    b.client().pause_device(&a_id).await?;
    let marker_data = root.join("marker-data");
    std::fs::create_dir(&marker_data)?;
    std::fs::write(marker_data.join("retained.bin"), b"retained marker bytes")?;
    let marker_keys = a.client().generate_share().await?;
    let marker_share = a
        .client()
        .validate_share_key(&marker_keys.read_write_key)
        .await?;
    let mf = a
        .client()
        .join_folder(
            &JoinFolderOptions::new(marker_share, TargetPath::local(&marker_data)).paused(true),
        )
        .await?;
    a.client()
        .update_folder_scan_configuration(
            &mf.configuration.id,
            &verysync_sidecar::FolderScanPatch::default()
                .watcher(false)
                .rescan_interval_seconds(0),
        )
        .await?;
    a.client().resume_folder(&mf.configuration.id).await?;
    a.client().request_scan(&mf.configuration.id).await?;
    indexed_files(a.client(), &mf.configuration.id, 1).await?;
    let before = a.client().folder(&mf.configuration.id).await?;
    assert!(before
        .extra
        .get("secretKey")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| !s.is_empty()));
    assert_eq!(before.extra["markerName"], ".verysync");
    assert_eq!(before.extra["autoRepairtMarker"], false);
    a.client().pause_folder(&mf.configuration.id).await?;
    std::fs::rename(marker_data.join(".verysync"), root.join("marker-backup"))?;
    a.client().resume_folder(&mf.configuration.id).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if a.client().folder_status(&mf.configuration.id).await?.state
                == Some(verysync_sidecar::FolderState::Error)
            {
                break Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let repaired = a
        .client()
        .request_marker_repair(&mf.configuration.id)
        .await?;
    assert!(repaired.success && repaired.error.is_empty());
    assert!(!std::fs::symlink_metadata(marker_data.join(".verysync"))?
        .file_type()
        .is_symlink());
    assert!(marker_data.join(".verysync").is_dir() && root.join("marker-backup").is_dir());
    a.restart(Duration::from_secs(30)).await?;
    a.client().request_scan(&mf.configuration.id).await?;
    indexed_files(a.client(), &mf.configuration.id, 1).await?;
    let after = a.client().folder(&mf.configuration.id).await?;
    assert!(before.id == after.id);
    for field in ["secretKey", "readOnlySecret", "readWriteSecret"] {
        assert!(before.extra.get(field) == after.extra.get(field));
    }
    assert!(matches!(
        a.client()
            .request_marker_repair(&FolderId::parse("missing")?)
            .await,
        Err(Error::FolderNotFound { .. })
    ));
    assert_eq!(
        std::fs::read(marker_data.join("retained.bin"))?,
        b"retained marker bytes"
    );
    for core in [&mut b, &mut a] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!(
        "public receive-only and marker recovery evidence: {}",
        json!({"actual_receiveonly_fixture_readback":true,"actual_original_received_bytes":true,"actual_tracked_edit_observed_in_changes":true,"actual_local_edit_reverted":true,"actual_ro_key_deletion_autorestored_before_explicit_revert":true,"actual_unindexed_local_addition_bytes_retained":true,"actual_source_files_unchanged":true,"actual_local_changes_clear":true,"wrong_mode_rejected":true,"actual_missing_marker_error_observed":true,"actual_marker_repair_acknowledgement":true,"actual_marker_directory_recreated_without_symlink":true,"original_marker_backup_retained":true,"actual_same_folder_and_share_keys_after_restart":true,"actual_scan_recovers_after_explicit_restart":true,"all_retained_marker_data_bytes_preserved":true,"missing_folder_rejected":true,"both_actual_normal_tree_exits":true})
    );
    Ok(())
}

#[tokio::test]
async fn actual_sendonly_override_restores_remote_data_and_preserves_authority() -> TestResult {
    use verysync_sidecar::{
        DeviceTransport, JoinFolderOptions, RawMethod, RawRequest, RequestEffect,
    };
    let root = tempfile::Builder::new()
        .prefix("vssover-")
        .tempdir()?
        .keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    let a_address = private_tcp(a.client()).await?;
    let b_address = private_tcp(b.client()).await?;
    let keys = a.client().generate_share().await?;
    let ak = a.client().validate_share_key(&keys.read_write_key).await?;
    let bk = b.client().validate_share_key(&keys.read_write_key).await?;
    let source = root.join("authority");
    let other = root.join("other");
    std::fs::create_dir(&source)?;
    let original = b"send-only authoritative synthetic bytes";
    std::fs::write(source.join("override.bin"), original)?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(ak, TargetPath::local(&source)).paused(true))
        .await?;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(bk, TargetPath::local(&other)).paused(true))
        .await?;
    let r = a
        .client()
        .raw_request(
            &RawRequest::new(
                RawMethod::Patch,
                ["rest", "config", "folders", af.configuration.id.as_str()],
                RequestEffect::MayModify,
            )?
            .json_body(&json!({"type":"sendonly"}))?,
        )
        .await?;
    assert_eq!(r.status(), 200);
    assert_eq!(
        a.client().folder(&af.configuration.id).await?.extra["type"],
        "sendonly"
    );
    for (client, folder, peer, address) in [
        (a.client(), &af.configuration.id, &b_id, b_address),
        (b.client(), &bf.configuration.id, &a_id, a_address),
    ] {
        client
            .create_device(
                &CreateDeviceOptions::new(peer.clone()).settings(
                    DevicePatch::default()
                        .addresses(vec![address])
                        .allowed_transports(vec![DeviceTransport::Tcp]),
                ),
            )
            .await?;
        client.share_folder_with(folder, peer).await?;
        client.resume_folder(folder).await?;
    }
    a.client().request_scan(&af.configuration.id).await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if std::fs::read(other.join("override.bin")).is_ok_and(|v| v == original) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    let remote = b"synthetic remote edit requiring authority override";
    std::fs::write(other.join("override.bin"), remote)?;
    b.client().request_scan(&bf.configuration.id).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let status = a.client().folder_status(&af.configuration.id).await?;
            if status.need_bytes.is_some_and(|n| n > 0) {
                break Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    assert_eq!(std::fs::read(source.join("override.bin"))?, original);
    a.client()
        .request_override_remote_changes(&af.configuration.id)
        .await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if std::fs::read(other.join("override.bin")).is_ok_and(|v| v == original) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    assert_eq!(std::fs::read(other.join("override.bin"))?, original);
    assert!(matches!(
        a.client()
            .request_revert_local_changes(&af.configuration.id)
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert_eq!(std::fs::read(source.join("override.bin"))?, original);
    a.client().pause_device(&b_id).await?;
    b.client().pause_device(&a_id).await?;
    for core in [&mut b, &mut a] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!(
        "public send-only override evidence: {}",
        json!({"actual_sendonly_fixture_readback":true,"actual_initial_remote_received_bytes":true,"actual_remote_modified_version_observed":true,"authority_retains_original_before_override":true,"actual_remote_original_bytes_restored":true,"authority_retains_original_after_override":true,"wrong_mode_revert_rejected":true,"both_actual_normal_tree_exits":true})
    );
    Ok(())
}
