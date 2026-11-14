//! Per-protocol reverse, bidirectional conflict and selected real data effects.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
#[path = "common/storage_diagnostic.rs"]
mod storage_diagnostic;
#[path = "common/storage_service.rs"]
mod storage_service;
use managed_fixture::{options, TestResult};
use std::{
    fs::{File, FileTimes},
    path::Path,
    time::{Duration, SystemTime},
};
use verysync_sidecar::*;
async fn analyze(core: &ManagedInstance, id: &LocalSyncJobId) -> TestResult<LocalSyncPreview> {
    let op = core.client().start_local_sync_preview(id).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let s = core.client().local_sync_status(id).await?;
            assert_eq!(s.operation_id.as_ref(), Some(&op.id));
            assert!(
                s.last_error.as_deref().unwrap_or_default().is_empty(),
                "native analysis failed: {:?}",
                s.last_error
            );
            if s.state == "idle" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    let p = core.client().local_sync_preview(id).await?;
    assert_eq!(p.operation_id, op.id);
    assert_eq!(p.scan_issue_count, 0);
    Ok(p)
}
async fn run(
    core: &ManagedInstance,
    id: &LocalSyncJobId,
    p: &LocalSyncPreviewId,
    selection: &LocalSyncSelection,
    peer: &storage_service::Service,
    root: &Path,
    phase: &str,
) -> TestResult {
    let r = match core.client().run_local_sync_preview(id, p, selection).await {
        Ok(run) => run,
        Err(error) => {
            eprintln!("synthetic protocol start failure phase: {phase}");
            storage_diagnostic::native_rejection(&error, &peer.endpoint, root);
            return Err(error.into());
        }
    };
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let observed = match core.client().local_sync_run(id).await {
                Ok(value) => value,
                Err(error) => {
                    storage_diagnostic::native_rejection(&error, &peer.endpoint, root);
                    return Err(error.into());
                }
            };
            assert_eq!(observed.id, r.id);
            if !observed.finished.starts_with("0001-") {
                assert_eq!(observed.summary.failed, 0);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}
fn remote(
    service: &storage_service::Service,
    protocol: StorageProtocol,
    name: &str,
) -> TestResult<StorageEndpoint> {
    let mut uri = url::Url::parse(service.endpoint.uri())?;
    uri.path_segments_mut()
        .map_err(|_| "URI path unavailable")?
        .pop_if_empty()
        .push(name)
        .push("");
    let user = service
        .endpoint
        .extra()
        .get("user")
        .and_then(serde_json::Value::as_str)
        .ok_or("synthetic user missing")?;
    let password = service
        .endpoint
        .extra()
        .get("password")
        .and_then(serde_json::Value::as_str)
        .ok_or("synthetic password missing")?;
    let mut e = StorageEndpoint::remote(protocol, uri.as_str())?
        .credentials(user, password)?
        .connection_timeout_seconds(6);
    if protocol == StorageProtocol::Sftp {
        e = e.insecure_tls(true)?;
    }
    Ok(e)
}
fn set_file(path: &Path, bytes: &[u8], seconds: u64) -> TestResult {
    std::fs::write(path, bytes)?;
    File::options().write(true).open(path)?.set_times(
        FileTimes::new().set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)),
    )?;
    Ok(())
}
async fn effects(protocol: StorageProtocol) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vsp-advanced-")
        .tempdir()?
        .keep();
    let mut peer = storage_service::Service::start(protocol, &root, Duration::ZERO)?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let a = root.join("reverse-a");
    let b = peer.share.join("reverse");
    std::fs::create_dir(&a)?;
    std::fs::create_dir(&b)?;
    std::fs::write(a.join("keep.txt"), b"reverse local only")?;
    std::fs::write(b.join("remote 中文 %.txt"), b"reverse remote payload")?;
    let job = core
        .client()
        .create_local_sync_job(
            &CreateLocalSyncJob::new(
                "reverse protocol",
                StorageEndpoint::local(TargetPath::local(&a))?,
                remote(&peer, protocol, "reverse")?,
                LocalSyncMode::MirrorBToA,
            )?
            .ignore_permissions(true),
        )
        .await?;
    let p = analyze(&core, &job.job_id).await?;
    run(
        &core,
        &job.job_id,
        &p.id,
        &LocalSyncSelection::all(),
        &peer,
        &root,
        "reverse-copy",
    )
    .await?;
    assert_eq!(
        std::fs::read(a.join("remote 中文 %.txt"))?,
        b"reverse remote payload"
    );
    assert_eq!(
        std::fs::read(b.join("remote 中文 %.txt"))?,
        b"reverse remote payload"
    );
    assert_eq!(std::fs::read(a.join("keep.txt"))?, b"reverse local only");
    core.client().delete_local_sync_job(&job.job_id).await?;
    for (name, policy) in [
        ("newer", LocalSyncConflictPolicy::Newer),
        ("larger", LocalSyncConflictPolicy::Larger),
        ("manual", LocalSyncConflictPolicy::Manual),
    ] {
        let a = root.join(name);
        let b = peer.share.join(name);
        std::fs::create_dir(&a)?;
        std::fs::create_dir(&b)?;
        std::fs::write(a.join("conflict.bin"), b"original common")?;
        std::fs::write(a.join("a-only.txt"), b"from A")?;
        std::fs::write(b.join("b-only.txt"), b"from B")?;
        let job = core
            .client()
            .create_local_sync_job(
                &CreateLocalSyncJob::new(
                    name,
                    StorageEndpoint::local(TargetPath::local(&a))?,
                    remote(&peer, protocol, name)?,
                    LocalSyncMode::Bidirectional,
                )?
                .ignore_permissions(true)
                .conflict_policy(policy)?,
            )
            .await?;
        let p = analyze(&core, &job.job_id).await?;
        run(
            &core,
            &job.job_id,
            &p.id,
            &LocalSyncSelection::all(),
            &peer,
            &root,
            &format!("{name}-initial-two-way"),
        )
        .await?;
        for side in [&a, &b] {
            assert_eq!(
                std::fs::read(side.join("conflict.bin"))?,
                b"original common"
            );
            assert_eq!(std::fs::read(side.join("a-only.txt"))?, b"from A");
            assert_eq!(std::fs::read(side.join("b-only.txt"))?, b"from B");
        }
        set_file(
            &a.join("conflict.bin"),
            b"larger older A payload",
            1700001000,
        )?;
        set_file(&b.join("conflict.bin"), b"B", 1700002000)?;
        let mut p = analyze(&core, &job.job_id).await?;
        if name == "manual" {
            let actions = core
                .client()
                .local_sync_preview_actions(&job.job_id, &p.id, 0, 100)
                .await?;
            assert!(actions
                .iter()
                .any(|x| x.kind == "conflict" && x.path == "conflict.bin"));
            let old = p.id.clone();
            p = core
                .client()
                .resolve_local_sync_conflict(
                    &job.job_id,
                    &old,
                    &LocalSyncConflictResolution::at_path(
                        "conflict.bin",
                        LocalSyncConflictSide::A,
                    )?,
                )
                .await?;
            assert_ne!(p.id, old);
            assert_eq!(
                std::fs::read(a.join("conflict.bin"))?,
                b"larger older A payload"
            );
            assert_eq!(std::fs::read(b.join("conflict.bin"))?, b"B");
        }
        run(
            &core,
            &job.job_id,
            &p.id,
            &LocalSyncSelection::all(),
            &peer,
            &root,
            &format!("{name}-resolved-conflict"),
        )
        .await?;
        let expected: &[u8] = if name == "newer" {
            b"B"
        } else {
            b"larger older A payload"
        };
        for side in [&a, &b] {
            assert_eq!(std::fs::read(side.join("conflict.bin"))?, expected);
            assert_eq!(std::fs::read(side.join("a-only.txt"))?, b"from A");
            assert_eq!(std::fs::read(side.join("b-only.txt"))?, b"from B");
        }
        if name == "manual" {
            std::fs::write(a.join("selected.txt"), b"explicit selected")?;
            std::fs::write(a.join("unselected.txt"), b"remain unselected")?;
            let p = analyze(&core, &job.job_id).await?;
            let actions = core
                .client()
                .local_sync_preview_actions(&job.job_id, &p.id, 0, 100)
                .await?;
            let chosen = actions
                .iter()
                .find(|x| x.path == "selected.txt")
                .ok_or("selected remote action absent")?
                .id;
            let selection =
                LocalSyncSelection::including(vec![LocalSyncActionRange::single(chosen)])?;
            let summary = core
                .client()
                .local_sync_selection_summary(&job.job_id, &p.id, &selection)
                .await?;
            assert_eq!(summary.copy_files, 1);
            assert_eq!(summary.copy_bytes, b"explicit selected".len() as u64);
            run(
                &core,
                &job.job_id,
                &p.id,
                &selection,
                &peer,
                &root,
                "manual-selected-only",
            )
            .await?;
            assert_eq!(std::fs::read(b.join("selected.txt"))?, b"explicit selected");
            assert!(!b.join("unselected.txt").exists());
            assert_eq!(
                std::fs::read(a.join("unselected.txt"))?,
                b"remain unselected"
            );
        }
        core.client().delete_local_sync_job(&job.job_id).await?;
        assert_eq!(std::fs::read(a.join("conflict.bin"))?, expected);
        assert_eq!(std::fs::read(b.join("conflict.bin"))?, expected);
    }
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let core_arch = core.client().instance().version.arch.clone();
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    peer.stop()?;
    println!(
        "public advanced storage protocol evidence: {}",
        serde_json::json!({"protocol":format!("{protocol:?}"),"native_rust_test_arch":std::env::consts::ARCH,"native_core_reported_arch":core_arch,"protocol_peer_python_platform":peer.python_platform,"actual_reverse_remote_to_local_bytes":true,"actual_reverse_local_sentinel_retained":true,"actual_two_way_initial_both_directions":true,"actual_remote_newer_conflict":true,"actual_remote_larger_conflict":true,"actual_remote_manual_conflict_preview_only":true,"actual_explicit_conflict_execution":true,"actual_selected_native_summary":true,"actual_remote_selected_only_execution":true,"actual_unselected_local_and_remote_untouched":true,"actual_registration_removal_retains_data":true,"actual_same_identity_normal_exit":true,"actual_exact_peer_stopped":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test]
async fn public_ftp_reverse_two_way_conflicts_and_selection() -> TestResult {
    effects(StorageProtocol::Ftp).await
}
#[tokio::test]
async fn public_sftp_reverse_two_way_conflicts_and_selection() -> TestResult {
    effects(StorageProtocol::Sftp).await
}
#[tokio::test]
async fn public_smb_reverse_two_way_conflicts_and_selection() -> TestResult {
    effects(StorageProtocol::Smb).await
}
#[tokio::test]
async fn public_webdav_reverse_two_way_conflicts_and_selection() -> TestResult {
    effects(StorageProtocol::WebDav).await
}
