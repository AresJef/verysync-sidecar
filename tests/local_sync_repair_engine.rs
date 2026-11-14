//! Actual missing-marker and incompatible two-way baseline recovery.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::{path::Path, time::Duration};
use verysync_sidecar::*;
async fn terminal(core: &ManagedInstance, id: &LocalSyncJobId) -> TestResult<LocalSyncStatus> {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let s = core.client().local_sync_status(id).await?;
            if s.state == "idle" || s.last_error.as_deref().is_some_and(|e| !e.is_empty()) {
                return Ok(s);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?
}
async fn analyze(core: &ManagedInstance, id: &LocalSyncJobId) -> TestResult<LocalSyncPreview> {
    let op = core.client().start_local_sync_preview(id).await?;
    let s = terminal(core, id).await?;
    assert_eq!(s.operation_id.as_ref(), Some(&op.id));
    assert!(s.last_error.as_deref().unwrap_or_default().is_empty());
    let p = core.client().local_sync_preview(id).await?;
    assert_eq!(p.operation_id, op.id);
    assert_eq!(p.scan_issue_count, 0);
    Ok(p)
}
async fn execute(
    core: &ManagedInstance,
    id: &LocalSyncJobId,
    preview: &LocalSyncPreviewId,
) -> TestResult {
    let run = core
        .client()
        .run_local_sync_preview_all(id, preview)
        .await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let r = core.client().local_sync_run(id).await?;
            assert_eq!(r.id, run.id);
            if !r.finished.starts_with("0001-") {
                assert_eq!(r.summary.failed, 0);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}
fn original_files(a: &Path, b: &Path) -> TestResult {
    for root in [a, b] {
        assert_eq!(std::fs::read(root.join("a.txt"))?, b"original A");
        assert_eq!(std::fs::read(root.join("b.txt"))?, b"original B");
    }
    Ok(())
}
#[tokio::test]
async fn public_marker_rebuild_and_baseline_recovery_restore_real_safety_guards_without_implicit_run(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vls-repair-public-")
        .tempdir()?
        .keep();
    let a = root.join("a");
    let b = root.join("b");
    std::fs::create_dir(&a)?;
    std::fs::create_dir(&b)?;
    std::fs::write(a.join("a.txt"), b"original A")?;
    std::fs::write(b.join("b.txt"), b"original B")?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let job = core
        .client()
        .create_local_sync_job(
            &CreateLocalSyncJob::new(
                "reviewed repair",
                StorageEndpoint::local(TargetPath::local(&a))?,
                StorageEndpoint::local(TargetPath::local(&b))?,
                LocalSyncMode::Bidirectional,
            )?
            .ignore_permissions(true),
        )
        .await?;
    let preview = analyze(&core, &job.job_id).await?;
    execute(&core, &job.job_id, &preview.id).await?;
    original_files(&a, &b)?;
    let marker = a.join(".verysync-localsync");
    assert!(marker.is_dir());
    let saved_marker = root.join("saved-a-marker");
    std::fs::rename(&marker, &saved_marker)?;
    core.client().start_local_sync_preview(&job.job_id).await?;
    let failed = terminal(&core, &job.job_id).await?;
    assert!(failed
        .last_error
        .as_deref()
        .is_some_and(|e| e.contains("synchronization folder marker missing")));
    original_files(&a, &b)?;
    let receipt = core.client().rebuild_local_sync_markers(&job).await?;
    assert_eq!(receipt.job_id, job.job_id);
    assert!(marker.is_dir() && saved_marker.is_dir());
    let healthy = analyze(&core, &job.job_id).await?;
    assert_eq!(healthy.count, 0);
    original_files(&a, &b)?;
    let baseline_dir = root
        .join("core")
        .join("localsync")
        .join("v2")
        .join("bisync");
    let states = std::fs::read_dir(&baseline_dir)?.collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(states.len(), 1);
    let baseline = states[0].path().join("state.bin");
    let prior_baseline = std::fs::read(&baseline)?;
    assert!(!prior_baseline.is_empty());
    std::fs::write(root.join("original-baseline.bin"), &prior_baseline)?;
    let changed = core
        .client()
        .update_local_sync_job(
            &job.job_id,
            &LocalSyncJobPatch::default().ignore_permissions(false),
        )
        .await?;
    assert!(changed.requested_fields_match);
    core.client().start_local_sync_preview(&job.job_id).await?;
    let failed = terminal(&core, &job.job_id).await?;
    assert!(failed
        .last_error
        .as_deref()
        .is_some_and(|e| e.contains("bisync state does not match endpoints or comparison rules")));
    assert_eq!(std::fs::read(&baseline)?, prior_baseline);
    original_files(&a, &b)?;
    assert!(matches!(
        core.client().recover_local_sync_baseline(&job).await,
        Err(Error::InvalidConfiguration { .. })
    ));
    std::fs::write(
        a.join("after-recovery.txt"),
        b"explicit post-recovery payload",
    )?;
    let current = core.client().local_sync_job(&job.job_id).await?;
    let recovery = core.client().recover_local_sync_baseline(&current).await?;
    assert_eq!(recovery.job_id, job.job_id);
    assert_eq!(recovery.scan_issue_count, 0);
    assert!(recovery.count > 0);
    assert!(!b.join("after-recovery.txt").exists());
    assert!(!baseline.exists());
    original_files(&a, &b)?;
    execute(&core, &job.job_id, &recovery.id).await?;
    assert_eq!(
        std::fs::read(b.join("after-recovery.txt"))?,
        b"explicit post-recovery payload"
    );
    assert_eq!(
        std::fs::read(a.join("after-recovery.txt"))?,
        b"explicit post-recovery payload"
    );
    assert!(baseline.is_file());
    assert_ne!(std::fs::read(&baseline)?, prior_baseline);
    assert_eq!(
        std::fs::read(root.join("original-baseline.bin"))?,
        prior_baseline
    );
    original_files(&a, &b)?;
    let clean = analyze(&core, &job.job_id).await?;
    assert_eq!(clean.count, 0);
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(analyze(&core, &job.job_id).await?.count, 0);
    original_files(&a, &b)?;
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    println!(
        "public Local Sync recovery evidence: {}",
        serde_json::json!({"actual_two_way_initial_baseline":true,"actual_missing_marker_guard":true,"actual_native_marker_directory_recreated":true,"actual_saved_marker_retained":true,"actual_post_rebuild_analysis_restored":true,"actual_comparison_change_baseline_mismatch":true,"actual_old_baseline_retained_before_recovery":true,"stale_reviewed_snapshot_refused":true,"actual_native_recovery_returns_fresh_preview":true,"no_implicit_file_execution":true,"actual_explicit_execution_rebuilds_baseline":true,"actual_original_and_new_file_bytes_preserved":true,"actual_prior_baseline_test_backup_preserved":true,"actual_clean_analysis_after_restart":true,"actual_same_identity_normal_tree_exit":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
