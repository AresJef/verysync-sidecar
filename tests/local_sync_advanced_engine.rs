//! Public selected execution, reverse data flow and real two-way conflicts.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::{
    path::Path,
    time::{Duration, SystemTime},
};
use verysync_sidecar::*;

async fn analyze(core: &ManagedInstance, id: &LocalSyncJobId) -> TestResult<LocalSyncPreview> {
    let op = core.client().start_local_sync_preview(id).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status = core.client().local_sync_status(id).await?;
            assert_eq!(status.operation_id.as_ref(), Some(&op.id));
            assert!(status.last_error.as_deref().unwrap_or_default().is_empty());
            if status.state == "idle" {
                return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    let preview = core.client().local_sync_preview(id).await?;
    assert_eq!(preview.operation_id, op.id);
    assert_eq!(preview.scan_issue_count, 0);
    Ok(preview)
}
async fn finish(
    core: &ManagedInstance,
    id: &LocalSyncJobId,
    run: &LocalSyncRunId,
) -> TestResult<LocalSyncRun> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let result = core.client().local_sync_run(id).await?;
            assert_eq!(&result.id, run);
            if !result.finished.starts_with("0001-") {
                assert_eq!(result.summary.failed, 0);
                return Ok(result);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?
}
fn endpoints(a: &Path, b: &Path) -> Result<(StorageEndpoint, StorageEndpoint)> {
    Ok((
        StorageEndpoint::local(TargetPath::local(a))?,
        StorageEndpoint::local(TargetPath::local(b))?,
    ))
}
async fn shut(mut core: ManagedInstance, identity: &DeviceId) -> TestResult {
    assert_eq!(&core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    Ok(())
}
#[tokio::test]
async fn public_selected_and_excluded_actions_leave_unselected_actual_files_untouched() -> TestResult
{
    let root = tempfile::Builder::new().prefix("vlsa-").tempdir()?.keep();
    let a = root.join("a");
    let b = root.join("b");
    std::fs::create_dir(&a)?;
    std::fs::create_dir(&b)?;
    for name in ["a.txt", "b.txt", "c.txt"] {
        std::fs::write(a.join(name), name.as_bytes())?;
    }
    std::fs::write(b.join("keep.bin"), b"destination-only")?;
    let core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let (ea, eb) = endpoints(&a, &b)?;
    let job = core
        .client()
        .create_local_sync_job(
            &CreateLocalSyncJob::new("selected actions", ea, eb, LocalSyncMode::MirrorAToB)?
                .ignore_permissions(true),
        )
        .await?;
    let initial = analyze(&core, &job.job_id).await?;
    assert_eq!(initial.count, 3);
    let actions = core
        .client()
        .local_sync_preview_actions(&job.job_id, &initial.id, 0, 100)
        .await?;
    let chosen = actions
        .iter()
        .find(|x| x.path == "a.txt")
        .ok_or("missing chosen action")?
        .id;
    let selection = LocalSyncSelection::including(vec![LocalSyncActionRange::single(chosen)])?;
    let totals = core
        .client()
        .local_sync_selection_summary(&job.job_id, &initial.id, &selection)
        .await?;
    assert_eq!(totals.copy_files, 1);
    assert_eq!(totals.copy_bytes, 5);
    assert_eq!(totals.conflicts, 0);
    let empty = LocalSyncSelection::including(Vec::new())?;
    assert_eq!(
        core.client()
            .local_sync_selection_summary(&job.job_id, &initial.id, &empty)
            .await?
            .copy_files,
        0
    );
    assert!(matches!(
        core.client()
            .run_local_sync_preview(&job.job_id, &initial.id, &empty)
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    let outside = LocalSyncSelection::including(vec![LocalSyncActionRange::single(initial.count)])?;
    assert!(matches!(
        core.client()
            .run_local_sync_preview(&job.job_id, &initial.id, &outside)
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(!b.join("a.txt").exists());
    let receipt = core
        .client()
        .run_local_sync_preview(&job.job_id, &initial.id, &selection)
        .await?;
    assert_eq!(
        finish(&core, &job.job_id, &receipt.id)
            .await?
            .summary
            .completed,
        1
    );
    assert_eq!(std::fs::read(b.join("a.txt"))?, b"a.txt");
    assert!(!b.join("b.txt").exists() && !b.join("c.txt").exists());
    let next = analyze(&core, &job.job_id).await?;
    assert_ne!(next.id, initial.id);
    assert!(matches!(
        core.client()
            .local_sync_selection_summary(&job.job_id, &initial.id, &selection)
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    let actions = core
        .client()
        .local_sync_preview_actions(&job.job_id, &next.id, 0, 100)
        .await?;
    let excluded = actions
        .iter()
        .find(|x| x.path == "c.txt")
        .ok_or("missing excluded action")?
        .id;
    let selection = LocalSyncSelection::all_except(vec![LocalSyncActionRange::single(excluded)])?;
    assert_eq!(
        core.client()
            .local_sync_selection_summary(&job.job_id, &next.id, &selection)
            .await?
            .copy_files,
        1
    );
    let receipt = core
        .client()
        .run_local_sync_preview(&job.job_id, &next.id, &selection)
        .await?;
    assert_eq!(
        finish(&core, &job.job_id, &receipt.id)
            .await?
            .summary
            .completed,
        1
    );
    assert_eq!(std::fs::read(b.join("b.txt"))?, b"b.txt");
    assert!(!b.join("c.txt").exists());
    assert_eq!(std::fs::read(b.join("keep.bin"))?, b"destination-only");
    for name in ["a.txt", "b.txt", "c.txt"] {
        assert_eq!(std::fs::read(a.join(name))?, name.as_bytes());
    }
    let results = core
        .client()
        .local_sync_run_results(&job.job_id, &receipt.id, 0, 100)
        .await?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].path, "b.txt");
    shut(core, &identity).await?;
    println!(
        "public advanced selection evidence: {}",
        serde_json::json!({"actual_include_single_action":true,"actual_exclude_action":true,"actual_native_selected_copy_totals":true,"actual_empty_summary":true,"empty_and_outside_execution_refused_before_write":true,"stale_preview_refused":true,"actual_unselected_source_and_destination_retained":true,"actual_exact_result_identity":true,"actual_normal_same_identity_exit":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test]
async fn public_reverse_mirror_copies_b_to_a_and_preserves_extraneous_data() -> TestResult {
    let root = tempfile::Builder::new().prefix("vlsr-").tempdir()?.keep();
    let a = root.join("a");
    let b = root.join("b");
    std::fs::create_dir(&a)?;
    std::fs::create_dir(&b)?;
    std::fs::write(b.join("source.bin"), b"reverse source")?;
    std::fs::write(a.join("keep.bin"), b"reverse destination-only")?;
    let core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let (ea, eb) = endpoints(&a, &b)?;
    let job = core
        .client()
        .create_local_sync_job(
            &CreateLocalSyncJob::new("reverse", ea, eb, LocalSyncMode::MirrorBToA)?
                .ignore_permissions(true),
        )
        .await?;
    let preview = analyze(&core, &job.job_id).await?;
    let actions = core
        .client()
        .local_sync_preview_actions(&job.job_id, &preview.id, 0, 100)
        .await?;
    assert!(actions.iter().any(|x| x.path == "source.bin"
        && x.from.as_deref() == Some("b")
        && x.to.as_deref() == Some("a")));
    let receipt = core
        .client()
        .run_local_sync_preview_all(&job.job_id, &preview.id)
        .await?;
    finish(&core, &job.job_id, &receipt.id).await?;
    assert_eq!(std::fs::read(a.join("source.bin"))?, b"reverse source");
    assert_eq!(std::fs::read(b.join("source.bin"))?, b"reverse source");
    assert_eq!(
        std::fs::read(a.join("keep.bin"))?,
        b"reverse destination-only"
    );
    assert!(!b.join("keep.bin").exists());
    shut(core, &identity).await?;
    println!(
        "public reverse Local Sync evidence: {}",
        serde_json::json!({"actual_reverse_action_direction":true,"actual_b_to_a_payload":true,"actual_source_retained":true,"actual_destination_only_retained":true,"actual_no_unrequested_forward_copy":true,"actual_normal_same_identity_exit":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
fn modified(path: &Path, seconds: u64) -> TestResult {
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.set_times(
        std::fs::FileTimes::new()
            .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)),
    )?;
    Ok(())
}
async fn conflict(policy: LocalSyncConflictPolicy) -> TestResult {
    let root = tempfile::Builder::new().prefix("vlsc-").tempdir()?.keep();
    let a = root.join("a");
    let b = root.join("b");
    std::fs::create_dir(&a)?;
    std::fs::create_dir(&b)?;
    for path in [&a, &b] {
        std::fs::write(path.join("shared.txt"), b"baseline")?;
        modified(&path.join("shared.txt"), 1700000000)?;
    }
    std::fs::write(a.join("from-a.bin"), b"a-only")?;
    std::fs::write(b.join("from-b.bin"), b"b-only")?;
    let core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let (ea, eb) = endpoints(&a, &b)?;
    let job = core
        .client()
        .create_local_sync_job(
            &CreateLocalSyncJob::new(
                "two-way actual conflict",
                ea,
                eb,
                LocalSyncMode::Bidirectional,
            )?
            .ignore_permissions(true)
            .conflict_policy(policy)?,
        )
        .await?;
    let initial = analyze(&core, &job.job_id).await?;
    let receipt = core
        .client()
        .run_local_sync_preview_all(&job.job_id, &initial.id)
        .await?;
    finish(&core, &job.job_id, &receipt.id).await?;
    assert_eq!(std::fs::read(a.join("from-b.bin"))?, b"b-only");
    assert_eq!(std::fs::read(b.join("from-a.bin"))?, b"a-only");
    let older_larger = b"older but substantially larger side A";
    let newer_smaller = b"new B";
    std::fs::write(a.join("shared.txt"), older_larger)?;
    std::fs::write(b.join("shared.txt"), newer_smaller)?;
    modified(&a.join("shared.txt"), 1700001000)?;
    modified(&b.join("shared.txt"), 1700002000)?;
    let preview = analyze(&core, &job.job_id).await?;
    let totals = core
        .client()
        .local_sync_selection_summary(&job.job_id, &preview.id, &LocalSyncSelection::all())
        .await?;
    let (preview, expected) = match policy {
        LocalSyncConflictPolicy::Manual => {
            assert_eq!(totals.conflicts, 1);
            assert_eq!(std::fs::read(a.join("shared.txt"))?, older_larger);
            assert_eq!(std::fs::read(b.join("shared.txt"))?, newer_smaller);
            let resolved = core
                .client()
                .resolve_local_sync_conflict(
                    &job.job_id,
                    &preview.id,
                    &LocalSyncConflictResolution::at_path("shared.txt", LocalSyncConflictSide::A)?,
                )
                .await?;
            assert_ne!(resolved.id, preview.id);
            assert_eq!(std::fs::read(a.join("shared.txt"))?, older_larger);
            assert_eq!(std::fs::read(b.join("shared.txt"))?, newer_smaller);
            assert_eq!(
                core.client()
                    .local_sync_selection_summary(
                        &job.job_id,
                        &resolved.id,
                        &LocalSyncSelection::all()
                    )
                    .await?
                    .conflicts,
                0
            );
            (resolved, older_larger.as_slice())
        }
        LocalSyncConflictPolicy::Newer => {
            assert_eq!(totals.conflicts, 0);
            (preview, newer_smaller.as_slice())
        }
        LocalSyncConflictPolicy::Larger => {
            assert_eq!(totals.conflicts, 0);
            (preview, older_larger.as_slice())
        }
    };
    let receipt = core
        .client()
        .run_local_sync_preview_all(&job.job_id, &preview.id)
        .await?;
    finish(&core, &job.job_id, &receipt.id).await?;
    assert_eq!(std::fs::read(a.join("shared.txt"))?, expected);
    assert_eq!(std::fs::read(b.join("shared.txt"))?, expected);
    shut(core, &identity).await?;
    println!(
        "public two-way Local Sync evidence: {}",
        serde_json::json!({"policy":format!("{policy:?}"),"actual_initial_both_directions":true,"actual_simultaneous_different_changes":true,"actual_native_conflict_totals":true,"actual_winning_bytes_both_sides":true,"manual_resolution_preview_only_verified":if matches!(policy,LocalSyncConflictPolicy::Manual){Some(true)}else{None},"actual_normal_same_identity_exit":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test]
async fn public_two_way_newer_chooses_actual_newer_bytes() -> TestResult {
    conflict(LocalSyncConflictPolicy::Newer).await
}
#[tokio::test]
async fn public_two_way_larger_chooses_actual_larger_bytes() -> TestResult {
    conflict(LocalSyncConflictPolicy::Larger).await
}
#[tokio::test]
async fn public_two_way_manual_resolution_changes_only_preview_until_explicit_run() -> TestResult {
    conflict(LocalSyncConflictPolicy::Manual).await
}
