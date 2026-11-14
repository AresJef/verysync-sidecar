//! Actual native automatic triggers and explicit free-entitlement normalization.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::{path::Path, time::Duration};
use verysync_sidecar::*;
async fn wait_file(path: &Path, bytes: &[u8]) -> TestResult {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if std::fs::read(path).is_ok_and(|b| b == bytes) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    Ok(())
}
#[tokio::test]
async fn public_native_enablement_and_startup_copy_actual_files_without_manual_run() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vls-startup-")
        .tempdir()?
        .keep();
    let a = root.join("source");
    let b = root.join("target");
    std::fs::create_dir(&a)?;
    std::fs::create_dir(&b)?;
    std::fs::write(a.join("first.txt"), b"first automatic payload")?;
    std::fs::write(b.join("keep.txt"), b"target only")?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let job = core
        .client()
        .create_local_sync_job(
            &CreateLocalSyncJob::new(
                "explicit startup",
                StorageEndpoint::local(TargetPath::local(&a))?,
                StorageEndpoint::local(TargetPath::local(&b))?,
                LocalSyncMode::MirrorAToB,
            )?
            .ignore_permissions(true)
            .enabled(false)
            .sync_on_startup(true),
        )
        .await?;
    assert!(job.sync_on_startup && !job.enabled);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!b.join("first.txt").exists());
    let enabled = core
        .client()
        .update_local_sync_job(&job.job_id, &LocalSyncJobPatch::default().enabled(true))
        .await?;
    assert!(enabled.requested_fields_match && enabled.configuration.sync_on_startup);
    wait_file(&b.join("first.txt"), b"first automatic payload").await?;
    std::fs::write(a.join("second.txt"), b"after native restart")?;
    assert!(!b.join("second.txt").exists());
    core.restart(Duration::from_secs(30)).await?;
    wait_file(&b.join("second.txt"), b"after native restart").await?;
    let updated = core
        .client()
        .update_local_sync_job(
            &job.job_id,
            &LocalSyncJobPatch::default()
                .sync_on_startup(false)
                .schedule(LocalSyncSchedule::off()),
        )
        .await?;
    assert!(updated.requested_fields_match && !updated.configuration.sync_on_startup);
    assert_eq!(updated.configuration.label, "explicit startup");
    assert_eq!(updated.configuration.schedule_mode.as_deref(), Some("off"));
    assert_eq!(
        std::fs::read(a.join("first.txt"))?,
        b"first automatic payload"
    );
    assert_eq!(
        std::fs::read(a.join("second.txt"))?,
        b"after native restart"
    );
    assert_eq!(
        std::fs::read(b.join("first.txt"))?,
        b"first automatic payload"
    );
    assert_eq!(std::fs::read(b.join("keep.txt"))?, b"target only");
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    println!(
        "public Local Sync automation evidence: {}",
        serde_json::json!({"actual_disabled_job_does_not_execute":true,"actual_enablement_triggers_native_copy":true,"actual_restart_triggers_native_copy":true,"no_manual_preview_or_run_calls":true,"actual_trigger_disable_readback":true,"actual_unrelated_configuration_preserved":true,"actual_source_and_target_sentinel_preserved":true,"actual_same_identity_normal_tree_exit":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test]
async fn public_free_watch_and_schedules_are_reconciled_as_normalized_not_applied() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vls-pro-guard-")
        .tempdir()?
        .keep();
    let a = root.join("source");
    let b = root.join("target");
    std::fs::create_dir(&a)?;
    std::fs::create_dir(&b)?;
    std::fs::write(a.join("source.txt"), b"source must remain")?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    for kind in ["watch", "interval", "calendar"] {
        let base = CreateLocalSyncJob::new(
            kind,
            StorageEndpoint::local(TargetPath::local(&a))?,
            StorageEndpoint::local(TargetPath::local(&b))?,
            LocalSyncMode::MirrorAToB,
        )?
        .enabled(false)
        .ignore_permissions(true);
        let (input, patch) = match kind {
            "watch" => (
                base.watch_changes(true, 10)?,
                LocalSyncJobPatch::default().watch_changes(true, 10)?,
            ),
            "interval" => (
                base.schedule(LocalSyncSchedule::interval(60)?),
                LocalSyncJobPatch::default().schedule(LocalSyncSchedule::interval(60)?),
            ),
            _ => {
                let schedule = LocalSyncSchedule::calendar(
                    vec![LocalSyncCalendarRule::new(
                        vec![1, 2, 3, 4, 5, 6, 7],
                        vec!["23:59".to_owned()],
                    )?],
                    "UTC",
                )?;
                (
                    base.schedule(schedule.clone()),
                    LocalSyncJobPatch::default().schedule(schedule),
                )
            }
        };
        assert!(core.client().local_sync_jobs().await?.is_empty());
        assert!(matches!(
            core.client().create_local_sync_job(&input).await,
            Err(Error::MutationOutcomeUnknown { .. })
        ));
        let jobs = core.client().local_sync_jobs().await?;
        assert_eq!(jobs.len(), 1);
        let job = &jobs[0];
        assert!(!job.enabled && !job.sync_on_startup);
        assert_eq!(job.watch_changes, Some(false));
        assert_eq!(job.schedule_mode.as_deref(), Some("off"));
        let observed = core
            .client()
            .update_local_sync_job(&job.job_id, &patch)
            .await?;
        assert!(!observed.requested_fields_match);
        assert_eq!(observed.configuration.label, kind);
        assert!(!observed.configuration.enabled);
        assert_eq!(std::fs::read(a.join("source.txt"))?, b"source must remain");
        assert!(!b.join("source.txt").exists());
        core.client().delete_local_sync_job(&job.job_id).await?;
    }
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    println!(
        "public Local Sync free automation guard evidence: {}",
        serde_json::json!({"actual_watch_normalized_off":true,"actual_interval_normalized_off":true,"actual_calendar_normalized_off":true,"creation_mismatch_is_unknown_outcome":true,"actual_single_registration_reconciled_without_retry":true,"update_reports_requested_fields_mismatch":true,"actual_source_and_target_unchanged":true,"actual_same_identity_normal_tree_exit":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
