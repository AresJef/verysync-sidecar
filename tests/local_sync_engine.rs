//! Public native Local Sync effects use one independent synthetic state root.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::{
    CreateLocalSyncJob, LocalSyncJobPatch, LocalSyncMode, ManagedInstance, StorageEndpoint,
    TargetPath,
};

#[tokio::test]
async fn local_sync_business_native_executes_reviewed_preview_and_reads_exact_run() -> TestResult {
    use sha2::{Digest, Sha256};
    use verysync_sidecar::{
        Client, ConnectOptions, LocalSyncActionRange, LocalSyncRegistrationOutcome,
        LocalSyncRunOutcome, LocalSyncRunReceipt, LocalSyncSelection, LocalSyncWorkflowOptions,
        OperationCompletion, OperationOptions,
    };
    let root = tempfile::Builder::new().prefix("vls-flow-").tempdir()?;
    let source = root.path().join("source");
    let target = root.path().join("target");
    std::fs::create_dir(&source)?;
    std::fs::create_dir(&target)?;
    let mut core = ManagedInstance::start(options(&root.path().join("c"))?).await?;
    let verified: TestResult = async {
        let one = b"fixed synthetic first payload";
        let two = b"fixed synthetic second payload that must stay unselected";
        std::fs::write(source.join("selected.txt"), one)?;
        std::fs::write(source.join("unselected.txt"), two)?;
        std::fs::write(target.join("outside.bin"), b"target sentinel")?;
        let registration = core.client().create_local_sync_job_and_verify(
            &CreateLocalSyncJob::new(
                "one explicit synthetic preview",
                StorageEndpoint::local(TargetPath::local(&source))?,
                StorageEndpoint::local(TargetPath::local(&target))?,
                LocalSyncMode::MirrorAToB,
            )?.ignore_permissions(true),
            OperationOptions::new(Duration::from_secs(12)),
        ).await?;
        assert_eq!(registration.outcome, LocalSyncRegistrationOutcome::CurrentMatches, "{registration:?}");
        assert!(registration.write.dispatched && registration.write.response_complete);
        let job = registration.observed.ok_or("the exact native job was not read back")?;
        let bounds = || LocalSyncWorkflowOptions::new(10, OperationOptions::new(Duration::from_secs(24))).page_size(1);
        let plan = core.client().preview_local_sync_and_verify(&job.job_id, bounds()).await?;
        assert_eq!(plan.completion(), OperationCompletion::Completed, "{plan:?}");
        assert_eq!(plan.actions.len(), 2);
        assert!(!target.join("selected.txt").exists());
        let exact = plan.preview.ok_or("native preview missing")?;
        assert_eq!(plan.initial?.id, exact.operation_id);
        let selected = plan.actions.iter().find(|action| action.path == "selected.txt").ok_or("selected action missing")?.id;
        let report = core.client()
            .execute_local_sync_preview(
                &job.job_id, &exact.id,
                &LocalSyncSelection::including(vec![LocalSyncActionRange::single(selected)])?,
                bounds(),
            ).await?;
        if report.outcome != LocalSyncRunOutcome::Completed {
            use std::error::Error as _;
            let original = report.initial.as_ref().and_then(|result| result.as_ref().err());
            let later = core.client().local_sync_run(&job.job_id).await?;
            println!("{}", serde_json::json!({
                "controlled_nanosecond_or_count_probe":true,
                "sdk_initial":original.map(ToString::to_string),
                "sdk_cause":original.and_then(|error|error.source()).map(ToString::to_string),
                "sdk_observation_error":report.observation_error.as_ref().map(ToString::to_string),
                "selected_count":1,"preview_count":2,"native_run_count":later.count,
                "elapsed_time_fields":[later.started,later.finished],
                "native_summary":[later.summary.completed,later.summary.failed,later.summary.skipped],
                "extra_field_names":later.extra.keys().collect::<Vec<_>>()
            }));
            return Err("the native Local Sync acknowledgement did not bind as expected".into());
        }
        assert!(report.write.dispatched && report.write.response_complete);
        let receipt = report.receipt.ok_or("native run was not bound")?;
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].action_id, selected);
        assert_eq!(report.results[0].path, "selected.txt");
        assert_eq!(report.terminal.as_ref().map(|run| run.summary.skipped), Some(1));
        assert_eq!(report.selected_summary.as_ref().map(|summary| summary.skipped), Some(0));
        assert_eq!(report.terminal.as_ref().map(|run| &run.id), Some(receipt.run()));
        assert_eq!(Sha256::digest(std::fs::read(target.join("selected.txt"))?), Sha256::digest(one));
        assert!(!target.join("unselected.txt").exists());
        assert_eq!(std::fs::read(target.join("outside.bin"))?, b"target sentinel");
        let private_bytes = receipt.encode()?;
        let reopened = LocalSyncRunReceipt::decode(&private_bytes)?;
        let borrowed = Client::connect(
            ConnectOptions::new(core.client().endpoint().clone(), core.client().gui_authentication().await?.api_key()?)
                .expected_device_id(core.client().instance().device_id.clone()),
        ).await?;
        let observed = borrowed.observe_local_sync_execution(&reopened, bounds()).await?;
        assert_eq!(observed.outcome, LocalSyncRunOutcome::Completed, "{observed:?}");
        assert!(!observed.write.dispatched && observed.initial.is_none());
        assert_eq!(observed.results.len(), 1);
        assert_eq!(observed.receipt.as_ref().map(|receipt| receipt.run()), Some(receipt.run()));
        let next = core.client().preview_local_sync_and_verify(&job.job_id, bounds()).await?;
        assert_eq!(next.completion(), OperationCompletion::Completed, "{next:?}");
        let newer_plan = next.preview.ok_or("new native preview missing")?;
        let new = core.client()
            .execute_local_sync_preview(&job.job_id, &newer_plan.id, &LocalSyncSelection::all(), bounds()).await?;
        assert_eq!(new.outcome, LocalSyncRunOutcome::Completed, "{new:?}");
        let replaced = borrowed.observe_local_sync_execution(&reopened, bounds()).await?;
        assert_eq!(replaced.outcome, LocalSyncRunOutcome::Unconfirmed, "{replaced:?}");
        assert!(replaced.results.is_empty() && !replaced.write.dispatched);
        assert_eq!(Sha256::digest(std::fs::read(target.join("unselected.txt"))?), Sha256::digest(two));
        assert_eq!(std::fs::read(source.join("selected.txt"))?, one);
        println!("Checked Local Sync workflow: exact preview, two independent pages, one selected action, digest and sentinel preserved, reopened receipt zero writes, newer result never substituted for older run");
        Ok(())
    }.await;
    let exit = core.shutdown(Duration::from_secs(15)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced);
    root.close()?;
    println!("Checked Local Sync workflow: owned tree exited and fixture removed");
    verified
}

#[tokio::test]
async fn public_local_sync_preview_execution_and_registration_changes_preserve_actual_data(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vls-public-")
        .tempdir()?
        .keep();
    let source = root.join("source 中文 %");
    let target = root.join("target 中文 %");
    std::fs::create_dir_all(source.join("nested"))?;
    std::fs::create_dir_all(&target)?;
    let payload = b"synthetic public Local Sync payload";
    std::fs::write(source.join("nested").join("file %.txt"), payload)?;
    std::fs::write(target.join("keep.bin"), b"target-only sentinel")?;
    let a = StorageEndpoint::local(TargetPath::local(&source))?;
    let b = StorageEndpoint::local(TargetPath::local(&target))?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    assert!(core.client().local_sync_health().await?.available);
    let config = core.client().local_sync_configuration().await?;
    assert_eq!(config.version, 1);
    assert!(config.jobs.is_empty());
    let probe = core.client().probe_storage_endpoint(&a).await?;
    assert!(probe.r#move && probe.atomic_replace && probe.preserves_mod_time);
    let listing = core.client().browse_storage_endpoint(&a, "").await?;
    assert!(listing
        .entries
        .iter()
        .any(|e| e.path == "nested" && e.directory));
    core.client()
        .create_storage_directory(&a, "nested", "created 中文 %")
        .await?;
    assert!(source.join("nested").join("created 中文 %").is_dir());
    let options = CreateLocalSyncJob::new(
        "explicit synthetic job",
        a.clone(),
        b.clone(),
        LocalSyncMode::MirrorAToB,
    )?
    .ignore_permissions(true);
    let job = core.client().create_local_sync_job(&options).await?;
    assert!(job.group.is_none());
    assert_eq!(core.client().local_sync_jobs().await?.len(), 1);
    assert!(!job.delete_extraneous && !job.sync_on_startup);
    assert_eq!(job.schedule_mode.as_deref(), Some("off"));
    assert_eq!(job.watch_changes, Some(false));
    assert!(!target.join("nested").exists());
    let initial = core.client().local_sync_status(&job.job_id).await?;
    assert_eq!(initial.state, "idle");
    assert!(initial.operation_id.is_none());
    let states = core.client().local_sync_statuses().await?;
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].job_id, job.job_id);
    let operation = core.client().start_local_sync_preview(&job.job_id).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let state = core.client().local_sync_status(&job.job_id).await?;
            assert_eq!(state.operation_id.as_ref(), Some(&operation.id));
            assert!(state.last_error.as_deref().unwrap_or_default().is_empty());
            if state.state == "idle" {
                break Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    let preview = core.client().local_sync_preview(&job.job_id).await?;
    assert_eq!(preview.operation_id, operation.id);
    assert_eq!(preview.scan_issue_count, 0);
    let actions = core
        .client()
        .local_sync_preview_actions(&job.job_id, &preview.id, 0, 100)
        .await?;
    assert_eq!(actions.len() as u64, preview.count);
    assert!(actions.iter().any(|action| action.id == 0));
    assert!(actions
        .iter()
        .any(|action| action.kind == "copy" && action.path == "nested/file %.txt"));
    assert!(!target.join("nested").exists());
    let stale = verysync_sidecar::LocalSyncPreviewId::parse("synthetic-stale-preview")?;
    assert!(matches!(
        core.client()
            .run_local_sync_preview_all(&job.job_id, &stale)
            .await,
        Err(verysync_sidecar::Error::InvalidConfiguration { .. })
    ));
    assert!(!target.join("nested").exists());
    let run = core
        .client()
        .run_local_sync_preview_all(&job.job_id, &preview.id)
        .await?;
    let completed = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let snapshot = core.client().local_sync_run(&job.job_id).await?;
            assert_eq!(snapshot.id, run.id);
            if !snapshot.finished.starts_with("0001-") {
                break Ok::<_, Box<dyn std::error::Error + Send + Sync>>(snapshot);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    assert_eq!(completed.summary.failed, 0);
    assert_eq!(completed.summary.completed, preview.count);
    assert_eq!(
        std::fs::read(target.join("nested").join("file %.txt"))?,
        payload
    );
    assert_eq!(
        std::fs::read(source.join("nested").join("file %.txt"))?,
        payload
    );
    assert_eq!(
        std::fs::read(target.join("keep.bin"))?,
        b"target-only sentinel"
    );
    assert!(target.join("nested").join("created 中文 %").is_dir());
    let results = core
        .client()
        .local_sync_run_results(&job.job_id, &run.id, 0, 100)
        .await?;
    assert_eq!(results.len() as u64, preview.count);
    assert!(results
        .iter()
        .any(|r| r.path == "nested/file %.txt" && r.bytes == Some(payload.len() as u64)));
    let history = core
        .client()
        .local_sync_history(Some(&job.job_id), 1, 100)
        .await?;
    assert_eq!(history.total, preview.count);
    assert!(history.records.iter().all(|r| r.job_id == job.job_id));
    let original = serde_json::to_value(&job)?;
    let patch = LocalSyncJobPatch::default().label("renamed explicit job")?;
    let updated = core
        .client()
        .update_local_sync_job(&job.job_id, &patch)
        .await?;
    assert!(updated.requested_fields_match);
    let mut expected = original;
    expected["label"] = serde_json::json!("renamed explicit job");
    assert_eq!(serde_json::to_value(&updated.configuration)?, expected);
    let grouped = core
        .client()
        .update_local_sync_job(
            &job.job_id,
            &LocalSyncJobPatch::default().group("explicit group")?,
        )
        .await?;
    assert!(grouped.requested_fields_match);
    expected["group"] = serde_json::json!("explicit group");
    assert_eq!(serde_json::to_value(&grouped.configuration)?, expected);
    let ungrouped = core
        .client()
        .update_local_sync_job(&job.job_id, &LocalSyncJobPatch::default().group("")?)
        .await?;
    assert!(ungrouped.requested_fields_match && ungrouped.configuration.group.is_none());
    expected
        .as_object_mut()
        .ok_or("job serialization is not an object")?
        .remove("group");
    assert_eq!(serde_json::to_value(&ungrouped.configuration)?, expected);
    assert!(!format!("{job:?} {preview:?} {run:?} {a:?} {history:?}")
        .contains(source.to_str().ok_or("private source UTF8")?));
    core.client().delete_local_sync_job(&job.job_id).await?;
    assert!(core.client().local_sync_jobs().await?.is_empty());
    assert_eq!(
        std::fs::read(target.join("nested").join("file %.txt"))?,
        payload
    );
    assert_eq!(
        std::fs::read(target.join("keep.bin"))?,
        b"target-only sentinel"
    );
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public Local Sync basic evidence: {}",
        serde_json::json!({
        "actual_native_health_and_empty_config":true,"actual_basic_probe":true,
        "actual_browse_and_nested_mkdir":true,"actual_create_and_native_defaults":true,
        "actual_no_startup_schedule_watch_or_deletion_enabled":true,"actual_preview_operation_identity":true,
        "actual_preview_actions_with_zero_id":true,"actual_preview_does_not_copy":true,
        "actual_separate_run_identity_and_finish":true,"actual_completed_zero_failed_actions":true,
        "actual_nested_unicode_percent_data_and_source_retained":true,"actual_target_only_data_retained":true,
        "actual_paged_result_bytes":true,"actual_history_job_and_count":true,
        "actual_scoped_label_update_preserves_all_other_settings":true,"actual_private_debug":true,
        "actual_delete_registration_preserves_data":true,"actual_same_identity":true,
        "actual_nonempty_global_and_initial_idle_status":true,
        "actual_stale_preview_refused_without_data_change":true,
        "actual_optional_and_explicit_group_roundtrip":true,
        "actual_normal_owned_tree_exit":true})
    );
    Ok(())
}
