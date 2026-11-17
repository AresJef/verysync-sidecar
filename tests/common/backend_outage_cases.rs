//! Independent backend request failures and data preservation, outside an active run.
use super::{finished_run, options, ready_preview, snapshot, storage_service, TestResult};
use std::time::{Duration, Instant};
use verysync_sidecar::{
    CreateLocalSyncJob, Error, LocalSyncJobPatch, LocalSyncMode, ManagedInstance, StorageEndpoint,
    StorageProtocol, TargetPath,
};

fn native_failure<T>(result: verysync_sidecar::Result<T>) -> TestResult<u16> {
    let Err(mut error) = result else {
        return Err("stopped owned backend unexpectedly accepted a request".into());
    };
    while let Error::MutationOutcomeUnknown { source, .. } = error {
        error = *source;
    }
    let response = match error {
        Error::Api { response, .. } | Error::Http { response } => response,
        other => {
            return Err(
                format!("backend outage lacks a completed native response: {other:?}").into(),
            )
        }
    };
    let body: serde_json::Value = serde_json::from_slice(response.body_bytes())?;
    assert_eq!(response.status(), 500);
    assert!(body["error"].as_str().is_some_and(|text| !text.is_empty()));
    Ok(response.status())
}

async fn effects(protocol: StorageProtocol) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-backend-")
        .tempdir()?
        .keep();
    let source = root.join("source");
    std::fs::create_dir(&source)?;
    let initial_name = "initial 中文 %.bin";
    let recovered_name = "recovered 中文 %.bin";
    let initial = vec![0x31; 128 * 1024 + 43];
    let later = vec![0x72; 64 * 1024 + 29];
    std::fs::write(source.join(initial_name), &initial)?;
    let mut peer = storage_service::Service::start(protocol, &root, Duration::ZERO)?;
    std::fs::write(
        peer.share.join("sentinel.bin"),
        b"retained backend sentinel",
    )?;
    // Observe the native backend's completed refusal. The SDK's default timeout
    // remains unchanged, as do the independent in-flight/Stop tests.
    let mut core = ManagedInstance::start(
        options(&root.join("core"))?.management_request_timeout(Duration::from_secs(30))?,
    )
    .await?;
    let result = async {
        let identity = core.client().instance().device_id.clone();
        let job = core.client().create_local_sync_job(
            &CreateLocalSyncJob::new("backend request boundary",
                StorageEndpoint::local(TargetPath::local(&source))?,
                peer.endpoint.clone(), LocalSyncMode::MirrorAToB)?.ignore_permissions(true),
        ).await?;
        let preview = ready_preview(&core, &job.job_id).await?;
        let run = core.client().run_local_sync_preview_all(&job.job_id, &preview.id).await?;
        let completed = finished_run(&core, &job.job_id, &run.id).await?;
        assert_eq!(completed.summary.failed, 0);
        assert_eq!(std::fs::read(peer.share.join(initial_name))?, initial);
        assert_eq!(core.client().local_sync_status(&job.job_id).await?.state, "idle");
        let before = snapshot(&peer.share)?;
        peer.stop()?;
        let started = Instant::now();
        let probe_status = native_failure(core.client().probe_storage_endpoint(&peer.endpoint).await)?;
        let probe_elapsed_ms = started.elapsed().as_millis();
        let started = Instant::now();
        let browse_status = native_failure(core.client().browse_storage_endpoint(&peer.endpoint, "").await)?;
        let browse_elapsed_ms = started.elapsed().as_millis();
        assert_eq!(snapshot(&peer.share)?, before);
        assert_eq!(std::fs::read(source.join(initial_name))?, initial);
        assert_eq!(core.client().local_sync_run(&job.job_id).await?.id, run.id);
        assert!(!source.join(recovered_name).exists());
        let mut recovered = storage_service::Service::start(protocol, &root, Duration::ZERO)?;
        let recovery = async {
            assert_ne!(serde_json::to_value(&recovered.endpoint)?["uri"],
                       serde_json::to_value(&peer.endpoint)?["uri"]);
            let updated = core.client().update_local_sync_job(&job.job_id,
                &LocalSyncJobPatch::default().side_b(recovered.endpoint.clone())).await?;
            assert!(updated.requested_fields_match);
            assert_eq!(snapshot(&recovered.share)?, before);
            std::fs::write(source.join(recovered_name), &later)?;
            let preview = ready_preview(&core, &job.job_id).await?;
            assert!(preview.count > 0);
            assert_eq!(snapshot(&recovered.share)?, before);
            let next = core.client().run_local_sync_preview_all(&job.job_id, &preview.id).await?;
            assert_ne!(next.id, run.id);
            assert_eq!(finished_run(&core, &job.job_id, &next.id).await?.summary.failed, 0);
            assert_eq!(std::fs::read(recovered.share.join(initial_name))?, initial);
            assert_eq!(std::fs::read(recovered.share.join(recovered_name))?, later);
            assert_eq!(std::fs::read(source.join(initial_name))?, initial);
            assert_eq!(std::fs::read(source.join(recovered_name))?, later);
            assert_eq!(std::fs::read(recovered.share.join("sentinel.bin"))?, b"retained backend sentinel");
            core.client().delete_local_sync_job(&job.job_id).await?;
            assert_eq!(std::fs::read(recovered.share.join(initial_name))?, initial);
            assert_eq!(std::fs::read(recovered.share.join(recovered_name))?, later);
            assert_eq!(core.client().system_status().await?.device_id, identity);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }.await;
        recovered.stop()?;
        recovery?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(serde_json::json!({
            "protocol":format!("{protocol:?}"),"probe_status":probe_status,"browse_status":browse_status,
            "probe_elapsed_ms":probe_elapsed_ms,"browse_elapsed_ms":browse_elapsed_ms,
            "actual_completed_backend_refusals":true,"no_active_run_or_stop_at_outage":true,
            "prior_run_receipt_retained":true,"destination_snapshot_stable_during_outage":true,
            "explicit_endpoint_update_before_recovery":true,"preview_does_not_copy":true,
            "new_owned_endpoint_address":true,
            "separate_explicit_recovery_run":true,"all_source_and_destination_bytes":true,
            "destination_only_sentinel_retained":true,"unregister_preserves_files":true,
            "identity_retained":true,"both_owned_peers_stopped":true
        }))
    }.await;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    peer.stop()?;
    assert_eq!(exit.code, Some(0));
    assert!(!exit.forced && exit.tree_stopped && exit.state_released);
    let mut receipt = result?;
    receipt["normal_tree_and_state_exit"] = true.into();
    println!("public backend request outage evidence: {receipt}");
    std::fs::remove_dir_all(root)?;
    Ok(())
}

pub async fn run() -> TestResult {
    for protocol in [
        StorageProtocol::Ftp,
        StorageProtocol::Sftp,
        StorageProtocol::Smb,
        StorageProtocol::WebDav,
    ] {
        effects(protocol).await?;
    }
    Ok(())
}
