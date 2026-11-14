//! Actual native protocol traffic and data effects, with synthetic owned peers.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
#[path = "common/storage_service.rs"]
mod storage_service;
use managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::{
    CreateLocalSyncJob, LocalSyncJobId, LocalSyncMode, LocalSyncRun, ManagedInstance,
    StorageEndpoint, StorageProtocol, TargetPath,
};

async fn execute(core: &ManagedInstance, id: &LocalSyncJobId) -> TestResult<LocalSyncRun> {
    let operation = core.client().start_local_sync_preview(id).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status = core.client().local_sync_status(id).await?;
            assert_eq!(status.operation_id.as_ref(), Some(&operation.id));
            assert!(status.last_error.as_deref().unwrap_or_default().is_empty());
            if status.state == "idle" {
                break Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    let preview = core.client().local_sync_preview(id).await?;
    assert_eq!(preview.operation_id, operation.id);
    assert!(preview.count > 0);
    let receipt = core
        .client()
        .run_local_sync_preview_all(id, &preview.id)
        .await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let run = core.client().local_sync_run(id).await?;
            assert_eq!(run.id, receipt.id);
            if !run.finished.starts_with("0001-") {
                assert_eq!(run.summary.failed, 0);
                return Ok(run);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?
}
async fn protocol_effects(protocol: StorageProtocol) -> TestResult {
    let root = tempfile::Builder::new().prefix("vsp-").tempdir()?.keep();
    let source = root.join("source");
    std::fs::create_dir_all(source.join("nested"))?;
    let payload = b"actual VerySync native protocol payload";
    std::fs::write(source.join("nested").join("payload 中文 %.txt"), payload)?;
    let mut server = storage_service::Service::start(protocol, &root)?;
    std::fs::write(
        server.share.join("sentinel.bin"),
        b"protocol destination-only sentinel",
    )?;
    // rclone v1.69.3 SFTP getSftpConnection retries authentication failures
    // through its native pacer. Explicitly budget this observed native work;
    // the library's ten-second default remains unchanged. A deadline error
    // must never be reported as a completed authentication refusal.
    let request_seconds = if protocol == StorageProtocol::Sftp {
        30
    } else {
        10
    };
    let settings = options(&root.join("core"))?
        .management_request_timeout(Duration::from_secs(request_seconds))?;
    let mut core = ManagedInstance::start(settings).await?;
    let identity = core.client().instance().device_id.clone();
    let authentication_started = std::time::Instant::now();
    let bad = core
        .client()
        .probe_storage_endpoint(&server.bad_endpoint)
        .await;
    let error = bad.expect_err("native core accepted incorrect remote credentials");
    let cause = match &error {
        verysync_sidecar::Error::MutationOutcomeUnknown { source, .. } => source.as_ref(),
        other => other,
    };
    assert!(
        matches!(
            cause,
            verysync_sidecar::Error::Api { .. }
                | verysync_sidecar::Error::Http { .. }
                | verysync_sidecar::Error::AccessDenied { .. }
        ),
        "incorrect credentials did not produce an actual native rejection: {cause:?}"
    );
    let authentication_refusal_elapsed_ms = authentication_started.elapsed().as_millis();
    let probe = core
        .client()
        .probe_storage_endpoint(&server.endpoint)
        .await?;
    assert!(!probe.time_precision.is_empty());
    core.client()
        .create_storage_directory(&server.endpoint, "", "created 中文 %")
        .await?;
    assert!(server.share.join("created 中文 %").is_dir());
    let listed = core
        .client()
        .browse_storage_endpoint(&server.endpoint, "")
        .await?;
    assert!(listed
        .entries
        .iter()
        .any(|e| e.path == "created 中文 %" && e.directory));
    let local = StorageEndpoint::local(TargetPath::local(&source))?;
    let options = CreateLocalSyncJob::new(
        "Explicit synthetic protocol job",
        local,
        server.endpoint.clone(),
        LocalSyncMode::MirrorAToB,
    )?
    .ignore_permissions(true);
    let job = core.client().create_local_sync_job(&options).await?;
    let completed = execute(&core, &job.job_id).await?;
    assert_eq!(
        std::fs::read(server.share.join("nested").join("payload 中文 %.txt"))?,
        payload
    );
    assert_eq!(
        std::fs::read(source.join("nested").join("payload 中文 %.txt"))?,
        payload
    );
    assert_eq!(
        std::fs::read(server.share.join("sentinel.bin"))?,
        b"protocol destination-only sentinel"
    );
    let results = core
        .client()
        .local_sync_run_results(&job.job_id, &completed.id, 0, 100)
        .await?;
    assert!(results
        .iter()
        .any(|r| r.path == "nested/payload 中文 %.txt" && r.bytes == Some(payload.len() as u64)));
    core.client().delete_local_sync_job(&job.job_id).await?;
    assert_eq!(
        std::fs::read(server.share.join("nested").join("payload 中文 %.txt"))?,
        payload
    );
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let core_arch = core.client().instance().version.arch.clone();
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    server.stop()?;
    println!(
        "public storage protocol evidence: {}",
        serde_json::json!({
        "protocol":format!("{protocol:?}"),"explicit_management_request_seconds":request_seconds,"authentication_refusal_elapsed_ms":authentication_refusal_elapsed_ms,"native_rust_test_arch":std::env::consts::ARCH,
        "native_core_reported_arch":core_arch,"protocol_peer_python_platform":server.python_platform,
        "actual_incorrect_credentials_refused":true,"actual_native_probe":true,
        "actual_protocol_directory_creation_and_listing":true,"actual_exact_preview_operation":true,
        "actual_explicit_native_protocol_run":true,"actual_payload_and_source_bytes":true,
        "actual_destination_only_sentinel_preserved":true,"actual_result_payload_byte_count":true,
        "actual_registration_removal_preserves_data":true,"actual_same_identity":true,
        "actual_normal_core_tree_exit":true,"actual_exact_protocol_peer_stopped":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test]
async fn public_ftp_uses_the_native_core_for_actual_authenticated_data_effects() -> TestResult {
    protocol_effects(StorageProtocol::Ftp).await
}
#[tokio::test]
async fn public_sftp_uses_the_native_core_for_actual_authenticated_data_effects() -> TestResult {
    protocol_effects(StorageProtocol::Sftp).await
}
#[tokio::test]
async fn public_webdav_uses_the_native_core_for_actual_authenticated_data_effects() -> TestResult {
    protocol_effects(StorageProtocol::WebDav).await
}
#[tokio::test]
async fn public_smb_uses_the_native_core_for_actual_authenticated_data_effects() -> TestResult {
    protocol_effects(StorageProtocol::Smb).await
}
