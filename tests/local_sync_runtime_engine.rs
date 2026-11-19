//! Real in-flight controls, native Local Sync events, cancellation and restart.
#[path = "common/backend_outage_cases.rs"]
mod backend_outage_cases;
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
#[path = "common/storage_service.rs"]
mod storage_service;
use managed_fixture::{options, TestResult};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, time::Duration};
use verysync_sidecar::*;

#[tokio::test]
async fn public_backend_requests_preserve_actual_outage_errors_and_data() -> TestResult {
    backend_outage_cases::run().await
}
fn snapshot(root: &Path) -> TestResult<BTreeMap<String, (u64, [u8; 32])>> {
    let mut result = BTreeMap::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let bytes = std::fs::read(entry.path())?;
            result.insert(
                entry.file_name().to_string_lossy().into_owned(),
                (bytes.len() as u64, Sha256::digest(&bytes).into()),
            );
        }
    }
    Ok(result)
}
fn completed(root: &Path) -> TestResult<usize> {
    let mut count = 0;
    for n in 0..16 {
        match std::fs::read(root.join(format!("file-{n:02}.bin"))) {
            Ok(bytes) if bytes.len() == 262144 && bytes.iter().all(|b| *b == 0x5a) => count += 1,
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(count)
}

#[tokio::test]
async fn public_local_sync_controls_real_inflight_data_and_observes_native_event_continuity(
) -> TestResult {
    runtime(StorageProtocol::Sftp).await
}
#[tokio::test]
async fn public_ftp_controls_actual_inflight_data_and_native_events() -> TestResult {
    runtime(StorageProtocol::Ftp).await
}
#[tokio::test]
async fn public_smb_controls_actual_inflight_data_and_native_events() -> TestResult {
    runtime(StorageProtocol::Smb).await
}
#[tokio::test]
async fn public_webdav_controls_actual_inflight_data_and_native_events() -> TestResult {
    runtime(StorageProtocol::WebDav).await
}
async fn runtime(protocol: StorageProtocol) -> TestResult {
    let root = tempfile::Builder::new().prefix("vlsrt-").tempdir()?.keep();
    let source = root.join("source");
    std::fs::create_dir(&source)?;
    let payload = vec![0x5au8; 262144];
    for n in 0..16 {
        std::fs::write(source.join(format!("file-{n:02}.bin")), &payload)?;
    }
    let before = snapshot(&source)?;
    let mut peer = storage_service::Service::start(protocol, &root, Duration::from_millis(40))?;
    std::fs::write(peer.share.join("sentinel.bin"), b"runtime destination-only")?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let mut events = core
        .client()
        .subscribe_local_sync_events(LocalSyncEventOptions::default().wait_seconds(0)?)?;
    let job = core
        .client()
        .create_local_sync_job(
            &CreateLocalSyncJob::new(
                "explicit inflight run",
                StorageEndpoint::local(TargetPath::local(&source))?,
                peer.endpoint.clone(),
                LocalSyncMode::MirrorAToB,
            )?
            .ignore_permissions(true),
        )
        .await?;
    let analysis = core.client().start_local_sync_preview(&job.job_id).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let s = core.client().local_sync_status(&job.job_id).await?;
            assert_eq!(s.operation_id.as_ref(), Some(&analysis.id));
            if s.state == "idle" {
                return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    let preview = core.client().local_sync_preview(&job.job_id).await?;
    let run = core
        .client()
        .run_local_sync_preview_all(&job.job_id, &preview.id)
        .await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if completed(&peer.share)? > 0 {
                return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    let running = core.client().local_sync_status(&job.job_id).await?;
    assert_eq!(running.state, "running");
    let operation = running
        .operation_id
        .ok_or("native operation identity missing")?;
    let wrong = LocalSyncOperationId::parse("another-private-operation")?;
    assert!(matches!(
        core.client()
            .control_local_sync_operation(&job.job_id, &wrong, LocalSyncOperationControl::Stop)
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    let pause = core
        .client()
        .control_local_sync_operation(&job.job_id, &operation, LocalSyncOperationControl::Pause)
        .await?;
    assert_eq!(pause.observed.state, "paused");
    tokio::time::sleep(Duration::from_secs(1)).await;
    // The native paused state gates new work but is not an I/O cancellation
    // acknowledgement: an already opened temporary payload can still commit.
    // Wait for that actual per-file boundary, then retain the full, single
    // 500ms hash-stability assertion. Do not discard temporary files from it.
    let pause_drain_started = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = core.client().local_sync_status(&job.job_id).await?;
            assert_eq!(status.state, "paused");
            assert_eq!(status.operation_id.as_ref(), Some(&operation));
            let entries = std::fs::read_dir(&peer.share)?.collect::<std::io::Result<Vec<_>>>()?;
            let temporary = entries.iter().any(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(".verysync-") && n.ends_with(".tmp"))
            });
            if !temporary {
                return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    let pause_inflight_drain_millis = pause_drain_started.elapsed().as_millis();
    println!("native paused in-flight drain milliseconds: {pause_inflight_drain_millis}");
    let paused = snapshot(&peer.share)?;
    let paused_count = completed(&peer.share)?;
    assert!(paused_count > 0 && paused_count < 16);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(snapshot(&peer.share)?, paused);
    assert_eq!(
        core.client().local_sync_status(&job.job_id).await?.state,
        "paused"
    );
    let resumed = core
        .client()
        .control_local_sync_operation(&job.job_id, &operation, LocalSyncOperationControl::Resume)
        .await?;
    assert_eq!(resumed.observed.operation_id.as_ref(), Some(&operation));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if completed(&peer.share)? > paused_count {
                return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    core.client()
        .control_local_sync_operation(&job.job_id, &operation, LocalSyncOperationControl::Stop)
        .await?;
    let stopped = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let status = core.client().local_sync_status(&job.job_id).await?;
            assert_eq!(status.operation_id.as_ref(), Some(&operation));
            if status.state == "idle" {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(status);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    assert_eq!(stopped.last_run_cancelled, Some(true));
    let final_run = core.client().local_sync_run(&job.job_id).await?;
    assert_eq!(final_run.id, run.id);
    assert_eq!(final_run.cancelled, Some(true));
    assert!(!final_run.finished.starts_with("0001-"));
    let final_files = snapshot(&peer.share)?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(snapshot(&peer.share)?, final_files);
    let final_count = completed(&peer.share)?;
    assert!(final_count >= paused_count && final_count < 16);
    assert_eq!(snapshot(&source)?, before);
    assert_eq!(
        std::fs::read(peer.share.join("sentinel.bin"))?,
        b"runtime destination-only"
    );
    let mut seen = Vec::new();
    let mut prior = 0;
    let mut buffered_cursor_checked = false;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match events.next().await.ok_or("event stream ended")?? {
                LocalSyncEventStreamItem::Event { event, cursor } => {
                    assert!(event.sequence > prior);
                    assert_eq!(cursor.last_sequence, event.sequence);
                    prior = event.sequence;
                    if !buffered_cursor_checked {
                        assert!(events.buffered_items() > 0);
                        assert_eq!(events.cursor().last_sequence, event.sequence);
                        buffered_cursor_checked = true;
                    }
                    if event.job_id.as_ref() == Some(&job.job_id) {
                        seen.push(event.kind.clone());
                        if event.kind == "run_finished" {
                            assert_eq!(event.cancelled, Some(true));
                            return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
                        }
                    }
                }
                LocalSyncEventStreamItem::Gap(gap) => {
                    return Err(format!("unexpected native event gap {:?}", gap.reason).into())
                }
            }
        }
    })
    .await??;
    for kind in [
        "preview_ready",
        "run_started",
        "paused",
        "resumed",
        "run_finished",
    ] {
        assert!(
            seen.iter().any(|x| x == kind),
            "missing native event {kind}"
        );
    }
    let cursor = events.cursor().clone();
    let future = core
        .client()
        .local_sync_events(cursor.last_sequence + 100, 0)
        .await?;
    assert!(future.reset);
    let mut pending = core.client().subscribe_local_sync_events(
        LocalSyncEventOptions::default()
            .resume(cursor.clone())
            .wait_seconds(55)?,
    )?;
    assert!(
        matches!(pending.next().await,Some(Ok(LocalSyncEventStreamItem::Gap(g)))if g.reason==EventGapReason::ResumedContinuityUnverified)
    );
    let cancellation = pending.cancellation_handle();
    let task = tokio::spawn(async move { pending.next().await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!task.is_finished());
    cancellation.cancel();
    assert!(tokio::time::timeout(Duration::from_secs(1), task)
        .await??
        .is_none());
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let mut resumed_stream = core.client().subscribe_local_sync_events(
        LocalSyncEventOptions::default()
            .resume(cursor.clone())
            .wait_seconds(0)?,
    )?;
    assert!(
        matches!(resumed_stream.next().await,Some(Ok(LocalSyncEventStreamItem::Gap(g))) if g.reason==EventGapReason::ResumedContinuityUnverified)
    );
    assert!(cursor.engine_started_at.is_some());
    core.restart(Duration::from_secs(30)).await?;
    let gap = tokio::time::timeout(Duration::from_secs(3), resumed_stream.next())
        .await?
        .ok_or("resumed stream ended")??;
    assert!(
        matches!(gap,LocalSyncEventStreamItem::Gap(g) if g.reason==EventGapReason::EngineStartTimeChanged && g.resume_from.last_sequence==0 && g.resume_from.engine_started_at!=cursor.engine_started_at)
    );
    assert_eq!(core.client().system_status().await?.device_id, identity);
    assert_eq!(snapshot(&source)?, before);
    assert_eq!(snapshot(&peer.share)?, final_files);
    println!(
        "public native Local Sync runtime evidence: {}",
        serde_json::json!({"protocol":format!("{protocol:?}"),"actual_inflight_payload_before_pause":true,"actual_paused_state_and_file_hash_stability":true,"actual_resume_advances_files":true,"actual_stop_cancelled_exact_run":true,"actual_stopped_file_hash_stability":true,"actual_source_and_destination_only_retained":true,"wrong_operation_refused_before_control":true,"actual_native_pause_resume_finish_events":true,"actual_consumed_cursor_not_buffered_tail":true,"actual_native_future_cursor_reset":true,"actual_native_restart_continuity_gap":true,"actual_pending_read_cancelled_without_core_stop":true,"paused_complete_files":paused_count,"stopped_complete_files":final_count,"peer_platform":peer.python_platform})
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    peer.stop()?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn public_ftp_disconnect_has_explicit_owned_recovery_and_exact_data() -> TestResult {
    disconnected(StorageProtocol::Ftp, false).await
}
#[tokio::test]
async fn public_ftp_disconnect_finished_operation_refuses_stop_and_recovers_exact_data(
) -> TestResult {
    disconnected(StorageProtocol::Ftp, true).await
}
#[tokio::test]
async fn public_sftp_disconnect_has_explicit_owned_recovery_and_exact_data() -> TestResult {
    disconnected(StorageProtocol::Sftp, false).await
}
#[tokio::test]
async fn public_smb_disconnect_has_explicit_owned_recovery_and_exact_data() -> TestResult {
    disconnected(StorageProtocol::Smb, false).await
}
#[tokio::test]
async fn public_webdav_disconnect_has_explicit_owned_recovery_and_exact_data() -> TestResult {
    disconnected(StorageProtocol::WebDav, false).await
}
async fn ready_preview(
    core: &ManagedInstance,
    job: &LocalSyncJobId,
) -> TestResult<LocalSyncPreview> {
    let op = core.client().start_local_sync_preview(job).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status = core.client().local_sync_status(job).await?;
            assert_eq!(status.operation_id.as_ref(), Some(&op.id));
            if status.state == "idle" {
                assert!(status.last_error.as_deref().unwrap_or_default().is_empty());
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    let preview = core.client().local_sync_preview(job).await?;
    assert_eq!(preview.operation_id, op.id);
    assert_eq!(preview.scan_issue_count, 0);
    Ok(preview)
}
async fn finished_run(
    core: &ManagedInstance,
    job: &LocalSyncJobId,
    id: &LocalSyncRunId,
) -> TestResult<LocalSyncRun> {
    let mut last = None;
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let run = core.client().local_sync_run(job).await?;
            assert_eq!(&run.id, id);
            last = Some(serde_json::json!({"finished":run.finished,"completed":run.summary.completed,"failed":run.summary.failed,"skipped":run.summary.skipped,"extra_fields":run.extra.keys().collect::<Vec<_>>() }));
            if !run.finished.starts_with("0001-") {
                return Ok(run);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if result.is_err() {
        let status = core.client().local_sync_status(job).await?;
        eprintln!("disconnect run did not finish within original bound: last={last:?} state={} error_present={} progress={:?}",status.state,status.last_error.as_deref().is_some_and(|e|!e.is_empty()),status.progress.as_ref().map(|p|(p.finished_files,p.finished_actions,p.bytes_transferred)));
    }
    result?
}
fn completed_stop_reply(status: u16, body: &[u8]) -> bool {
    status == 404
        && serde_json::from_slice::<serde_json::Value>(body)
            .is_ok_and(|value| value == serde_json::json!({"error":"job not found","result":{}}))
}
fn completed_stop_error(error: &Error) -> bool {
    matches!(error, Error::MutationOutcomeUnknown { source, .. }
        if matches!(source.as_ref(), Error::Http { response }
            if completed_stop_reply(response.status(), response.body_bytes())))
}
#[test]
fn completed_stop_refusal_does_not_accept_unrelated_errors_or_acknowledgements() {
    let actual = br#"{"error":"job not found","result":{}}"#;
    assert!(completed_stop_reply(404, actual));
    for status in [200, 400, 401, 409, 500] {
        assert!(!completed_stop_reply(status, actual));
    }
    for body in [
        br#"{}"#.as_slice(),
        br#"{"error":"different","result":null}"#,
        br#"{"error":"job not found"}"#,
        br#"{"error":"job not found","result":null}"#,
        br#"{"error":"job not found","result":null,"unknown":true}"#,
        b"invalid",
    ] {
        assert!(!completed_stop_reply(404, body));
    }
}

async fn disconnected(protocol: StorageProtocol, terminal_before_stop: bool) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vls-disconnect-")
        .tempdir()?
        .keep();
    let source = root.join("source");
    std::fs::create_dir(&source)?;
    for n in 0..16 {
        std::fs::write(source.join(format!("file-{n:02}.bin")), vec![0x5a; 262144])?;
    }
    let original = snapshot(&source)?;
    let mut peer = storage_service::Service::start(protocol, &root, Duration::from_millis(40))?;
    std::fs::write(
        peer.share.join("sentinel.bin"),
        b"disconnect destination-only",
    )?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let job = core
        .client()
        .create_local_sync_job(
            &CreateLocalSyncJob::new(
                "explicit disconnect",
                StorageEndpoint::local(TargetPath::local(&source))?,
                peer.endpoint.clone(),
                LocalSyncMode::MirrorAToB,
            )?
            .ignore_permissions(true),
        )
        .await?;
    // Establish actual persisted registration before intentionally interrupting
    // a later run. An in-memory create/readback is not an fsync receipt.
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(
        core.client().local_sync_job(&job.job_id).await?.job_id,
        job.job_id
    );
    let preview = ready_preview(&core, &job.job_id).await?;
    let receipt = core
        .client()
        .run_local_sync_preview_all(&job.job_id, &preview.id)
        .await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let count = completed(&peer.share)?;
            if count > 0 {
                assert!(count < 16);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    assert_eq!(
        core.client().local_sync_status(&job.job_id).await?.state,
        "running"
    );
    peer.stop()?;
    if terminal_before_stop {
        // Explicitly finish this owned interrupted run before probing its
        // terminal control boundary; this is not a retry after uncertainty.
        let current = core.client().local_sync_status(&job.job_id).await?;
        let operation = current
            .operation_id
            .ok_or("owned interrupted operation absent")?;
        if current.state != "error" {
            if let Err(error) = core
                .client()
                .control_local_sync_operation(
                    &job.job_id,
                    &operation,
                    LocalSyncOperationControl::Stop,
                )
                .await
            {
                if !completed_stop_error(&error) {
                    return Err(error.into());
                }
            }
        }
        let failed = finished_run(&core, &job.job_id, &receipt.id).await?;
        assert!(failed.summary.completed > 0 && failed.summary.failed > 0);
        assert!(failed
            .error
            .as_deref()
            .is_some_and(|error| !error.is_empty()));
    }
    let interrupted = core.client().local_sync_status(&job.job_id).await?;
    let operation = interrupted
        .operation_id
        .ok_or("interrupted operation absent")?;
    let saved_results;
    let observed_old_cancellation;
    let mut terminal_stop_refused = false;
    let recovered_by_force = if protocol == StorageProtocol::Ftp {
        let stop_started = std::time::Instant::now();
        eprintln!(
            "ftp-disconnect-stop-begin management_retry_count=0 pre_state_running={} pre_state_idle={} pre_state_canceling={}",
            interrupted.state == "running", interrupted.state == "idle", interrupted.state == "canceling"
        );
        let stopped = core
            .client()
            .control_local_sync_operation(&job.job_id, &operation, LocalSyncOperationControl::Stop)
            .await;
        match stopped {
            Ok(observed) => {
                assert!(
                    !terminal_before_stop,
                    "completed run must retain its actual native Stop refusal"
                );
                eprintln!(
                    "ftp-disconnect-stop-end elapsed_ms={} outcome=receipt operation_matches={} post_state_running={} post_state_idle={} post_state_canceling={}",
                    stop_started.elapsed().as_millis(),
                    observed.observed.operation_id.as_ref() == Some(&operation),
                    observed.observed.state == "running",
                    observed.observed.state == "idle",
                    observed.observed.state == "canceling",
                );
            }
            Err(error) => {
                if !completed_stop_error(&error) {
                    return Err(error.into());
                }
                // A 404 alone could also mean a missing job. Independently
                // reconcile the exact existing job, operation and finished run;
                // this is caller-side recovery, never a successful Stop receipt.
                let status = core.client().local_sync_status(&job.job_id).await?;
                let failed = core.client().local_sync_run(&job.job_id).await?;
                assert_eq!(
                    core.client().local_sync_job(&job.job_id).await?.job_id,
                    job.job_id
                );
                assert_eq!(status.operation_id.as_ref(), Some(&operation));
                assert_eq!(status.state, "error");
                assert!(status
                    .last_error
                    .as_deref()
                    .is_some_and(|text| !text.is_empty()));
                assert_eq!(failed.id, receipt.id);
                assert_eq!(failed.job_id, job.job_id);
                assert!(!failed.finished.starts_with("0001-"));
                assert!(failed.summary.completed > 0 && failed.summary.failed > 0);
                assert!(failed.error.as_deref().is_some_and(|text| !text.is_empty()));
                terminal_stop_refused = true;
                eprintln!("ftp-disconnect-stop-end elapsed_ms={} outcome=native404_refusal existing_job_exact_finished_failed_run=true sdk_error_preserved=true automatic_retry=false", stop_started.elapsed().as_millis());
            }
        }
        let failed = finished_run(&core, &job.job_id, &receipt.id).await?;
        assert!(failed.summary.completed > 0 && failed.summary.failed > 0);
        // A disconnect can finish with native errors before the separate stop
        // request arrives. Preserve optional cancellation instead of inventing it.
        observed_old_cancellation = failed.cancelled;
        assert!(failed
            .error
            .as_deref()
            .is_some_and(|error| !error.is_empty()));
        saved_results = core
            .client()
            .local_sync_run_results(&job.job_id, &failed.id, 0, 100)
            .await?;
        assert!(saved_results.iter().any(|result| result
            .extra
            .get("error")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|e| !e.is_empty())));
        false
    } else {
        observed_old_cancellation = None;
        // Deliberately selected by this test caller. A protocol I/O wait may
        // outlive a native stop request; the SDK never escalates automatically.
        let unfinished = core.client().local_sync_run(&job.job_id).await?;
        assert_eq!(unfinished.id, receipt.id);
        assert!(unfinished.finished.starts_with("0001-"));
        // Capture a real run receipt. Action pages can still be unavailable
        // while their results have not been published; no empty page is invented.
        saved_results = Vec::new();
        let terminated = core.force_stop(Duration::from_secs(10)).await?;
        assert!(terminated.tree_stopped && terminated.state_released && terminated.forced);
        if let Err(error) = core.restart(Duration::from_secs(30)).await {
            for name in [".verysync-sidecar-lease", "verysync.lock"] {
                use fs2::FileExt;
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(root.join("core").join(name))?;
                eprintln!(
                    "private restart lock {name}: {:?}",
                    file.try_lock_exclusive().map_err(|e| e.kind())
                );
            }
            return Err(error.into());
        }
        assert_eq!(core.client().system_status().await?.device_id, identity);
        true
    };
    let partial = snapshot(&peer.share)?;
    let partial_count = completed(&peer.share)?;
    assert!(partial_count > 0 && partial_count < 16);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(snapshot(&peer.share)?, partial);
    assert_eq!(snapshot(&source)?, original);
    assert_eq!(
        std::fs::read(peer.share.join("sentinel.bin"))?,
        b"disconnect destination-only"
    );
    // A new private peer has a new address and credentials. Recovery is an
    // explicit caller action, not an SDK retry or an implicit file rollback.
    let mut recovered_peer = storage_service::Service::start(protocol, &root, Duration::ZERO)?;
    let updated = core
        .client()
        .update_local_sync_job(
            &job.job_id,
            &LocalSyncJobPatch::default().side_b(recovered_peer.endpoint.clone()),
        )
        .await?;
    assert!(updated.requested_fields_match);
    assert_eq!(snapshot(&recovered_peer.share)?, partial);
    let repaired = ready_preview(&core, &job.job_id).await?;
    assert_ne!(repaired.id, preview.id);
    assert!(repaired.count > 0);
    assert_eq!(snapshot(&recovered_peer.share)?, partial);
    let next = core
        .client()
        .run_local_sync_preview_all(&job.job_id, &repaired.id)
        .await?;
    assert_ne!(next.id, receipt.id);
    let complete = finished_run(&core, &job.job_id, &next.id).await?;
    if complete.summary.failed != 0 {
        let results = core
            .client()
            .local_sync_run_results(&job.job_id, &next.id, 0, 100)
            .await?;
        let mut private = vec![root.to_string_lossy().into_owned()];
        fn collect(value: &serde_json::Value, out: &mut Vec<String>) {
            match value {
                serde_json::Value::String(text) if text.len() >= 8 => out.push(text.clone()),
                serde_json::Value::Array(values) => {
                    for value in values {
                        collect(value, out);
                    }
                }
                serde_json::Value::Object(values) => {
                    for value in values.values() {
                        collect(value, out);
                    }
                }
                _ => (),
            }
        }
        for endpoint in [&peer.endpoint, &recovered_peer.endpoint] {
            collect(&serde_json::to_value(endpoint)?, &mut private);
        }
        private.sort_by_key(|s| std::cmp::Reverse(s.len()));
        let redact = |text: &str| {
            let mut text = text.to_owned();
            for value in &private {
                text = text.replace(value, "[PRIVATE_TEST_VALUE]");
            }
            text.chars()
                .filter(|c| !c.is_control())
                .take(512)
                .collect::<String>()
        };
        let errors = results
            .iter()
            .filter_map(|r| {
                r.extra
                    .get("error")
                    .filter(|v| v.as_str().is_none_or(|s| !s.is_empty()))
            })
            .take(32)
            .map(|v| redact(&v.to_string()))
            .collect::<Vec<_>>();
        eprintln!(
            "native disconnect recovery diagnostics: {}",
            serde_json::json!({"failed_actions":complete.summary.failed,"completed_actions":complete.summary.completed,"results":results.len(),"run_error":complete.error.as_deref().map(redact),"action_errors":errors,"complete_payload_files":completed(&recovered_peer.share)?,"destination_files":snapshot(&recovered_peer.share)?.len()})
        );
    }
    assert_eq!(complete.summary.failed, 0);
    assert_eq!(completed(&recovered_peer.share)?, 16);
    assert_eq!(snapshot(&source)?, original);
    assert_eq!(
        std::fs::read(recovered_peer.share.join("sentinel.bin"))?,
        b"disconnect destination-only"
    );
    // Native results belong to the current run, not durable run history.
    // Previously read records stay caller-owned; a stale run must not silently
    // return the current run's results or be retried under another identity.
    assert!(recovered_by_force || !saved_results.is_empty());
    assert!(
        matches!(core.client().local_sync_run_results(&job.job_id, &receipt.id, 0, 100).await, Err(Error::Http{response}) if response.status()==409)
    );
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    recovered_peer.stop()?;
    println!(
        "public protocol disconnect recovery evidence: {}",
        serde_json::json!({"protocol":format!("{protocol:?}"),"actual_inflight_copy_before_owned_peer_stop":true,"actual_explicit_owned_recovery":true,"actual_prior_run_receipt_retained":true,"actual_completed_partial_files_retained":true,"actual_full_partial_snapshot_stable_without_retry":true,"actual_source_and_sentinel_preserved":true,"actual_explicit_new_endpoint_readback":true,"actual_new_preview_has_remaining_actions_without_copy":true,"actual_separate_explicit_new_run":true,"actual_all_sixteen_exact_destination_payloads":true,"actual_stale_result_identity_refused":true,"actual_same_identity_and_final_normal_owned_exit":true,"partial_complete_files":partial_count,"explicit_force_before_restart":recovered_by_force,"observed_old_run_cancelled":observed_old_cancellation,"old_native_completion_claimed":false,"actual_native_terminal_stop_refusal":terminal_stop_refused,"terminal_boundary_explicitly_prepared":terminal_before_stop})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
