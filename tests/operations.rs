//! Real next-scan observations, separate from command acknowledgement.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Duration;
use verysync_sidecar::{
    CreateFolderOptions, Error, FolderId, FolderState, ManagedInstance, RawMethod, RawRequest,
    RequestEffect, ScanPhase, TargetPath,
};

async fn prepare(
    client: &verysync_sidecar::Client,
    state: &std::path::Path,
    id: &FolderId,
) -> TestResult<std::path::PathBuf> {
    let path = state.join("scan sample");
    std::fs::create_dir(&path)?;
    std::fs::write(path.join("original.bin"), b"synthetic original scan sample")?;
    client
        .create_folder(
            &CreateFolderOptions::new(id.clone(), TargetPath::local(path.clone())).paused(true),
        )
        .await?;
    // Fixture-only watcher setup; typed advanced settings have a separate gate.
    let setup = RawRequest::new(
        RawMethod::Patch,
        ["rest", "config", "folders", id.as_str()],
        RequestEffect::MayModify,
    )?
    .json_body(&json!({"fsWatcherEnabled":false}))?;
    assert_eq!(client.raw_request(&setup).await?.status(), 200);
    assert_eq!(client.folder(id).await?.extra["fsWatcherEnabled"], false);
    client.resume_folder(id).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let s = client.folder_status(id).await?;
            if s.state == Some(FolderState::Idle) && s.local_files == Some(1) {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await??;
    Ok(path)
}

#[tokio::test]
async fn real_scan_observation_requires_actual_entry_exit_and_index_effect() -> TestResult {
    let root = tempfile::Builder::new().prefix("vso-").tempdir()?.keep();
    let state = root.join("state");
    let mut instance = ManagedInstance::start(options(&state)?).await?;
    let client = instance.client().clone();
    let identity = client.instance().device_id.clone();
    let id = FolderId::parse("sidecar-task-scan")?;
    let path = prepare(&client, &state, &id).await?;
    let sample = Sha256::digest(std::fs::read(path.join("original.bin"))?);
    let mut observation = client.observe_next_scan(&id).await?;
    assert_eq!(observation.phase(), ScanPhase::AwaitingStart);
    for n in 0..1280 {
        std::fs::write(
            path.join(format!("new-{n:04}.bin")),
            [(n % 256) as u8; 2048],
        )?;
    }
    let (ack, completed) = tokio::join!(
        client.request_scan(&id),
        observation.wait(Duration::from_secs(20))
    );
    ack?;
    let completed = completed?;
    assert_eq!(completed.folder_id, id);
    assert_eq!(completed.exited_to, FolderState::Idle);
    assert!(completed.ended.last_id > completed.started.last_id);
    assert_eq!(completed.snapshot.local_files, Some(1281));
    assert_eq!(observation.phase(), ScanPhase::Ended);
    let progress_reported = completed.progress.is_some();
    observation.close().await?;
    assert_eq!(
        Sha256::digest(std::fs::read(path.join("original.bin"))?),
        sample
    );
    assert_eq!(client.system_status().await?.device_id, identity);
    let exit = instance.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced);
    std::fs::remove_dir_all(root)?;
    println!(
        "public scan observation evidence: {}",
        json!({"typed_scan_request_executed":true,"actual_scan_entry_observed":true,
        "actual_scan_exit_observed":true,"actual_1280_new_files_indexed":true,"original_sample_sha_retained":true,
        "snapshot_separate_from_acknowledgement":true,"observation_close_leaves_engine_running":true,"actual_normal_tree_exit":true,
        "progress_availability":if progress_reported {"upstream_event_observed"} else {"unknown_no_progress_event"}})
    );
    Ok(())
}

#[tokio::test]
async fn cancelling_observation_never_stops_an_independently_submitted_scan() -> TestResult {
    let root = tempfile::Builder::new().prefix("vsc-").tempdir()?.keep();
    let state = root.join("state");
    let mut instance = ManagedInstance::start(options(&state)?).await?;
    let client = instance.client().clone();
    let identity = client.instance().device_id.clone();
    let id = FolderId::parse("sidecar-cancel-observation")?;
    let path = prepare(&client, &state, &id).await?;
    let mut observation = client.observe_next_scan(&id).await?;
    for n in 0..1280 {
        std::fs::write(
            path.join(format!("queued-{n:04}.bin")),
            [(n % 256) as u8; 2048],
        )?;
    }
    let requester = client.clone();
    let target = id.clone();
    // The test caller owns this independent modifying request, not the observer.
    let request = tokio::spawn(async move { requester.request_scan(&target).await });
    assert!(matches!(
        observation.wait(Duration::from_millis(1)).await,
        Err(Error::Timeout { .. })
    ));
    observation.close().await?;
    request.await??;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let s = client.folder_status(&id).await?;
            if s.state == Some(FolderState::Idle) && s.local_files == Some(1281) {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await??;
    assert_eq!(client.system_status().await?.device_id, identity);
    client.pause_folder(&id).await?;
    assert!(matches!(
        client.observe_next_scan(&id).await,
        Err(Error::ScanNotIdle)
    ));
    assert!(matches!(
        client.request_scan(&id).await,
        Err(Error::ScanNotIdle)
    ));
    let exit = instance.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced);
    std::fs::remove_dir_all(root)?;
    println!(
        "public scan cancellation evidence: {}",
        json!({"wait_timeout_does_not_send_stop":true,
        "observation_closed_while_independent_request_owned_by_caller":true,"actual_request_completed_after_observation_close":true,
        "actual_files_indexed":true,"engine_remained_authenticated":true,"paused_observation_rejected":true,
        "paused_request_rejected":true,"actual_normal_tree_exit":true})
    );
    Ok(())
}
