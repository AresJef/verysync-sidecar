//! Read-only continued observation of an isolated, fixed native program.
#![cfg(feature = "engine-tests")]

#[path = "common/managed_fixture.rs"]
mod managed_fixture;

use managed_fixture::TestResult;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;
use verysync_sidecar::{
    Client, CreateFolderOptions, DeviceId, EventGapReason, EventOptions, EventStreamItem, FolderId,
    FolderObservationPosition, FolderObservationRefresh, ManagedExitObservationOutcome,
    ManagedInstance, TargetPath,
};

const SHORT: Duration = Duration::from_millis(80);
const WAIT: Duration = Duration::from_secs(20);
const SAMPLE: &[u8] = b"observation retained this synthetic data\n";

fn private_root() -> TestResult<tempfile::TempDir> {
    let mut root = tempfile::Builder::new();
    root.prefix("vss-obsv-");
    #[cfg(unix)]
    return Ok(root.tempdir_in("/tmp")?);
    #[cfg(windows)]
    Ok(root.tempdir()?)
}

async fn open(folder_root: &Path) -> TestResult<ManagedInstance> {
    Ok(ManagedInstance::start(managed_fixture::options(&folder_root.join("state"))?).await?)
}

fn events() -> verysync_sidecar::Result<EventOptions> {
    EventOptions::default()
        .poll_interval(SHORT)?
        .queue_capacity(2)
}

async fn collected_files(client: &Client, folder: &FolderId) -> TestResult {
    tokio::time::timeout(WAIT, async {
        loop {
            if client.folder_status(folder).await?.local_files == Some(1) {
                return Ok::<_, verysync_sidecar::Error>(());
            }
            tokio::time::sleep(SHORT).await;
        }
    })
    .await??;
    Ok(())
}

async fn same_identity(client: &Client, device: &DeviceId) -> TestResult {
    let identity = client.observe_control_identity().await?;
    assert_eq!(identity.device_id(), device);
    assert!(identity.process_generation().is_none());
    Ok(())
}

#[tokio::test]
async fn native_observation_resumes_a_folder_and_confirms_the_exact_later_exit() -> TestResult {
    let root = private_root()?;
    let instance = open(root.path()).await?;
    let client = instance.client().clone();
    let generation = instance.control_generation();
    let pid = instance.process_id();
    let identity = client.instance().device_id.clone();
    let watched = FolderId::parse("native-control-observation")?;
    let folder = root.path().join("fixture-files");
    std::fs::create_dir(&folder)?;
    let sample = folder.join("preserve.bin");
    std::fs::write(&sample, SAMPLE)?;
    let digest = Sha256::digest(SAMPLE);

    client
        .create_folder(&CreateFolderOptions::new(
            watched.clone(),
            TargetPath::local(folder.clone()),
        ))
        .await?;
    collected_files(&client, &watched).await?;
    let observer = client.observe_folder(&watched, None, events()?).await?;
    assert_eq!(observer.snapshot().status.local_files, Some(1));
    assert_eq!(observer.snapshot().task_id(), None);
    let saved = serde_json::to_vec(observer.position())?;
    observer.close().await?;
    same_identity(&client, &identity).await?;
    assert_eq!(instance.process_id(), pid);

    let restore: FolderObservationPosition = serde_json::from_slice(&saved)?;
    assert_eq!(restore.folder_id(), &watched);
    let mut continued = client.resume_folder_observation(restore, events()?).await?;
    let resumed = continued
        .next_within(WAIT)
        .await?
        .ok_or("resume ended early")?;
    assert!(matches!(
        resumed.item,
        EventStreamItem::Gap(gap) if gap.reason == EventGapReason::ResumedContinuityUnverified
    ));
    assert!(matches!(resumed.refresh, FolderObservationRefresh::Read));

    // The test explicitly changes a synthetic file and requests this scan.
    // The independent observer receives the resulting native state.
    std::fs::write(folder.join("counted.bin"), b"new synthetic native input\n")?;
    client.request_scan(&watched).await?;
    tokio::time::timeout(WAIT, async {
        loop {
            let Some(update) = continued.next().await else {
                return Err("native observation ended before indexed data was read".into());
            };
            let update = update?;
            if matches!(update.refresh, FolderObservationRefresh::Read)
                && continued.snapshot().status.local_files == Some(2)
            {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
        }
    })
    .await??;
    assert_eq!(
        continued.last_gap(),
        Some(EventGapReason::ResumedContinuityUnverified)
    );
    continued.close().await?;
    assert_eq!(Sha256::digest(std::fs::read(&sample)?), digest);

    let early = instance.observe_control_exit(&generation, SHORT).await?;
    assert_eq!(early.generation, generation);
    assert!(early.waited >= SHORT);
    assert!(matches!(
        early.outcome,
        ManagedExitObservationOutcome::TimedOut
    ));
    same_identity(&client, &identity).await?;
    assert_eq!(instance.process_id(), pid);
    assert_eq!(instance.control_generation(), generation);

    // An explicit separate command is the only shutdown request in this case.
    client.request_shutdown().await?;
    let later = instance.observe_control_exit(&generation, WAIT).await?;
    assert_eq!(later.generation, early.generation);
    let ManagedExitObservationOutcome::Exited(exit) = later.outcome else {
        return Err("waiting for the same generation did not confirm exit".into());
    };
    assert_eq!(exit.code, Some(0));
    assert!(exit.tree_stopped && exit.state_released && !exit.forced);
    assert_eq!(Sha256::digest(std::fs::read(&sample)?), digest);
    drop(instance);
    root.close()?;
    println!(
        "control observation native evidence {}",
        json!({
            "folder_status_observed_from_real_index": true,
            "updates_from_native_scan_after_resume": true,
            "borrowed_generation_unknown": true,
            "task_id_unknown": true,
            "timeout_ms": early.waited.as_millis(),
            "same_generation_reachable_after_timeout": true,
            "shutdown_requested_by_fixture_only": true,
            "same_generation_normal_exit_and_state_release": true,
            "synthetic_file_digest_preserved": true,
            "temporary_root_removed": true,
        })
    );
    Ok(())
}

async fn run_packed_observer(
    executable: &Path,
    arguments: &[&std::ffi::OsStr],
    input: &serde_json::Value,
) -> TestResult<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let mut app = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let result: TestResult = async {
        let mut input_pipe = app.stdin.take().ok_or("observer input pipe is absent")?;
        serde_json::to_writer(&mut input_pipe, input)?;
        input_pipe.flush()?;
        drop(input_pipe);
        let now = Instant::now();
        while app.try_wait()?.is_none() {
            if now.elapsed() >= WAIT {
                return Err("packaged observer exceeded its deadline".into());
            }
            tokio::time::sleep(SHORT).await;
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        let _ = app.kill();
        let _ = app.wait();
        return Err(error);
    }
    let output = app.wait_with_output()?;
    assert!(output.stdout.len() <= 8192 && output.stderr.len() <= 8192);
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    for field in ["endpoint", "api_key", "expected_device_id", "folder_id"] {
        if let Some(value) = input[field].as_str() {
            assert!(
                !stdout.contains(value) && !stderr.contains(value),
                "observer leaked a private input"
            );
        }
    }
    if !output.status.success() {
        return Err("Packaged observer returned a non-zero status.".into());
    }
    assert!(stderr.is_empty());
    Ok(stdout)
}

#[tokio::test]
async fn packed_observer_stops_and_resumes_in_an_independent_process() -> TestResult {
    use std::{ffi::OsStr, net::TcpListener, path::PathBuf};
    use verysync_sidecar::{ManagedOptions, ManagementEndpoint};

    let executable = PathBuf::from(std::env::var_os("VERYSYNC_TEST_OBSERVATION_EXAMPLE").ok_or(
        "select the separately built package consumer through VERYSYNC_TEST_OBSERVATION_EXAMPLE",
    )?);
    assert!(executable.is_absolute() && executable.is_file());
    let root = private_root()?;
    let fixture = managed_fixture::options(&root.path().join("state"))?;
    let reserved = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = format!("http://{}/", reserved.local_addr()?);
    let options = ManagedOptions::new(
        fixture.program().clone(),
        fixture.state_directory(),
        ManagementEndpoint::http(&address)?,
    )?
    .startup_timeout(WAIT)?;
    drop(reserved);
    let mut instance = ManagedInstance::start(options).await?;
    let client = instance.client();
    let identity = client.instance().device_id.clone();
    let generation = instance.control_generation();
    let configuration = client.configuration().await?;
    let key = configuration.native_document()["gui"]["apiKey"]
        .as_str()
        .ok_or("isolated native credential was absent")?;
    let folder = root.path().join("sample-dir");
    std::fs::create_dir(&folder)?;
    let sample = folder.join("untouched.bin");
    std::fs::write(&sample, SAMPLE)?;
    let watched = FolderId::parse("packed-observer-test-folder")?;
    client
        .create_folder(&CreateFolderOptions::new(
            watched.clone(),
            TargetPath::local(folder),
        ))
        .await?;
    collected_files(client, &watched).await?;

    let first_position = root.path().join("first.json");
    let second_position = root.path().join("second.json");
    let first_input = json!({
        "endpoint": address,
        "api_key": key,
        "expected_device_id": identity,
        "folder_id": watched,
        "wait_ms": 25,
    });
    let started = run_packed_observer(
        &executable,
        &[OsStr::new("start"), first_position.as_os_str()],
        &first_input,
    )
    .await?;
    assert!(started.contains("VerySync supplied no task ID"));
    assert!(started.contains("Stopped watching."));
    same_identity(client, &identity).await?;
    assert_eq!(instance.control_generation(), generation);
    let first: FolderObservationPosition =
        serde_json::from_slice(&std::fs::read(&first_position)?)?;
    assert_eq!(first.folder_id(), &watched);

    let second_input = json!({
        "endpoint": address,
        "api_key": key,
        "expected_device_id": identity,
        "wait_ms": 1000,
    });
    let resumed = run_packed_observer(
        &executable,
        &[
            OsStr::new("resume"),
            first_position.as_os_str(),
            second_position.as_os_str(),
        ],
        &second_input,
    )
    .await?;
    assert!(resumed
        .contains("Some updates may be missing between the saved position and this subscription."));
    assert!(resumed.contains("Stopped watching."));
    let second: FolderObservationPosition =
        serde_json::from_slice(&std::fs::read(second_position)?)?;
    assert_eq!(first, second);
    same_identity(client, &identity).await?;
    assert_eq!(instance.control_generation(), generation);
    assert_eq!(std::fs::read(sample)?, SAMPLE);
    let exit = instance.shutdown(WAIT).await?;
    assert!(exit.code == Some(0) && exit.tree_stopped && exit.state_released && !exit.forced);
    drop(instance);
    root.close()?;
    println!(
        "control observation independently launched example evidence {}",
        json!({
            "executable_supplied_by_caller": true,
            "first_process_stopped_its_read_wait": true,
            "second_process_resumed_same_consumer_position": true,
            "resume_reports_gap": true,
            "output_private_inputs_excluded": true,
            "native_generation_kept_running_after_each_example": true,
            "sample_bytes_preserved": true,
            "owned_exit_and_state_release": true,
            "temporary_root_removed": true,
        })
    );
    Ok(())
}

#[tokio::test]
async fn native_folder_observation_reopens_saved_cursor_after_owned_generation_changed(
) -> TestResult {
    let root = private_root()?;
    let mut instance = open(root.path()).await?;
    let generation = instance.control_generation();
    let identity = instance.client().instance().device_id.clone();
    let watched = FolderId::parse("native-control-observation-restart")?;
    let folder = root.path().join("fixture-files");
    std::fs::create_dir(&folder)?;
    let sample = folder.join("retained.bin");
    std::fs::write(&sample, SAMPLE)?;
    instance
        .client()
        .create_folder(&CreateFolderOptions::new(
            watched.clone(),
            TargetPath::local(folder),
        ))
        .await?;
    collected_files(instance.client(), &watched).await?;

    let old = instance
        .client()
        .observe_folder(&watched, None, events()?)
        .await?;
    let old_started_at = old
        .snapshot()
        .engine_started_at()
        .ok_or("native start time unavailable before restart")?
        .to_owned();
    let saved = serde_json::to_vec(old.position())?;
    old.close().await?;
    // Separate native wall-clock seconds even on a fast fixture.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    instance.restart(WAIT).await?;
    assert_ne!(instance.control_generation(), generation);
    assert_eq!(instance.client().instance().device_id, identity);
    let new_started_at = instance
        .client()
        .system_status()
        .await?
        .start_time
        .ok_or("native start time unavailable after restart")?;
    assert_ne!(old_started_at, new_started_at);

    let position: FolderObservationPosition = serde_json::from_slice(&saved)?;
    let mut reopened = instance
        .client()
        .resume_folder_observation(position, events()?)
        .await?;
    assert_eq!(
        reopened.position().cursor().engine_started_at.as_deref(),
        Some(old_started_at.as_str())
    );
    assert_eq!(
        reopened
            .snapshot()
            .trigger_cursor
            .engine_started_at
            .as_deref(),
        Some(new_started_at.as_str())
    );
    assert_eq!(
        reopened.snapshot().engine_started_at(),
        Some(new_started_at.as_str())
    );
    assert_eq!(reopened.snapshot().status.local_files, Some(1));
    let resume_gap = reopened
        .next_within(WAIT)
        .await?
        .ok_or("resumed observation ended before continuity gap")?;
    assert!(matches!(resume_gap.item, EventStreamItem::Gap(gap)
        if gap.reason == EventGapReason::ResumedContinuityUnverified));
    assert!(matches!(
        resume_gap.refresh,
        FolderObservationRefresh::Failed(verysync_sidecar::Error::EventGenerationChanged)
    ));
    let generation_gap = reopened
        .next_within(WAIT)
        .await?
        .ok_or("resumed observation ended before native generation gap")?;
    assert!(matches!(generation_gap.item, EventStreamItem::Gap(gap)
        if gap.reason == EventGapReason::EngineStartTimeChanged));
    assert!(matches!(
        generation_gap.refresh,
        FolderObservationRefresh::Read
    ));
    assert_eq!(
        reopened.position().cursor().engine_started_at.as_deref(),
        Some(new_started_at.as_str())
    );
    assert_eq!(reopened.snapshot().status.local_files, Some(1));
    reopened.close().await?;

    let exit = instance.shutdown(WAIT).await?;
    assert!(exit.code == Some(0) && exit.tree_stopped && exit.state_released && !exit.forced);
    assert_eq!(std::fs::read(sample)?, SAMPLE);
    drop(instance);
    root.close()?;
    println!(
        "folder native restart evidence {}",
        json!({
            "owned_new_generation": true,
            "same_logical_device": true,
            "fresh_snapshot_bound_to_real_new_start": true,
            "saved_position_not_advanced_before_gap_delivery": true,
            "ordered_resume_then_restart_gaps": true,
            "synthetic_file_bytes_preserved": true,
            "owned_exit_and_state_release": true,
            "temporary_root_removed": true,
        })
    );
    Ok(())
}
