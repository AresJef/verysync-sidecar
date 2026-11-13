//! Actual public event subscriptions against private fixed-baseline engines.
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::Path;
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::options;
use std::time::Duration;
use verysync_sidecar::{
    Client, CreateFolderOptions, EventCursor, EventGapReason, EventKind, EventOptions,
    EventStreamItem, EventSubscription, FolderId, FolderPatch, ManagedInstance, TargetPath,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn fast() -> TestResult<EventOptions> {
    Ok(EventOptions::default().poll_interval(Duration::from_millis(20))?)
}
async fn next(stream: &mut EventSubscription) -> TestResult<EventStreamItem> {
    Ok(tokio::time::timeout(Duration::from_secs(15), stream.next())
        .await?
        .ok_or("event stream ended")??)
}
fn credential(state: &Path) -> TestResult<String> {
    let config = rmpv::decode::read_value(&mut std::io::Cursor::new(std::fs::read(
        state.join("setting.dat"),
    )?))?;
    Ok(config["4"]["6"]
        .as_str()
        .ok_or("private test credential missing")?
        .to_owned())
}
fn identity_hashes(state: &Path) -> TestResult<Vec<Vec<u8>>> {
    ["key.pem", "cert.pem", ".verysync-sidecar-identity"]
        .iter()
        .map(|name| Ok(Sha256::digest(std::fs::read(state.join(name))?).to_vec()))
        .collect()
}
async fn await_kind(stream: &mut EventSubscription, wanted: EventKind) -> TestResult {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let EventStreamItem::Event(event) = next(stream).await? {
                if event.kind == wanted {
                    return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
                }
            }
        }
    })
    .await??;
    Ok(())
}
async fn authenticated(client: &Client, expected: &verysync_sidecar::DeviceId) -> TestResult {
    assert_eq!(&client.system_status().await?.device_id, expected);
    Ok(())
}

#[tokio::test]
async fn actual_changes_unknown_events_and_backpressure_preserve_the_engine_and_data() -> TestResult
{
    let root = tempfile::Builder::new().prefix("vse-").tempdir()?.keep();
    let state = root.join("state");
    let mut owner = ManagedInstance::start(options(&state)?).await?;
    let client = owner.client().clone();
    let identity = client.instance().device_id.clone();
    let current = client.system_status().await?;
    let resume = EventCursor {
        device_id: identity.clone(),
        engine_started_at: current.start_time,
        last_id: 0,
    };
    let key = credential(&state)?;
    let mut stream = client
        .subscribe_events(fast()?.resume_from(resume)?)
        .await?;
    assert!(
        matches!(next(&mut stream).await?,EventStreamItem::Gap(g) if g.reason==EventGapReason::ResumedContinuityUnverified)
    );
    let mut unknown = false;
    while !unknown {
        if let EventStreamItem::Event(event) = next(&mut stream).await? {
            unknown |= matches!(event.kind, EventKind::Unknown(_));
            assert!(!format!("{event:?}").contains(&key));
        }
    }
    assert!(unknown);
    let path = state.join("synthetic events");
    std::fs::create_dir(&path)?;
    std::fs::write(path.join("sample.bin"), b"synthetic event sample retained")?;
    let sample = Sha256::digest(std::fs::read(path.join("sample.bin"))?);
    let id = FolderId::parse("sidecar-event-sample")?;
    client
        .create_folder(
            &CreateFolderOptions::new(id.clone(), TargetPath::local(path.clone())).paused(true),
        )
        .await?;
    client.resume_folder(&id).await?;
    client.pause_folder(&id).await?;
    let mut names = [false; 4];
    let mut secret_payload = false;
    tokio::time::timeout(Duration::from_secs(15), async {
        while !names.iter().all(|v| *v) {
            if let EventStreamItem::Event(event) = next(&mut stream).await? {
                assert!(!format!("{event:?}").contains(&key));
                match event.kind {
                    EventKind::ConfigurationSaved => {
                        names[0] = true;
                        secret_payload |= event.data().to_string().contains(&key);
                    }
                    EventKind::FolderResumed => {
                        names[1] = true;
                        assert_eq!(event.data()["id"], id.as_str());
                    }
                    EventKind::FolderPaused => {
                        names[2] = true;
                        assert_eq!(event.data()["id"], id.as_str());
                    }
                    EventKind::StateChanged => {
                        names[3] = true;
                        assert_eq!(event.data()["folder"], id.as_str());
                    }
                    _ => (),
                }
            }
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    assert!(secret_payload);
    stream.close().await?;
    authenticated(&client, &identity).await?;
    let mut slow = client.subscribe_events(fast()?.queue_capacity(2)?).await?;
    let unconsumed = slow.cursor().clone();
    client.resume_folder(&id).await?;
    client.pause_folder(&id).await?;
    // Observe asynchronous delivery within a deadline, without assuming that
    // configuration readback also means events have already reached subscribers.
    tokio::time::timeout(Duration::from_secs(8), async {
        while slow.buffered_items() < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    assert_eq!(slow.buffered_items(), 2);
    assert_eq!(slow.cursor(), &unconsumed);
    let EventStreamItem::Event(first) = next(&mut slow).await? else {
        return Err("queued real event missing".into());
    };
    let EventStreamItem::Event(second) = next(&mut slow).await? else {
        return Err("second queued real event missing".into());
    };
    assert!(
        first.cursor.last_id > unconsumed.last_id && second.cursor.last_id > first.cursor.last_id
    );
    slow.close().await?;
    authenticated(&client, &identity).await?;
    let dropped = client.subscribe_events(fast()?).await?;
    drop(dropped);
    authenticated(&client, &identity).await?;
    assert_eq!(
        Sha256::digest(std::fs::read(path.join("sample.bin"))?),
        sample
    );
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(&root)?;
    println!(
        "public event stream evidence: {}",
        json!({"actual_configuration_saved":true,"actual_folder_pause_resume":true,
        "actual_state_changed":true,"actual_unknown_names_retained":true,"actual_secret_payload_hidden_in_debug":true,
        "bounded_queue_observed":true,"unconsumed_cursor_not_advanced":true,"close_and_drop_leave_engine_authenticated":true,
        "sample_sha_retained":true,"actual_normal_tree_exit":true})
    );
    Ok(())
}

#[tokio::test]
async fn real_tail_loss_future_cursor_and_restart_report_gaps_and_resume_explicitly() -> TestResult
{
    let root = tempfile::Builder::new().prefix("vsg-").tempdir()?.keep();
    let state = root.join("state");
    let mut owner = ManagedInstance::start(options(&state)?).await?;
    let client = owner.client().clone();
    let identity = client.instance().device_id.clone();
    let hashes = identity_hashes(&state)?;
    let id = FolderId::parse("sidecar-event-gap")?;
    client
        .create_folder(
            &CreateFolderOptions::new(id.clone(), TargetPath::local(state.join("gap sample")))
                .paused(true),
        )
        .await?;
    let baseline = client.subscribe_events(fast()?).await?;
    let cursor = baseline.cursor().clone();
    baseline.close().await?;
    for number in 0..4 {
        client
            .update_folder(&id, &FolderPatch::default().label(format!("tail {number}")))
            .await?;
    }
    let mut tail = client
        .subscribe_events(fast()?.batch_limit(1)?.resume_from(cursor)?)
        .await?;
    // A small requested tail deliberately discards available intermediate IDs.
    let gap = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let EventStreamItem::Gap(gap) = next(&mut tail).await? {
                if gap.reason == EventGapReason::MissingEvents {
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(gap);
                }
            }
        }
    })
    .await??;
    assert!(gap.resume_from.last_id > gap.previous.last_id);
    tail.close().await?;
    let future = EventCursor {
        device_id: identity.clone(),
        engine_started_at: client.system_status().await?.start_time,
        last_id: 1_000_000,
    };
    let mut ahead = client
        .subscribe_events(fast()?.resume_from(future)?)
        .await?;
    assert!(
        matches!(next(&mut ahead).await?,EventStreamItem::Gap(g) if g.reason==EventGapReason::ResumedContinuityUnverified)
    );
    assert!(
        matches!(next(&mut ahead).await?,EventStreamItem::Gap(g) if g.reason==EventGapReason::CursorReset)
    );
    ahead.close().await?;
    authenticated(&client, &identity).await?;
    let policy = fast()?
        .reconnect_attempts(64)?
        .reconnect_delay(Duration::from_millis(500))?;
    let mut stream = client.subscribe_events(policy).await?;
    let first_start = stream.cursor().engine_started_at.clone();
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped);
    assert!(
        matches!(next(&mut stream).await?,EventStreamItem::Gap(g) if g.reason==EventGapReason::ConnectionInterrupted)
    );
    owner.restart(Duration::from_secs(30)).await?;
    let new_start = owner.client().system_status().await?.start_time;
    assert_ne!(new_start, first_start);
    let mut recovered = false;
    let mut generation_gap = false;
    tokio::time::timeout(Duration::from_secs(20), async {
        while !recovered || !generation_gap {
            match next(&mut stream).await? {
                EventStreamItem::Reconnected { .. } => recovered = true,
                EventStreamItem::Gap(g) if g.reason == EventGapReason::EngineStartTimeChanged => {
                    generation_gap = true
                }
                _ => (),
            }
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    assert!(
        owner
            .client()
            .update_folder(&id, &FolderPatch::default().label("after restart"))
            .await?
            .requested_fields_match
    );
    await_kind(&mut stream, EventKind::ConfigurationSaved).await?;
    assert_eq!(stream.cursor().engine_started_at, new_start);
    stream.close().await?;
    authenticated(owner.client(), &identity).await?;
    assert_eq!(identity_hashes(&state)?, hashes);
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced);
    std::fs::remove_dir_all(&root)?;
    println!(
        "public event recovery evidence: {}",
        json!({"actual_tail_gap_observed":true,"future_cursor_reconciled_before_event_request":true,
        "actual_engine_shutdown_observed":true,"actual_transport_interruption_reported":true,"actual_reconnect_observed":true,
        "actual_restart_generation_gap":true,"new_generation_config_event_observed":true,"identity_files_retained":true,
        "subscription_close_leaves_engine_running":true,"actual_final_tree_exit":true})
    );
    Ok(())
}
