//! Request witnesses for continuation and folder-scoped snapshot reconciliation.

use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::{JoinHandle, JoinSet};
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, DeviceId, Error, EventGapReason, EventOptions, EventStreamItem,
    FolderId, FolderObservation, FolderObservationPosition, FolderObservationRefresh, FolderState,
    ManagementEndpoint,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const WAIT: Duration = Duration::from_secs(3);
const INTERVAL: Duration = Duration::from_millis(10);
const ID: &str = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";
const PEER: &str = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
const KEY: &str = "private-synthetic-folder-observation-key";
const SELECTED: &str = "watched + scope";
const OTHER: &str = "unrelated";

#[derive(Default)]
struct ScriptState {
    events: Vec<Value>,
    reads: Vec<String>,
    fail_event_reads: usize,
    fail_folder_reads: usize,
    hold_folder: bool,
    indexed_files: u64,
    replacement_started_at: Option<&'static str>,
}

struct Script {
    state: Mutex<ScriptState>,
    snapshot_started: Notify,
    release_snapshot: Notify,
}

impl Script {
    fn record(&self, event: u64, folder: &str, files: u64) {
        let mut state = self.state.lock().unwrap();
        state.events.push(json!({
            "id":event, "type":"StateChanged", "time":"2026-11-27T00:00:00Z",
            "data":{"folder":folder,"private":KEY}
        }));
        state.indexed_files = files;
    }

    fn reads(&self) -> Vec<String> {
        self.state.lock().unwrap().reads.clone()
    }
}

struct Origin {
    script: Arc<Script>,
    client: Client,
    task: JoinHandle<TestResult>,
}

impl Origin {
    async fn start() -> TestResult<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let endpoint = ManagementEndpoint::http(&format!("http://{}/", listener.local_addr()?))?;
        let script = Arc::new(Script {
            state: Mutex::new(ScriptState::default()),
            snapshot_started: Notify::new(),
            release_snapshot: Notify::new(),
        });
        script.record(1, SELECTED, 1);
        let server_state = Arc::clone(&script);
        let task = tokio::spawn(async move {
            let mut active = JoinSet::new();
            loop {
                tokio::select! {
                    ready = active.join_next(), if !active.is_empty() => {
                        ready.ok_or("request was absent")???;
                    }
                    accepted = listener.accept() => {
                        let (socket, _) = accepted?;
                        active.spawn(serve(socket, Arc::clone(&server_state)));
                    }
                }
            }
        });
        let options = ConnectOptions::new(endpoint, ApiKey::new(KEY)?)
            .expected_device_id(DeviceId::parse(ID)?)
            .request_timeout(WAIT)?;
        let client = Client::connect(options).await?;
        Ok(Self {
            script,
            client,
            task,
        })
    }

    fn assert_requests(&self) {
        let requests = self.script.reads();
        assert!(requests.iter().all(|request| {
            let path = request.split('?').next().unwrap();
            matches!(
                path,
                "/rest/system/version"
                    | "/rest/system/status"
                    | "/rest/events"
                    | "/rest/db/status"
                    | "/rest/db/completion"
            )
        }));
        assert!(requests
            .iter()
            .filter(|r| r.starts_with("/rest/db/"))
            .all(|r| {
                let parsed = url::Url::parse(&format!("http://localhost{r}")).unwrap();
                let folder = parsed
                    .query_pairs()
                    .find(|(name, _)| name == "folder")
                    .unwrap()
                    .1;
                folder == SELECTED
            }));
    }

    fn folder_reads(&self) -> usize {
        self.script
            .reads()
            .iter()
            .filter(|r| r.starts_with("/rest/db/status?"))
            .count()
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(mut socket: TcpStream, script: Arc<Script>) -> TestResult {
    let mut bytes = Vec::new();
    while !bytes.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        let mut buffer = [0; 1024];
        let n = socket.read(&mut buffer).await?;
        if n == 0 {
            return Ok(());
        }
        bytes.extend_from_slice(&buffer[..n]);
        if bytes.len() > 8192 {
            return Err("fixture request exceeded its bound".into());
        }
    }
    let headers = std::str::from_utf8(&bytes)?;
    let request = headers.lines().next().ok_or("request is empty")?;
    let mut fields = request.split_ascii_whitespace();
    let method = fields.next().ok_or("request lacks method")?;
    let target = fields.next().ok_or("request lacks target")?;
    assert!(headers
        .lines()
        .any(|line| line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("x-api-key") && value.trim() == KEY
        })));
    let url = url::Url::parse(&format!("http://localhost{target}"))?;
    let number = |key| -> TestResult<u64> {
        Ok(url
            .query_pairs()
            .find(|(name, _)| name == key)
            .ok_or("query value missing")?
            .1
            .parse()?)
    };
    let (status, body, held) = {
        let mut state = script.state.lock().unwrap();
        state.reads.push(if method == "GET" {
            target.to_owned()
        } else {
            format!("{method} {target}")
        });
        match (method, url.path()) {
            ("GET", "/rest/system/version") => (
                200,
                json!({"version":"v2.33.2","os":"linux","arch":"amd64"}),
                false,
            ),
            ("GET", "/rest/system/status") => (
                200,
                json!({"myID":ID,"startTime":state.replacement_started_at.unwrap_or("unchanged-start")}),
                false,
            ),
            ("GET", "/rest/db/status") if state.fail_folder_reads != 0 => {
                state.fail_folder_reads -= 1;
                (503, json!({}), false)
            }
            ("GET", "/rest/db/status") => {
                let held = std::mem::take(&mut state.hold_folder);
                (
                    200,
                    json!({"state":"idle","localFiles":state.indexed_files}),
                    held,
                )
            }
            ("GET", "/rest/db/completion") => {
                assert!(url
                    .query_pairs()
                    .any(|(name, value)| name == "device" && value == PEER));
                (
                    200,
                    json!({"completion":0.0,"needItems":state.indexed_files}),
                    false,
                )
            }
            ("GET", "/rest/events") if state.fail_event_reads != 0 => {
                state.fail_event_reads -= 1;
                return Ok(());
            }
            ("GET", "/rest/events") => {
                let since = number("since")?;
                let limit = number("limit")? as usize;
                let matching: Vec<_> = state
                    .events
                    .iter()
                    .filter(|row| row["id"].as_u64().unwrap() > since)
                    .collect();
                (
                    200,
                    json!(&matching[matching.len().saturating_sub(limit)..]),
                    false,
                )
            }
            _ => (404, json!({}), false),
        }
    };
    if held {
        script.snapshot_started.notify_one();
        script.release_snapshot.notified().await;
    }
    let body = serde_json::to_vec(&body)?;
    let response = format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    if socket.write_all(response.as_bytes()).await.is_ok() {
        let _ = socket.write_all(&body).await;
    }
    Ok(())
}

fn options() -> TestResult<EventOptions> {
    Ok(EventOptions::default()
        .queue_capacity(1)?
        .poll_interval(INTERVAL)?
        .reconnect_attempts(1)?
        .reconnect_delay(INTERVAL)?)
}

async fn next(
    observer: &mut FolderObservation,
) -> TestResult<verysync_sidecar::FolderObservationUpdate> {
    Ok(observer
        .next_within(WAIT)
        .await?
        .ok_or("observation unexpectedly ended")?)
}

async fn wait_for_queue(observer: &FolderObservation) -> TestResult {
    tokio::time::timeout(WAIT, async {
        while observer.buffered_items() == 0 {
            tokio::time::sleep(INTERVAL).await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn updates_during_snapshot_and_a_real_gap_preserve_the_consumed_positions() -> TestResult {
    let origin = Origin::start().await?;
    origin.script.state.lock().unwrap().hold_folder = true;
    let selected = FolderId::parse(SELECTED)?;
    let peer = DeviceId::parse(PEER)?;
    let client = origin.client.clone();
    let initial = tokio::spawn(async move {
        client
            .observe_folder(&selected, Some(&peer), options().unwrap())
            .await
    });
    tokio::time::timeout(WAIT, origin.script.snapshot_started.notified()).await?;
    origin.script.record(2, SELECTED, 2);
    origin.script.record(4, SELECTED, 4);
    origin.script.record(5, OTHER, 5);
    origin.script.release_snapshot.notify_one();
    let mut observer = initial.await??;
    assert_eq!(observer.position().cursor().last_id, 1);
    assert_eq!(observer.snapshot().status.state, Some(FolderState::Idle));
    assert_eq!(observer.snapshot().status.local_files, Some(1));
    assert_eq!(
        observer
            .snapshot()
            .peer_completion
            .as_ref()
            .unwrap()
            .need_items,
        Some(5)
    );
    assert_eq!(observer.snapshot().task_id(), None);
    wait_for_queue(&observer).await?;
    tokio::time::sleep(INTERVAL * 3).await;
    let blocked_reads = origin.script.reads().len();
    tokio::time::sleep(INTERVAL * 3).await;
    assert_eq!(origin.script.reads().len(), blocked_reads);
    assert_eq!(observer.buffered_items(), 1);
    assert_eq!(observer.position().cursor().last_id, 1);

    let update = next(&mut observer).await?;
    assert!(matches!(update.item, EventStreamItem::Event(ref event) if event.cursor.last_id == 2));
    assert!(matches!(update.refresh, FolderObservationRefresh::Read));
    assert_eq!(observer.position().cursor().last_id, 2);

    // A failed reconciliation must still expose the gap and the old snapshot.
    origin.script.state.lock().unwrap().fail_folder_reads = 1;
    let update = next(&mut observer).await?;
    assert!(
        matches!(update.item, EventStreamItem::Gap(ref gap) if gap.reason == EventGapReason::MissingEvents)
    );
    assert!(matches!(
        update.refresh,
        FolderObservationRefresh::Failed(_)
    ));
    assert_eq!(observer.last_gap(), Some(EventGapReason::MissingEvents));
    assert_eq!(observer.position().cursor().last_id, 3);
    assert_eq!(observer.snapshot().trigger_cursor.last_id, 2);
    let saved = serde_json::to_vec(observer.position())?;

    let update = next(&mut observer).await?;
    assert!(matches!(update.item, EventStreamItem::Event(ref event) if event.cursor.last_id == 4));
    assert_eq!(observer.position().cursor().last_id, 4);
    assert_eq!(observer.last_gap(), Some(EventGapReason::MissingEvents));
    let count = origin.folder_reads();
    let update = next(&mut observer).await?;
    assert!(matches!(update.item, EventStreamItem::Event(ref event) if event.cursor.last_id == 5));
    assert!(matches!(
        update.refresh,
        FolderObservationRefresh::NotNeeded
    ));
    assert_eq!(origin.folder_reads(), count);
    assert!(!format!("{update:?}").contains(KEY));
    observer.close().await?;

    let persisted: FolderObservationPosition = serde_json::from_slice(&saved)?;
    let mut resumed = origin
        .client
        .resume_folder_observation(persisted, options()?)
        .await?;
    assert!(matches!(next(&mut resumed).await?.item,
        EventStreamItem::Gap(gap) if gap.reason == EventGapReason::ResumedContinuityUnverified));
    assert_eq!(resumed.position().cursor().last_id, 3);
    assert!(matches!(next(&mut resumed).await?.item,
        EventStreamItem::Event(event) if event.cursor.last_id == 4));
    resumed.close().await?;
    origin.assert_requests();
    println!(
        "folder controlled overlap evidence {}",
        json!({
            "initial_consumer_anchor": 1,
            "initial_status_before_update": true,
            "status_and_completion_are_separate_reads": true,
            "delivered_consumer_positions": [2, 3, 4, 5],
            "gap_retained_after_refresh_failure": true,
            "explicit_resume_from": 3,
            "queue_bound": 1,
            "unrelated_folder_reads": 0,
            "mutation_requests": 0,
        })
    );
    Ok(())
}

#[tokio::test]
async fn cancellation_and_disconnect_do_not_discard_events_or_schedule_writes() -> TestResult {
    let origin = Origin::start().await?;
    let mut observer = origin
        .client
        .observe_folder(&FolderId::parse(SELECTED)?, None, options()?)
        .await?;
    origin.script.state.lock().unwrap().hold_folder = true;
    origin.script.record(2, SELECTED, 2);
    let timed = {
        let next = observer.next_within(Duration::from_secs(1));
        tokio::pin!(next);
        tokio::select! {
            _ = origin.script.snapshot_started.notified() => next.await,
            _ = &mut next => return Err("next ended before the held snapshot was reached".into()),
        }
    };
    assert!(matches!(timed, Err(Error::Timeout { .. })));
    assert_eq!(observer.position().cursor().last_id, 1);
    origin.script.release_snapshot.notify_one();
    assert!(matches!(next(&mut observer).await?.item,
        EventStreamItem::Event(event) if event.cursor.last_id == 2));

    origin.script.state.lock().unwrap().fail_event_reads = 1;
    assert!(matches!(next(&mut observer).await?.item,
        EventStreamItem::Gap(gap) if gap.reason == EventGapReason::ConnectionInterrupted));
    assert_eq!(observer.position().cursor().last_id, 2);
    assert!(matches!(
        next(&mut observer).await?.item,
        EventStreamItem::Reconnected { attempts_used: 1 }
    ));
    assert_eq!(
        observer.last_gap(),
        Some(EventGapReason::ConnectionInterrupted)
    );
    origin.script.record(3, SELECTED, 3);
    assert!(matches!(next(&mut observer).await?.item,
        EventStreamItem::Event(event) if event.cursor.last_id == 3));
    observer.close().await?;

    // Allow any request already accepted by the server to settle.
    tokio::time::sleep(INTERVAL * 3).await;
    let count = origin.script.reads().len();
    tokio::time::sleep(INTERVAL * 5).await;
    assert_eq!(origin.script.reads().len(), count);
    origin.assert_requests();
    println!(
        "folder controlled cancellation evidence {}",
        json!({
            "pending_event_preserved_after_timeout": true,
            "transport_gap_reported": true,
            "read_retry_reconnected": true,
            "subsequent_reads_after_close": 0,
            "mutation_requests": 0,
        })
    );
    Ok(())
}

#[tokio::test]
async fn resume_rejects_a_different_device_or_unscoped_cursor_before_reads() -> TestResult {
    let origin = Origin::start().await?;
    let id = FolderId::parse(SELECTED)?;
    let observer = origin.client.observe_folder(&id, None, options()?).await?;
    let mut saved = serde_json::to_value(observer.position())?;
    let ordinary = observer.position().cursor().clone();
    observer.close().await?;
    tokio::time::sleep(INTERVAL * 2).await;
    let count = origin.script.reads().len();

    saved["cursor"]["device_id"] = json!(PEER);
    let wrong: FolderObservationPosition = serde_json::from_value(saved)?;
    assert!(matches!(
        origin
            .client
            .resume_folder_observation(wrong, options()?)
            .await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert!(matches!(
        origin
            .client
            .observe_folder(&id, None, options()?.resume_from(ordinary)?)
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert_eq!(origin.script.reads().len(), count);
    println!(
        "folder controlled resume boundary evidence {}",
        json!({
            "conflicting_device_reads": 0,
            "unscoped_cursor_reads": 0,
        })
    );
    Ok(())
}

#[tokio::test]
async fn a_queued_event_cannot_replace_the_snapshot_with_another_engine_generation() -> TestResult {
    let origin = Origin::start().await?;
    let mut observer = origin
        .client
        .observe_folder(&FolderId::parse(SELECTED)?, None, options()?)
        .await?;
    assert_eq!(observer.snapshot().status.local_files, Some(1));
    assert_eq!(
        observer.snapshot().engine_started_at(),
        Some("unchanged-start")
    );
    origin.script.record(2, SELECTED, 2);
    wait_for_queue(&observer).await?;
    {
        let mut state = origin.script.state.lock().unwrap();
        state.replacement_started_at = Some("replacement-start");
        state.events.clear();
        state.indexed_files = 99;
    }
    let folder_reads = origin.folder_reads();
    let update = next(&mut observer).await?;
    assert!(matches!(update.item, EventStreamItem::Event(ref event)
        if event.cursor.last_id == 2 && event.cursor.engine_started_at.as_deref() == Some("unchanged-start")));
    assert!(matches!(
        update.refresh,
        FolderObservationRefresh::Failed(Error::EventGenerationChanged)
    ));
    assert_eq!(origin.folder_reads(), folder_reads);
    assert_eq!(observer.snapshot().status.local_files, Some(1));
    assert_eq!(
        observer.snapshot().engine_started_at(),
        Some("unchanged-start")
    );
    assert_eq!(observer.position().cursor().last_id, 2);
    assert_eq!(observer.last_gap(), None);
    let saved = observer.position().clone();

    let gap = next(&mut observer).await?;
    assert!(matches!(gap.item, EventStreamItem::Gap(ref gap)
        if gap.reason == EventGapReason::EngineStartTimeChanged && gap.resume_from.last_id == 0));
    assert!(matches!(gap.refresh, FolderObservationRefresh::Read));
    assert_eq!(observer.snapshot().trigger_cursor.last_id, 0);
    assert_eq!(observer.snapshot().status.local_files, Some(99));
    assert_eq!(
        observer.snapshot().engine_started_at(),
        Some("replacement-start")
    );

    origin.script.record(1, SELECTED, 100);
    let update = next(&mut observer).await?;
    assert!(matches!(update.item, EventStreamItem::Event(ref event)
        if event.cursor.last_id == 1 && event.cursor.engine_started_at.as_deref() == Some("replacement-start")));
    assert!(matches!(update.refresh, FolderObservationRefresh::Read));
    assert_eq!(
        observer.last_gap(),
        Some(EventGapReason::EngineStartTimeChanged)
    );
    assert_eq!(observer.snapshot().status.local_files, Some(100));
    observer.close().await?;

    let mut reopened = origin
        .client
        .resume_folder_observation(saved, options()?)
        .await?;
    assert_eq!(reopened.position().cursor().last_id, 2);
    assert_eq!(
        reopened.position().cursor().engine_started_at.as_deref(),
        Some("unchanged-start")
    );
    assert_eq!(reopened.snapshot().trigger_cursor.last_id, 1);
    assert_eq!(
        reopened.snapshot().engine_started_at(),
        Some("replacement-start")
    );
    assert_eq!(reopened.snapshot().status.local_files, Some(100));
    let resume_gap = next(&mut reopened).await?;
    assert!(matches!(resume_gap.item, EventStreamItem::Gap(ref gap)
        if gap.reason == EventGapReason::ResumedContinuityUnverified));
    assert!(matches!(
        resume_gap.refresh,
        FolderObservationRefresh::Failed(Error::EventGenerationChanged)
    ));
    assert_eq!(reopened.snapshot().status.local_files, Some(100));
    let generation_gap = next(&mut reopened).await?;
    assert!(matches!(generation_gap.item, EventStreamItem::Gap(ref gap)
        if gap.reason == EventGapReason::EngineStartTimeChanged));
    assert!(matches!(
        generation_gap.refresh,
        FolderObservationRefresh::Read
    ));
    assert_eq!(reopened.position().cursor().last_id, 1);
    assert_eq!(reopened.snapshot().status.local_files, Some(100));
    reopened.close().await?;
    origin.assert_requests();
    println!(
        "folder controlled engine generation evidence {}",
        json!({
            "old_event_kept_and_consumed": 2,
            "wrong_generation_did_not_replace_snapshot": true,
            "new_snapshot_read_on_ordered_generation_gap": true,
            "new_generation_event_observed": 1,
            "saved_old_cursor_reopened_with_fresh_native_anchor": true,
            "resumed_continuity_gap_and_actual_generation_gap_both_retained": true,
            "mutation_requests": 0,
        })
    );
    Ok(())
}
