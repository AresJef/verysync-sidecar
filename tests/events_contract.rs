//! Synthetic event transport/failure evidence; not engine-effect acceptance.
#[path = "common/event_gap_continuity.rs"]
mod event_gap_continuity;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Notify};
use tokio::task::{JoinHandle, JoinSet};
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, DeviceId, Error, EventCursor, EventFilter, EventGapReason,
    EventKind, EventOptions, EventSource, EventStreamItem, EventSubscription, ManagementEndpoint,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const ID: &str = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";
const OTHER: &str = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
const KEY: &str = "synthetic-event-contract-secret";

fn event(id: u64, name: &str) -> Value {
    json!({"id":id,"globalID":id+100,"time":"2026-11-13T01:00:00Z","type":name,"data":{"private":KEY},"future_field":KEY})
}
struct State {
    events: Mutex<Vec<Value>>,
    disk_events: Mutex<Vec<Value>>,
    filtered_events: Mutex<std::collections::BTreeMap<String, Vec<Value>>>,
    filter_queries: Mutex<Vec<String>>,
    disk_reads: AtomicUsize,
    generation: Mutex<String>,
    failures_left: AtomicUsize,
    failures_observed: AtomicUsize,
    event_reads: AtomicUsize,
    hold: AtomicBool,
    held: AtomicUsize,
    cancelled: AtomicUsize,
    denied: AtomicBool,
    rotate_generation: AtomicUsize,
    folder_state: Mutex<String>,
    folder_paused: AtomicBool,
    scan_requests: AtomicUsize,
    hold_snapshot: AtomicBool,
    snapshots_held: AtomicUsize,
    released: Notify,
}
struct Server {
    state: Arc<State>,
    endpoint: ManagementEndpoint,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<TestResult>>,
}
fn consume_failure(counter: &AtomicUsize) -> bool {
    let mut current = counter.load(Ordering::SeqCst);
    loop {
        if current == 0 {
            return false;
        }
        match counter.compare_exchange_weak(
            current,
            current - 1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}
impl Server {
    async fn start() -> TestResult<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let endpoint = ManagementEndpoint::http(&format!("http://{}/", listener.local_addr()?))?;
        let state = Arc::new(State {
            events: Mutex::new(vec![event(1, "StartupCompleted")]),
            disk_events: Mutex::new(vec![]),
            filtered_events: Mutex::new(std::collections::BTreeMap::new()),
            filter_queries: Mutex::new(Vec::new()),
            disk_reads: AtomicUsize::new(0),
            generation: Mutex::new("generation-one".to_owned()),
            failures_left: AtomicUsize::new(0),
            failures_observed: AtomicUsize::new(0),
            event_reads: AtomicUsize::new(0),
            hold: AtomicBool::new(false),
            held: AtomicUsize::new(0),
            cancelled: AtomicUsize::new(0),
            denied: AtomicBool::new(false),
            rotate_generation: AtomicUsize::new(0),
            folder_state: Mutex::new("idle".to_owned()),
            folder_paused: AtomicBool::new(false),
            scan_requests: AtomicUsize::new(0),
            hold_snapshot: AtomicBool::new(false),
            snapshots_held: AtomicUsize::new(0),
            released: Notify::new(),
        });
        let (stop, mut stopped) = oneshot::channel();
        let worker = state.clone();
        let task = tokio::spawn(async move {
            let mut requests = JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut stopped => { requests.abort_all(); while requests.join_next().await.is_some() {} return Ok(()); },
                    completed = requests.join_next(), if !requests.is_empty() => { completed.ok_or("request join disappeared")???; },
                    incoming = listener.accept() => {
                        let (socket, _) = incoming?;
                        if requests.len() >= 32 { return Err("synthetic connection bound exceeded".into()); }
                        requests.spawn(serve(socket, worker.clone()));
                    },
                }
            }
        });
        Ok(Self {
            state,
            endpoint,
            stop: Some(stop),
            task: Some(task),
        })
    }
    async fn client(&self) -> TestResult<Client> {
        Ok(Client::connect(
            ConnectOptions::new(self.endpoint.clone(), ApiKey::new(KEY)?)
                .expected_device_id(DeviceId::parse(ID)?)
                .request_timeout(Duration::from_secs(2))?,
        )
        .await?)
    }
    fn replace(&self, events: Vec<Value>) {
        *self.state.events.lock().unwrap() = events;
    }
    async fn finish(mut self) -> TestResult {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.await??;
        }
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
async fn serve(mut socket: TcpStream, state: Arc<State>) -> TestResult {
    let mut bytes = Vec::new();
    while !bytes.windows(4).any(|v| v == b"\r\n\r\n") {
        let mut buffer = [0; 1024];
        let size = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut buffer)).await??;
        if size == 0 || bytes.len() + size > 8192 {
            return Err("invalid bounded event fixture request".into());
        }
        bytes.extend_from_slice(&buffer[..size]);
    }
    let header = std::str::from_utf8(&bytes)?;
    if !header
        .lines()
        .filter_map(|v| v.split_once(':'))
        .any(|(n, v)| n.eq_ignore_ascii_case("x-api-key") && v.trim() == KEY)
    {
        return Err("event fixture request authentication mismatch".into());
    }
    let route = header
        .lines()
        .next()
        .and_then(|v| v.split_whitespace().nth(1))
        .ok_or("missing route")?;
    let url = url::Url::parse(&format!("http://127.0.0.1{route}"))?;
    let value = match url.path() {
        "/rest/system/version" => {
            json!({"version":"v2.33.2","longVersion":"synthetic","os":"linux","arch":"amd64"})
        }
        "/rest/system/status" => {
            json!({"myID":ID,"startTime":state.generation.lock().unwrap().clone()})
        }
        "/rest/events" | "/rest/events/disk" => {
            let disk = url.path() == "/rest/events/disk";
            if disk {
                state.disk_reads.fetch_add(1, Ordering::SeqCst);
            }
            state.event_reads.fetch_add(1, Ordering::SeqCst);
            let rotation = state.rotate_generation.load(Ordering::SeqCst);
            if rotation == 1
                || (rotation == 2
                    && url
                        .query_pairs()
                        .any(|(key, value)| key == "limit" && value != "1"))
            {
                *state.generation.lock().unwrap() =
                    format!("rotated-{}", state.event_reads.load(Ordering::SeqCst));
            }
            if consume_failure(&state.failures_left) {
                state.failures_observed.fetch_add(1, Ordering::SeqCst);
                return Ok(());
            }
            if state.hold.load(Ordering::SeqCst) {
                state.held.fetch_add(1, Ordering::SeqCst);
                let mut byte = [0; 1];
                tokio::select! {
                    _=state.released.notified()=>(),
                    ended=socket.read(&mut byte)=> { if ended?==0 { state.cancelled.fetch_add(1,Ordering::SeqCst); return Ok(()); } return Err("unexpected event request body".into()); },
                }
            }
            let query: std::collections::BTreeMap<_, _> = url.query_pairs().into_owned().collect();
            let since: u64 = query.get("since").ok_or("since missing")?.parse()?;
            let limit: usize = query.get("limit").ok_or("limit missing")?.parse()?;
            let events = if let Some(filter) = query.get("events") {
                assert!(!disk, "disk route must not receive a name filter");
                state.filter_queries.lock().unwrap().push(filter.clone());
                state
                    .filtered_events
                    .lock()
                    .unwrap()
                    .get(filter)
                    .cloned()
                    .unwrap_or_default()
            } else {
                let selected = if disk {
                    &state.disk_events
                } else {
                    &state.events
                };
                selected.lock().unwrap().clone()
            };
            let events: Vec<_> = events
                .into_iter()
                .filter(|e| e["id"].as_u64().unwrap_or(u64::MAX) > since)
                .collect();
            json!(&events[events.len().saturating_sub(limit)..])
        }
        "/rest/db/status" => {
            if state.hold_snapshot.load(Ordering::SeqCst) {
                state.snapshots_held.fetch_add(1, Ordering::SeqCst);
                let mut byte = [0; 1];
                tokio::select! {
                    _=state.released.notified()=>(),
                    ended=socket.read(&mut byte)=>{if ended?==0 {return Ok(());}return Err("unexpected snapshot body".into());},
                }
            }
            json!({"state":state.folder_state.lock().unwrap().clone(),"localFiles":17})
        }
        "/rest/db/scan" => {
            if !header.starts_with("POST ") {
                return Err("scan command must use POST".into());
            }
            state.scan_requests.fetch_add(1, Ordering::SeqCst);
            json!({})
        }
        "/rest/config" => {
            json!({"folders":[{"id":"scan-contract","path":"/synthetic-only","label":"Scan contract","paused":state.folder_paused.load(Ordering::SeqCst)}]})
        }
        _ => return Err("unapproved event fixture route".into()),
    };
    let status = if state.denied.load(Ordering::SeqCst) {
        403
    } else {
        200
    };
    let body = serde_json::to_vec(&value)?;
    let head = format!(
        "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = socket.write_all(head.as_bytes()).await;
    let _ = socket.write_all(&body).await;
    Ok(())
}
fn fast() -> TestResult<EventOptions> {
    Ok(EventOptions::default()
        .poll_interval(Duration::from_millis(10))?
        .reconnect_delay(Duration::from_millis(10))?)
}
async fn next(stream: &mut EventSubscription) -> TestResult<EventStreamItem> {
    Ok(tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await?
        .ok_or("stream ended")??)
}
async fn observed(counter: &AtomicUsize, at_least: usize) -> TestResult {
    tokio::time::timeout(Duration::from_secs(2), async {
        while counter.load(Ordering::SeqCst) < at_least {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}

#[test]
fn options_validate_bounds_and_cursor_without_a_runtime() -> TestResult {
    assert!(EventOptions::default().queue_capacity(0).is_err());
    assert!(EventOptions::default().queue_capacity(1025).is_err());
    assert!(EventOptions::default().batch_limit(0).is_err());
    assert!(EventOptions::default().batch_limit(257).is_err());
    assert!(EventOptions::default()
        .poll_interval(Duration::ZERO)
        .is_err());
    assert!(EventOptions::default().reconnect_attempts(65).is_err());
    assert!(EventOptions::default()
        .reconnect_delay(Duration::ZERO)
        .is_err());
    assert!(EventOptions::default()
        .resume_from(EventCursor {
            source: EventSource::Standard,
            device_id: DeviceId::parse(ID)?,
            engine_started_at: None,
            last_id: u64::MAX
        })
        .is_err());
    Ok(())
}

#[tokio::test]
async fn unknown_payloads_are_retained_but_all_debug_views_hide_them() -> TestResult {
    let server = Server::start().await?;
    let client = server.client().await?;
    *server.state.generation.lock().unwrap() = KEY.to_owned();
    let mut stream = client.subscribe_events(fast()?).await?;
    server.replace(vec![event(1, "StartupCompleted"), event(2, KEY)]);
    let item = next(&mut stream).await?;
    assert!(!format!("{item:?} {stream:?}").contains(KEY));
    let EventStreamItem::Event(actual) = item else {
        return Err("event missing".into());
    };
    assert_eq!(actual.kind, EventKind::Unknown(KEY.to_owned()));
    assert_eq!(actual.data()["private"], KEY);
    assert_eq!(actual.extra()["future_field"], KEY);
    assert_eq!(stream.cursor().last_id, 2);
    stream.close().await?;
    server.finish().await
}

#[tokio::test]
async fn slow_consumers_have_a_bound_and_cursors_never_acknowledge_unconsumed_items() -> TestResult
{
    let server = Server::start().await?;
    let client = server.client().await?;
    let mut stream = client.subscribe_events(fast()?.queue_capacity(2)?).await?;
    server.replace((1..=80).map(|id| event(id, "FutureType")).collect());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(stream.buffered_items(), 2);
    assert_eq!(stream.cursor().last_id, 1);
    let EventStreamItem::Event(first) = next(&mut stream).await? else {
        return Err("first event missing".into());
    };
    assert_eq!(first.cursor.last_id, 2);
    assert_eq!(stream.cursor().last_id, 2);
    stream.close().await?;
    server.finish().await
}

#[tokio::test]
async fn cancelling_next_preserves_the_subscription_and_pending_event() -> TestResult {
    let server = Server::start().await?;
    let client = server.client().await?;
    let mut stream = client.subscribe_events(fast()?).await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(30), stream.next())
            .await
            .is_err()
    );
    assert_eq!(stream.cursor().last_id, 1);
    server.replace(vec![event(1, "StartupCompleted"), event(2, "ConfigSaved")]);
    assert!(
        matches!(next(&mut stream).await?,EventStreamItem::Event(e) if e.kind==EventKind::ConfigurationSaved)
    );
    stream.close().await?;
    server.finish().await
}

#[tokio::test]
async fn a_newest_tail_gap_and_reported_restart_require_reconciliation() -> TestResult {
    let server = Server::start().await?;
    let client = server.client().await?;
    let mut stream = client.subscribe_events(fast()?.batch_limit(1)?).await?;
    server.replace((1..=5).map(|id| event(id, "FutureType")).collect());
    let EventStreamItem::Gap(gap) = next(&mut stream).await? else {
        return Err("gap missing".into());
    };
    assert_eq!(gap.reason, EventGapReason::MissingEvents);
    assert_eq!(gap.resume_from.last_id, 4);
    assert!(matches!(next(&mut stream).await?,EventStreamItem::Event(e) if e.cursor.last_id==5));
    *server.state.generation.lock().unwrap() = "generation-two".to_owned();
    let EventStreamItem::Gap(gap) = next(&mut stream).await? else {
        return Err("restart gap missing".into());
    };
    assert_eq!(gap.reason, EventGapReason::EngineStartTimeChanged);
    stream.close().await?;
    server.finish().await
}

#[tokio::test]
async fn resume_checks_identity_before_io_and_reports_uncertain_continuity() -> TestResult {
    let server = Server::start().await?;
    let client = server.client().await?;
    let bad = EventCursor {
        source: EventSource::Standard,
        device_id: DeviceId::parse(OTHER)?,
        engine_started_at: None,
        last_id: 1,
    };
    assert!(matches!(
        client.subscribe_events(fast()?.resume_from(bad)?).await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert_eq!(server.state.event_reads.load(Ordering::SeqCst), 0);
    let cursor = EventCursor {
        source: EventSource::Standard,
        device_id: DeviceId::parse(ID)?,
        engine_started_at: Some("generation-one".to_owned()),
        last_id: 1,
    };
    let mut stream = client
        .subscribe_events(fast()?.resume_from(cursor)?)
        .await?;
    assert!(
        matches!(next(&mut stream).await?,EventStreamItem::Gap(g) if g.reason==EventGapReason::ResumedContinuityUnverified)
    );
    stream.close().await?;
    server.finish().await
}

#[tokio::test]
async fn reconnect_budget_is_finite_and_success_does_not_reset_it() -> TestResult {
    let server = Server::start().await?;
    let client = server.client().await?;
    let mut stream = client
        .subscribe_events(fast()?.reconnect_attempts(1)?)
        .await?;
    server.state.failures_left.store(1, Ordering::SeqCst);
    assert!(
        matches!(next(&mut stream).await?,EventStreamItem::Gap(g) if g.reason==EventGapReason::ConnectionInterrupted)
    );
    assert!(matches!(
        next(&mut stream).await?,
        EventStreamItem::Reconnected { attempts_used: 1 }
    ));
    server.state.failures_left.store(10, Ordering::SeqCst);
    assert!(
        matches!(next(&mut stream).await?,EventStreamItem::Gap(g) if g.reason==EventGapReason::ConnectionInterrupted)
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), stream.next()).await?,
        Some(Err(Error::Transport { .. }))
    ));
    assert!(stream.next().await.is_none());
    assert_eq!(server.state.failures_observed.load(Ordering::SeqCst), 2);
    stream.close().await?;
    server.finish().await
}

#[tokio::test]
async fn disabled_reconnect_and_forbidden_reads_never_retry() -> TestResult {
    for forbidden in [false, true] {
        let server = Server::start().await?;
        let client = server.client().await?;
        let mut stream = client
            .subscribe_events(fast()?.reconnect_attempts(0)?)
            .await?;
        if forbidden {
            server.state.denied.store(true, Ordering::SeqCst);
        } else {
            server.state.failures_left.store(10, Ordering::SeqCst);
        }
        if !forbidden {
            assert!(matches!(next(&mut stream).await?, EventStreamItem::Gap(_)));
        }
        let terminal = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await?
            .ok_or("terminal missing")?;
        assert!(matches!(
            (forbidden, terminal),
            (true, Err(Error::AccessDenied { .. })) | (false, Err(Error::Transport { .. }))
        ));
        assert!(stream.next().await.is_none());
        assert_eq!(
            server.state.failures_observed.load(Ordering::SeqCst),
            usize::from(!forbidden)
        );
        stream.close().await?;
        server.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn close_and_drop_cancel_actual_pending_http_reads_without_touching_the_client() -> TestResult
{
    let server = Server::start().await?;
    let client = server.client().await?;
    for explicit in [true, false] {
        server.state.hold.store(false, Ordering::SeqCst);
        let stream = client.subscribe_events(fast()?).await?;
        server.state.hold.store(true, Ordering::SeqCst);
        let expected = server.state.held.load(Ordering::SeqCst) + 1;
        observed(&server.state.held, expected).await?;
        if explicit {
            stream.close().await?;
        } else {
            drop(stream);
        }
        observed(&server.state.cancelled, expected).await?;
        assert_eq!(client.system_status().await?.device_id.as_str(), ID);
    }
    server.finish().await
}

#[tokio::test]
async fn malformed_or_disordered_events_end_without_retry_and_hide_diagnostics() -> TestResult {
    let server = Server::start().await?;
    let client = server.client().await?;
    let mut stream = client.subscribe_events(fast()?).await?;
    server.replace(vec![
        event(1, "StartupCompleted"),
        event(3, "FutureType"),
        event(2, "FutureType"),
    ]);
    let error = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await?
        .ok_or("schema error missing")?
        .expect_err("unordered events accepted");
    assert!(!format!("{error:?} {error}").contains(KEY));
    assert!(
        matches!(error,Error::InvalidResponse{response,..} if String::from_utf8_lossy(response.body_bytes()).contains(KEY))
    );
    assert!(stream.next().await.is_none());
    assert_eq!(server.state.failures_observed.load(Ordering::SeqCst), 0);
    stream.close().await?;
    server.replace(vec![
        json!({"id":2,"time":"","type":"Bad","data":{"private":KEY}}),
    ]);
    assert!(matches!(
        client.subscribe_events(fast()?).await,
        Err(Error::InvalidResponse { .. })
    ));
    server.finish().await
}

#[tokio::test]
async fn a_generation_change_during_a_snapshot_is_never_assigned_to_the_old_cursor() -> TestResult {
    let server = Server::start().await?;
    let client = server.client().await?;
    server.state.rotate_generation.store(1, Ordering::SeqCst);
    assert!(matches!(
        client.subscribe_events(fast()?).await,
        Err(Error::EventGenerationChanged)
    ));
    server.state.rotate_generation.store(0, Ordering::SeqCst);
    let mut stream = client
        .subscribe_events(fast()?.reconnect_attempts(0)?)
        .await?;
    let cursor = stream.cursor().clone();
    server.replace(vec![event(1, "StartupCompleted"), event(2, "ConfigSaved")]);
    server.state.rotate_generation.store(2, Ordering::SeqCst);
    assert!(
        matches!(next(&mut stream).await?,EventStreamItem::Gap(g) if g.reason==EventGapReason::ObservationChanged)
    );
    assert_eq!(stream.cursor(), &cursor);
    assert!(matches!(
        stream.next().await,
        Some(Err(Error::EventGenerationChanged))
    ));
    assert!(stream.next().await.is_none());
    stream.close().await?;
    server.finish().await
}

fn scan_event(id: u64, from: &str, to: &str) -> Value {
    let mut value = event(id, "StateChanged");
    value["data"] = json!({"folder":"scan-contract","from":from,"to":to});
    value
}

#[tokio::test]
async fn scan_observation_uses_real_transitions_and_preserves_unknown_progress_values() -> TestResult
{
    use verysync_sidecar::{FolderId, FolderState, ScanPhase};
    let server = Server::start().await?;
    let client = server.client().await?;
    let mut scan = client
        .observe_next_scan(&FolderId::parse("scan-contract")?)
        .await?;
    let mut progress = event(3, "FolderScanProgress");
    progress["data"] =
        json!({"folder":"scan-contract","current":4,"total":10,"rate":2.5,"future":KEY});
    server.replace(vec![
        event(1, "StartupCompleted"),
        scan_event(2, "idle", "scanning"),
        progress,
        scan_event(4, "scanning", "idle"),
    ]);
    let result = scan.wait(Duration::from_secs(5)).await?;
    assert_eq!(result.started.last_id, 2);
    assert_eq!(result.ended.last_id, 4);
    assert_eq!(result.exited_to, FolderState::Idle);
    assert_eq!(result.snapshot.local_files, Some(17));
    let progress = result
        .progress
        .as_ref()
        .ok_or("actual progress not retained")?;
    assert_eq!(progress.current, Some(4));
    assert_eq!(progress.total, Some(10));
    assert_eq!(progress.rate, Some(2.5));
    assert_eq!(progress.raw()["future"], KEY);
    assert!(!format!("{result:?} {scan:?}").contains(KEY));
    assert_eq!(scan.phase(), ScanPhase::Ended);
    assert_eq!(server.state.scan_requests.load(Ordering::SeqCst), 0);
    scan.close().await?;
    server.finish().await
}

#[tokio::test]
async fn missing_scan_entry_and_event_gaps_never_become_completion() -> TestResult {
    use verysync_sidecar::{FolderId, ScanPhase};
    for gap in [false, true] {
        let server = Server::start().await?;
        let client = server.client().await?;
        let mut scan = client
            .observe_next_scan(&FolderId::parse("scan-contract")?)
            .await?;
        server.replace(vec![
            event(1, "StartupCompleted"),
            if gap {
                scan_event(4, "idle", "scanning")
            } else {
                scan_event(2, "scanning", "idle")
            },
        ]);
        assert!(matches!(
            scan.wait(Duration::from_secs(5)).await,
            Err(Error::ScanObservationLost)
        ));
        assert_eq!(scan.phase(), ScanPhase::ObservationLost);
        assert!(matches!(
            scan.next_update().await,
            Err(Error::ScanObservationLost)
        ));
        scan.close().await?;
        server.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn scan_wait_timeout_and_close_never_send_a_mutation() -> TestResult {
    use verysync_sidecar::{FolderId, ScanPhase};
    let server = Server::start().await?;
    let client = server.client().await?;
    let mut scan = client
        .observe_next_scan(&FolderId::parse("scan-contract")?)
        .await?;
    assert!(scan.wait(Duration::ZERO).await.is_err());
    assert!(scan.wait(Duration::MAX).await.is_err());
    assert!(matches!(
        scan.wait(Duration::from_millis(10)).await,
        Err(Error::Timeout { .. })
    ));
    assert_eq!(scan.phase(), ScanPhase::AwaitingStart);
    scan.close().await?;
    assert_eq!(server.state.scan_requests.load(Ordering::SeqCst), 0);
    client.system_status().await?;
    server.finish().await
}

#[tokio::test]
async fn cancelling_terminal_snapshot_wait_does_not_lose_scan_completion() -> TestResult {
    use verysync_sidecar::FolderId;
    let server = Server::start().await?;
    let client = server.client().await?;
    let mut scan = client
        .observe_next_scan(&FolderId::parse("scan-contract")?)
        .await?;
    server.state.hold_snapshot.store(true, Ordering::SeqCst);
    server.replace(vec![
        event(1, "StartupCompleted"),
        scan_event(2, "idle", "scanning"),
        scan_event(3, "scanning", "idle"),
    ]);
    let waiting = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while server.state.snapshots_held.load(Ordering::SeqCst) == 0 {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    // Cancel only after observing the actual pending terminal-snapshot request.
    tokio::select! {
        result = scan.wait(Duration::from_secs(10)) => panic!("snapshot should remain pending: {result:?}"),
        () = waiting => (),
    }
    assert!(server.state.snapshots_held.load(Ordering::SeqCst) > 0);
    server.state.hold_snapshot.store(false, Ordering::SeqCst);
    server.state.released.notify_waiters();
    assert_eq!(scan.wait(Duration::from_secs(5)).await?.ended.last_id, 3);
    scan.close().await?;
    server.finish().await
}

#[tokio::test]
async fn scan_requests_are_explicit_and_paused_targets_reject_before_post() -> TestResult {
    use verysync_sidecar::FolderId;
    let server = Server::start().await?;
    let client = server.client().await?;
    let id = FolderId::parse("scan-contract")?;
    client.request_scan(&id).await?;
    assert_eq!(server.state.scan_requests.load(Ordering::SeqCst), 1);
    server.state.folder_paused.store(true, Ordering::SeqCst);
    *server.state.folder_state.lock().unwrap() = "paused".to_owned();
    assert!(matches!(
        client.request_scan(&id).await,
        Err(Error::ScanNotIdle)
    ));
    assert!(matches!(
        client.observe_next_scan(&id).await,
        Err(Error::ScanNotIdle)
    ));
    assert!(matches!(
        client
            .request_scan_subpaths(&id, &[verysync_sidecar::TargetPath::local("sample.bin")])
            .await,
        Err(Error::ScanNotIdle)
    ));
    server.state.folder_paused.store(false, Ordering::SeqCst);
    *server.state.folder_state.lock().unwrap() = "scanning".to_owned();
    assert_eq!(
        client.folder_status(&id).await?.state,
        Some(verysync_sidecar::FolderState::Scanning)
    );
    let error = client.observe_next_scan(&id).await.unwrap_err();
    assert!(matches!(error, Error::ScanNotIdle));
    assert_eq!(server.state.scan_requests.load(Ordering::SeqCst), 1);
    server.finish().await?;
    let display = error.to_string();
    let debug = format!("{error:?}");
    assert!(std::error::Error::source(&error).is_none());
    assert!(!format!("{display} {debug}").contains(KEY));
    println!(
        "candidate feedback: {}",
        json!({
            "case":"busy-observe-next-scan", "type":"ScanNotIdle", "display":display,
            "debug":debug, "cause":null, "additional_scan_posts":0, "normal_scan_posts":1
        })
    );
    assert!(display.contains("If it is busy, wait for the current activity to finish"));
    assert_eq!(debug, format!("Error({display})"));
    Ok(())
}

#[tokio::test]
async fn scan_phase_exit_does_not_claim_peer_sync_or_mask_error_states() -> TestResult {
    use verysync_sidecar::{FolderId, FolderState};
    for next in ["syncing", "paused", "error"] {
        let server = Server::start().await?;
        let client = server.client().await?;
        let mut scan = client
            .observe_next_scan(&FolderId::parse("scan-contract")?)
            .await?;
        *server.state.folder_state.lock().unwrap() = next.to_owned();
        server.replace(vec![
            event(1, "StartupCompleted"),
            scan_event(2, "idle", "scanning"),
            scan_event(3, "scanning", next),
        ]);
        let result = scan.wait(Duration::from_secs(5)).await?;
        assert_ne!(result.exited_to, FolderState::Idle);
        assert_eq!(serde_json::to_value(&result.exited_to)?, next);
        assert_eq!(result.snapshot.state, Some(result.exited_to.clone()));
        scan.close().await?;
        server.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn disk_event_sources_are_distinct_and_resume_mismatch_is_rejected_before_io() -> TestResult {
    let server = Server::start().await?;
    let client = server.client().await?;
    let mut disk = client.subscribe_disk_events(fast()?).await?;
    assert_eq!(disk.cursor().source, EventSource::Disk);
    assert_eq!(disk.cursor().last_id, 0);
    assert!(tokio::time::timeout(Duration::from_millis(25), disk.next())
        .await
        .is_err());
    let standard = client.subscribe_events(fast()?).await?;
    assert_eq!(standard.cursor().source, EventSource::Standard);
    assert_eq!(standard.cursor().last_id, 1);
    let wrong_for_disk = standard.cursor().clone();
    let wrong_for_standard = disk.cursor().clone();
    standard.close().await?;
    disk.close().await?;
    let reads = server.state.event_reads.load(Ordering::SeqCst);
    assert!(matches!(
        client
            .subscribe_disk_events(fast()?.resume_from(wrong_for_disk)?)
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        client
            .subscribe_events(fast()?.resume_from(wrong_for_standard)?)
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert_eq!(server.state.event_reads.load(Ordering::SeqCst), reads);
    let mut disk = client
        .subscribe_disk_events(fast()?.queue_capacity(2)?)
        .await?;
    *server.state.disk_events.lock().unwrap() = vec![
        event(1, "LocalChangeDetected"),
        event(2, "RemoteChangeDetected"),
        event(3, KEY),
    ];
    tokio::time::timeout(Duration::from_secs(2), async {
        while disk.buffered_items() < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    assert_eq!(disk.buffered_items(), 2);
    assert_eq!(disk.cursor().last_id, 0);
    for (id, kind) in [
        (1, EventKind::LocalChangeDetected),
        (2, EventKind::RemoteChangeDetected),
        (3, EventKind::Unknown(KEY.to_owned())),
    ] {
        let item = next(&mut disk).await?;
        assert!(!format!("{item:?}").contains(KEY));
        let EventStreamItem::Event(e) = item else {
            return Err("expected disk event".into());
        };
        assert_eq!(e.cursor.source, EventSource::Disk);
        assert_eq!(e.cursor.last_id, id);
        assert_eq!(e.kind, kind);
        assert_eq!(e.data()["private"], KEY);
        assert_eq!(e.extra()["future_field"], KEY);
        let stored = serde_json::to_vec(&e.cursor)?;
        assert_eq!(serde_json::from_slice::<EventCursor>(&stored)?, e.cursor);
    }
    let cursor = disk.cursor().clone();
    disk.close().await?;
    let mut resumed = client
        .subscribe_disk_events(fast()?.resume_from(cursor)?)
        .await?;
    assert!(
        matches!(next(&mut resumed).await?,EventStreamItem::Gap(g) if g.reason==EventGapReason::ResumedContinuityUnverified && g.resume_from.source==EventSource::Disk)
    );
    resumed.close().await?;
    assert!(server.state.disk_reads.load(Ordering::SeqCst) > 0);
    server.finish().await
}

#[tokio::test]
async fn disk_event_tail_loss_and_malformed_batches_use_existing_strict_bounds() -> TestResult {
    let server = Server::start().await?;
    let client = server.client().await?;
    *server.state.disk_events.lock().unwrap() = vec![event(1, "LocalChangeDetected")];
    let mut disk = client
        .subscribe_disk_events(fast()?.batch_limit(1)?)
        .await?;
    *server.state.disk_events.lock().unwrap() =
        (1..=4).map(|id| event(id, "LocalChangeDetected")).collect();
    assert!(
        matches!(next(&mut disk).await?,EventStreamItem::Gap(g) if g.reason==EventGapReason::MissingEvents && g.previous.source==EventSource::Disk)
    );
    assert!(matches!(next(&mut disk).await?,EventStreamItem::Event(e) if e.cursor.last_id==4));
    disk.close().await?;
    *server.state.disk_events.lock().unwrap() =
        vec![json!({"id":1,"type":"LocalChangeDetected","time":""})];
    assert!(matches!(
        client.subscribe_disk_events(fast()?).await,
        Err(Error::InvalidResponse { .. })
    ));
    server.finish().await
}

#[tokio::test]
async fn disk_event_initial_transport_failure_returns_without_retry_or_task() -> TestResult {
    let server = Server::start().await?;
    let client = server.client().await?;
    server.state.failures_left.store(1, Ordering::SeqCst);
    assert!(matches!(
        client
            .subscribe_disk_events(fast()?.reconnect_attempts(64)?)
            .await,
        Err(Error::Transport { .. })
    ));
    assert_eq!(server.state.disk_reads.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(server.state.disk_reads.load(Ordering::SeqCst), 1);
    server.finish().await
}

#[test]
fn event_name_filters_are_canonical_private_bounded_and_validate_deserialized_input() -> TestResult
{
    let f = EventFilter::new([
        EventKind::StateChanged,
        EventKind::ConfigurationSaved,
        EventKind::StateChanged,
    ])?;
    let same = EventFilter::new([EventKind::ConfigurationSaved, EventKind::StateChanged])?;
    assert_eq!(f, same);
    assert_eq!(
        f.names().collect::<Vec<_>>(),
        vec!["ConfigSaved", "StateChanged"]
    );
    let serialized = serde_json::to_string(&f)?;
    assert_eq!(serialized, "\"ConfigSaved,StateChanged\"");
    assert_eq!(serde_json::from_str::<EventFilter>(&serialized)?, f);
    for name in [
        "",
        "a,b",
        "ConfigSaved StateChanged",
        " leading",
        "line\nfeed",
    ] {
        assert!(EventFilter::new([EventKind::Unknown(name.to_owned())]).is_err());
    }
    assert!(EventFilter::new([]).is_err());
    assert!(EventFilter::new([EventKind::Unknown("x".repeat(129))]).is_err());
    assert!(EventFilter::new((0..65).map(|_| EventKind::StateChanged)).is_err());
    for serialized in ["\"\"", "\"x,,y\"", "\"x y\"", "{}", "null"] {
        assert!(serde_json::from_str::<EventFilter>(serialized).is_err());
    }
    let private = EventFilter::new([EventKind::Unknown(KEY.to_owned())])?;
    assert!(!format!("{private:?} {:?}", EventSource::Filtered(private.clone())).contains(KEY));
    Ok(())
}

#[tokio::test]
async fn filtered_event_sources_keep_independent_ids_and_canonical_query_masks() -> TestResult {
    let server = Server::start().await?;
    let client = server.client().await?;
    let filter = EventFilter::new([
        EventKind::StateChanged,
        EventKind::ConfigurationSaved,
        EventKind::ConfigurationSaved,
    ])?;
    let different = EventFilter::new([EventKind::FolderPaused])?;
    server.state.filtered_events.lock().unwrap().insert(
        "ConfigSaved,StateChanged".to_owned(),
        vec![event(1, "ConfigSaved")],
    );
    let mut stream = client
        .subscribe_filtered_events(filter.clone(), fast()?)
        .await?;
    assert_eq!(
        stream.cursor().source,
        EventSource::Filtered(filter.clone())
    );
    assert_eq!(stream.cursor().last_id, 1);
    server
        .state
        .filtered_events
        .lock()
        .unwrap()
        .get_mut("ConfigSaved,StateChanged")
        .unwrap()
        .push(event(2, "StateChanged"));
    let EventStreamItem::Event(e) = next(&mut stream).await? else {
        return Err("filtered record missing".into());
    };
    assert_eq!(e.kind, EventKind::StateChanged);
    assert_eq!(e.cursor.source, EventSource::Filtered(filter.clone()));
    assert_eq!(e.cursor.last_id, 2);
    let cursor = stream.cursor().clone();
    stream.close().await?;
    let before = server.state.event_reads.load(Ordering::SeqCst);
    assert!(matches!(
        client
            .subscribe_filtered_events(different, fast()?.resume_from(cursor.clone())?)
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        client
            .subscribe_events(fast()?.resume_from(cursor.clone())?)
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        client
            .subscribe_disk_events(fast()?.resume_from(cursor.clone())?)
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert_eq!(server.state.event_reads.load(Ordering::SeqCst), before);
    let equivalent = EventFilter::new([EventKind::ConfigurationSaved, EventKind::StateChanged])?;
    let mut resumed = client
        .subscribe_filtered_events(equivalent, fast()?.resume_from(cursor)?)
        .await?;
    assert!(
        matches!(next(&mut resumed).await?,EventStreamItem::Gap(g) if g.reason==EventGapReason::ResumedContinuityUnverified&&g.resume_from.source==EventSource::Filtered(filter.clone()))
    );
    resumed.close().await?;
    assert!(server
        .state
        .filter_queries
        .lock()
        .unwrap()
        .iter()
        .all(|s| s == "ConfigSaved,StateChanged"));
    server.finish().await
}
