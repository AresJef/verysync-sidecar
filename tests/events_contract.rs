//! Synthetic event transport/failure evidence; not engine-effect acceptance.
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
    ApiKey, Client, ConnectOptions, DeviceId, Error, EventCursor, EventGapReason, EventKind,
    EventOptions, EventStreamItem, EventSubscription, ManagementEndpoint,
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
    generation: Mutex<String>,
    failures_left: AtomicUsize,
    failures_observed: AtomicUsize,
    event_reads: AtomicUsize,
    hold: AtomicBool,
    held: AtomicUsize,
    cancelled: AtomicUsize,
    denied: AtomicBool,
    rotate_generation: AtomicUsize,
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
            generation: Mutex::new("generation-one".to_owned()),
            failures_left: AtomicUsize::new(0),
            failures_observed: AtomicUsize::new(0),
            event_reads: AtomicUsize::new(0),
            hold: AtomicBool::new(false),
            held: AtomicUsize::new(0),
            cancelled: AtomicUsize::new(0),
            denied: AtomicBool::new(false),
            rotate_generation: AtomicUsize::new(0),
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
        "/rest/events" => {
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
            let events: Vec<_> = state
                .events
                .lock()
                .unwrap()
                .iter()
                .filter(|e| e["id"].as_u64().unwrap_or(u64::MAX) > since)
                .cloned()
                .collect();
            json!(&events[events.len().saturating_sub(limit)..])
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
