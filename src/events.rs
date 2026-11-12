//! Bounded, caller-owned event subscriptions for the fixed baseline.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::{Client, DeviceId, Error, ResponseDiagnostic, Result, BASELINE_ENGINE_VERSION};

/// A consumed position in the upstream event sequence, bound to engine identity.
///
/// The start time is the upstream string, not a durable generation identifier.
/// Resuming always reports that continuity needs reconciliation; it cannot prove
/// no unobserved restart occurred between subscriptions.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct EventCursor {
    /// Authenticated engine device identity.
    pub device_id: DeviceId,
    /// Reported engine start time, when available.
    pub engine_started_at: Option<String>,
    /// Last consumed sequence ID; zero means before the first event.
    pub last_id: u64,
}
impl fmt::Debug for EventCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventCursor")
            .field("device_id", &self.device_id)
            .field("generation_reported", &self.engine_started_at.is_some())
            .field("last_id", &self.last_id)
            .finish()
    }
}

/// Event names whose presence has been observed in the fixed engine baseline.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum EventKind {
    /// The engine saved its configuration. Payloads can contain credentials.
    ConfigurationSaved,
    /// One folder was paused.
    FolderPaused,
    /// One folder resumed.
    FolderResumed,
    /// One folder's activity state changed.
    StateChanged,
    /// Another upstream name, retained without discarding its payload.
    Unknown(String),
}
impl fmt::Debug for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ConfigurationSaved => "ConfigurationSaved",
            Self::FolderPaused => "FolderPaused",
            Self::FolderResumed => "FolderResumed",
            Self::StateChanged => "StateChanged",
            Self::Unknown(_) => "Unknown(..)",
        })
    }
}

/// One bounded upstream event. Ordinary Debug excludes all payload/extra values.
#[derive(Clone)]
pub struct EngineEvent {
    /// Position after consuming this event.
    pub cursor: EventCursor,
    /// Upstream global ID, if supplied; not interchangeable with the sequence ID.
    pub global_id: Option<u64>,
    /// Upstream timestamp string, without clock normalization.
    pub time: String,
    /// Known name or an explicitly unknown name.
    pub kind: EventKind,
    data: serde_json::Value,
    extra: BTreeMap<String, serde_json::Value>,
}

impl EngineEvent {
    /// Explicitly inspect the upstream payload, which may contain credentials.
    pub fn data(&self) -> &serde_json::Value {
        &self.data
    }
    /// Inspect unmodeled envelope fields, without silently dropping them.
    pub fn extra(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.extra
    }
}
impl fmt::Debug for EngineEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineEvent")
            .field("cursor", &self.cursor)
            .field("kind", &self.kind)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// Why state must be queried again before treating event-derived data as complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EventGapReason {
    /// A new subscription resumed a cursor without a durable server generation token.
    ResumedContinuityUnverified,
    /// The reported engine start time changed.
    EngineStartTimeChanged,
    /// The newest sequence ID moved behind the consumed position.
    CursorReset,
    /// The next available event skipped one or more sequence IDs.
    MissingEvents,
    /// A transport failure or deadline interrupted observation.
    ConnectionInterrupted,
    /// A previously advertised batch was no longer available.
    BatchUnavailable,
    /// Status reads before and after the event snapshot disagreed on generation.
    ObservationChanged,
}

/// Explicit loss/uncertainty notification; callers must refresh relevant state.
#[derive(Clone, Debug)]
pub struct EventGap {
    /// The observed reason, without claiming a complete history of server failures.
    pub reason: EventGapReason,
    /// Position before this gap.
    pub previous: EventCursor,
    /// Position used after consuming this notification.
    pub resume_from: EventCursor,
}

/// An ordered event, gap notification or successful bounded reconnection.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum EventStreamItem {
    /// An actual upstream event.
    Event(EngineEvent),
    /// Continuity is incomplete or cannot be established; refresh state explicitly.
    Gap(EventGap),
    /// Reads recovered after this many total reconnect attempts in this subscription.
    Reconnected {
        /// Total attempts consumed; the budget is never reset by success.
        attempts_used: u16,
    },
}

/// Resource and recovery policy for one explicitly started event subscription.
#[derive(Clone, Debug)]
pub struct EventOptions {
    cursor: Option<EventCursor>,
    queue_capacity: usize,
    batch_limit: usize,
    poll_interval: Duration,
    reconnect_attempts: u16,
    reconnect_delay: Duration,
}
impl Default for EventOptions {
    fn default() -> Self {
        Self {
            cursor: None,
            queue_capacity: 32,
            batch_limit: 256,
            poll_interval: Duration::from_secs(1),
            reconnect_attempts: 3,
            reconnect_delay: Duration::from_secs(1),
        }
    }
}
impl EventOptions {
    /// Resume this cursor. Identity is checked before subscription network reads.
    pub fn resume_from(mut self, cursor: EventCursor) -> Result<Self> {
        if cursor.last_id >= i64::MAX as u64
            || cursor
                .engine_started_at
                .as_ref()
                .is_some_and(String::is_empty)
        {
            return Err(invalid_options());
        }
        self.cursor = Some(cursor);
        Ok(self)
    }
    /// Bound queued items to 1..=1024 (default 32); a full queue applies backpressure.
    pub fn queue_capacity(mut self, capacity: usize) -> Result<Self> {
        if !(1..=1024).contains(&capacity) {
            return Err(invalid_options());
        }
        self.queue_capacity = capacity;
        Ok(self)
    }
    /// Ask for at most 1..=256 events per buffered upstream response (default 256).
    /// The engine returns the newest tail, so small batches can produce explicit gaps.
    pub fn batch_limit(mut self, limit: usize) -> Result<Self> {
        if !(1..=256).contains(&limit) {
            return Err(invalid_options());
        }
        self.batch_limit = limit;
        Ok(self)
    }
    /// Set snapshot polling to 10ms..=60s (default 1s), independently of request deadlines.
    pub fn poll_interval(mut self, interval: Duration) -> Result<Self> {
        if interval < Duration::from_millis(10) || interval > Duration::from_secs(60) {
            return Err(invalid_options());
        }
        self.poll_interval = interval;
        Ok(self)
    }
    /// Set the lifetime reconnect budget, 0..=64. Zero disables automatic recovery.
    pub fn reconnect_attempts(mut self, attempts: u16) -> Result<Self> {
        if attempts > 64 {
            return Err(invalid_options());
        }
        self.reconnect_attempts = attempts;
        Ok(self)
    }
    /// Set fixed recovery delay to 10ms..=60s (default 1s); no mutation is retried.
    pub fn reconnect_delay(mut self, delay: Duration) -> Result<Self> {
        if delay < Duration::from_millis(10) || delay > Duration::from_secs(60) {
            return Err(invalid_options());
        }
        self.reconnect_delay = delay;
        Ok(self)
    }
}
fn invalid_options() -> Error {
    Error::InvalidConfiguration {
        reason: "event option is outside its documented bound",
    }
}

/// A bounded subscription whose task belongs to this value, never to the engine.
///
/// Dropping aborts its pending read/backpressure wait. [`Self::close`] also awaits
/// task cancellation. Neither action stops an engine. Cancelling [`Self::next`]
/// alone leaves the subscription active and does not consume a queued item.
pub struct EventSubscription {
    receiver: mpsc::Receiver<Result<EventStreamItem>>,
    task: Option<JoinHandle<()>>,
    cursor: EventCursor,
}
impl EventSubscription {
    /// Receive the next item or terminal error; `None` means the task has ended.
    pub async fn next(&mut self) -> Option<Result<EventStreamItem>> {
        let item = self.receiver.recv().await?;
        match &item {
            Ok(EventStreamItem::Event(event)) => self.cursor = event.cursor.clone(),
            Ok(EventStreamItem::Gap(gap)) => self.cursor = gap.resume_from.clone(),
            _ => (),
        }
        Some(item)
    }
    /// Position of the last consumed item, never a producer's unconsumed queue tail.
    pub fn cursor(&self) -> &EventCursor {
        &self.cursor
    }
    /// Current number of queued items, bounded by the selected capacity.
    pub fn buffered_items(&self) -> usize {
        self.receiver.len()
    }
    /// Cancel and await this subscription's task without sending an engine command.
    pub async fn close(mut self) -> Result<()> {
        self.receiver.close();
        if let Some(task) = self.task.take() {
            task.abort();
            match task.await {
                Ok(()) => (),
                Err(error) if error.is_cancelled() => (),
                Err(_) => return Err(Error::EventSubscriptionFailure),
            }
        }
        Ok(())
    }
}
impl Drop for EventSubscription {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl fmt::Debug for EventSubscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventSubscription")
            .field("cursor", &self.cursor)
            .field("buffered_items", &self.buffered_items())
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
pub(crate) struct WireEvent {
    id: u64,
    #[serde(rename = "globalID")]
    global_id: Option<u64>,
    time: String,
    #[serde(rename = "type")]
    name: String,
    #[serde(default)]
    data: serde_json::Value,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}
impl WireEvent {
    fn into_event(self, mut cursor: EventCursor) -> EngineEvent {
        cursor.last_id = self.id;
        let kind = match self.name.as_str() {
            "ConfigSaved" => EventKind::ConfigurationSaved,
            "FolderPaused" => EventKind::FolderPaused,
            "FolderResumed" => EventKind::FolderResumed,
            "StateChanged" => EventKind::StateChanged,
            _ => EventKind::Unknown(self.name),
        };
        EngineEvent {
            cursor,
            global_id: self.global_id,
            time: self.time,
            kind,
            data: self.data,
            extra: self.extra,
        }
    }
}

pub(crate) fn validate_wire(events: &[WireEvent], limit: usize) -> bool {
    events.len() <= limit
        && events
            .iter()
            .all(|e| e.id > 0 && e.id < i64::MAX as u64 && !e.name.is_empty() && !e.time.is_empty())
        && events.windows(2).all(|pair| pair[0].id < pair[1].id)
}

async fn head(client: &Client) -> Result<EventCursor> {
    let status = client.system_status().await?;
    let latest = client.event_wire(0, 1).await?;
    let after = client.system_status().await?;
    if status.start_time != after.start_time {
        return Err(Error::EventGenerationChanged);
    }
    Ok(EventCursor {
        device_id: status.device_id,
        engine_started_at: status.start_time,
        last_id: latest.last().map_or(0, |e| e.id),
    })
}

impl Client {
    /// Start an explicitly owned bounded event subscription for the fixed baseline.
    ///
    /// Establishes an authenticated current cursor before returning. With no
    /// resume cursor, earlier history is deliberately excluded. No background
    /// task is started if initial validation/reads fail. Polls use a newest-event
    /// snapshot before requesting a known available tail; this avoids the fixed
    /// engine's broken response observed for a cursor ahead of its current ID.
    pub async fn subscribe_events(&self, options: EventOptions) -> Result<EventSubscription> {
        tokio::runtime::Handle::try_current().map_err(|_| Error::InvalidConfiguration {
            reason: "event subscriptions require a Tokio runtime with I/O and timers",
        })?;
        if let Some(cursor) = &options.cursor {
            if cursor.device_id != self.instance().device_id {
                return Err(Error::IdentityMismatch {
                    expected: cursor.device_id.clone(),
                    actual: self.instance().device_id.clone(),
                });
            }
        }
        verify_version(self).await?;
        let latest = head(self).await?;
        let cursor = options.cursor.clone().unwrap_or_else(|| latest.clone());
        let (sender, receiver) = mpsc::channel(options.queue_capacity);
        let worker_cursor = cursor.clone();
        let client = self.clone();
        let task = tokio::spawn(async move {
            run(client, options, worker_cursor, latest, sender).await;
        });
        Ok(EventSubscription {
            receiver,
            task: Some(task),
            cursor,
        })
    }
}

async fn verify_version(client: &Client) -> Result<()> {
    if client.version().await?.version != BASELINE_ENGINE_VERSION {
        return Err(Error::IncompatibleVersion {
            actual: "event engine is outside the fixed baseline".to_owned(),
        });
    }
    Ok(())
}
async fn send(sender: &mpsc::Sender<Result<EventStreamItem>>, item: EventStreamItem) -> bool {
    sender.send(Ok(item)).await.is_ok()
}
async fn gap(
    sender: &mpsc::Sender<Result<EventStreamItem>>,
    reason: EventGapReason,
    previous: &EventCursor,
    resume_from: &EventCursor,
) -> bool {
    send(
        sender,
        EventStreamItem::Gap(EventGap {
            reason,
            previous: previous.clone(),
            resume_from: resume_from.clone(),
        }),
    )
    .await
}
async fn batch(
    client: &Client,
    options: &EventOptions,
    cursor: &mut EventCursor,
    latest: EventCursor,
    sender: &mpsc::Sender<Result<EventStreamItem>>,
) -> Result<bool> {
    let reason = if latest.engine_started_at != cursor.engine_started_at {
        Some(EventGapReason::EngineStartTimeChanged)
    } else if latest.last_id < cursor.last_id {
        Some(EventGapReason::CursorReset)
    } else {
        None
    };
    if let Some(reason) = reason {
        verify_version(client).await?;
        if !gap(sender, reason, cursor, &latest).await {
            return Ok(false);
        }
        *cursor = latest;
    } else if latest.last_id > cursor.last_id {
        let events = client
            .event_wire(cursor.last_id, options.batch_limit)
            .await?;
        if client.system_status().await?.start_time != cursor.engine_started_at {
            return Err(Error::EventGenerationChanged);
        }
        if let Some(first) = events.first() {
            if first.id <= cursor.last_id {
                return Err(invalid_batch());
            }
            if first.id != cursor.last_id + 1 {
                let mut resume = cursor.clone();
                resume.last_id = first.id - 1;
                if !gap(sender, EventGapReason::MissingEvents, cursor, &resume).await {
                    return Ok(false);
                }
            }
            for wire in events {
                let event = wire.into_event(cursor.clone());
                let next = event.cursor.clone();
                if !send(sender, EventStreamItem::Event(event)).await {
                    return Ok(false);
                }
                *cursor = next;
            }
        } else {
            if !gap(sender, EventGapReason::BatchUnavailable, cursor, &latest).await {
                return Ok(false);
            }
            *cursor = latest;
        }
    }
    Ok(true)
}
fn invalid_batch() -> Error {
    Error::InvalidResponse {
        operation: "read ordered engine events",
        response: ResponseDiagnostic::new(200, Vec::new()),
    }
}
async fn run(
    client: Client,
    options: EventOptions,
    mut cursor: EventCursor,
    initial: EventCursor,
    sender: mpsc::Sender<Result<EventStreamItem>>,
) {
    if options.cursor.is_some()
        && !gap(
            &sender,
            EventGapReason::ResumedContinuityUnverified,
            &cursor,
            &cursor,
        )
        .await
    {
        return;
    }
    let mut snapshot = Some(initial);
    let mut attempts = 0;
    let mut recovering = false;
    loop {
        let observation = async {
            if recovering {
                verify_version(&client).await?;
            }
            let latest = match snapshot.take() {
                Some(latest) => latest,
                None => head(&client).await?,
            };
            if recovering
                && !send(
                    &sender,
                    EventStreamItem::Reconnected {
                        attempts_used: attempts,
                    },
                )
                .await
            {
                return Ok(false);
            }
            batch(&client, &options, &mut cursor, latest, &sender).await
        };
        let result =
            tokio::select! { _ = sender.closed() => return, result = observation => result };
        match result {
            Ok(false) => return,
            Ok(true) => recovering = false,
            Err(error) => {
                let retryable = matches!(
                    error,
                    Error::Transport { .. } | Error::Timeout { .. } | Error::EventGenerationChanged
                );
                let reason = if matches!(error, Error::EventGenerationChanged) {
                    EventGapReason::ObservationChanged
                } else {
                    EventGapReason::ConnectionInterrupted
                };
                if retryable && !gap(&sender, reason, &cursor, &cursor).await {
                    return;
                }
                if !retryable || attempts >= options.reconnect_attempts {
                    let _ = sender.send(Err(error)).await;
                    return;
                }
                attempts += 1;
                recovering = true;
            }
        }
        tokio::select! {
            _ = sender.closed() => return,
            _ = tokio::time::sleep(if recovering { options.reconnect_delay } else { options.poll_interval }) => (),
        }
    }
}
