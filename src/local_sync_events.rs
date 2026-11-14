//! Pull-driven native Local Sync events, separate from P2P event sequences.
use crate::{Client, DeviceId, Error, EventGapReason, LocalSyncJobId, ResponseDiagnostic, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    time::Duration,
};
use tokio::sync::watch;

/// Identity and last consumed position for the native Local Sync event log.
/// The reported start time is not a durable server generation identifier.
#[derive(Clone, Serialize, Deserialize)]
pub struct LocalSyncEventCursor {
    /// Authenticated core identity; other devices cannot resume this cursor.
    pub device_id: DeviceId,
    /// Target-reported engine start time, when available.
    pub engine_started_at: Option<String>,
    /// Last consumed Local Sync sequence, distinct from P2P event IDs.
    pub last_sequence: u64,
}
impl fmt::Debug for LocalSyncEventCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSyncEventCursor")
            .field("generation_reported", &self.engine_started_at.is_some())
            .field("last_sequence", &self.last_sequence)
            .finish_non_exhaustive()
    }
}
/// One native event; private paths and unknown payloads are omitted by Debug.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalSyncEvent {
    /// Exact Local Sync sequence, including the native log's own ordering.
    pub sequence: u64,
    /// Registration identity when the event identifies one.
    #[serde(default, deserialize_with = "optional_job")]
    pub job_id: Option<LocalSyncJobId>,
    /// Exact native event category, retaining unknown future names.
    #[serde(rename = "type")]
    pub kind: String,
    /// Native timestamp text, without controller clock substitution.
    pub time: String,
    /// Native action ID when supplied. Some non-action events use zero as a
    /// placeholder, so interpret it together with the event category.
    pub action_id: Option<u64>,
    /// Private target-relative path when reported.
    pub path: Option<String>,
    /// Native progress bytes; these are not proof of durable destination bytes.
    pub bytes: Option<u64>,
    /// Native cancellation flag when reported.
    pub cancelled: Option<bool>,
    /// Other private native fields, including unknown event payloads.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for LocalSyncEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSyncEvent")
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}
/// Exact native event response; absent reset/missed flags are schema errors.
#[derive(Deserialize)]
pub struct LocalSyncEventBatch {
    /// Actual returned events, possibly a known empty list.
    pub events: Vec<LocalSyncEvent>,
    /// Native response cursor; it is not an automatically consumed position.
    pub cursor: u64,
    /// The native log reports a cursor reset.
    pub reset: bool,
    /// The native log reports missed history.
    pub missed: bool,
}
impl fmt::Debug for LocalSyncEventBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSyncEventBatch")
            .field("events", &self.events.len())
            .field("cursor", &self.cursor)
            .field("reset", &self.reset)
            .field("missed", &self.missed)
            .finish()
    }
}
/// One explicit continuity warning. Refresh affected state before relying on it.
#[derive(Clone, Debug)]
pub struct LocalSyncEventGap {
    /// Native reset, loss or observation uncertainty.
    pub reason: EventGapReason,
    /// Previously consumed position.
    pub previous: LocalSyncEventCursor,
    /// Position after consuming this warning.
    pub resume_from: LocalSyncEventCursor,
}
/// Actual event or explicit continuity warning; acknowledgements are not events.
#[derive(Debug)]
pub enum LocalSyncEventStreamItem {
    /// One actual native event and its consumed cursor.
    Event {
        /// Actual event from this native log.
        event: LocalSyncEvent,
        /// Position after consuming that event.
        cursor: LocalSyncEventCursor,
    },
    /// Lost or unverifiable continuity; no event is synthesized.
    Gap(LocalSyncEventGap),
}
/// Bounded explicit policy for a pull-driven Local Sync subscription.
#[derive(Clone, Debug)]
pub struct LocalSyncEventOptions {
    cursor: Option<LocalSyncEventCursor>,
    max_events: usize,
    wait_seconds: u8,
}
impl Default for LocalSyncEventOptions {
    fn default() -> Self {
        Self {
            cursor: None,
            max_events: 1024,
            wait_seconds: 1,
        }
    }
}
impl LocalSyncEventOptions {
    /// Resume an exact Local Sync cursor. The first item warns that durable
    /// continuity cannot be established by an upstream start-time string.
    pub fn resume(mut self, cursor: LocalSyncEventCursor) -> Self {
        self.cursor = Some(cursor);
        self
    }
    /// Bound one buffered batch to 1..=4096 events, default 1024. Native response
    /// byte limits still apply; oversized batches fail rather than being cut.
    pub fn max_events(mut self, max: usize) -> Result<Self> {
        if !(1..=4096).contains(&max) {
            return Err(crate::local_sync::invalid(
                "Local Sync event batch bound differs",
            ));
        }
        self.max_events = max;
        Ok(self)
    }
    /// Explicit native long-poll wait, 0..=55 seconds. Choose a management
    /// deadline that can contain it; the SDK does not change that deadline.
    pub fn wait_seconds(mut self, seconds: u8) -> Result<Self> {
        if seconds > 55 {
            return Err(crate::local_sync::invalid(
                "Local Sync event wait exceeds native bound",
            ));
        }
        self.wait_seconds = seconds;
        Ok(self)
    }
}
/// Independently cloneable cancellation handle; it sends no core command.
#[derive(Clone)]
pub struct LocalSyncEventCancellation {
    sender: watch::Sender<bool>,
}
impl LocalSyncEventCancellation {
    /// Cancel the pending read and end this subscription without stopping jobs.
    pub fn cancel(&self) {
        self.sender.send_replace(true);
    }
}
impl fmt::Debug for LocalSyncEventCancellation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalSyncEventCancellation(..)")
    }
}
/// Pull-driven, bounded event subscription with no background task or global
/// handler. Dropping a pending next future consumes no queued event. Errors end
/// this subscription after a gap and terminal error; resumption is explicit.
pub struct LocalSyncEventSubscription {
    client: Client,
    options: LocalSyncEventOptions,
    cursor: LocalSyncEventCursor,
    pending: VecDeque<Result<LocalSyncEventStreamItem>>,
    cancellation: LocalSyncEventCancellation,
    cancelled: watch::Receiver<bool>,
    ended: bool,
}
impl fmt::Debug for LocalSyncEventSubscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSyncEventSubscription")
            .field("buffered_items", &self.pending.len())
            .finish_non_exhaustive()
    }
}
impl Client {
    /// Create an explicit pull-driven Local Sync subscription. With no resume
    /// cursor, the retained native history is requested from sequence zero;
    /// native missed/reset flags remain visible. No network read starts here.
    ///
    /// ```no_run
    /// use verysync_sidecar::{Client, LocalSyncEventOptions, Result};
    /// # async fn observe(client: &Client) -> Result<()> {
    /// let mut events = client.subscribe_local_sync_events(LocalSyncEventOptions::default())?;
    /// let cancellation = events.cancellation_handle();
    /// if let Some(item) = events.next().await {
    ///     let _item = item?; // Inspect the event or gap and correlate actual state.
    ///     let _consumed = events.cursor().clone(); // Persist explicitly if needed.
    /// }
    /// cancellation.cancel(); // Sends no command to the core or storage job.
    /// # Ok(())
    /// # }
    /// ```
    pub fn subscribe_local_sync_events(
        &self,
        options: LocalSyncEventOptions,
    ) -> Result<LocalSyncEventSubscription> {
        if let Some(cursor) = &options.cursor {
            if cursor.device_id != self.instance().device_id {
                return Err(Error::IdentityMismatch {
                    expected: cursor.device_id.clone(),
                    actual: self.instance().device_id.clone(),
                });
            }
        }
        let cursor = options
            .cursor
            .clone()
            .unwrap_or_else(|| LocalSyncEventCursor {
                device_id: self.instance().device_id.clone(),
                engine_started_at: None,
                last_sequence: 0,
            });
        let (sender, cancelled) = watch::channel(false);
        let mut stream = LocalSyncEventSubscription {
            client: self.clone(),
            options,
            cursor,
            pending: VecDeque::new(),
            cancellation: LocalSyncEventCancellation { sender },
            cancelled,
            ended: false,
        };
        if stream.options.cursor.is_some() {
            let cursor = stream.cursor.clone();
            stream.gap(EventGapReason::ResumedContinuityUnverified, cursor);
        }
        Ok(stream)
    }
}
impl LocalSyncEventSubscription {
    /// Last consumed event/gap position, never an unconsumed batch tail.
    pub fn cursor(&self) -> &LocalSyncEventCursor {
        &self.cursor
    }
    /// Number of buffered items; event count never exceeds the configured bound.
    pub fn buffered_items(&self) -> usize {
        self.pending.len()
    }
    /// Clone a handle that can cancel an in-flight next call from another task.
    pub fn cancellation_handle(&self) -> LocalSyncEventCancellation {
        self.cancellation.clone()
    }
    /// End this subscription; no job, engine or other subscription is stopped.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
    fn gap(&mut self, reason: EventGapReason, resume_from: LocalSyncEventCursor) {
        self.pending
            .push_back(Ok(LocalSyncEventStreamItem::Gap(LocalSyncEventGap {
                reason,
                previous: self.cursor.clone(),
                resume_from,
            })));
    }
    fn fail(&mut self, reason: EventGapReason, error: Error) {
        self.gap(reason, self.cursor.clone());
        self.pending.push_back(Err(error));
        self.ended = true;
    }
    /// Read one actual event, continuity warning or terminal error. Reads are
    /// performed only while this future is polled. Cancellation drops the pending
    /// read; transport/protocol errors end observation without automatic retries.
    pub async fn next(&mut self) -> Option<Result<LocalSyncEventStreamItem>> {
        loop {
            if *self.cancelled.borrow() {
                return None;
            }
            if let Some(item) = self.pending.pop_front() {
                match &item {
                    Ok(LocalSyncEventStreamItem::Event { cursor, .. }) => {
                        self.cursor = cursor.clone()
                    }
                    Ok(LocalSyncEventStreamItem::Gap(gap)) => self.cursor = gap.resume_from.clone(),
                    Err(_) => (),
                }
                return Some(item);
            }
            if self.ended {
                return None;
            }
            let client = self.client.clone();
            let sequence = self.cursor.last_sequence;
            let wait = self.options.wait_seconds;
            let read = async move {
                let before = client.system_status().await?;
                let batch = client.local_sync_events(sequence, wait).await?;
                let after = client.system_status().await?;
                Ok::<_, Error>((before.start_time, batch, after.start_time))
            };
            let result = tokio::select! {biased; _=self.cancelled.changed()=>return None,result=read=>result};
            let (before, batch, after) = match result {
                Ok(value) => value,
                Err(error) => {
                    let reason = if matches!(error, Error::InvalidResponse { .. }) {
                        EventGapReason::BatchUnavailable
                    } else {
                        EventGapReason::ConnectionInterrupted
                    };
                    self.fail(reason, error);
                    continue;
                }
            };
            let mut observed = self.cursor.clone();
            observed.engine_started_at = after.clone();
            if before != after {
                observed.last_sequence = 0;
                self.gap(EventGapReason::ObservationChanged, observed);
                continue;
            }
            if self.cursor.engine_started_at.is_some() && self.cursor.engine_started_at != after {
                observed.last_sequence = 0;
                self.gap(EventGapReason::EngineStartTimeChanged, observed);
                continue;
            }
            self.cursor.engine_started_at = after;
            if batch.events.len() > self.options.max_events
                || batch.events.iter().any(|e| {
                    e.sequence == 0
                        || e.kind.is_empty()
                        || e.time.is_empty()
                        || e.sequence > batch.cursor
                })
                || batch
                    .events
                    .windows(2)
                    .any(|w| w[0].sequence >= w[1].sequence)
                || batch
                    .events
                    .last()
                    .is_some_and(|e| e.sequence != batch.cursor)
            {
                self.fail(EventGapReason::BatchUnavailable, invalid_batch());
                continue;
            }
            let reset = batch.reset || batch.cursor < sequence;
            let first = batch.events.first().map(|e| e.sequence);
            if !reset && first.is_some_and(|first| first <= sequence) {
                self.fail(EventGapReason::BatchUnavailable, invalid_batch());
                continue;
            }
            let skipped = first.is_some_and(|first| first > sequence.saturating_add(1));
            let mut queued_cursor = self.cursor.clone();
            if reset || batch.missed || skipped {
                let mut resume = self.cursor.clone();
                resume.last_sequence = first.map_or(batch.cursor, |first| first - 1);
                queued_cursor = resume.clone();
                self.gap(
                    if reset {
                        EventGapReason::CursorReset
                    } else {
                        EventGapReason::MissingEvents
                    },
                    resume,
                );
            } else if batch.events.is_empty() && batch.cursor != sequence {
                self.fail(EventGapReason::BatchUnavailable, invalid_batch());
                continue;
            }
            for event in batch.events {
                if event.sequence > queued_cursor.last_sequence.saturating_add(1) {
                    let mut resume = queued_cursor.clone();
                    resume.last_sequence = event.sequence - 1;
                    self.pending
                        .push_back(Ok(LocalSyncEventStreamItem::Gap(LocalSyncEventGap {
                            reason: EventGapReason::MissingEvents,
                            previous: queued_cursor.clone(),
                            resume_from: resume,
                        })));
                }
                let mut cursor = self.cursor.clone();
                cursor.last_sequence = event.sequence;
                queued_cursor = cursor.clone();
                self.pending
                    .push_back(Ok(LocalSyncEventStreamItem::Event { event, cursor }));
            }
            if self.pending.is_empty() {
                tokio::select! {biased; _=self.cancelled.changed()=>return None,_=tokio::time::sleep(Duration::from_millis(10))=>()}
            }
        }
    }
}
fn invalid_batch() -> Error {
    Error::InvalidResponse {
        operation: "validate native Local Sync event sequence",
        response: ResponseDiagnostic::new(200, Vec::new()),
    }
}

fn optional_job<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<LocalSyncJobId>, D::Error> {
    Option::<String>::deserialize(d)?
        .filter(|value| !value.is_empty())
        .map(LocalSyncJobId::parse)
        .transpose()
        .map_err(|_| serde::de::Error::custom("invalid native Local Sync event job identity"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_global_event_empty_job_is_absent_but_action_zero_is_preserved() {
        let event:LocalSyncEvent=serde_json::from_value(serde_json::json!({"sequence":1,"jobId":"","type":"configuration_changed","time":"native-time","actionId":0})).unwrap();
        assert!(event.job_id.is_none());
        assert_eq!(event.action_id, Some(0));
    }
}
