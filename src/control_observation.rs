//! Continued observations of a selected folder and optional peer.

use std::{
    fmt,
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};

use crate::{
    Client, CompletionSnapshot, DeviceId, Error, EventCursor, EventGapReason, EventKind,
    EventOptions, EventStreamItem, EventSubscription, FolderId, FolderStatus, Result,
};

/// A private, serializable position for one folder and optional peer.
///
/// Save a position after handling an update. It carries no credentials or
/// address. Resuming requires a connection to the same device, and reports
/// uncertainty about updates missed since the saved position.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FolderObservationPosition {
    folder: FolderId,
    peer: Option<DeviceId>,
    cursor: EventCursor,
}

impl FolderObservationPosition {
    /// The selected folder.
    pub fn folder_id(&self) -> &FolderId {
        &self.folder
    }

    /// The peer selected for completion reads, if any.
    pub fn peer_id(&self) -> Option<&DeviceId> {
        self.peer.as_ref()
    }

    /// The stream position associated with the last delivered update.
    pub fn cursor(&self) -> &EventCursor {
        &self.cursor
    }
}

impl fmt::Debug for FolderObservationPosition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FolderObservationPosition")
            .field("selected_peer", &self.peer.is_some())
            .field("last_id", &self.cursor.last_id)
            .finish_non_exhaustive()
    }
}

/// The last successful native folder reads, taken in a finite observation window.
///
/// Status and peer completion come from separate reads and can describe
/// different moments. An event can trigger a read, but its ID does not label
/// the resulting snapshot on the server.
pub struct FolderObservationSnapshot {
    /// Status from the native folder model.
    pub status: FolderStatus,
    /// Native completion for the one selected peer, if requested.
    pub peer_completion: Option<CompletionSnapshot>,
    /// Observation start on the caller's wall clock, before any requests.
    pub started_at: SystemTime,
    /// Observation end on the caller's wall clock, after identity checks.
    pub observed_at: SystemTime,
    /// Consumer position that triggered the read, or the anchor for the initial read.
    pub trigger_cursor: EventCursor,
    engine_started_at: Option<String>,
}

impl FolderObservationSnapshot {
    /// Engine start time reported during these reads, when known.
    ///
    /// This is an upstream string, not proof of a locally owned process.
    pub fn engine_started_at(&self) -> Option<&str> {
        self.engine_started_at.as_deref()
    }

    /// The folder model supplies no task ID for this observation.
    pub fn task_id(&self) -> Option<&str> {
        None
    }
}

impl fmt::Debug for FolderObservationSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FolderObservationSnapshot")
            .field("has_peer_completion", &self.peer_completion.is_some())
            .field("started_at", &self.started_at)
            .field("observed_at", &self.observed_at)
            .field("trigger_id", &self.trigger_cursor.last_id)
            .field("engine_start_reported", &self.engine_started_at.is_some())
            .finish_non_exhaustive()
    }
}

/// Whether this update replaced the last successful folder snapshot.
#[derive(Debug)]
#[non_exhaustive]
pub enum FolderObservationRefresh {
    /// This event did not identify the selected folder.
    NotNeeded,
    /// Current folder state was read using the selected scope.
    Read,
    /// The read failed. The previous snapshot is still available.
    Failed(Error),
}

/// An item from the bounded stream and the result of any corresponding read.
#[derive(Debug)]
pub struct FolderObservationUpdate {
    /// The ordered upstream event, gap, or reconnection notice. Explicit access
    /// to an event payload can reveal upstream private values.
    pub item: EventStreamItem,
    /// Whether a fresh folder snapshot was read.
    pub refresh: FolderObservationRefresh,
}

/// Caller-owned observation of one selected folder, with optional peer completion.
///
/// Dropping this value cancels the bounded subscription. Closing it explicitly
/// waits for cancellation. Neither causes the engine to scan, change a folder
/// or transfer files. A management connection has no owned lifecycle authority.
pub struct FolderObservation {
    client: Client,
    events: EventSubscription,
    pending: Option<EventStreamItem>,
    position: FolderObservationPosition,
    snapshot: FolderObservationSnapshot,
    last_gap: Option<EventGapReason>,
}

impl Client {
    /// Begin at the current standard event position, then read the selected folder.
    ///
    /// The subscription anchors before the snapshot, so new events can queue
    /// while the reads are in flight. The event stream and the native snapshots
    /// cannot be read atomically. No file is opened or operation requested.
    /// To resume a saved observation, use [Self::resume_folder_observation].
    pub async fn observe_folder(
        &self,
        folder: &FolderId,
        peer: Option<&DeviceId>,
        events: EventOptions,
    ) -> Result<FolderObservation> {
        reject_unscoped_cursor(&events)?;
        self.open_folder_observation(folder.clone(), peer.cloned(), events)
            .await
    }

    /// Continue watching the folder and optional peer in a saved position.
    ///
    /// Pass an ordinary event policy without another resume cursor. The stream
    /// reports that continuity across the saved position is uncertain.
    pub async fn resume_folder_observation(
        &self,
        position: FolderObservationPosition,
        events: EventOptions,
    ) -> Result<FolderObservation> {
        reject_unscoped_cursor(&events)?;
        let events = events.resume_from(position.cursor)?;
        self.open_folder_observation(position.folder, position.peer, events)
            .await
    }

    async fn open_folder_observation(
        &self,
        folder: FolderId,
        peer: Option<DeviceId>,
        options: EventOptions,
    ) -> Result<FolderObservation> {
        let resumed = options.has_resume_cursor();
        let events = self.subscribe_events(options).await?;
        let position = FolderObservationPosition {
            folder,
            peer,
            cursor: events.cursor().clone(),
        };
        let snapshot = read_folder_snapshot(self, &position, &position.cursor).await?;
        Ok(FolderObservation {
            client: self.clone(),
            events,
            pending: None,
            position,
            snapshot,
            last_gap: resumed.then_some(EventGapReason::ResumedContinuityUnverified),
        })
    }
}

fn reject_unscoped_cursor(events: &EventOptions) -> Result<()> {
    if events.has_resume_cursor() {
        return Err(Error::InvalidConfiguration {
            reason: "folder observation requires a folder observation position to resume",
        });
    }
    Ok(())
}

impl FolderObservation {
    /// Access the last successful snapshot. Check the latest update's refresh
    /// result before treating this snapshot as freshly read.
    pub fn snapshot(&self) -> &FolderObservationSnapshot {
        &self.snapshot
    }

    /// Access the last delivered cursor, even while other events are buffered.
    pub fn position(&self) -> &FolderObservationPosition {
        &self.position
    }

    /// The most recent continuity issue, retained after a successful refresh.
    pub fn last_gap(&self) -> Option<EventGapReason> {
        self.last_gap
    }

    /// Number queued within the configured bounds. One more item may be held
    /// while its snapshot is being read.
    pub fn buffered_items(&self) -> usize {
        self.events.buffered_items()
    }

    /// Wait for an update, terminal error, or end of the read subscription.
    ///
    /// The position advances only when an update is delivered. Cancelling this
    /// wait preserves its pending item and leaves the subscription open.
    /// A failed snapshot read still delivers its event or gap and leaves the
    /// last successful snapshot intact. Closing ends all subsequent polls.
    pub async fn next(&mut self) -> Option<Result<FolderObservationUpdate>> {
        if self.pending.is_none() {
            self.pending = match self.events.next().await? {
                Ok(item) => Some(item),
                Err(error) => return Some(Err(error)),
            };
        }

        let pending = self.pending.as_ref().expect("a received update is pending");
        let cursor = self.events.cursor();
        let refresh = match pending {
            EventStreamItem::Event(event) => {
                let id_field = match event.kind {
                    EventKind::FolderPaused | EventKind::FolderResumed => "id",
                    _ => "folder",
                };
                event
                    .data()
                    .get(id_field)
                    .and_then(serde_json::Value::as_str)
                    == Some(self.position.folder.as_str())
            }
            EventStreamItem::Gap(_) | EventStreamItem::Reconnected { .. } => true,
        };
        let refresh = if refresh {
            match read_folder_snapshot(&self.client, &self.position, cursor).await {
                Ok(snapshot) => {
                    self.snapshot = snapshot;
                    FolderObservationRefresh::Read
                }
                Err(error) => FolderObservationRefresh::Failed(error),
            }
        } else {
            FolderObservationRefresh::NotNeeded
        };

        let item = self
            .pending
            .take()
            .expect("the completed update is pending");
        if let EventStreamItem::Gap(gap) = &item {
            self.last_gap = Some(gap.reason);
        }
        self.position.cursor = cursor.clone();
        Some(Ok(FolderObservationUpdate { item, refresh }))
    }

    /// Wait up to a caller-selected duration without consuming undelivered updates.
    ///
    /// A timeout ends this wait only. Call [Self::close] to stop reading.
    pub async fn next_within(
        &mut self,
        limit: Duration,
    ) -> Result<Option<FolderObservationUpdate>> {
        tokio::time::timeout(limit, self.next())
            .await
            .map_err(|_| Error::Timeout {
                operation: "wait for a folder observation update",
            })?
            .transpose()
    }

    /// Stop and await cancellation of this subscription's read task.
    pub async fn close(self) -> Result<()> {
        self.events.close().await
    }
}

async fn read_folder_snapshot(
    client: &Client,
    position: &FolderObservationPosition,
    cursor: &EventCursor,
) -> Result<FolderObservationSnapshot> {
    let started_at = SystemTime::now();
    let before = client.system_status().await?;
    let status = client.folder_status(&position.folder).await?;
    let peer_completion = match &position.peer {
        Some(peer) => Some(
            client
                .folder_completion_snapshot(&position.folder, peer)
                .await?,
        ),
        None => None,
    };
    let after = client.system_status().await?;
    if before.start_time != after.start_time {
        return Err(Error::EventGenerationChanged);
    }
    Ok(FolderObservationSnapshot {
        status,
        peer_completion,
        started_at,
        observed_at: SystemTime::now(),
        trigger_cursor: cursor.clone(),
        engine_started_at: after.start_time,
    })
}
