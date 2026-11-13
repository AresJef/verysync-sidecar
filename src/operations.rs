//! Observations of actual folder scanning phases, not fabricated server jobs.
use std::fmt;
use std::time::Duration;

use crate::{
    Client, EngineEvent, Error, EventCursor, EventKind, EventOptions, EventStreamItem,
    EventSubscription, FolderId, FolderState, FolderStatus, ResponseDiagnostic, Result,
};

/// Latest phase actually observed for one folder after subscribing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanPhase {
    /// No scanning entry has yet been observed.
    AwaitingStart,
    /// The engine reported scan-waiting.
    Queued,
    /// A real transition into scanning was observed.
    Scanning,
    /// That scanning phase ended; this does not imply peer synchronization.
    Ended,
    /// Continuity was lost or the observation no longer establishes a full cycle.
    ObservationLost,
}

/// Optional reported progress values; no percentage or missing zero is invented.
#[derive(Clone)]
pub struct ScanProgress {
    /// Upstream nonnegative current count, if supplied in a recognized form.
    pub current: Option<u64>,
    /// Upstream nonnegative total count, if supplied in a recognized form.
    pub total: Option<u64>,
    /// Upstream reported rate, if supplied; no unit conversion is assumed.
    pub rate: Option<f64>,
    raw: serde_json::Value,
}
impl ScanProgress {
    /// Explicitly inspect the bounded original progress payload and unknown values.
    pub fn raw(&self) -> &serde_json::Value {
        &self.raw
    }
}
impl fmt::Debug for ScanProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScanProgress")
            .field("current", &self.current)
            .field("total", &self.total)
            .field("rate", &self.rate)
            .finish_non_exhaustive()
    }
}

/// A real scanning phase was observed to end; inspect its next state and snapshot.
/// This is not a receipt for every file, peer synchronization or a particular POST.
#[derive(Clone, Debug)]
pub struct ScanCompletion {
    /// Folder whose events were observed.
    pub folder_id: FolderId,
    /// Cursor of the observed entry into scanning.
    pub started: EventCursor,
    /// Cursor of the observed exit from scanning.
    pub ended: EventCursor,
    /// The actual next engine state; Error/Paused are not successful scanning.
    pub exited_to: FolderState,
    /// Fresh folder status read after that event, not inferred from an HTTP acknowledgement.
    pub snapshot: FolderStatus,
    /// Last actual progress payload, if one was delivered.
    pub progress: Option<ScanProgress>,
}

/// One observation update from the bounded engine event subscription.
#[derive(Clone, Debug)]
pub struct ScanUpdate {
    /// Actual observation phase.
    pub phase: ScanPhase,
    /// Last actual progress information, or unknown.
    pub progress: Option<ScanProgress>,
    /// Completed phase observation when available.
    pub completion: Option<ScanCompletion>,
}

/// A local observation of the next scan cycle, with no server operation ID.
///
/// Establish this before requesting a scan and coordinate other scan initiators
/// for the same folder. The engine provides no request-specific ID for correlating
/// concurrent scans. Dropping/closing this value cancels only its read subscription.
pub struct ScanObservation {
    client: Client,
    folder: FolderId,
    events: Option<EventSubscription>,
    phase: ScanPhase,
    started: Option<EventCursor>,
    progress: Option<ScanProgress>,
    pending_end: Option<(EventCursor, FolderState)>,
    completion: Option<ScanCompletion>,
}
impl fmt::Debug for ScanObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScanObservation")
            .field("folder", &self.folder)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}
impl Client {
    /// Observe the next complete scan cycle after the current event position.
    ///
    /// This sends no scan command and returns no invented server job ID. The
    /// folder must be idle at admission. Subscribe before request_scan and
    /// coordinate other initiators; a cycle cannot be tied to one POST by ID.
    pub async fn observe_next_scan(&self, folder: &FolderId) -> Result<ScanObservation> {
        let events = self
            .subscribe_events(EventOptions::default().reconnect_attempts(0)?)
            .await?;
        if self.folder_status(folder).await?.state != Some(FolderState::Idle) {
            events.close().await?;
            return Err(Error::ScanNotIdle);
        }
        Ok(ScanObservation {
            client: self.clone(),
            folder: folder.clone(),
            events: Some(events),
            phase: ScanPhase::AwaitingStart,
            started: None,
            progress: None,
            pending_end: None,
            completion: None,
        })
    }
}
impl ScanObservation {
    /// Folder being observed; not an operation ID.
    pub fn folder_id(&self) -> &FolderId {
        &self.folder
    }
    /// Read the latest observed phase without I/O.
    pub fn phase(&self) -> ScanPhase {
        self.phase
    }
    /// Borrow the last actual progress, or unknown.
    pub fn progress(&self) -> Option<&ScanProgress> {
        self.progress.as_ref()
    }
    fn update(&self) -> ScanUpdate {
        ScanUpdate {
            phase: self.phase,
            progress: self.progress.clone(),
            completion: self.completion.clone(),
        }
    }

    /// Await an actual state/progress update. Cancelling this wait preserves the session.
    /// Unrelated events are ignored; any gap makes this observation indeterminate.
    pub async fn next_update(&mut self) -> Result<ScanUpdate> {
        loop {
            if self.phase == ScanPhase::ObservationLost {
                return Err(Error::ScanObservationLost);
            }
            if self.completion.is_some() {
                return Ok(self.update());
            }
            if let Some((ended, exited_to)) = &self.pending_end {
                // Retain pending_end before this await: cancellation cannot lose
                // the terminal event while a fresh snapshot request is pending.
                let snapshot = self.client.folder_status(&self.folder).await?;
                let started = self.started.clone().ok_or(Error::ScanObservationLost)?;
                self.completion = Some(ScanCompletion {
                    folder_id: self.folder.clone(),
                    started,
                    ended: ended.clone(),
                    exited_to: exited_to.clone(),
                    snapshot,
                    progress: self.progress.clone(),
                });
                self.phase = ScanPhase::Ended;
                self.close_events().await?;
                return Ok(self.update());
            }
            let incoming = self
                .events
                .as_mut()
                .ok_or(Error::ScanObservationLost)?
                .next()
                .await;
            let event = match incoming {
                Some(Ok(EventStreamItem::Event(event))) => event,
                Some(Ok(EventStreamItem::Gap(_))) | None => {
                    self.phase = ScanPhase::ObservationLost;
                    self.close_events().await?;
                    return Err(Error::ScanObservationLost);
                }
                Some(Ok(_)) => continue,
                Some(Err(error)) => {
                    self.phase = ScanPhase::ObservationLost;
                    self.close_events().await?;
                    return Err(error);
                }
            };
            if event.data()["folder"] != self.folder.as_str() {
                continue;
            }
            if event.kind == EventKind::StateChanged {
                let (from, to) =
                    match state(&event, "from").and_then(|from| Ok((from, state(&event, "to")?))) {
                        Ok(pair) => pair,
                        Err(error) => {
                            self.phase = ScanPhase::ObservationLost;
                            self.close_events().await?;
                            return Err(error);
                        }
                    };
                if matches!(from, FolderState::Unknown(_)) || matches!(to, FolderState::Unknown(_))
                {
                    self.phase = ScanPhase::ObservationLost;
                    self.close_events().await?;
                    return Err(Error::ScanObservationLost);
                }
                if to == FolderState::Scanning {
                    if self.started.is_none() {
                        self.started = Some(event.cursor.clone());
                    }
                    self.phase = ScanPhase::Scanning;
                    return Ok(self.update());
                }
                if to == FolderState::ScanWaiting {
                    self.phase = ScanPhase::Queued;
                    return Ok(self.update());
                }
                if from == FolderState::Scanning {
                    if self.started.is_none() {
                        self.phase = ScanPhase::ObservationLost;
                        self.close_events().await?;
                        return Err(Error::ScanObservationLost);
                    }
                    self.pending_end = Some((event.cursor, to));
                }
            } else if matches!(&event.kind,EventKind::Unknown(name) if name=="FolderScanProgress") {
                self.progress = Some(ScanProgress {
                    current: event.data()["current"].as_u64(),
                    total: event.data()["total"].as_u64(),
                    rate: event.data()["rate"].as_f64().filter(|n| n.is_finite()),
                    raw: event.data().clone(),
                });
                return Ok(self.update());
            }
        }
    }

    /// Wait for a real scan phase to end within a nonzero caller deadline.
    /// Timeout/cancellation does not send a stop command or reset observation state.
    pub async fn wait(&mut self, timeout: Duration) -> Result<ScanCompletion> {
        if timeout.is_zero() {
            return Err(Error::InvalidConfiguration {
                reason: "scan observation deadline must be nonzero",
            });
        }
        let deadline = tokio::time::Instant::now().checked_add(timeout).ok_or(
            Error::InvalidConfiguration {
                reason: "scan observation deadline is not representable",
            },
        )?;
        tokio::time::timeout_at(deadline, async {
            loop {
                if let Some(completion) = self.next_update().await?.completion {
                    return Ok(completion);
                }
            }
        })
        .await
        .map_err(|_| Error::Timeout {
            operation: "observe scan phase exit",
        })?
    }
    /// Cancel this read-only observation and join its subscription task.
    /// An independently submitted scan request is not cancelled or stopped.
    pub async fn close(mut self) -> Result<()> {
        self.close_events().await
    }
    async fn close_events(&mut self) -> Result<()> {
        if let Some(events) = self.events.take() {
            events.close().await?;
        }
        Ok(())
    }
}
fn state(event: &EngineEvent, key: &str) -> Result<FolderState> {
    serde_json::from_value(event.data()[key].clone()).map_err(|_| Error::InvalidResponse {
        operation: "observe scan state transition",
        response: ResponseDiagnostic::new(
            200,
            serde_json::to_vec(event.data()).unwrap_or_default(),
        ),
    })
}
