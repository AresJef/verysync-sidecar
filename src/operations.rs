//! Observations of actual folder scanning phases, not fabricated server jobs.
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use crate::{
    Client, EngineEvent, Error, EventCursor, EventGap, EventKind, EventOptions, EventStreamItem,
    EventSubscription, FolderId, FolderState, FolderStatus, ManagementWriteEvidence,
    OperationCompletion, ResponseDiagnostic, Result, TargetPath,
};

/// Which scope the engine should scan.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ScanScope {
    /// Scan one configured folder.
    Folder(FolderId),
    /// Scan explicit relative target paths in one configured folder.
    Subpaths {
        /// Configured folder to scan.
        folder: FolderId,
        /// 1 through 256 relative paths using the target's syntax.
        paths: Vec<TargetPath>,
    },
    /// Request one native all-folders scan. Paused folders stay paused.
    All,
}

/// Evidence for one folder selected by a scan workflow.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScanFolderObservation {
    /// The folder was paused at admission to an all-folders request.
    Paused,
    /// A complete scan cycle and its subsequent status were observed.
    CycleObserved(Box<ScanCompletion>),
    /// Observation stopped or lost continuity before a cycle could be verified.
    Pending {
        /// Latest phase actually observed before finishing the workflow.
        last_phase: ScanPhase,
    },
    /// This folder's cycle or readback could not be verified.
    Unavailable {
        /// The reason this folder's observation could not complete.
        source: Error,
    },
}

/// Original scan reply and per-folder observations.
///
/// VerySync does not report a request ID for scans. A cycle is evidence of
/// activity on the same engine and folder during the watch, even after a lost
/// response. Coordinate other scan initiators before attributing it to this
/// request. Checking whether specific files were indexed is a separate read.
#[derive(Debug)]
#[non_exhaustive]
pub struct ScanWorkflowReport {
    /// The exact scope sent if dispatch occurred.
    pub scope: ScanScope,
    /// Whether the request entered transport and which reply was available.
    pub write: ManagementWriteEvidence,
    /// Initial request result, including a preflight failure or unknown outcome.
    pub original: Result<()>,
    /// Start of the event observation, when the engine supplied a start time.
    pub event_start: Option<EventCursor>,
    /// Explicit event gap, if it ended continuous observation.
    pub event_gap: Option<EventGap>,
    /// Observations for configured folders in the selected scope.
    pub folders: BTreeMap<FolderId, ScanFolderObservation>,
    /// A shared observation error or deadline after submission.
    pub observation_error: Option<Error>,
}

impl ScanWorkflowReport {
    /// Summarize the original request and scan evidence. A successful scan
    /// phase still provides no delivery or request-specific attribution.
    pub fn completion(&self) -> OperationCompletion {
        let mut observed = 0;
        let mut failed = false;
        let mut unknown = false;
        for folder in self.folders.values() {
            match folder {
                ScanFolderObservation::CycleObserved(cycle)
                    if matches!(cycle.exited_to, FolderState::Error | FolderState::Paused) =>
                {
                    failed = true;
                }
                ScanFolderObservation::CycleObserved(_) => observed += 1,
                ScanFolderObservation::Paused => {}
                ScanFolderObservation::Pending { .. }
                | ScanFolderObservation::Unavailable { .. } => {
                    unknown = true;
                }
            }
        }
        if observed != 0 && (unknown || failed || self.original.is_err()) {
            OperationCompletion::PartiallyCompleted
        } else if observed != 0 && self.observation_error.is_none() {
            OperationCompletion::Completed
        } else if !self.write.dispatched
            || (self.write.response_complete
                && matches!(
                    self.original,
                    Err(Error::Authentication { .. } | Error::AccessDenied { .. })
                ))
            || (failed && !unknown)
        {
            OperationCompletion::GoalNotMet
        } else {
            OperationCompletion::Unconfirmed
        }
    }
}

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
    cycle: ScanCycle,
    completion: Option<ScanCompletion>,
}

pub(crate) struct ScanCycle {
    phase: ScanPhase,
    started: Option<EventCursor>,
    progress: Option<ScanProgress>,
    pending_end: Option<(EventCursor, FolderState)>,
}

impl ScanCycle {
    pub(crate) fn new() -> Self {
        Self {
            phase: ScanPhase::AwaitingStart,
            started: None,
            progress: None,
            pending_end: None,
        }
    }

    pub(crate) fn phase(&self) -> ScanPhase {
        self.phase
    }

    pub(crate) fn has_ended(&self) -> bool {
        self.pending_end.is_some()
    }

    pub(crate) fn lose_observation(&mut self) {
        self.phase = ScanPhase::ObservationLost;
    }

    pub(crate) fn accept(&mut self, event: EngineEvent) -> Result<bool> {
        if event.kind == EventKind::StateChanged {
            let from = state(&event, "from")?;
            let to = state(&event, "to")?;
            if matches!(from, FolderState::Unknown(_)) || matches!(to, FolderState::Unknown(_)) {
                return Err(Error::ScanObservationLost);
            }
            if to == FolderState::Scanning {
                self.started.get_or_insert(event.cursor);
                self.phase = ScanPhase::Scanning;
                return Ok(true);
            }
            if to == FolderState::ScanWaiting {
                self.phase = ScanPhase::Queued;
                return Ok(true);
            }
            if from == FolderState::Scanning {
                if self.started.is_none() {
                    return Err(Error::ScanObservationLost);
                }
                self.pending_end = Some((event.cursor, to));
            }
        } else if matches!(&event.kind, EventKind::Unknown(name) if name == "FolderScanProgress") {
            self.progress = Some(ScanProgress {
                current: event.data()["current"].as_u64(),
                total: event.data()["total"].as_u64(),
                rate: event.data()["rate"].as_f64().filter(|n| n.is_finite()),
                raw: event.data().clone(),
            });
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) fn finish(
        &mut self,
        folder_id: FolderId,
        snapshot: FolderStatus,
    ) -> Result<ScanCompletion> {
        let started = self.started.clone().ok_or(Error::ScanObservationLost)?;
        let (ended, exited_to) = self.pending_end.clone().ok_or(Error::ScanObservationLost)?;
        self.phase = ScanPhase::Ended;
        Ok(ScanCompletion {
            folder_id,
            started,
            ended,
            exited_to,
            snapshot,
            progress: self.progress.clone(),
        })
    }
}
impl fmt::Debug for ScanObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScanObservation")
            .field("folder", &self.folder)
            .field("phase", &self.cycle.phase)
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
            cycle: ScanCycle::new(),
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
        self.cycle.phase
    }
    /// Borrow the last actual progress, or unknown.
    pub fn progress(&self) -> Option<&ScanProgress> {
        self.cycle.progress.as_ref()
    }
    fn update(&self) -> ScanUpdate {
        ScanUpdate {
            phase: self.cycle.phase,
            progress: self.cycle.progress.clone(),
            completion: self.completion.clone(),
        }
    }

    /// Await an actual state/progress update. Cancelling this wait preserves the session.
    /// Unrelated events are ignored; any gap makes this observation indeterminate.
    pub async fn next_update(&mut self) -> Result<ScanUpdate> {
        loop {
            if self.cycle.phase == ScanPhase::ObservationLost {
                return Err(Error::ScanObservationLost);
            }
            if self.completion.is_some() {
                return Ok(self.update());
            }
            if self.cycle.has_ended() {
                // Retain pending_end before this await: cancellation cannot lose
                // the terminal event while a fresh snapshot request is pending.
                let snapshot = self.client.folder_status(&self.folder).await?;
                self.completion = Some(self.cycle.finish(self.folder.clone(), snapshot)?);
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
                    self.cycle.lose_observation();
                    self.close_events().await?;
                    return Err(Error::ScanObservationLost);
                }
                Some(Ok(_)) => continue,
                Some(Err(error)) => {
                    self.cycle.lose_observation();
                    self.close_events().await?;
                    return Err(error);
                }
            };
            if event.data()["folder"] != self.folder.as_str() {
                continue;
            }
            match self.cycle.accept(event) {
                Ok(true) => return Ok(self.update()),
                Ok(false) => {}
                Err(error) => {
                    self.cycle.lose_observation();
                    self.close_events().await?;
                    return Err(error);
                }
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
