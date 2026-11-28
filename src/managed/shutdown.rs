//! Explicit graceful shutdown and separately chosen exact-tree termination.

use std::time::{Duration, Instant};
use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex as EvidenceMutex,
    },
};

use tokio::sync::{mpsc, watch, Mutex, OwnedMutexGuard};

use super::{
    ManagedControlGeneration, ManagedExit, ManagedExitObservation, ManagedExitObservationOutcome,
    ManagedInstance,
};
use crate::{operation_options::OperationContext, Error, OperationOptions, OperationPhase, Result};

const SHUTDOWN: &str = crate::error::GRACEFUL_SHUTDOWN_OPERATION;

/// Transport facts from the shutdown request made by one owning call.
pub type ShutdownRequestEvidence = crate::ManagementWriteEvidence;

/// The normal shutdown result and any later observation of the same owner.
#[derive(Debug)]
#[non_exhaustive]
pub struct ManagedShutdownReport {
    /// The exact original owned generation.
    pub generation: ManagedControlGeneration,
    /// The time allocated to the first shutdown wait.
    pub initial_limit: Duration,
    /// The request and response facts available when the operation returned.
    pub request: ShutdownRequestEvidence,
    /// The first result, retaining the actual timeout or request cause.
    pub original: Result<ManagedExit>,
    /// A later, read-only observation when the first result was uncertain.
    pub later: Option<Result<ManagedExitObservation>>,
}

impl ManagedShutdownReport {
    /// Return the first or later confirmed exit, including actual exit code,
    /// state release and whether a force operation was observed.
    pub fn confirmed_exit(&self) -> Option<&ManagedExit> {
        if let Ok(exit) = &self.original {
            return Some(exit);
        }
        match &self.later {
            Some(Ok(ManagedExitObservation {
                outcome: ManagedExitObservationOutcome::Exited(exit),
                ..
            })) => Some(exit),
            _ => None,
        }
    }
}

impl fmt::Display for ManagedShutdownReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.confirmed_exit().is_some() {
            return f.write_str("The original VerySync instance stopped and released its state.");
        }
        if !self.request.dispatched {
            return f.write_str("The wait ended before submitting a shutdown request. Check the original instance before taking further action.");
        }
        if self.request.response_complete
            && self
                .request
                .status
                .is_some_and(|status| matches!(status, 401 | 403))
        {
            return f.write_str("VerySync declined shutdown. Verify the credentials and management permissions for the original instance.");
        }
        f.write_str("The original instance's exit could not be confirmed. Check that instance before sending another shutdown request.")
    }
}

#[derive(Clone)]
pub(crate) struct ShutdownRequestTracking {
    wire: Arc<EvidenceMutex<ShutdownRequestEvidence>>,
    cancel: Option<watch::Receiver<bool>>,
    progress: Option<mpsc::Sender<OperationPhase>>,
}

impl ShutdownRequestTracking {
    fn new(context: &OperationContext) -> Self {
        Self {
            wire: Arc::default(),
            cancel: context.cancelled_on(),
            progress: context.progress_sender(),
        }
    }

    pub(crate) fn cancelled(&self) -> bool {
        self.cancel.as_ref().is_some_and(|signal| *signal.borrow())
    }

    fn update(&self, action: impl FnOnce(&mut ShutdownRequestEvidence)) {
        let mut evidence = self.wire.lock().unwrap_or_else(|error| error.into_inner());
        action(&mut evidence);
    }

    pub(crate) fn dispatched(&self) {
        self.update(|evidence| evidence.dispatched = true);
        if let Some(progress) = &self.progress {
            let _ = progress.try_send(OperationPhase::Submitting);
        }
    }

    pub(crate) fn response(&self, status: u16, complete: bool) {
        self.update(|evidence| {
            evidence.status = Some(status);
            evidence.response_complete = complete;
        });
    }

    fn evidence(&self) -> ShutdownRequestEvidence {
        *self.wire.lock().unwrap_or_else(|error| error.into_inner())
    }
}

/// Serializes an admitted shutdown request with the release of one owner's
/// state lease. An earlier client write can delay admission, but cannot delay
/// retirement of a request that has not yet reached this gate.
#[derive(Default)]
pub(crate) struct ShutdownAdmission {
    retired: AtomicBool,
    dispatch: Arc<Mutex<()>>,
}

impl ShutdownAdmission {
    pub(crate) async fn admit(&self) -> Option<OwnedMutexGuard<()>> {
        let guard = Arc::clone(&self.dispatch).lock_owned().await;
        (!self.is_retired()).then_some(guard)
    }

    pub(crate) fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }

    pub(super) fn retire(&self) {
        self.retired.store(true, Ordering::Release);
    }

    /// Called on the blocking owner thread, before dropping the state lease.
    pub(super) fn wait_for_dispatch(&self) {
        drop(self.dispatch.blocking_lock());
    }
}

pub(super) fn deadline(timeout: Duration) -> Result<tokio::time::Instant> {
    tokio::runtime::Handle::try_current().map_err(|_| Error::InvalidConfiguration {
        reason: "owned lifecycle operations require a Tokio runtime with I/O and timers",
    })?;
    if timeout.is_zero() {
        return Err(Error::InvalidConfiguration {
            reason: "owned lifecycle deadline must be nonzero",
        });
    }
    Instant::now()
        .checked_add(timeout)
        .map(tokio::time::Instant::from_std)
        .ok_or(Error::InvalidConfiguration {
            reason: "owned lifecycle deadline is not representable",
        })
}

impl ManagedInstance {
    /// Request normal API shutdown and wait for this exact process tree to exit.
    ///
    /// The total deadline covers fresh identity checking, the single typed API
    /// request and actual exit/state-lease release. HTTP acknowledgement alone
    /// never completes this method. An already observed exit is returned without
    /// another request; inspect its actual code/signal and forced flag.
    ///
    /// Errors use the normal typed authentication/business/unknown-write model.
    /// An admitted request can continue if a caller drops this future before
    /// its deadline. After a timeout, check whether the original owner is still
    /// running before sending another command. Dropping the owner still follows
    /// its configured lifetime policy.
    pub async fn shutdown(&mut self, timeout: Duration) -> Result<ManagedExit> {
        let deadline = deadline(timeout)?;
        tokio::time::timeout_at(deadline, self.graceful_shutdown(deadline, None))
            .await
            .map_err(|_| Error::Timeout {
                operation: "gracefully stop owned program",
            })?
    }

    async fn graceful_shutdown(
        &self,
        deadline: tokio::time::Instant,
        tracking: Option<ShutdownRequestTracking>,
    ) -> Result<ManagedExit> {
        tokio::select! {
            biased;
            report = self.observe_exit() => report,
            requested = self.client().request_owned_shutdown(
                Arc::clone(&self.shutdown_admission),
                deadline,
                tracking,
            ) => {
                requested?;
                self.observe_exit().await
            }
        }
    }

    /// Ask the original owned generation to shut down once and verify its exit.
    /// The first wait uses at most ten seconds or half of the total time,
    /// whichever is shorter. If its result is uncertain, the remaining time
    /// goes to passive observation of this same owner. The report distinguishes
    /// the request, actual exit, and release of the private state.
    pub async fn shutdown_and_verify(
        &mut self,
        options: OperationOptions,
    ) -> Result<ManagedShutdownReport> {
        let context = options.start()?;
        let report = self.shutdown_before(&context, context.deadline).await;
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    pub(super) async fn shutdown_before(
        &self,
        context: &OperationContext,
        deadline: tokio::time::Instant,
    ) -> ManagedShutdownReport {
        let generation = self.control_generation();
        let initial_limit =
            (deadline.duration_since(context.started) / 2).min(Duration::from_secs(10));
        let initial = context.started + initial_limit;
        let tracking = ShutdownRequestTracking::new(context);
        let original = context
            .wait(initial, SHUTDOWN, async {
                context.phase(OperationPhase::Checking);
                self.graceful_shutdown(initial, Some(tracking.clone()))
                    .await
            })
            .await;
        let later = if matches!(
            original,
            Err(Error::Timeout { .. } | Error::MutationOutcomeUnknown { .. })
        ) {
            Some(
                context
                    .wait(
                        deadline,
                        "confirm the original instance has stopped",
                        async {
                            context.phase(OperationPhase::Verifying);
                            self.observe_control_exit(
                                &generation,
                                deadline.saturating_duration_since(tokio::time::Instant::now()),
                            )
                            .await
                        },
                    )
                    .await,
            )
        } else {
            None
        };
        ManagedShutdownReport {
            generation,
            initial_limit,
            request: tracking.evidence(),
            original,
            later,
        }
    }

    /// Explicitly terminate only this owner's native process group/Job and wait.
    ///
    /// This sends no API request and can interrupt in-progress work. It is never
    /// selected automatically by shutdown on failure/timeout. The returned exit
    /// confirms actual containment exit and state-lease release; `forced` records
    /// whether the owner thread actually requested termination. An already exited
    /// program returns its existing observation. Cancelling this wait does not
    /// undo an already delivered termination request.
    pub async fn force_stop(&mut self, timeout: Duration) -> Result<ManagedExit> {
        let deadline = deadline(timeout)?;
        let forced = async {
            if self.exit_snapshot().is_none() {
                // A closed control channel can mean that normal exit won
                // the race. The exit observer distinguishes this from loss.
                let _ = self.request_force_cleanup();
            }
            self.observe_exit().await
        };
        tokio::time::timeout_at(deadline, forced)
            .await
            .map_err(|_| Error::Timeout {
                operation: "confirm explicit owned termination",
            })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn owned_shutdown_retirement_drains_admitted_work_and_refuses_new_work() {
        let admission = Arc::new(ShutdownAdmission::default());
        let admitted = admission
            .admit()
            .await
            .expect("active owner admits its write");
        let (retired, see_retired) = tokio::sync::oneshot::channel();
        let (released, mut see_release) = tokio::sync::oneshot::channel();
        let retiring = Arc::clone(&admission);
        let owner = std::thread::spawn(move || {
            retiring.retire();
            retired.send(()).unwrap();
            retiring.wait_for_dispatch();
            released.send(()).unwrap();
        });
        see_retired.await.unwrap();
        assert!(see_release.try_recv().is_err());
        drop(admitted);
        see_release.await.unwrap();
        owner.join().unwrap();
        assert!(admission.admit().await.is_none());
    }
}
