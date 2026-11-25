//! Explicit graceful shutdown and separately chosen exact-tree termination.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, OwnedMutexGuard};

use super::{ManagedExit, ManagedInstance};
use crate::{Error, Result};

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
    /// A timeout or dropped future can leave an admitted request in progress.
    /// Wait for the original owner's exit before sending another command. Dropping the owner still follows its
    /// separately documented default cleanup policy.
    pub async fn shutdown(&mut self, timeout: Duration) -> Result<ManagedExit> {
        let deadline = deadline(timeout)?;
        let graceful = async {
            tokio::select! {
                biased;
                report = self.observe_exit() => report,
                requested = self.client().request_owned_shutdown(
                    Arc::clone(&self.shutdown_admission),
                    deadline,
                ) => {
                    requested?;
                    self.observe_exit().await
                }
            }
        };
        tokio::time::timeout_at(deadline, graceful)
            .await
            .map_err(|_| Error::Timeout {
                operation: "gracefully stop owned program",
            })?
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
