//! Explicit graceful shutdown and separately chosen exact-tree termination.

use std::time::{Duration, Instant};

use super::{ManagedExit, ManagedInstance};
use crate::{Error, Result};

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
    /// A timeout or dropped future does not revoke the request, retry it or
    /// escalate to force. The owner remains intact: reconcile with wait_for_exit
    /// before another explicit action. Dropping the owner still follows its
    /// separately documented default cleanup policy.
    pub async fn shutdown(&mut self, timeout: Duration) -> Result<ManagedExit> {
        let deadline = deadline(timeout)?;
        let graceful = async {
            if self.exit_snapshot().is_some() {
                return self.wait_for_exit().await;
            }
            self.client().request_owned_shutdown().await?;
            self.wait_for_exit().await
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
                self.request_force_cleanup()?;
            }
            self.wait_for_exit().await
        };
        tokio::time::timeout_at(deadline, forced)
            .await
            .map_err(|_| Error::Timeout {
                operation: "confirm explicit owned termination",
            })?
    }
}
