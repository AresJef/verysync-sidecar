use std::{future::Future, time::Duration};

use tokio::{sync::watch, time::Instant};

use crate::{Error, Result};

/// Latest reported phase of a high-level operation. A progress receiver can
/// skip intermediate values. Inspect the returned report for final evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OperationPhase {
    /// No work has been reported yet.
    Pending,
    /// Read current state and check preconditions.
    Checking,
    /// A transient read failed and a bounded retry is pending.
    WaitingToRetry,
    /// The authorized request is being handed to the transport.
    Submitting,
    /// Read the current facts after submission.
    Verifying,
    /// Start the selected program and establish readiness.
    Starting,
    /// The call is returning its report.
    Finished,
}

/// Per-call options for a high-level business operation.
#[derive(Clone, Debug)]
pub struct OperationOptions {
    timeout: Duration,
    pub(crate) allow_read_retry: bool,
    cancel: Option<watch::Receiver<bool>>,
    progress: Option<watch::Sender<OperationPhase>>,
}

impl OperationOptions {
    /// Set one total timeout for queues, reads, writes and verification.
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            allow_read_retry: true,
            cancel: None,
            progress: None,
        }
    }

    /// Retain single-attempt reads even on a handle with transient reads enabled.
    pub fn without_read_retry(mut self) -> Self {
        self.allow_read_retry = false;
        self
    }

    /// Stop waiting when the receiver becomes true. Keep it true until the call
    /// returns. Closing the sender alone does not cancel the wait. An already
    /// submitted native operation can keep running.
    pub fn cancel_wait_on(mut self, signal: watch::Receiver<bool>) -> Self {
        self.cancel = Some(signal);
        self
    }

    /// Publish the latest phase without waiting for a progress reader.
    pub fn report_progress_to(mut self, progress: watch::Sender<OperationPhase>) -> Self {
        self.progress = Some(progress);
        self
    }

    pub(crate) fn start(self) -> Result<OperationContext> {
        tokio::runtime::Handle::try_current().map_err(|_| Error::InvalidConfiguration {
            reason: "business operations require a Tokio runtime with I/O and timers",
        })?;
        let started = Instant::now();
        let deadline = started
            .checked_add(self.timeout)
            .filter(|_| !self.timeout.is_zero())
            .ok_or(Error::InvalidConfiguration {
                reason: "the operation deadline must be positive and representable",
            })?;
        Ok(OperationContext {
            started,
            deadline,
            options: self,
        })
    }
}

pub(crate) struct OperationContext {
    pub(crate) started: Instant,
    pub(crate) deadline: Instant,
    options: OperationOptions,
}

impl OperationContext {
    pub(crate) fn read_retries_enabled(&self, handle_enabled: bool) -> bool {
        handle_enabled && self.options.allow_read_retry
    }

    pub(crate) fn phase(&self, phase: OperationPhase) {
        if let Some(progress) = &self.options.progress {
            progress.send_replace(phase);
        }
    }

    pub(crate) async fn wait<T>(
        &self,
        deadline: Instant,
        operation: &'static str,
        work: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        let deadline = deadline.min(self.deadline);
        let mut signal = self.options.cancel.clone();
        let cancelled = async move {
            if let Some(signal) = &mut signal {
                if signal.wait_for(|requested| *requested).await.is_ok() {
                    return;
                }
            }
            std::future::pending::<()>().await;
        };
        tokio::select! {
            biased;
            _ = cancelled => Err(Error::OperationWaitCancelled { operation }),
            _ = tokio::time::sleep_until(deadline) => Err(Error::Timeout { operation }),
            result = async {
                if Instant::now() >= deadline {
                    return Err(Error::Timeout { operation });
                }
                work.await
            } => result,
        }
    }
}
