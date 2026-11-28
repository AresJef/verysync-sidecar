use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    sync::{mpsc, watch},
    time::Instant,
};

use crate::{Error, Result, UpgradeCheckpoint};

type SaveUpgrade =
    dyn Fn(UpgradeCheckpoint) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send>> + Send + Sync;

/// A reported phase of a high-level operation. A full progress queue may miss
/// updates. Inspect the returned report for final evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OperationPhase {
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

/// How a high-level operation handled an observed first read failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReadRetryDecision {
    /// The caller or selected client kept single-attempt behavior.
    Disabled,
    /// The cause does not permit another read for this operation.
    CauseNotEligible,
    /// The operation cannot wait for the retry within its deadline.
    InsufficientTime,
    /// This connection and its shared handles have spent their allowance.
    SharedBudgetExhausted,
    /// The operation could proceed to its bounded retry phase.
    Permitted,
}

#[derive(Default)]
pub(crate) struct ReadRetryBudget(Mutex<VecDeque<Instant>>);

impl ReadRetryBudget {
    pub(crate) fn take(&self) -> bool {
        const LIMIT: usize = 4;
        const WINDOW: Duration = Duration::from_secs(1);
        let mut recent = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let now = Instant::now();
        while recent
            .front()
            .is_some_and(|oldest| now.duration_since(*oldest) >= WINDOW)
        {
            recent.pop_front();
        }
        if recent.len() >= LIMIT {
            return false;
        }
        recent.push_back(now);
        true
    }
}

/// Per-call options for a high-level business operation.
#[derive(Clone)]
pub struct OperationOptions {
    timeout: Duration,
    pub(crate) allow_read_retry: bool,
    cancel: Option<watch::Receiver<bool>>,
    progress: Option<mpsc::Sender<OperationPhase>>,
    save_upgrade: Option<Arc<SaveUpgrade>>,
}

impl OperationOptions {
    /// Set one total timeout for queues, reads, writes and verification.
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            allow_read_retry: true,
            cancel: None,
            progress: None,
            save_upgrade: None,
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

    /// Send phase updates without waiting. An update is dropped if the queue
    /// is full or closed. Use the returned report for the operation result.
    pub fn report_progress_to(mut self, progress: mpsc::Sender<OperationPhase>) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Require the fixed upgrade workflows to save private request checkpoints.
    ///
    /// Store the two stages in separate slots keyed by the operation ID. A
    /// pre-upload save failure prevents dispatch. If its future is cancelled,
    /// the application may still finish an already started storage write.
    /// Separate slots prevent that late write from overwriting the returned
    /// request state. Keep the callback asynchronous and independent of the
    /// instance's mutation lock. Storage receives evidence, not ownership or
    /// credentials.
    pub fn save_upgrade_checkpoints<Save, Saved>(mut self, save: Save) -> Self
    where
        Save: Fn(UpgradeCheckpoint) -> Saved + Send + Sync + 'static,
        Saved: Future<Output = io::Result<()>> + Send + 'static,
    {
        self.save_upgrade = Some(Arc::new(move |checkpoint| Box::pin(save(checkpoint))));
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

impl fmt::Debug for OperationOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperationOptions")
            .field("timeout", &self.timeout)
            .field("allow_read_retry", &self.allow_read_retry)
            .field("cancellation_configured", &self.cancel.is_some())
            .field("progress_configured", &self.progress.is_some())
            .field("upgrade_storage_configured", &self.save_upgrade.is_some())
            .finish()
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
            let _ = progress.try_send(phase);
        }
    }

    pub(crate) async fn save_upgrade(
        &self,
        deadline: Instant,
        make_checkpoint: impl FnOnce() -> UpgradeCheckpoint,
    ) -> Result<()> {
        const SAVE: &str = "save the private upgrade checkpoint";
        if let Some(save) = &self.options.save_upgrade {
            self.wait(deadline, SAVE, async {
                save(make_checkpoint())
                    .await
                    .map_err(|source| Error::LocalIo {
                        operation: SAVE,
                        source,
                    })
            })
            .await?;
        }
        Ok(())
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
