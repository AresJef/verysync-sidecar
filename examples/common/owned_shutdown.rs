//! Shut down once, then observe the same owned generation within the caller's deadline.

use std::time::{Duration, Instant};
use verysync_sidecar::{Error, ManagedExit, ManagedExitObservation, ManagedInstance, Result};

pub struct ShutdownReport {
    pub original: Result<ManagedExit>,
    pub later: Option<Result<ManagedExitObservation>>,
}

pub async fn shutdown_once_observing_exit(
    owner: &mut ManagedInstance,
    first_wait: Duration,
    total_wait: Duration,
) -> ShutdownReport {
    let start = Instant::now();
    let generation = owner.control_generation();
    let original = owner.shutdown(first_wait.min(total_wait)).await;
    let remaining = total_wait.saturating_sub(start.elapsed());
    let later = match &original {
        Err(Error::Timeout { .. } | Error::MutationOutcomeUnknown { .. })
            if !remaining.is_zero() =>
        {
            Some(owner.observe_control_exit(&generation, remaining).await)
        }
        _ => None,
    };
    ShutdownReport { original, later }
}
