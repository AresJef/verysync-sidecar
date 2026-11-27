//! Read-only waiting for an exact owned generation's exit.

use std::time::{Duration, Instant, SystemTime};

use super::{
    shutdown, ManagedControlGeneration, ManagedExit, ManagedGenerationStatus, ManagedInstance,
};
use crate::Result;

/// Whether this wait confirmed exit for the requested owned generation.
#[derive(Debug)]
#[non_exhaustive]
pub enum ManagedExitObservationOutcome {
    /// The deadline expired before this wait confirmed exit.
    TimedOut,
    /// The owner recorded exit, containment cleanup and state release.
    Exited(ManagedExit),
}

/// One wait result. Keep an earlier timeout separate from a later exit result.
#[derive(Debug)]
pub struct ManagedExitObservation {
    /// The observed startup generation.
    pub generation: ManagedControlGeneration,
    /// Elapsed monotonic time for this wait.
    pub waited: Duration,
    /// Wall-clock time when this wait returned.
    pub observed_at: SystemTime,
    /// Whether actual exit and cleanup were confirmed.
    pub outcome: ManagedExitObservationOutcome,
}

impl ManagedInstance {
    /// Wait for the selected owned generation without sending a shutdown request.
    ///
    /// Pass the same generation into a new wait after a timeout. A replacement
    /// is rejected. This does not trigger normal or forced termination, release
    /// the state directory, or change the owning handle's lifecycle policy.
    pub async fn observe_control_exit(
        &self,
        generation: &ManagedControlGeneration,
        limit: Duration,
    ) -> Result<ManagedExitObservation> {
        let start = Instant::now();
        let deadline = shutdown::deadline(limit)?;
        if matches!(
            self.check_control_generation(generation),
            ManagedGenerationStatus::Replaced | ManagedGenerationStatus::DifferentDevice
        ) {
            self.require_control_generation(generation)?;
        }

        let outcome = match tokio::time::timeout_at(deadline, self.observe_exit()).await {
            Ok(report) => ManagedExitObservationOutcome::Exited(report?),
            Err(_) => ManagedExitObservationOutcome::TimedOut,
        };
        Ok(ManagedExitObservation {
            generation: generation.clone(),
            waited: start.elapsed(),
            observed_at: SystemTime::now(),
            outcome,
        })
    }
}
