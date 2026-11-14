//! Explicit normal stop followed by authenticated startup of the same state.

use std::time::Duration;

use super::{shutdown, ManagedExit, ManagedInstance};
use crate::{Error, LocalProgram, ProgramInfo, Result};

/// Actual normal exit and newly authenticated executable metadata.
/// This is not a database rollback or a file-backup receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramTransition {
    /// The executable of the previous ready generation.
    pub previous_program: ProgramInfo,
    /// Confirmed exit and containment cleanup before the new core starts.
    pub previous_exit: ManagedExit,
    /// The executable of the newly authenticated generation.
    pub current_program: ProgramInfo,
}

impl ManagedInstance {
    /// Normally stop, then start the same program/state and authenticate again.
    ///
    /// One total deadline covers shutdown and new readiness. The configured
    /// startup deadline still applies to the new start. Success replaces this
    /// owner's Client, program information and exit observation with those of
    /// the authenticated new generation; persisted identity, credentials,
    /// folders and unrelated configuration are reused.
    ///
    /// A failed stop never starts a second owner or escalates to force. If the
    /// old generation stopped but the new start fails, this object retains the
    /// old exit observation and options so the caller can explicitly retry.
    /// A cancelled/failed new startup requests its own exact cleanup and retains
    /// partial state; cleanup can still be completing when an immediate retry
    /// reports the state busy. No automatic retry or rollback occurs. Borrowed
    /// Client clones retain their previous connection snapshot.
    pub async fn restart(&mut self, timeout: Duration) -> Result<()> {
        self.restart_with_program(self.options.program.clone(), timeout)
            .await
            .map(|_| ())
    }

    /// Normally stop this owned tree, select the explicit local program, then
    /// reuse state and authenticate the new generation under one total deadline.
    /// No program is downloaded, overwritten or selected implicitly. Existing
    /// version policy, state, identity and unrelated settings are retained.
    ///
    /// After the old tree stops, the new selection is retained even if startup
    /// fails or is cancelled. A subsequent `restart` retries that selection;
    /// it never silently reopens a possibly migrated database with the old
    /// binary. The last ready `program_info` and old exit observation remain
    /// available on failure. Await cleanup before retrying a busy state.
    ///
    /// This method performs no automatic rollback. Take an offline state backup
    /// before a real version change; executable replacement alone does not prove
    /// database downgrade compatibility or restore data. Borrowed Client clones
    /// retain their previous connection snapshot.
    pub async fn restart_with_program(
        &mut self,
        program: LocalProgram,
        timeout: Duration,
    ) -> Result<ProgramTransition> {
        let deadline = shutdown::deadline(timeout)?;
        tokio::time::timeout_at(deadline, async {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(restart_timeout());
            }
            let previous_program = self.program_info().clone();
            let previous_exit = self.shutdown(remaining).await?;
            self.options.program = program;
            self.state_ready_for_backup = false;
            if tokio::time::Instant::now() >= deadline {
                return Err(restart_timeout());
            }
            let next = Self::start(self.options.clone()).await?;
            let current_program = next.program_info().clone();
            *self = next;
            Ok(ProgramTransition {
                previous_program,
                previous_exit,
                current_program,
            })
        })
        .await
        .map_err(|_| restart_timeout())?
    }
}

fn restart_timeout() -> Error {
    Error::Timeout {
        operation: "restart owned program",
    }
}
