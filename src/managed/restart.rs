//! Explicit normal stop followed by authenticated startup of the same state.

use std::{fmt, time::Duration};

use super::{
    bootstrap::RestartOrigin, shutdown, ManagedExit, ManagedInstance, ManagedShutdownReport,
};
use crate::{
    Error, LocalProgram, OperationCompletion, OperationOptions, OperationPhase, ProgramInfo, Result,
};

const START: &str = "start the selected owned program";

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

/// Verified shutdown of the original owner and readiness of the selected program.
#[derive(Debug)]
#[non_exhaustive]
pub struct ManagedRestartReport {
    /// Original shutdown request and any later evidence of this tree's exit.
    pub shutdown: ManagedShutdownReport,
    /// The selected startup was requested. Inspect the transition for readiness.
    pub startup_attempted: bool,
    /// Observed authenticated process transition, when the new owner is ready.
    pub transition: Option<ProgramTransition>,
    /// A startup failure, timeout or cancellation, when available.
    pub startup_error: Option<Error>,
}

impl ManagedRestartReport {
    /// Summarize the shutdown and new readiness goal.
    pub fn completion(&self) -> OperationCompletion {
        if self.transition.is_some() {
            return OperationCompletion::Completed;
        }
        match self.shutdown.confirmed_exit() {
            Some(exit) if normal_stop(exit) => OperationCompletion::PartiallyCompleted,
            Some(_) => OperationCompletion::GoalNotMet,
            None if !self.shutdown.request.dispatched => OperationCompletion::GoalNotMet,
            None => OperationCompletion::Unconfirmed,
        }
    }
}

impl fmt::Display for ManagedRestartReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.completion() {
            OperationCompletion::Completed =>
                f.write_str("VerySync restarted on the original state and is ready."),
            OperationCompletion::PartiallyCompleted => {
                f.write_str("The original instance stopped. The selected program could not be confirmed ready.")?;
                if let Some(source) = &self.startup_error {
                    write!(f, " {source}")?;
                }
                Ok(())
            }
            _ if self.shutdown.confirmed_exit().is_some() =>
                f.write_str("The original instance exited without a confirmed normal shutdown. Check its exit result before starting it again."),
            _ => fmt::Display::fmt(&self.shutdown, f),
        }
    }
}

impl ManagedInstance {
    /// Normally stop this generation once and authenticate the same selected
    /// program on the existing private state. A delayed initial response can
    /// be reconciled without issuing a second stop. One timeout covers both
    /// stop observation and startup.
    pub async fn restart_and_verify(
        &mut self,
        options: OperationOptions,
    ) -> Result<ManagedRestartReport> {
        self.restart_with_program_and_verify(self.options.program.clone(), options)
            .await
    }

    /// Normally stop the original generation and start the explicit local
    /// program on the same state. A normal tree exit and state release are
    /// required before startup. A failed startup retains the new program as
    /// the selected program and the original exit in the report.
    pub async fn restart_with_program_and_verify(
        &mut self,
        program: LocalProgram,
        options: OperationOptions,
    ) -> Result<ManagedRestartReport> {
        let context = options.start()?;
        let stop_deadline = context.started
            + context
                .deadline
                .duration_since(context.started)
                .mul_f64(2.0 / 3.0);
        let shutdown = self.shutdown_before(&context, stop_deadline).await;
        let mut report = ManagedRestartReport {
            shutdown,
            startup_attempted: false,
            transition: None,
            startup_error: None,
        };
        if let Some(exit) = report
            .shutdown
            .confirmed_exit()
            .filter(|exit| normal_stop(exit))
        {
            let startup = context
                .wait(context.deadline, START, async {
                    context.phase(OperationPhase::Starting);
                    report.startup_attempted = true;
                    let origin = self.restart_origin(true);
                    self.start_on_stopped_state(
                        program,
                        exit.clone(),
                        context.deadline,
                        Some(origin),
                    )
                    .await
                })
                .await;
            match startup {
                Ok(transition) => report.transition = Some(transition),
                Err(source) => report.startup_error = Some(source),
            }
        }
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

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
            let previous_exit = self.shutdown(remaining).await?;
            self.start_on_stopped_state(program, previous_exit, deadline, None)
                .await
        })
        .await
        .map_err(|_| restart_timeout())?
    }

    pub(super) fn restart_origin(&self, clean_stop_required: bool) -> RestartOrigin {
        RestartOrigin {
            generation: self.generation,
            program_sha256: self.program_info().sha256,
            device_id: self.client().instance().device_id.clone(),
            clean_stop_required,
        }
    }

    pub(super) async fn start_on_stopped_state(
        &mut self,
        program: LocalProgram,
        previous_exit: ManagedExit,
        deadline: tokio::time::Instant,
        origin: Option<RestartOrigin>,
    ) -> Result<ProgramTransition> {
        let previous_program = self.program_info().clone();
        self.options.program = program;
        self.state_ready_for_backup = false;
        if tokio::time::Instant::now() >= deadline {
            return Err(restart_timeout());
        }
        let workflow_deadline = origin.as_ref().map(|_| deadline.into_std());
        let next = Self::start_bound(self.options.clone(), origin, workflow_deadline).await?;
        let current_program = next.program_info().clone();
        *self = next;
        Ok(ProgramTransition {
            previous_program,
            previous_exit,
            current_program,
        })
    }
}

fn normal_stop(exit: &ManagedExit) -> bool {
    exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0)
}

fn restart_timeout() -> Error {
    Error::Timeout {
        operation: "restart owned program",
    }
}
