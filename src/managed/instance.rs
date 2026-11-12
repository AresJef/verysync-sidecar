//! One private owner thread holds native process containment and the state lease.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use tokio::sync::{oneshot, watch};

use super::{bootstrap, io_error, process::OwnedProcess, ManagedOptions};
use crate::{ApiKey, Client, ConnectOptions, DeviceId, Error, ProgramInfo, Result};

/// Observed exit of this managed program and its native containment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedExit {
    /// Actual normal exit code, absent when terminated by a Unix signal.
    pub code: Option<i32>,
    /// Actual Unix termination signal; absent on Windows or a normal exit.
    pub signal: Option<i32>,
    /// Whether owner cancellation/drop requested forced cleanup.
    pub forced: bool,
    /// Whether the private process group or Job was confirmed empty.
    pub tree_stopped: bool,
}

/// A library-owned local program, distinct from a borrowed management `Client`.
///
/// Explicit startup checks the executable and private state, then authenticates
/// the selected endpoint and verifies its persisted identity before returning.
/// The private owner thread retains the state lease through process cleanup.
/// Dropping this owner requests exact contained-process cleanup; a cloned Client
/// does not extend ownership. Await `wait_for_exit` to observe actual termination.
/// No process, service, logger or parent signal handler is installed implicitly.
pub struct ManagedInstance {
    client: Client,
    info: ProgramInfo,
    state: PathBuf,
    pid: u32,
    _owner: Sender<()>,
    exit: watch::Receiver<Option<ManagedExit>>,
}

struct ReadyContext {
    info: ProgramInfo,
    key: ApiKey,
    identity: DeviceId,
    state: PathBuf,
    pid: u32,
}

impl ManagedInstance {
    /// Start the selected official fixed-baseline program using private state.
    ///
    /// Requires a caller-owned Tokio runtime with I/O and timers. Preparation,
    /// filesystem operations and blocking process reaping run on one private
    /// thread. A dropped/failed startup closes its ownership channel so that
    /// thread cleans up only its exact processes. Partial private state remains
    /// available for diagnosis/retry; it is never cleared to conceal a failure.
    pub async fn start(options: ManagedOptions) -> Result<Self> {
        tokio::runtime::Handle::try_current().map_err(|_| Error::InvalidConfiguration {
            reason: "managed startup requires a Tokio runtime with I/O and timers",
        })?;
        let deadline =
            Instant::now()
                .checked_add(options.timeout)
                .ok_or(Error::InvalidConfiguration {
                    reason: "managed startup deadline is not representable",
                })?;
        let (owner, cancel) = mpsc::channel();
        let (ready_sender, ready) = oneshot::channel();
        let (exit_sender, exit) = watch::channel(None);
        let worker_options = options.clone();
        std::thread::Builder::new()
            .name("verysync-sidecar-owner".to_owned())
            .spawn(move || {
                owner_thread(worker_options, cancel, ready_sender, exit_sender, deadline)
            })
            .map_err(|e| io_error("create private owner thread", e))?;
        let startup = async {
            let context = ready.await.map_err(|_| Error::ManagedFailure {
                reason: "owner ended before startup metadata",
            })??;
            let client = loop {
                if let Some(report) = *exit.borrow() {
                    return Err(Error::ManagedProcessExited { code: report.code });
                }
                let connection = ConnectOptions::new(options.endpoint.clone(), context.key.clone())
                    .expected_device_id(context.identity.clone())
                    .request_timeout(Duration::from_secs(1))?;
                match Client::connect(connection).await {
                    Ok(client) => break client,
                    Err(Error::Transport { .. } | Error::Timeout { .. }) => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    Err(error) => return Err(error),
                }
            };
            if let Some(report) = *exit.borrow() {
                return Err(Error::ManagedProcessExited { code: report.code });
            }
            Ok(Self {
                client,
                info: context.info,
                state: context.state,
                pid: context.pid,
                _owner: owner,
                exit,
            })
        };
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), startup)
            .await
            .map_err(|_| Error::Timeout {
                operation: "start managed instance",
            })?
    }

    /// Borrow management access; cloning the Client never takes ownership.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Inspect the executable identity checked at startup.
    pub fn program_info(&self) -> &ProgramInfo {
        &self.info
    }

    /// Borrow the canonical native private state directory.
    pub fn state_directory(&self) -> &Path {
        &self.state
    }

    /// Return the retained root child's PID as diagnostic data, not a kill token.
    pub fn process_id(&self) -> u32 {
        self.pid
    }

    /// Wait for actual process-tree exit and release of the private state lease.
    ///
    /// This does not send a shutdown request. Place a caller-selected timeout
    /// around this future if needed; cancelling the wait does not stop the owner.
    pub async fn wait_for_exit(&mut self) -> Result<ManagedExit> {
        loop {
            if let Some(report) = *self.exit.borrow() {
                if !report.tree_stopped {
                    return Err(Error::ManagedFailure {
                        reason: "owned process-tree cleanup could not be confirmed",
                    });
                }
                return Ok(report);
            }
            self.exit
                .changed()
                .await
                .map_err(|_| Error::ManagedFailure {
                    reason: "owner ended without an exit report",
                })?;
        }
    }
}

impl fmt::Debug for ManagedInstance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedInstance")
            .field("program", &self.info)
            .field("root_pid", &self.pid)
            .finish_non_exhaustive()
    }
}

fn owner_thread(
    options: ManagedOptions,
    cancel: Receiver<()>,
    ready: oneshot::Sender<Result<ReadyContext>>,
    exit: watch::Sender<Option<ManagedExit>>,
    deadline: Instant,
) {
    let mut prepared = match bootstrap::prepare(&options, &cancel, deadline) {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    let state = prepared.lease.path().to_owned();
    let mut command = bootstrap::command(&prepared.binary, &state);
    command
        .arg("serve")
        .arg("--home")
        .arg(&state)
        .args(["--no-browser", "--no-restart", "--no-upgrade"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Keep the library lease. Only the official lock is handed back just before
    // spawn so the official process can acquire it itself. External launchers
    // of the same private state must coordinate this non-atomic handoff.
    prepared.lease.release_engine_lock_for_spawn();
    let mut process = match OwnedProcess::spawn(command, false) {
        Ok(process) => process,
        Err(error) => {
            drop(prepared.lease);
            let _ = ready.send(Err(io_error("spawn owned program", error)));
            return;
        }
    };
    let context = ReadyContext {
        info: prepared.info,
        key: prepared.key,
        identity: prepared.identity,
        state,
        pid: process.id(),
    };
    let lease = prepared.lease;
    if ready.send(Ok(context)).is_err() {
        drop(process);
        drop(lease);
        return;
    }
    let mut forced = false;
    let status = loop {
        match process.try_wait() {
            Ok(Some(status)) => break Some(status),
            Err(_) => {
                forced = true;
                let _ = process.abort();
                break process.try_wait().ok().flatten();
            }
            Ok(None) => {}
        }
        match cancel.recv_timeout(Duration::from_millis(10)) {
            Err(RecvTimeoutError::Timeout) => {}
            _ => {
                forced = true;
                let _ = process.abort();
                break process.try_wait().ok().flatten();
            }
        }
    };
    let tree_stopped = process.finish().is_ok() && process.tree_stopped().unwrap_or(false);
    let report = ManagedExit {
        code: status.as_ref().and_then(ExitStatus::code),
        signal: exit_signal(status.as_ref()),
        forced,
        tree_stopped,
    };
    drop(process);
    drop(lease);
    let _ = exit.send(Some(report));
}

fn exit_signal(status: Option<&ExitStatus>) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.and_then(ExitStatusExt::signal)
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}
