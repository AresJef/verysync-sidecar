//! One private owner thread holds native process containment and the state lease.

use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use tokio::sync::{oneshot, watch};

use super::{bootstrap, io_error, process::OwnedProcess, ManagedOptions};
use crate::{
    ApiKey, Client, ConnectOptions, DeviceId, Error, ProcessDiagnostic, ProgramInfo, Result,
};

/// Observed exit of this managed program and its native containment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedExit {
    /// Actual normal exit code, absent when terminated by a Unix signal.
    pub code: Option<i32>,
    /// Actual Unix termination signal; absent on Windows or a normal exit.
    pub signal: Option<i32>,
    /// Whether owner cancellation/drop requested forced cleanup.
    pub forced: bool,
    /// Whether the private process group or Job has no live members.
    pub tree_stopped: bool,
    /// Bounded private output, excluded from ordinary Debug text.
    pub diagnostic: ProcessDiagnostic,
}

/// A library-owned local program, distinct from a borrowed management `Client`.
///
/// Explicit startup checks the executable and private state, then authenticates
/// the selected endpoint and verifies its persisted identity before returning.
/// The private owner thread retains the state lease through process cleanup.
/// The default lifetime requests exact contained-process cleanup on owner drop.
/// Explicit Persistent lifetime retains a successfully started core instead; a
/// cloned Client never takes ownership. Await `wait_for_exit` for actual termination.
/// No process, service, logger or parent signal handler is installed implicitly.
pub struct ManagedInstance {
    pub(super) options: ManagedOptions,
    client: Client,
    info: ProgramInfo,
    state: PathBuf,
    pid: u32,
    _owner: Sender<()>,
    exit: watch::Receiver<Option<ManagedExit>>,
    pub(super) state_ready_for_backup: bool,
}

struct ReadyContext {
    info: ProgramInfo,
    key: ApiKey,
    identity: DeviceId,
    state: PathBuf,
    pid: u32,
}

impl ManagedInstance {
    pub(super) fn exit_snapshot(&self) -> Option<ManagedExit> {
        self.exit.borrow().as_ref().cloned()
    }

    pub(super) fn request_force_cleanup(&self) -> Result<()> {
        self._owner.send(()).map_err(|_| Error::ManagedFailure {
            reason: "owned control thread is no longer available",
        })
    }

    /// Start the selected program using private state and explicit version policy.
    /// The default accepts only the fixed validated baseline.
    ///
    /// Requires a caller-owned Tokio runtime with I/O and timers. Preparation,
    /// filesystem operations and blocking process reaping run on one private
    /// thread. A dropped/failed startup closes its ownership channel so that
    /// thread cleans up only its exact processes. Partial private state remains
    /// available for diagnosis/retry; it is never cleared to conceal a failure.
    /// Cleanup continues independently of the Tokio runtime, but dropping this
    /// future does not synchronously wait for process exit. An immediate explicit
    /// retry can return [`Error::ManagedStateInUse`] while cleanup owns the lease.
    /// Dropping a Tokio task's JoinHandle alone does not cancel that task.
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
        let committed = Arc::new(AtomicBool::new(false));
        let worker_committed = committed.clone();
        std::thread::Builder::new()
            .name("verysync-sidecar-owner".to_owned())
            .spawn(move || {
                owner_thread(
                    worker_options,
                    cancel,
                    ready_sender,
                    exit_sender,
                    deadline,
                    worker_committed,
                )
            })
            .map_err(|e| io_error("create private owner thread", e))?;
        let startup = async {
            let context = ready.await.map_err(|_| Error::ManagedFailure {
                reason: "owner ended before startup metadata",
            })??;
            let client = loop {
                if let Some(report) = exit.borrow().as_ref().cloned() {
                    return Err(Error::ManagedProcessExited {
                        operation: "reach authenticated managed readiness",
                        code: report.code,
                        diagnostic: Some(report.diagnostic),
                    });
                }
                let connection = ConnectOptions::new(options.endpoint.clone(), context.key.clone())
                    .expected_device_id(context.identity.clone())
                    .version_policy(options.version_policy)
                    .request_timeout(options.request_timeout)?;
                match Client::connect(connection).await {
                    Ok(client) => break client,
                    Err(Error::Transport { .. } | Error::Timeout { .. }) => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    Err(error) => return Err(error),
                }
            };
            if let Some(report) = exit.borrow().as_ref().cloned() {
                return Err(Error::ManagedProcessExited {
                    operation: "reach authenticated managed readiness",
                    code: report.code,
                    diagnostic: Some(report.diagnostic),
                });
            }
            if client.instance().version.version != context.info.version {
                return Err(Error::ProgramRejected {
                    reason: "management version differs from the selected program's CLI version",
                });
            }
            committed.store(true, Ordering::Release);
            Ok(Self {
                options,
                client,
                info: context.info,
                state: context.state,
                pid: context.pid,
                _owner: owner,
                exit,
                state_ready_for_backup: true,
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

    /// Select a native GUI authentication mode once and adopt the API-key
    /// connection after GUI reload. Actual LDAP login is verified separately.
    pub async fn set_gui_auth_mode(
        &mut self,
        mode: &crate::GuiAuthMode,
        timeout: Duration,
    ) -> Result<crate::GuiAuthModeUpdate> {
        let update = self.client.set_gui_auth_mode(mode, timeout).await?;
        self.client = update.client.clone();
        Ok(update)
    }

    /// Set local GUI credentials once and adopt the authenticated API-key
    /// connection after native GUI reload. No core restart or force is used.
    /// A separate GUI login verifies the supplied password.
    pub async fn set_local_gui_credentials(
        &mut self,
        credentials: &crate::GuiCredentials,
        timeout: Duration,
    ) -> Result<crate::GuiCredentialUpdate> {
        let update = self
            .client
            .set_local_gui_credentials(credentials, timeout)
            .await?;
        self.client = update.client.clone();
        Ok(update)
    }

    /// Rotate the management key once and adopt the freshly authenticated
    /// connection for subsequent owned lifecycle operations. The root process
    /// is not restarted. Old borrowed clients retain their previous credential.
    /// Check the returned readback/refusal flags. After cancellation or unknown
    /// outcome, explicitly reconnect with the retained proposed key.
    pub async fn rotate_api_key(
        &mut self,
        key: ApiKey,
        timeout: Duration,
    ) -> Result<crate::ApiKeyRotation> {
        let rotation = self.client.rotate_api_key(key, timeout).await?;
        self.client = rotation.client.clone();
        Ok(rotation)
    }

    /// Read-only credential recovery for this same owned identity. A failed
    /// authentication leaves the owner and its original connection intact.
    /// Performs no key change, restart or process termination.
    pub async fn reconnect_with_api_key(&mut self, key: ApiKey) -> Result<()> {
        let client = self.client.reconnect_with_api_key(key).await?;
        self.client = client;
        Ok(())
    }

    /// Inspect the executable identity checked at startup.
    pub fn program_info(&self) -> &ProgramInfo {
        &self.info
    }

    /// The program selected for the next startup. After a failed program switch
    /// this can differ from `program_info`, which describes the last ready core.
    pub fn selected_program(&self) -> &crate::LocalProgram {
        &self.options.program
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
            if let Some(report) = self.exit.borrow().as_ref().cloned() {
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
    committed: Arc<AtomicBool>,
) {
    let mut prepared = match bootstrap::prepare(&options, &cancel, deadline) {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    let state = prepared.lease.path().to_owned();
    let spawned = spawn_core(
        &prepared.binary,
        &state,
        &mut prepared.lease,
        options.lifetime,
        options.upgrade_checks,
    );
    let (mut process, mut capture) = match spawned {
        Ok(pair) => pair,
        Err(error) => {
            drop(prepared.lease);
            let _ = ready.send(Err(error));
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
        // Periodically reset the private capture; bounded reads never expose
        // more than 64 KiB. Output is never forwarded to a global logger.
        if capture
            .metadata()
            .is_ok_and(|metadata| metadata.len() > 65536)
        {
            let _ = capture.set_len(0);
            let _ = capture.seek(SeekFrom::Start(0));
        }
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
            Err(RecvTimeoutError::Disconnected)
                if options.lifetime == super::ManagedLifetime::Persistent
                    && committed.load(Ordering::Acquire) =>
            {
                // Keep the exact child/lease on this existing owner thread.
                // Abrupt caller exit releases OS handles without a service.
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => {
                forced = true;
                let _ = process.abort();
                break process.try_wait().ok().flatten();
            }
        }
    };
    let tree_stopped = process.finish().is_ok() && process.tree_stopped().unwrap_or(false);
    let _ = capture.seek(SeekFrom::Start(0));
    let mut diagnostic = Vec::new();
    let _ = Read::by_ref(&mut capture)
        .take(65536)
        .read_to_end(&mut diagnostic);
    let report = ManagedExit {
        code: status.as_ref().and_then(ExitStatus::code),
        signal: exit_signal(status.as_ref()),
        forced,
        tree_stopped,
        diagnostic: ProcessDiagnostic::new(diagnostic),
    };
    drop(process);
    drop(lease);
    // Publish only after releasing the diagnostic handle as well. On Windows
    // this private handle denies rename/delete while it remains open.
    drop(capture);
    let _ = exit.send(Some(report));
}

fn spawn_core(
    binary: &Path,
    state: &Path,
    lease: &mut super::state::StateLease,
    lifetime: super::ManagedLifetime,
    upgrade_checks: super::ManagedUpgradeChecks,
) -> Result<(OwnedProcess, File)> {
    let mut capture = super::native::open_private(&state.join(".verysync-sidecar-core.log"), false)
        .map_err(|e| io_error("open private core diagnostics", e))?;
    capture
        .set_len(0)
        .map_err(|e| io_error("reset private core diagnostics", e))?;
    capture
        .seek(SeekFrom::Start(0))
        .map_err(|e| io_error("position private core diagnostics", e))?;
    let mut command = bootstrap::command(binary, state);
    command
        .arg("serve")
        .arg("--home")
        .arg(state)
        .args(["--no-browser", "--no-restart"]);
    if upgrade_checks == super::ManagedUpgradeChecks::Disabled {
        command.arg("--no-upgrade");
    } else {
        command.env_remove("STNOUPGRADE");
    }
    lease.release_engine_lock_for_spawn();
    let retained = lifetime == super::ManagedLifetime::CallerOwned;
    let io = super::process::ProcessIo {
        stdin_pipe: false,
        stdout: if retained {
            Some(
                capture
                    .try_clone()
                    .map_err(|e| io_error("capture core output", e))?,
            )
        } else {
            None
        },
        stderr: if retained {
            Some(
                capture
                    .try_clone()
                    .map_err(|e| io_error("capture core errors", e))?,
            )
        } else {
            None
        },
    };
    Ok((
        OwnedProcess::spawn(command, false, lifetime, io)
            .map_err(|e| io_error("spawn owned program", e))?,
        capture,
    ))
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
