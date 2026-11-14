//! Shared exact-program, stopped-state CLI execution and cancellation ownership.
use super::{bootstrap, io_error, state, ManagedInstance};
use crate::{Error, ProcessDiagnostic, Result};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    sync::mpsc,
    time::{Duration, Instant},
};
pub(super) struct CliPlan {
    pub arguments: Vec<String>,
    pub positional: Vec<String>,
    pub operation: &'static str,
    pub may_modify: bool,
    pub clean_stop_required: bool,
}
pub(super) struct CliExit {
    pub code: Option<i32>,
    pub tree_stopped: bool,
    pub diagnostic: ProcessDiagnostic,
}
impl ManagedInstance {
    pub(super) async fn run_stopped_cli(
        &mut self,
        plan: CliPlan,
        timeout: Duration,
    ) -> Result<CliExit> {
        let exit = self
            .exit_snapshot()
            .filter(|exit| exit.tree_stopped)
            .ok_or(Error::ManagedFailure {
                reason: "CLI operation requires a confirmed stopped owned tree",
            })?;
        if plan.clean_stop_required
            && (!self.state_ready_for_backup || exit.forced || exit.code != Some(0))
        {
            return Err(Error::ManagedFailure {
                reason: "CLI upgrade requires a known normally stopped owner",
            });
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .filter(|_| !timeout.is_zero())
            .ok_or(Error::InvalidConfiguration {
                reason: "CLI deadline must be positive and representable",
            })?;
        let source = self.selected_program().path().to_owned();
        let expected = self.program_info().sha256;
        let state = self.state_directory().to_owned();
        let management_socket = self
            .options
            .endpoint
            .socket_path()
            .map(std::path::Path::to_owned);
        let (cancel, cancelled) = mpsc::channel::<()>();
        let (send, receive) = tokio::sync::oneshot::channel();
        self.state_ready_for_backup = false;
        std::thread::Builder::new()
            .name("verysync-sidecar-stopped-cli".into())
            .spawn(move || {
                let result = (|| {
                    let state = state::existing(&state)?;
                    let mut lease = state::StateLease::acquire(&state)?;
                    if plan.arguments.first().is_some_and(|s| s == "debug") {
                        let management_socket = management_socket
                            .as_deref()
                            .and_then(|path| std::fs::canonicalize(path).ok());
                        verify_database_state(
                            lease.path(),
                            management_socket.as_deref(),
                            &cancelled,
                            deadline,
                        )?;
                    }
                    #[cfg(windows)]
                    let source = dunce::canonicalize(&source);
                    #[cfg(not(windows))]
                    let source = std::fs::canonicalize(&source);
                    let source = source.map_err(|e| io_error("resolve selected CLI program", e))?;
                    // Executables are public artifacts, not private state files.
                    // Refuse special files and swapped final-component aliases without requiring
                    // a private state-file ACL on a caller-supplied program.
                    let mut open = std::fs::OpenOptions::new();
                    open.read(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        open.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
                    }
                    #[cfg(windows)]
                    {
                        use std::os::windows::fs::OpenOptionsExt;
                        open.custom_flags(
                            windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
                        );
                    }
                    let mut file = open
                        .open(&source)
                        .map_err(|e| io_error("open selected CLI program", e))?;
                    let metadata = file
                        .metadata()
                        .map_err(|e| io_error("inspect selected CLI program", e))?;
                    if !metadata.is_file() || metadata.len() > 256 * 1024 * 1024 {
                        return Err(Error::ProgramRejected {
                            reason: "CLI program is not a bounded regular file",
                        });
                    }
                    #[cfg(windows)]
                    {
                        use std::os::windows::fs::MetadataExt;
                        if metadata.file_attributes()
                            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                            != 0
                        {
                            return Err(Error::ProgramRejected {
                                reason: "CLI program is a reparse point",
                            });
                        }
                    }
                    let mut hash = Sha256::new();
                    let mut buffer = [0; 65536];
                    loop {
                        bootstrap::check_active(&cancelled, deadline)?;
                        let n = file
                            .read(&mut buffer)
                            .map_err(|e| io_error("verify selected CLI program", e))?;
                        if n == 0 {
                            break;
                        }
                        hash.update(&buffer[..n]);
                    }
                    if <[u8; 32]>::from(hash.finalize()) != expected {
                        return Err(Error::ProgramRejected {
                            reason: "CLI program differs from the last ready generation",
                        });
                    }
                    // Windows must be able to replace the old executable. Do not
                    // retain a verification handle across the modifying CLI.
                    drop(file);
                    let args = plan
                        .arguments
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>();
                    let positional = plan
                        .positional
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>();
                    lease.release_engine_lock_for_spawn();
                    let outcome = bootstrap::cli_capture_positional(
                        &source,
                        lease.path(),
                        &args,
                        &positional,
                        None,
                        &cancelled,
                        deadline,
                    );
                    let (status, bytes) = outcome.map_err(|source| {
                        if !plan.may_modify {
                            source
                        } else {
                            Error::MutationOutcomeUnknown {
                                operation: plan.operation,
                                source: Box::new(source),
                            }
                        }
                    })?;
                    Ok(CliExit {
                        code: status.code(),
                        tree_stopped: true,
                        diagnostic: ProcessDiagnostic::new(bytes),
                    })
                })();
                let _ = send.send(result);
            })
            .map_err(|e| io_error("create contained CLI worker", e))?;
        let result = receive.await.map_err(|_| Error::ManagedFailure {
            reason: "CLI worker ended without an outcome",
        })?;
        drop(cancel);
        result
    }
}

// Inspect only the stopped private state, never registered synchronization
// roots. No alias is followed; the lease is held through native cleanup.
fn verify_database_state(
    root: &std::path::Path,
    management_socket: Option<&std::path::Path>,
    cancelled: &mpsc::Receiver<()>,
    deadline: Instant,
) -> Result<()> {
    #[cfg(not(unix))]
    let _ = management_socket;
    let mut pending = vec![(root.to_owned(), 0usize)];
    let mut entries = 0usize;
    while let Some((directory, depth)) = pending.pop() {
        bootstrap::check_active(cancelled, deadline)?;
        for item in std::fs::read_dir(&directory)
            .map_err(|e| io_error("enumerate stopped database state", e))?
        {
            bootstrap::check_active(cancelled, deadline)?;
            let item = item.map_err(|e| io_error("read stopped database state entry", e))?;
            entries += 1;
            if entries > 65536 {
                return Err(Error::UnmanagedState);
            }
            let path = item.path();
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|e| io_error("inspect stopped database state entry", e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                if Some(path.as_path()) == management_socket && metadata.file_type().is_socket() {
                    continue;
                }
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes()
                    & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                    != 0
                {
                    return Err(Error::UnmanagedState);
                }
            }
            if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
                return Err(Error::UnmanagedState);
            }
            if metadata.is_dir() {
                if depth >= 63 {
                    return Err(Error::UnmanagedState);
                }
                pending.push((path, depth + 1));
            }
        }
    }
    Ok(())
}
