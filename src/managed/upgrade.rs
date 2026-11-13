//! Explicit stopped-state CLI upgrades with exact child containment.
use super::{bootstrap, io_error, state, ManagedInstance};
use crate::{Error, ProcessDiagnostic, Result};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    io::Read,
    sync::mpsc,
    time::{Duration, Instant},
};
use url::Url;

/// Explicit native CLI operation. Provider/from-URL modes can overwrite the
/// selected executable; they do not use the SDK's checksum-pinned downloader.
#[derive(Clone)]
pub enum KernelUpgradeCommand {
    /// Run only the kernel provider availability check.
    Check,
    /// Perform the upgrade selected by the kernel's current provider.
    Provider,
    /// Force the explicitly supplied HTTP(S) archive URL. The kernel handles
    /// transport/extraction; this is not an SDK SHA-256 validation guarantee.
    FromUrl(Url),
}
impl fmt::Debug for KernelUpgradeCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Check => "Check",
            Self::Provider => "Provider",
            Self::FromUrl(_) => "FromUrl([REDACTED])",
        })
    }
}
/// Actual contained CLI exit and bounded private output. Exit zero alone does
/// not establish replacement, database compatibility or future readiness.
#[derive(Debug)]
pub struct KernelUpgradeExit {
    /// Actual native exit code; provider check may use a nonzero available code.
    pub code: Option<i32>,
    /// Exact helper containment has ended, including descendant cleanup.
    pub tree_stopped: bool,
    /// Output can contain private data; explicitly inspect only when needed.
    pub diagnostic: ProcessDiagnostic,
}
impl ManagedInstance {
    /// Run one CLI upgrade/check against this already normally stopped owner.
    /// The SDK state lease remains held through contained CLI exit. The upstream
    /// lock is checked, then released before spawn so the CLI can own it itself.
    /// No implicit stop/start, retry, fallback or rollback occurs. Select a
    /// dedicated writable program copy for modifying commands, never a shared
    /// cache generation. Supply the new hash explicitly before restarting.
    ///
    /// Cancellation/deadline requests exact helper cleanup; the private worker
    /// retains locks until cleanup ends. A mutation may already have occurred.
    /// This invalidates the old clean-generation backup claim even for checks;
    /// successfully start and normally stop again before taking a new snapshot.
    pub async fn run_cli_upgrade(
        &mut self,
        command: KernelUpgradeCommand,
        timeout: Duration,
    ) -> Result<KernelUpgradeExit> {
        if !self.state_ready_for_backup
            || !self
                .exit_snapshot()
                .is_some_and(|e| e.tree_stopped && !e.forced && e.code == Some(0))
        {
            return Err(Error::ManagedFailure {
                reason: "CLI upgrade requires a known normally stopped owner",
            });
        }
        if let KernelUpgradeCommand::FromUrl(url) = &command {
            if !matches!(url.scheme(), "https" | "http")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(Error::InvalidConfiguration { reason: "CLI upgrade requires an explicit HTTP(S) archive URL without credentials or fragment" });
            }
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .filter(|_| !timeout.is_zero())
            .ok_or(Error::InvalidConfiguration {
                reason: "CLI upgrade deadline must be positive and representable",
            })?;
        let source = self.selected_program().path().to_owned();
        let expected = self.program_info().sha256;
        let state = self.state_directory().to_owned();
        let (cancel, cancelled) = mpsc::channel::<()>();
        let (send, receive) = tokio::sync::oneshot::channel();
        self.state_ready_for_backup = false;
        std::thread::Builder::new()
            .name("verysync-sidecar-cli-upgrade".into())
            .spawn(move || {
                let result = (|| {
                    let state = state::existing(&state)?;
                    let mut lease = state::StateLease::acquire(&state)?;
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
                    let mut args = vec!["upgrade"];
                    match &command {
                        KernelUpgradeCommand::Check => args.push("--check-only"),
                        KernelUpgradeCommand::Provider => {}
                        KernelUpgradeCommand::FromUrl(url) => {
                            args.push("--from");
                            args.push(url.as_str());
                        }
                    }
                    lease.release_engine_lock_for_spawn();
                    let outcome = bootstrap::cli_capture(
                        &source,
                        lease.path(),
                        &args,
                        None,
                        &cancelled,
                        deadline,
                    );
                    let (status, bytes) = outcome.map_err(|source| {
                        if matches!(command, KernelUpgradeCommand::Check) {
                            source
                        } else {
                            Error::MutationOutcomeUnknown {
                                operation: "run kernel CLI upgrade",
                                source: Box::new(source),
                            }
                        }
                    })?;
                    Ok(KernelUpgradeExit {
                        code: status.code(),
                        tree_stopped: true,
                        diagnostic: ProcessDiagnostic::new(bytes),
                    })
                })();
                let _ = send.send(result);
            })
            .map_err(|e| io_error("create contained CLI upgrade worker", e))?;
        let result = receive.await.map_err(|_| Error::ManagedFailure {
            reason: "CLI upgrade worker ended without an outcome",
        })?;
        drop(cancel);
        result
    }
}
