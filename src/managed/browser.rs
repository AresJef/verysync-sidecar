//! Explicit GUI dispatch through a separately owned native helper profile.
use super::{
    bootstrap, io_error, launcher::LauncherProcess, native, process::ProcessIo, state,
    ManagedInstance, ManagedOptions,
};
use crate::{Error, LocalProgram, ProgramInfo, Result};
use std::{
    fmt, fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::mpsc,
    time::{Duration, Instant},
};

const ROLE: &str = ".verysync-sidecar-browser-helper";
const ROLE_FORMAT: &[u8] = b"verysync-sidecar native browser helper v1\n";

/// Actual exit of the native browser command, not observation of a window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeBrowserOutcome {
    /// The exact launcher root exited zero and its descendant lifetime was released.
    CommandSucceeded,
    /// The exact root exited unsuccessfully; a desktop request may already exist.
    NativeFailure,
}
/// Result of an explicit native browser request. It never claims a visible GUI.
pub struct NativeBrowserExit {
    /// Actual normal root code, absent for a signal or other abnormal native exit.
    pub code: Option<i32>,
    /// Classification of the observed root exit.
    pub outcome: NativeBrowserOutcome,
    /// Exact short-lived launcher PID; not a browser window or browser PID.
    pub launcher_pid: u32,
    /// Program fingerprint and version checked against the last ready core.
    pub program: ProgramInfo,
    /// Whether native --verify was requested.
    pub native_verify_requested: bool,
    /// Whether the SDK authenticated the target identity before dispatch.
    pub authenticated_identity_checked: bool,
    /// Whether the root-success guard was released; it does not prove a window exists.
    pub descendants_released: bool,
    /// Whether the separate helper's engine lock and library lease were released.
    pub helper_state_released: bool,
    helper_state: PathBuf,
}
impl NativeBrowserExit {
    /// Explicit access to the dedicated persistent helper state path.
    pub fn helper_state_directory(&self) -> &Path {
        &self.helper_state
    }
}
impl fmt::Debug for NativeBrowserExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeBrowserExit")
            .field("code", &self.code)
            .field("outcome", &self.outcome)
            .field("launcher_pid", &self.launcher_pid)
            .field("native_verify_requested", &self.native_verify_requested)
            .field(
                "authenticated_identity_checked",
                &self.authenticated_identity_checked,
            )
            .field("descendants_released", &self.descendants_released)
            .field("helper_state_released", &self.helper_state_released)
            .finish_non_exhaustive()
    }
}

fn canonical(path: &Path) -> std::io::Result<PathBuf> {
    #[cfg(windows)]
    {
        dunce::canonicalize(path)
    }
    #[cfg(not(windows))]
    {
        fs::canonicalize(path)
    }
}
fn alias(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        return metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0;
    }
    #[cfg(not(windows))]
    {
        false
    }
}
// Resolve an existing ancestor before creating anything. Comparing only the
// caller's path spelling would miss aliases and Windows short/long names.
fn disjoint_helper_path(candidate: &Path, primary: &Path) -> Result<PathBuf> {
    if !candidate.is_absolute()
        || candidate.as_os_str().as_encoded_bytes().contains(&0)
        || candidate
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(Error::InvalidConfiguration {
            reason:
                "browser helper state must be an absolute path without parent components or NUL",
        });
    }
    candidate.to_str().ok_or(Error::PathEncoding)?;
    let mut ancestor = candidate;
    let mut missing = Vec::new();
    loop {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if !metadata.is_dir() || alias(&metadata) {
                    return Err(Error::UnmanagedState);
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if missing.len() >= 256 {
                    return Err(Error::UnmanagedState);
                }
                missing.push(
                    ancestor
                        .file_name()
                        .ok_or(Error::UnmanagedState)?
                        .to_owned(),
                );
                ancestor = ancestor.parent().ok_or(Error::UnmanagedState)?;
            }
            Err(error) => return Err(io_error("inspect browser helper ancestor", error)),
        }
    }
    let mut resolved =
        canonical(ancestor).map_err(|e| io_error("resolve browser helper ancestor", e))?;
    for part in missing.into_iter().rev() {
        resolved.push(part);
    }
    if resolved.starts_with(primary) || primary.starts_with(&resolved) {
        return Err(Error::UnmanagedState);
    }
    Ok(resolved)
}
fn require_role(path: &Path) -> Result<()> {
    state::existing(path)?;
    let mut bytes = Vec::new();
    native::open_private(&path.join(ROLE), true)
        .map_err(|_| Error::UnmanagedState)?
        .take(128)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error("read browser helper role", e))?;
    if bytes != ROLE_FORMAT {
        return Err(Error::UnmanagedState);
    }
    Ok(())
}
fn admit_helper_state(candidate: &Path, primary: &Path) -> Result<PathBuf> {
    let resolved = disjoint_helper_path(candidate, primary)?;
    let existing = match fs::read_dir(&resolved) {
        Ok(mut entries) => entries
            .next()
            .transpose()
            .map_err(|e| io_error("inspect browser helper state", e))?
            .is_some(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(io_error("inspect browser helper state", e)),
    };
    if existing {
        require_role(&resolved)?;
    }
    let lease = state::StateLease::acquire(&resolved)?;
    if lease.path().starts_with(primary) || primary.starts_with(lease.path()) {
        return Err(Error::UnmanagedState);
    }
    if existing {
        require_role(lease.path())?;
    } else {
        let mut role = native::create_private(&lease.path().join(ROLE))
            .map_err(|e| io_error("mark browser helper state", e))?;
        role.write_all(ROLE_FORMAT)
            .map_err(|e| io_error("write browser helper role", e))?;
        role.sync_all()
            .map_err(|e| io_error("persist browser helper role", e))?;
    }
    let path = lease.path().to_owned();
    drop(lease);
    Ok(path)
}
fn active(cancel: &mpsc::Receiver<()>, deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(Error::Timeout {
            operation: "request native browser",
        });
    }
    match cancel.try_recv() {
        Err(mpsc::TryRecvError::Empty) => Ok(()),
        _ => Err(Error::ManagedFailure {
            reason: "native browser request was cancelled",
        }),
    }
}

impl ManagedInstance {
    /// Explicitly ask the last-ready program to dispatch its HTTP(S) GUI URL.
    ///
    /// `helper_state` must be new/empty or already marked as a browser helper.
    /// It must be separate from the owned core state, including parent/child
    /// relationships and resolved aliases. A fresh helper generates its own
    /// private identity/configuration; no primary keys, folders or data are copied.
    /// The helper never serves, listens, installs a service or starts synchronization.
    /// Existing ordinary application/managed-core profiles are not adopted.
    ///
    /// When `verify` is true, authenticate the owned target identity within this
    /// total deadline, then pass native --verify. The native probe does not itself
    /// certify authentication or HTTP status. Native HTTPS trust is independent
    /// from caller SDK TLS configuration. False allows dispatch to the last
    /// configured URL even after an explicit owned-core stop, with no SDK probe.
    /// A Unix-socket-only target has no browser URL and is rejected.
    ///
    /// Only the exact root is awaited. A zero exit releases desktop descendants;
    /// it does not prove a browser/window opened. Native failure or cancellation
    /// can follow an already dispatched desktop request, so graphical rollback
    /// is not promised. Ordinary core and CLI containment is unchanged.
    /// Standard streams are discarded rather than retained by a desktop process.
    /// Preparation errors preserve existing private metadata diagnostics.
    /// The separate helper profile persists for explicit diagnosis/reuse.
    pub async fn request_native_browser(
        &self,
        helper_state: impl Into<PathBuf>,
        verify: bool,
        timeout: Duration,
    ) -> Result<NativeBrowserExit> {
        tokio::runtime::Handle::try_current().map_err(|_| Error::InvalidConfiguration {
            reason: "native browser request requires Tokio",
        })?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .filter(|_| !timeout.is_zero())
            .ok_or(Error::InvalidConfiguration {
                reason: "browser deadline must be positive and representable",
            })?;
        if self.options.endpoint.http_url().is_none() {
            return Err(Error::UnsupportedTransport {
                transport: "native browser requires an explicit HTTP(S) management URL",
            });
        }
        let info = self.program_info().clone();
        let program =
            LocalProgram::new(self.selected_program().path())?.expected_sha256(info.sha256);
        let mut options =
            ManagedOptions::new(program, helper_state, self.options.endpoint.clone())?;
        options.version_policy = self.options.version_policy;
        let primary = self.state_directory().to_owned();
        if verify {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.client().system_status(),
            )
            .await
            .map_err(|_| Error::Timeout {
                operation: "authenticate native browser target",
            })??;
        }
        let (cancel, cancelled) = mpsc::channel();
        let (send, receive) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("verysync-sidecar-browser".into())
            .spawn(move || {
                let mut dispatched = false;
                let result = (|| {
                    active(&cancelled, deadline)?;
                    options.state = admit_helper_state(&options.state, &primary)?;
                    active(&cancelled, deadline)?;
                    let mut prepared = bootstrap::prepare(&options, &cancelled, deadline)?;
                    if prepared.info != info {
                        return Err(Error::ProgramRejected {
                            reason: "browser program differs from the last ready core",
                        });
                    }
                    require_role(prepared.lease.path())?;
                    let helper_state = prepared.lease.path().to_owned();
                    let mut command = bootstrap::command(&prepared.binary, &helper_state);
                    command.arg("browser").arg("--home").arg(&helper_state);
                    if verify {
                        command.arg("--verify");
                    }
                    active(&cancelled, deadline)?;
                    prepared.lease.release_engine_lock_for_spawn();
                    let mut launcher = LauncherProcess::spawn(
                        command,
                        ProcessIo {
                            stdin_pipe: false,
                            stdout: None,
                            stderr: None,
                        },
                    )
                    .map_err(|e| io_error("spawn native browser launcher", e))?;
                    dispatched = true;
                    let launcher_pid = launcher.id();
                    let status = loop {
                        active(&cancelled, deadline)?;
                        if let Some(status) = launcher
                            .try_wait()
                            .map_err(|e| io_error("observe native browser root", e))?
                        {
                            break status;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    };
                    let succeeded = status.success();
                    if succeeded {
                        launcher
                            .release_after_success()
                            .map_err(|e| io_error("release native browser launcher", e))?;
                    } else {
                        drop(launcher);
                    }
                    prepared.lease.confirm_engine_released(deadline)?;
                    drop(prepared.lease);
                    Ok(NativeBrowserExit {
                        code: status.code(),
                        outcome: if succeeded {
                            NativeBrowserOutcome::CommandSucceeded
                        } else {
                            NativeBrowserOutcome::NativeFailure
                        },
                        launcher_pid,
                        program: info,
                        native_verify_requested: verify,
                        authenticated_identity_checked: verify,
                        descendants_released: succeeded,
                        helper_state_released: true,
                        helper_state,
                    })
                })();
                let result = result.map_err(|source| {
                    if dispatched {
                        Error::MutationOutcomeUnknown {
                            operation: "request native browser",
                            source: Box::new(source),
                        }
                    } else {
                        source
                    }
                });
                let _ = send.send(result);
            })
            .map_err(|e| io_error("create native browser worker", e))?;
        let result = receive.await.map_err(|_| Error::ManagedFailure {
            reason: "native browser worker ended without an outcome",
        })?;
        drop(cancel);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn helper_role_is_separate_and_reusable_without_adopting_an_owned_core() -> TestResult {
        let root = tempfile::tempdir()?;
        let primary = state::StateLease::acquire(&root.path().join("primary"))?;
        let helper = admit_helper_state(&root.path().join("helper"), primary.path())?;
        fs::write(helper.join("retained"), b"owned helper data")?;
        assert_eq!(admit_helper_state(&helper, primary.path())?, helper);
        assert_eq!(fs::read(helper.join("retained"))?, b"owned helper data");
        let other = state::StateLease::acquire(&root.path().join("other-core"))?;
        let other_path = other.path().to_owned();
        drop(other);
        assert!(matches!(
            admit_helper_state(&other_path, primary.path()),
            Err(Error::UnmanagedState)
        ));
        assert!(!other_path.join(ROLE).exists());
        Ok(())
    }
    #[test]
    fn overlapping_or_ordinary_profiles_are_refused_before_creating_helper_files() -> TestResult {
        let root = tempfile::tempdir()?;
        let primary = state::StateLease::acquire(&root.path().join("primary"))?;
        fs::write(primary.path().join("sentinel"), b"primary bytes")?;
        for path in [
            primary.path().to_owned(),
            primary.path().join("nested"),
            canonical(root.path())?,
        ] {
            assert!(matches!(
                admit_helper_state(&path, primary.path()),
                Err(Error::UnmanagedState)
            ));
        }
        let ordinary = root.path().join("ordinary");
        fs::create_dir(&ordinary)?;
        fs::write(ordinary.join("data"), b"not adopted")?;
        assert!(admit_helper_state(&ordinary, primary.path()).is_err());
        assert!(!ordinary.join(ROLE).exists());
        assert!(!primary.path().join("nested").exists());
        assert_eq!(fs::read(primary.path().join("sentinel"))?, b"primary bytes");
        assert_eq!(fs::read(ordinary.join("data"))?, b"not adopted");
        assert!(matches!(
            disjoint_helper_path(Path::new("relative"), primary.path()),
            Err(Error::InvalidConfiguration { .. })
        ));
        Ok(())
    }
    #[test]
    fn a_corrupt_browser_role_is_not_repaired_or_adopted() -> TestResult {
        let root = tempfile::tempdir()?;
        let primary = state::StateLease::acquire(&root.path().join("primary"))?;
        let helper = admit_helper_state(&root.path().join("helper"), primary.path())?;
        fs::write(helper.join(ROLE), b"unrecognized role")?;
        fs::write(helper.join("retained"), b"retained bytes")?;
        assert!(matches!(
            admit_helper_state(&helper, primary.path()),
            Err(Error::UnmanagedState)
        ));
        assert_eq!(fs::read(helper.join(ROLE))?, b"unrecognized role");
        assert_eq!(fs::read(helper.join("retained"))?, b"retained bytes");
        Ok(())
    }
    #[test]
    fn browser_result_debug_does_not_expose_private_helper_paths_or_native_text() {
        let exit = NativeBrowserExit {
            code: Some(1),
            outcome: NativeBrowserOutcome::NativeFailure,
            launcher_pid: 7,
            program: ProgramInfo {
                version: "private-native-version".to_owned(),
                sha256: [0; 32],
            },
            native_verify_requested: false,
            authenticated_identity_checked: false,
            descendants_released: false,
            helper_state_released: true,
            helper_state: std::env::temp_dir().join("private-browser-helper"),
        };
        let debug = format!("{exit:?}");
        assert!(!debug.contains("private-browser-helper"));
        assert!(!debug.contains("private-native-version"));
    }
    #[cfg(unix)]
    #[test]
    fn helper_aliases_cannot_create_files_inside_the_primary() -> TestResult {
        let root = tempfile::tempdir()?;
        let primary = state::StateLease::acquire(&root.path().join("primary"))?;
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(primary.path(), &alias)?;
        for candidate in [alias.clone(), alias.join("nested")] {
            assert!(admit_helper_state(&candidate, primary.path()).is_err());
        }
        assert!(!primary.path().join("nested").exists());
        assert!(!primary.path().join(ROLE).exists());
        Ok(())
    }
}
