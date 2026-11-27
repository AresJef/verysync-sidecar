//! Read-only observations of an explicitly selected owner's program.

use super::{bootstrap, io_error, native, state, ManagedInstance};
use crate::{Error, OfficialProgram, Result, UpgradeOutcome, UpgradeReceipt};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::mpsc,
    time::{Duration, Instant, SystemTime},
};

const MAX_PROGRAM_BYTES: u64 = 256 * 1024 * 1024;

/// How the program file compared with the two digests fixed before dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UpgradeProgramMatch {
    /// The current file matches the exact target executable.
    Target,
    /// The current file still matches the original executable.
    Previous,
    /// The current digest matches neither expected executable.
    Other,
    /// The SDK could not establish a stable, trusted comparison.
    Unconfirmed(UpgradeProgramUncertainty),
}

/// Why an observation did not establish the current program file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UpgradeProgramUncertainty {
    /// The original receipt did not record an unknown modification.
    OriginalOutcomeIsKnown,
    /// There was no recorded position and distinct trusted target digest.
    NoTrustedTarget,
    /// The saved owner or stopped generation no longer matches.
    OwnerChanged,
    /// The original tree is active or cleanup or another writer still holds the lease.
    WriterNotFinished,
    /// The program was missing, inaccessible, outside its bound or unstable.
    FileUnverified,
    /// The observation deadline expired.
    TimedOut,
}

/// A later observation of the same program position. These findings say what
/// was observed on disk. They do not identify who wrote the file or confirm
/// another startup, a database migration, or the original response.
#[derive(Debug)]
#[non_exhaustive]
pub struct UpgradeProgramObservation {
    /// The initiating receipt's correlation ID.
    pub operation_id: [u8; 16],
    /// The original outcome. Later observations never replace it.
    pub original_outcome: UpgradeOutcome,
    /// Time when this observation completed.
    pub observed_at: SystemTime,
    /// The verified current file's SHA-256, if obtained.
    pub current_sha256: Option<[u8; 32]>,
    /// The comparison or the reason no comparison is available.
    pub comparison: UpgradeProgramMatch,
    /// The underlying local error, when one caused the observation to fail.
    pub source: Option<Error>,
}

#[derive(Clone)]
pub(crate) struct UpgradeObservationScope {
    position: PathBuf,
    parent_identity: native::FileIdentity,
    pub(crate) previous: [u8; 32],
    pub(crate) target: [u8; 32],
}

impl ManagedInstance {
    pub(super) async fn bind_upgrade_observation(
        &self,
        target: &OfficialProgram,
        deadline: Instant,
    ) -> Result<UpgradeObservationScope> {
        let target = fixed_program_digest(target, &self.client().instance().version)?;
        let previous = self.program_info().sha256;
        if previous == target {
            return Err(Error::InvalidConfiguration {
                reason: "the candidate executable must differ from the previous executable",
            });
        }
        let selected = self.selected_program().path().to_owned();
        run_read_worker(deadline, move |cancelled| {
            let parent = selected.parent().ok_or(Error::InvalidConfiguration {
                reason: "the dedicated executable must have a parent directory",
            })?;
            let parent = canonical_position(parent)?;
            let name = selected.file_name().ok_or(Error::InvalidConfiguration {
                reason: "the dedicated executable must have a filename",
            })?;
            let position = parent.join(name);
            let directory = open_resource(&parent, true)?;
            let scope = UpgradeObservationScope {
                position,
                parent_identity: stamp(&directory)?.identity,
                previous,
                target,
            };
            if scope.read_program(&cancelled, deadline)? != previous {
                return Err(Error::ProgramRejected {
                    reason:
                        "the selected program differs from the owner's last verified executable",
                });
            }
            Ok(scope)
        })
        .await
    }

    /// Inspect the original owner's dedicated program after an unknown upgrade.
    ///
    /// The initiating call must bind a trusted target before dispatch. Use
    /// the same owning handle after its process and upgrade worker have exited.
    /// No request or process is started. The SDK opens existing private state
    /// and the executable read-only. Coordinate external writers to these
    /// directories, including other applications using the same executable.
    pub async fn observe_upgrade_program(
        &self,
        receipt: &UpgradeReceipt,
        timeout: Duration,
    ) -> Result<UpgradeProgramObservation> {
        use UpgradeProgramMatch::*;
        use UpgradeProgramUncertainty::*;

        let deadline = read_deadline(timeout)?;
        let outcome = receipt.outcome();
        let mut report = UpgradeProgramObservation {
            operation_id: receipt.operation_id(),
            original_outcome: outcome,
            observed_at: SystemTime::now(),
            current_sha256: None,
            comparison: Unconfirmed(OriginalOutcomeIsKnown),
            source: None,
        };
        let finish = |mut report: UpgradeProgramObservation, comparison| {
            report.comparison = comparison;
            report.observed_at = SystemTime::now();
            Ok(report)
        };
        if outcome != UpgradeOutcome::Unknown {
            return finish(report, Unconfirmed(OriginalOutcomeIsKnown));
        }
        let Some(scope) = receipt.observation_scope.clone() else {
            return finish(report, Unconfirmed(NoTrustedTarget));
        };
        if receipt.owner_generation() != Some(self.generation)
            || receipt.device_id() != &self.client().instance().device_id
            || scope.previous != self.program_info().sha256
        {
            return finish(report, Unconfirmed(OwnerChanged));
        }
        if !self
            .exit_snapshot()
            .is_some_and(|exit| exit.tree_stopped && exit.state_released)
        {
            return finish(report, Unconfirmed(WriterNotFinished));
        }

        let root = self.state_directory().to_owned();
        let selected = self.selected_program().path().to_owned();
        let generation = self.generation;
        let result = run_read_worker(deadline, move |cancelled| {
            let guard = state::StoppedProgramObservation::acquire(&root)?;
            if !guard.matches_generation(generation, scope.previous)? {
                return Ok((Unconfirmed(OwnerChanged), None));
            }
            if canonical_position(&selected)? != scope.position {
                return Ok((Unconfirmed(OwnerChanged), None));
            }
            let current = scope.read_program(&cancelled, deadline)?;
            if !guard.matches_generation(generation, scope.previous)? {
                return Ok((Unconfirmed(OwnerChanged), None));
            }
            Ok((
                if current == scope.target {
                    Target
                } else if current == scope.previous {
                    Previous
                } else {
                    Other
                },
                Some(current),
            ))
        })
        .await;
        match result {
            Ok((comparison, digest)) => {
                report.current_sha256 = digest;
                finish(report, comparison)
            }
            Err(source) => {
                let reason = match source {
                    Error::ManagedStateInUse { .. } => WriterNotFinished,
                    Error::Timeout { .. } => TimedOut,
                    _ => FileUnverified,
                };
                report.source = Some(source);
                finish(report, Unconfirmed(reason))
            }
        }
    }
}

pub(super) fn read_deadline(timeout: Duration) -> Result<Instant> {
    Instant::now()
        .checked_add(timeout)
        .filter(|_| !timeout.is_zero())
        .ok_or(Error::InvalidConfiguration {
            reason: "program observation deadline must be positive and representable",
        })
}

async fn run_read_worker<T: Send + 'static>(
    deadline: Instant,
    work: impl FnOnce(mpsc::Receiver<()>) -> Result<T> + Send + 'static,
) -> Result<T> {
    let (cancel, cancelled) = mpsc::channel();
    let task = tokio::task::spawn_blocking(move || work(cancelled));
    let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), task).await;
    drop(cancel);
    match result {
        Ok(Ok(value)) => value,
        Ok(Err(_)) => Err(Error::ManagedFailure {
            reason: "program observation worker ended without a result",
        }),
        Err(_) => Err(Error::Timeout {
            operation: "observe selected upgrade program",
        }),
    }
}

fn canonical_position(path: &Path) -> Result<PathBuf> {
    #[cfg(windows)]
    let canonical = dunce::canonicalize(path);
    #[cfg(not(windows))]
    let canonical = fs::canonicalize(path);
    canonical.map_err(|e| io_error("resolve selected upgrade program position", e))
}

fn open_resource(path: &Path, directory: bool) -> Result<fs::File> {
    native::open_observed_resource(path, directory)
        .map_err(|e| io_error("open selected upgrade program resource", e))
}

fn stamp(file: &fs::File) -> Result<native::FileStamp> {
    native::observed_file_stamp(file)
        .map_err(|e| io_error("inspect selected upgrade program resource", e))
}

impl UpgradeObservationScope {
    fn read_program(&self, cancelled: &mpsc::Receiver<()>, deadline: Instant) -> Result<[u8; 32]> {
        let unstable = || Error::ProgramRejected {
            reason: "the selected program or its containing directory changed during observation",
        };
        let parent = self.position.parent().ok_or_else(unstable)?;
        let directory = open_resource(parent, true)?;
        let parent_before = stamp(&directory)?;
        if parent_before.identity != self.parent_identity {
            return Err(unstable());
        }
        let mut program = open_resource(&self.position, false)?;
        let before = stamp(&program)?;
        if before.links != 1 || before.bytes == 0 || before.bytes > MAX_PROGRAM_BYTES {
            return Err(Error::ProgramRejected {
                reason:
                    "the selected program must be a single linked regular file of at most 256 MiB",
            });
        }
        let mut hash = Sha256::new();
        let mut total = 0;
        let mut buffer = [0; 65536];
        loop {
            bootstrap::check_active(cancelled, deadline)?;
            let count = program
                .read(&mut buffer)
                .map_err(|e| io_error("read selected upgrade program", e))?;
            if count == 0 {
                break;
            }
            total += count as u64;
            if total > before.bytes {
                return Err(unstable());
            }
            hash.update(&buffer[..count]);
        }
        let now = open_resource(&self.position, false)?;
        let parent_now = open_resource(parent, true)?;
        if total != before.bytes
            || stamp(&program)? != before
            || stamp(&now)? != before
            || stamp(&directory)? != parent_before
            || stamp(&parent_now)? != parent_before
        {
            return Err(unstable());
        }
        bootstrap::check_active(cancelled, deadline)?;
        Ok(hash.finalize().into())
    }
}

// These program digests are independently derived from the matching verified
// archive. Match the release catalog's archive identity, never an asserted
// version string or a post-upgrade read of the program being verified.
fn fixed_program_digest(
    target: &OfficialProgram,
    version: &crate::EngineVersion,
) -> Result<[u8; 32]> {
    use crate::{BuildVariant, ProgramArchitecture::*, ProgramOs::*};

    #[derive(serde::Deserialize)]
    struct Catalog {
        version: String,
        packages: Vec<Binary>,
    }
    #[derive(serde::Deserialize)]
    struct Binary {
        archive_sha256: String,
        binary_sha256: String,
    }

    let selected = target.target();
    let matches_host = matches!(
        (
            selected.os(),
            selected.architecture(),
            version.os.as_str(),
            version.arch.as_str()
        ),
        (Linux, Amd64, "linux", "amd64")
            | (Linux, Arm64, "linux", "arm64")
            | (MacOs, Amd64, "darwin", "amd64")
            | (MacOs, Arm64, "darwin", "arm64")
            | (Windows, Amd64, "windows", "amd64")
            | (Windows, Arm64, "windows", "arm64")
    );
    let invalid = || Error::InvalidConfiguration {
        reason: "no trusted executable digest for this release and owned engine architecture",
    };
    if !matches_host || selected.variant() != BuildVariant::Standard {
        return Err(invalid());
    }
    let manifest: Catalog = serde_json::from_str(include_str!(
        "../../releases/verysync-v2.33.2-standard-binaries.json"
    ))
    .map_err(|_| invalid())?;
    if manifest.version != target.version().as_str() {
        return Err(invalid());
    }
    let archive = target.archive_sha256();
    let mut matches = manifest
        .packages
        .into_iter()
        .filter(|item| decode_digest(&item.archive_sha256) == Some(archive));
    let digest = matches
        .next()
        .and_then(|item| decode_digest(&item.binary_sha256));
    if matches.next().is_some() {
        return Err(invalid());
    }
    digest.ok_or_else(invalid)
}

fn decode_digest(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut digest = [0; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(digest)
}
