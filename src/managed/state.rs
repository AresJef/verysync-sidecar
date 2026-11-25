//! Private-directory admission and cross-process state leases.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fs2::FileExt;

use super::{io_error, native};
use crate::{Error, Result};

pub(super) const MARKER: &str = ".verysync-sidecar-state";
pub(super) const LEASE: &str = ".verysync-sidecar-lease";
pub(super) const FORMAT: &[u8] = b"verysync-sidecar private state v1\n";
pub(super) const RESTORE_INCOMPLETE: &str = ".verysync-sidecar-restore-incomplete";

pub(super) const GENERATION: &str = ".verysync-sidecar-generation";
const GENERATION_FORMAT: &[u8] = b"verysync-sidecar generation v1\n";
pub(super) type Generation = [u8; 32];

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationRecord {
    generation: Generation,
    stopped_program: Option<[u8; 32]>,
    clean_stop: bool,
}

fn require_complete(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path.join(RESTORE_INCOMPLETE)) {
        Ok(_) => Err(Error::UnmanagedState),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error("inspect state restore completion", error)),
    }
}

fn present(path: &Path, operation: &'static str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(operation, error)),
    }
}

fn unmarked_has_other_entries(path: &Path) -> Result<bool> {
    for entry in fs::read_dir(path).map_err(|e| io_error("inspect unmarked state", e))? {
        let entry = entry.map_err(|e| io_error("read unmarked state entry", e))?;
        if entry.file_name() != LEASE {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Admit existing private state for reads only, without creating files or leases.
pub(super) fn existing(path: &Path) -> Result<PathBuf> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| io_error("inspect existing private state", e))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::UnmanagedState);
    }
    native::private_directory(path, &metadata)
        .map_err(|e| io_error("check existing state privacy", e))?;
    let path = canonical(path).map_err(|e| io_error("resolve existing private state", e))?;
    require_complete(&path)?;
    let mut bytes = Vec::new();
    native::open_private(&path.join(MARKER), true)
        .map_err(|e| io_error("open existing state marker", e))?
        .take(128)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error("read existing state marker", e))?;
    if bytes != FORMAT {
        return Err(Error::UnmanagedState);
    }
    Ok(path)
}

pub(super) struct StateLease {
    path: PathBuf,
    _file: File,
    #[cfg(windows)]
    _directory: File,
    engine_lock: Option<File>,
    owner_process: u32,
}

impl Drop for StateLease {
    fn drop(&mut self) {
        // flock belongs to an open-file description: an incidental dup/fork can
        // keep it alive after close. Release at the creating owner's lifetime
        // boundary, while an inherited copy must never unlock its parent's lease.
        if self.owner_process == std::process::id() {
            if let Some(lock) = &self.engine_lock {
                let _ = FileExt::unlock(lock);
            }
            let _ = FileExt::unlock(&self._file);
        }
    }
}

impl StateLease {
    pub(super) fn acquire(path: &Path) -> Result<Self> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if let Err(error) = native::create_directory(path) {
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(io_error("create private state", error));
                    }
                }
                fs::symlink_metadata(path).map_err(|e| io_error("inspect created state", e))?
            }
            Err(error) => return Err(io_error("inspect state", error)),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::UnmanagedState);
        }
        native::private_directory(path, &metadata)
            .map_err(|e| io_error("check state privacy", e))?;
        let path = canonical(path).map_err(|e| io_error("resolve private state", e))?;
        #[cfg(windows)]
        let directory = native::retain_private_directory(&path)
            .map_err(|e| io_error("retain private state", e))?;
        require_complete(&path)?;

        let marker = path.join(MARKER);
        // The first owner creates the lease before writing the state marker.
        // Admit this transition to the lock check only with library control
        // names. Re-read the marker if the other owner made progress while
        // this directory was being inspected.
        let marker_present = || present(&marker, "inspect state marker");
        if !marker_present()? && unmarked_has_other_entries(&path)? && !marker_present()? {
            return Err(Error::UnmanagedState);
        }
        let file = native::open_private(&path.join(LEASE), false)
            .map_err(|e| io_error("open state lease", e))?;
        if !marker_present()?
            && file
                .metadata()
                .map_err(|e| io_error("inspect initializing state lease", e))?
                .len()
                != 0
        {
            return Err(Error::UnmanagedState);
        }
        file.try_lock_exclusive().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock || error.raw_os_error() == Some(33) {
                Error::ManagedStateInUse {
                    lock: crate::ManagedStateLock::LibraryLease,
                }
            } else {
                io_error("lock private state", error)
            }
        })?;
        if marker_present()? {
            let mut input = native::open_private(&marker, true)
                .map_err(|e| io_error("open state marker", e))?;
            let mut bytes = Vec::new();
            Read::by_ref(&mut input)
                .take(128)
                .read_to_end(&mut bytes)
                .map_err(|e| io_error("read state marker", e))?;
            if bytes != FORMAT {
                return Err(Error::UnmanagedState);
            }
        } else {
            if unmarked_has_other_entries(&path)? {
                return Err(Error::UnmanagedState);
            }
            let mut output =
                native::create_private(&marker).map_err(|e| io_error("create state marker", e))?;
            output
                .write_all(FORMAT)
                .map_err(|e| io_error("write state marker", e))?;
            output
                .sync_all()
                .map_err(|e| io_error("persist state marker", e))?;
        }
        let engine_lock_path = path.join("verysync.lock");
        let engine_lock_exists = match fs::symlink_metadata(&engine_lock_path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(io_error("inspect upstream state lock", error)),
        };
        let engine_lock = if engine_lock_exists {
            let lock = native::open_owned_lock(&engine_lock_path)
                .map_err(|e| io_error("open upstream state lock", e))?;
            lock.try_lock_exclusive().map_err(|error| {
                if error.kind() == io::ErrorKind::WouldBlock || error.raw_os_error() == Some(33) {
                    Error::ManagedStateInUse {
                        lock: crate::ManagedStateLock::EngineLock,
                    }
                } else {
                    io_error("check upstream state lock", error)
                }
            })?;
            Some(lock)
        } else {
            None
        };
        Ok(Self {
            path,
            _file: file,
            #[cfg(windows)]
            _directory: directory,
            engine_lock,
            owner_process: std::process::id(),
        })
    }

    pub(super) fn begin_generation(&self) -> Result<Generation> {
        let mut generation = [0; 32];
        getrandom::fill(&mut generation).map_err(|_| Error::ManagedFailure {
            reason: "could not create a unique state run identifier",
        })?;
        self.write_generation(&GenerationRecord {
            generation,
            stopped_program: None,
            clean_stop: false,
        })?;
        Ok(generation)
    }

    pub(super) fn record_stop(
        &self,
        generation: Generation,
        program: [u8; 32],
        clean_stop: bool,
    ) -> Result<()> {
        if self.read_generation()?.generation != generation {
            return Err(Error::ManagedFailure {
                reason: "private state belongs to a different run",
            });
        }
        self.write_generation(&GenerationRecord {
            generation,
            stopped_program: Some(program),
            clean_stop,
        })
    }

    pub(super) fn require_stopped_generation(
        &self,
        generation: Generation,
        program: [u8; 32],
        clean_required: bool,
    ) -> Result<()> {
        let record = self.read_generation()?;
        if record.generation != generation
            || record.stopped_program != Some(program)
            || (clean_required && !record.clean_stop)
        {
            return Err(Error::ManagedFailure {
                reason: "private state does not match this stopped owner and program",
            });
        }
        Ok(())
    }

    fn read_generation(&self) -> Result<GenerationRecord> {
        let file = native::open_private(&self.path.join(GENERATION), true)
            .map_err(|e| io_error("open stopped state record", e))?;
        let mut bytes = Vec::new();
        file.take(1025)
            .read_to_end(&mut bytes)
            .map_err(|e| io_error("read stopped state record", e))?;
        let body = bytes
            .strip_prefix(GENERATION_FORMAT)
            .filter(|_| bytes.len() <= 1024)
            .ok_or(Error::UnmanagedState)?;
        serde_json::from_slice(body).map_err(|_| Error::ManagedFailure {
            reason: "private state has no complete stopped run record",
        })
    }

    fn write_generation(&self, record: &GenerationRecord) -> Result<()> {
        let mut file = native::open_private(&self.path.join(GENERATION), false)
            .map_err(|e| io_error("open private run record", e))?;
        let mut present = Vec::new();
        Read::by_ref(&mut file)
            .take(GENERATION_FORMAT.len() as u64)
            .read_to_end(&mut present)
            .map_err(|e| io_error("check private run record format", e))?;
        if !GENERATION_FORMAT.starts_with(&present) {
            return Err(Error::UnmanagedState);
        }
        let body = serde_json::to_vec(record).map_err(|_| Error::ManagedFailure {
            reason: "could not encode private run record",
        })?;
        // The private lease is still held. A partial body cannot certify a
        // stopped run. Keep the format prefix intact across interrupted updates.
        file.write_all(&GENERATION_FORMAT[present.len()..])
            .and_then(|_| file.set_len(GENERATION_FORMAT.len() as u64))
            .and_then(|_| file.seek(SeekFrom::Start(GENERATION_FORMAT.len() as u64)))
            .and_then(|_| file.write_all(&body))
            .and_then(|_| file.sync_all())
            .map_err(|e| io_error("persist private run record", e))
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn release_engine_lock_for_spawn(&mut self) {
        if let Some(lock) = self.engine_lock.take() {
            if self.owner_process == std::process::id() {
                let _ = FileExt::unlock(&lock);
            }
        }
    }

    /// Confirm the exact owned state's upstream lock is available after native
    /// containment exit, while retaining our separate library lease. This is a
    /// bounded observation of resource release, never a startup/write retry.
    pub(super) fn confirm_engine_released(&self, deadline: Instant) -> Result<()> {
        loop {
            let lock = match native::open_owned_lock(&self.path.join("verysync.lock")) {
                Ok(lock) => lock,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(io_error("observe owned engine state release", error)),
            };
            match lock.try_lock_exclusive() {
                Ok(()) => return Ok(()),
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.raw_os_error() == Some(33) => {}
                Err(error) => return Err(io_error("observe owned engine lock release", error)),
            }
            drop(lock);
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Error::Timeout {
                    operation: "confirm owned engine state release",
                });
            }
            std::thread::sleep(remaining.min(Duration::from_millis(10)));
        }
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

#[cfg(test)]
mod tests {

    #[test]
    fn first_owner_and_contender_observe_an_initializing_lease() -> Result<()> {
        let fixture = tempfile::tempdir().map_err(|e| io_error("make owned test root", e))?;
        let path = fixture.path().join("state");
        native::create_directory(&path).map_err(|e| io_error("make owned test state", e))?;
        let file = native::open_private(&path.join(LEASE), false)
            .map_err(|e| io_error("make the initializing lease", e))?;
        file.try_lock_exclusive()
            .map_err(|e| io_error("hold the initializing lease", e))?;
        assert!(matches!(
            StateLease::acquire(&path),
            Err(Error::ManagedStateInUse {
                lock: crate::ManagedStateLock::LibraryLease
            })
        ));
        assert!(!path.join(MARKER).exists());
        FileExt::unlock(&file).map_err(|e| io_error("release the initializing lease", e))?;
        drop(file);
        let first = StateLease::acquire(&path)?;
        assert!(matches!(
            StateLease::acquire(&path),
            Err(Error::ManagedStateInUse {
                lock: crate::ManagedStateLock::LibraryLease
            })
        ));
        drop(first);
        StateLease::acquire(&path)?;
        println!(
            "initialization evidence: locked before marker, locked after marker, and reopened"
        );
        Ok(())
    }

    #[test]
    fn simultaneous_fresh_owners_have_one_winner() -> Result<()> {
        let fixture = tempfile::tempdir().map_err(|e| io_error("make owned test root", e))?;
        let path = fixture.path().join("state");
        let rendezvous = std::sync::Barrier::new(2);
        let start = || {
            rendezvous.wait();
            let result = StateLease::acquire(&path);
            rendezvous.wait();
            result
        };
        let results = std::thread::scope(|scope| {
            let second = scope.spawn(start);
            let first = start();
            (first, second.join().unwrap())
        });
        match results {
            (Ok(lease), Err(Error::ManagedStateInUse { .. }))
            | (Err(Error::ManagedStateInUse { .. }), Ok(lease)) => drop(lease),
            _ => panic!("two callers must observe one owner and one in-use result"),
        }
        assert_eq!(
            fs::read(path.join(MARKER)).map_err(|e| io_error("read state marker", e))?,
            FORMAT
        );
        Ok(())
    }

    #[test]
    fn stopped_run_records_follow_the_latest_lease_and_program() -> Result<()> {
        let root = tempfile::tempdir().map_err(|e| io_error("create run fixture", e))?;
        let state = root.path().join("private");
        let a = StateLease::acquire(&state)?;
        let old = a.begin_generation()?;
        let first_program = [11; 32];
        let next_program = [22; 32];
        assert!(a
            .require_stopped_generation(old, first_program, true)
            .is_err());
        a.record_stop(old, first_program, true)?;
        a.require_stopped_generation(old, first_program, true)?;
        a.require_stopped_generation(old, first_program, true)?;
        assert!(a
            .require_stopped_generation(old, next_program, true)
            .is_err());
        drop(a);

        let b = StateLease::acquire(&state)?;
        let current = b.begin_generation()?;
        assert_ne!(old, current);
        assert!(b
            .require_stopped_generation(old, first_program, true)
            .is_err());
        b.record_stop(current, next_program, false)?;
        assert!(b
            .require_stopped_generation(old, first_program, false)
            .is_err());
        assert!(b
            .require_stopped_generation(current, next_program, true)
            .is_err());
        b.require_stopped_generation(current, next_program, false)?;
        Ok(())
    }

    #[test]
    fn pending_and_incomplete_run_records_never_certify_a_stopped_run() -> Result<()> {
        let root = tempfile::tempdir().map_err(|e| io_error("create incomplete run fixture", e))?;
        let lease = StateLease::acquire(&root.path().join("private"))?;
        let old = lease.begin_generation()?;
        let program = [11; 32];
        lease.record_stop(old, program, true)?;
        let marker = lease.path().join(GENERATION);
        let file = native::open_private(&marker, false)
            .map_err(|e| io_error("open fixture run record", e))?;
        file.set_len(GENERATION_FORMAT.len() as u64 + 1)
            .map_err(|e| io_error("truncate fixture run record", e))?;
        drop(file);
        assert!(lease
            .require_stopped_generation(old, program, false)
            .is_err());
        let new = lease.begin_generation()?;
        assert!(lease
            .require_stopped_generation(old, program, false)
            .is_err());
        assert!(lease
            .require_stopped_generation(new, program, false)
            .is_err());
        lease.record_stop(new, program, true)?;
        lease.require_stopped_generation(new, program, true)?;
        Ok(())
    }

    use super::*;

    #[cfg(unix)]
    #[test]
    fn owner_release_does_not_wait_for_an_inherited_duplicate_descriptor() -> Result<()> {
        let root = tempfile::tempdir().map_err(|e| io_error("make duplicate lease root", e))?;
        let path = root.path().join("state");
        let owner = StateLease::acquire(&path)?;
        // dup and fork retain the same flock open-file description. A process
        // being created by another thread must not extend this owner's lease.
        let inherited = owner
            ._file
            .try_clone()
            .map_err(|e| io_error("duplicate lease descriptor", e))?;
        drop(owner);
        let next = StateLease::acquire(&path)?;
        assert!(
            inherited.try_lock_exclusive().is_err(),
            "old duplicate must not bypass the next owner"
        );
        drop(next);
        drop(inherited);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn an_inherited_owner_copy_must_not_unlock_the_creating_process() -> Result<()> {
        let root = tempfile::tempdir().map_err(|e| io_error("make foreign lease root", e))?;
        let path = root.path().join("state");
        let mut owner = StateLease::acquire(&path)?;
        let inherited = owner
            ._file
            .try_clone()
            .map_err(|e| io_error("duplicate foreign lease", e))?;
        // The stored creator differs from the process dropping the copied value,
        // as it does in a fork child. The real duplicated OS lock must stay held.
        owner.owner_process = std::process::id().wrapping_add(1);
        drop(owner);
        assert!(matches!(
            StateLease::acquire(&path),
            Err(Error::ManagedStateInUse { .. })
        ));
        FileExt::unlock(&inherited).map_err(|e| io_error("release test duplicate", e))?;
        let _next = StateLease::acquire(&path)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn spawn_release_does_not_leave_an_upstream_probe_lock_on_a_duplicate() -> Result<()> {
        let root = tempfile::tempdir().map_err(|e| io_error("make upstream duplicate root", e))?;
        let path = root.path().join("state");
        drop(StateLease::acquire(&path)?);
        drop(
            native::create_private(&path.join("verysync.lock"))
                .map_err(|e| io_error("create test upstream lock", e))?,
        );
        let mut owner = StateLease::acquire(&path)?;
        let inherited = owner
            .engine_lock
            .as_ref()
            .expect("existing upstream lock")
            .try_clone()
            .map_err(|e| io_error("duplicate upstream probe", e))?;
        owner.release_engine_lock_for_spawn();
        let probe = native::open_owned_lock(&path.join("verysync.lock"))
            .map_err(|e| io_error("reopen upstream probe", e))?;
        probe
            .try_lock_exclusive()
            .map_err(|e| io_error("check upstream release", e))?;
        drop(inherited);
        Ok(())
    }

    #[test]
    fn exit_state_confirmation_observes_real_lock_release_and_remains_bounded() -> Result<()> {
        let base = tempfile::tempdir().map_err(|e| io_error("make release test root", e))?;
        let path = base.path().join("state");
        let lease = StateLease::acquire(&path)?;
        lease.confirm_engine_released(Instant::now())?;
        assert!(
            !path.join("verysync.lock").exists(),
            "release observation created an upstream lock"
        );
        let held = native::create_private(&path.join("verysync.lock"))
            .map_err(|e| io_error("create release test lock", e))?;
        held.try_lock_exclusive()
            .map_err(|e| io_error("hold release test lock", e))?;
        assert!(matches!(
            lease.confirm_engine_released(Instant::now() + Duration::from_millis(20)),
            Err(Error::Timeout {
                operation: "confirm owned engine state release"
            })
        ));
        assert!(matches!(
            StateLease::acquire(&path),
            Err(Error::ManagedStateInUse {
                lock: crate::ManagedStateLock::LibraryLease
            })
        ));
        drop(held);
        lease.confirm_engine_released(Instant::now() + Duration::from_secs(1))?;
        Ok(())
    }

    #[test]
    fn private_state_is_exclusive_and_reusable_without_changing_data() -> Result<()> {
        let base = tempfile::tempdir().map_err(|e| io_error("make test root", e))?;
        let path = base.path().join("state");
        let lease = StateLease::acquire(&path)?;
        assert_eq!(
            lease.path(),
            canonical(&path).map_err(|e| io_error("resolve test root", e))?
        );
        fs::write(path.join("synthetic"), b"retained").map_err(|e| io_error("write sample", e))?;
        assert!(matches!(
            StateLease::acquire(&path),
            Err(Error::ManagedStateInUse {
                lock: crate::ManagedStateLock::LibraryLease
            })
        ));
        drop(lease);
        let _second = StateLease::acquire(&path)?;
        assert_eq!(
            fs::read(path.join("synthetic")).map_err(|e| io_error("read sample", e))?,
            b"retained"
        );
        Ok(())
    }

    #[test]
    fn arbitrary_existing_state_is_never_adopted_or_rewritten() -> Result<()> {
        let base = tempfile::tempdir().map_err(|e| io_error("make test root", e))?;
        let path = base.path().join("state");
        native::create_directory(&path).map_err(|e| io_error("make test state", e))?;
        fs::write(
            path.join("setting.dat"),
            b"unrelated private application data",
        )
        .map_err(|e| io_error("write sample", e))?;
        assert!(matches!(
            StateLease::acquire(&path),
            Err(Error::UnmanagedState)
        ));
        assert_eq!(
            fs::read(path.join("setting.dat")).map_err(|e| io_error("read sample", e))?,
            b"unrelated private application data"
        );
        assert!(!path.join(LEASE).exists());
        Ok(())
    }

    #[test]
    fn upstream_lock_contention_is_distinct_from_the_library_lease() -> Result<()> {
        let base = tempfile::tempdir().map_err(|e| io_error("make lock test root", e))?;
        let path = base.path().join("state");
        drop(StateLease::acquire(&path)?);
        let held = native::create_private(&path.join("verysync.lock"))
            .map_err(|e| io_error("create test engine lock", e))?;
        held.try_lock_exclusive()
            .map_err(|e| io_error("hold test engine lock", e))?;
        assert!(matches!(
            StateLease::acquire(&path),
            Err(Error::ManagedStateInUse {
                lock: crate::ManagedStateLock::EngineLock
            })
        ));
        drop(held);
        let _lease = StateLease::acquire(&path)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn state_and_control_file_symlinks_are_rejected() -> Result<()> {
        let base = tempfile::tempdir().map_err(|e| io_error("make test root", e))?;
        let outside = base.path().join("outside");
        native::create_directory(&outside).map_err(|e| io_error("make outside", e))?;
        let alias = base.path().join("alias");
        std::os::unix::fs::symlink(&outside, &alias).map_err(|e| io_error("make test alias", e))?;
        assert!(matches!(
            StateLease::acquire(&alias),
            Err(Error::UnmanagedState)
        ));
        let state = base.path().join("state");
        let lease = StateLease::acquire(&state)?;
        drop(lease);
        fs::remove_file(state.join(MARKER)).map_err(|e| io_error("remove test marker", e))?;
        std::os::unix::fs::symlink(outside.join("untouched"), state.join(MARKER))
            .map_err(|e| io_error("make marker alias", e))?;
        assert!(StateLease::acquire(&state).is_err());
        assert!(!outside.join("untouched").exists());
        Ok(())
    }
}
