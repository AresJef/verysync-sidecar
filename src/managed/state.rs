//! Private-directory admission and cross-process state leases.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;

use super::{io_error, native};
use crate::{Error, Result};

pub(super) const MARKER: &str = ".verysync-sidecar-state";
pub(super) const LEASE: &str = ".verysync-sidecar-lease";
pub(super) const FORMAT: &[u8] = b"verysync-sidecar private state v1\n";
pub(super) const RESTORE_INCOMPLETE: &str = ".verysync-sidecar-restore-incomplete";

fn require_complete(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path.join(RESTORE_INCOMPLETE)) {
        Ok(_) => Err(Error::UnmanagedState),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error("inspect state restore completion", error)),
    }
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
    engine_lock: Option<File>,
}

impl StateLease {
    pub(super) fn acquire(path: &Path) -> Result<Self> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(Error::UnmanagedState);
                }
                native::private_directory(path, &metadata)
                    .map_err(|e| io_error("check state privacy", e))?;
                if !path.join(MARKER).exists()
                    && fs::read_dir(path)
                        .map_err(|e| io_error("inspect state", e))?
                        .next()
                        .is_some()
                {
                    return Err(Error::UnmanagedState);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                native::create_directory(path).map_err(|e| io_error("create private state", e))?;
            }
            Err(error) => return Err(io_error("inspect state", error)),
        }
        let path = canonical(path).map_err(|e| io_error("resolve private state", e))?;
        require_complete(&path)?;
        let file = native::open_private(&path.join(LEASE), false)
            .map_err(|e| io_error("open state lease", e))?;
        file.try_lock_exclusive().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock || error.raw_os_error() == Some(33) {
                Error::ManagedStateInUse
            } else {
                io_error("lock private state", error)
            }
        })?;
        let marker = path.join(MARKER);
        if marker
            .try_exists()
            .map_err(|e| io_error("inspect state marker", e))?
        {
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
            if fs::read_dir(&path)
                .map_err(|e| io_error("inspect new state", e))?
                .any(|entry| entry.map_or(true, |entry| entry.file_name() != LEASE))
            {
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
                    Error::ManagedStateInUse
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
            engine_lock,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn release_engine_lock_for_spawn(&mut self) {
        self.engine_lock.take();
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
    use super::*;

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
            Err(Error::ManagedStateInUse)
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
