//! Unix private resources. Unsafe calls are limited to this native boundary.
#![allow(unsafe_code)]

use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::ptr;

pub(in crate::managed) struct ProcessGuard {
    master: Option<File>,
    group: libc::pid_t,
}

pub(in crate::managed) fn spawn(
    mut command: Command,
    helper: bool,
) -> io::Result<(Child, ProcessGuard)> {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: Valid writable descriptor outputs and null optional terminal
    // parameters. Successful descriptors immediately receive unique owners.
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openpty succeeded and returned two independently owned descriptors.
    let master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    for file in [&master, &slave] {
        // SAFETY: Each descriptor is live; F_GETFD/F_SETFD use native constants.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        if flags < 0
            || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    // Helpers retain pipe stdin for a private generated password. Their stderr
    // slave supplies the controlling terminal; the long-running core uses stdin.
    let terminal = if helper { 2 } else { 0 };
    if helper {
        command.stderr(Stdio::from(slave));
    } else {
        command.stdin(Stdio::from(slave));
    }
    #[cfg(target_os = "linux")]
    command.env("VSMONITORED", "yes");
    // SAFETY: The closure executes only in the newly forked child. It calls
    // async-signal-safe native functions, allocates no memory, takes no locks,
    // resets child-only HUP/mask and never alters the parent's global signals.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::signal(libc::SIGHUP, libc::SIG_DFL) == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
            let mut empty: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&mut empty) != 0
                || libc::sigprocmask(libc::SIG_SETMASK, &empty, ptr::null_mut()) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(terminal, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    let group = child.id() as libc::pid_t;
    Ok((
        child,
        ProcessGuard {
            master: Some(master),
            group,
        },
    ))
}

impl ProcessGuard {
    pub(in crate::managed) fn stop(&mut self, child: &mut Child) -> io::Result<()> {
        self.master.take();
        // Only an exact unreaped child reserves this PID/group identity. After
        // reaping, master closure remains safe and no group signal is issued.
        if child.try_wait()?.is_none() {
            // SAFETY: The exact child is still unreaped. Signal only its own
            // separately created session/group after checking native membership.
            if unsafe { libc::getpgid(self.group) } == self.group
                && unsafe { libc::kill(-self.group, libc::SIGKILL) } < 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err(io::Error::last_os_error());
            }
            child.kill()?;
        }
        Ok(())
    }

    pub(in crate::managed) fn tree_stopped(&self) -> io::Result<bool> {
        // SAFETY: Signal zero only observes the private group. A recycled ID can
        // cause conservative failure, never a signal to another process group.
        if unsafe { libc::kill(-self.group, 0) } == 0 {
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(true)
        } else {
            Err(error)
        }
    }
}

pub(in crate::managed) fn private_directory(_path: &Path, metadata: &Metadata) -> io::Result<()> {
    // SAFETY: geteuid has no pointer arguments and only reads the caller's ID.
    if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "state must belong exclusively to the current user",
        ));
    }
    Ok(())
}

pub(in crate::managed) fn create_directory(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)
}

fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
}

pub(in crate::managed) fn open_private(path: &Path, read_only: bool) -> io::Result<File> {
    let mut options = options();
    options.read(true);
    if !read_only {
        options.write(true).create(true);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "control file must be private and regular",
        ));
    }
    Ok(file)
}

pub(in crate::managed) fn create_private(path: &Path) -> io::Result<File> {
    options().write(true).read(true).create_new(true).open(path)
}

pub(in crate::managed) fn protect_generated(path: &Path) -> io::Result<()> {
    let file = options().read(true).write(true).open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("generated resource is not regular"));
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

pub(in crate::managed) fn open_owned_lock(path: &Path) -> io::Result<File> {
    let file = options().read(true).write(true).open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid only reads the caller's current effective identity.
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "upstream lock is not an owned regular file",
        ));
    }
    Ok(file)
}
