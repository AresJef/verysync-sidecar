//! Unix private resources. Unsafe calls are limited to this native boundary.
#![allow(unsafe_code)]

use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::ptr;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    // Darwin exports this reentrant function, but libc 0.2.191 does not declare it.
    fn ptsname_r(fd: libc::c_int, buffer: *mut libc::c_char, length: libc::size_t) -> libc::c_int;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn private_pty() -> io::Result<(File, File)> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: Native flags open one new private PTY master. CLOEXEC is atomic
    // with allocation; there is no openpty-to-fcntl inheritance interval.
    let fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: The successful native open returned one uniquely owned descriptor.
    let master = unsafe { File::from_raw_fd(fd) };
    // SAFETY: Both functions operate only on this live private master.
    if unsafe { libc::grantpt(fd) } != 0 || unsafe { libc::unlockpt(fd) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut name = [0 as libc::c_char; 1024];
    // SAFETY: The writable buffer has the exact supplied capacity. Successful
    // ptsname_r writes a NUL-terminated native path in this caller-owned buffer.
    #[cfg(target_os = "macos")]
    let result = unsafe { ptsname_r(fd, name.as_mut_ptr(), name.len()) };
    #[cfg(target_os = "linux")]
    let result = unsafe { libc::ptsname_r(fd, name.as_mut_ptr(), name.len()) };
    if result != 0 {
        #[cfg(target_os = "macos")]
        return Err(io::Error::last_os_error()); // Darwin returns -1 and sets errno.
        #[cfg(target_os = "linux")]
        return Err(io::Error::from_raw_os_error(result)); // glibc/musl return errno.
    }
    // SAFETY: The successful reentrant native call guaranteed termination.
    let path = unsafe { CStr::from_ptr(name.as_ptr()) };
    let slave = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(Path::new(OsStr::from_bytes(path.to_bytes())))?;
    Ok((master, slave))
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod pty_tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn private_pty_descriptors_are_close_on_exec() -> io::Result<()> {
        let (master, slave) = private_pty()?;
        for file in [&master, &slave] {
            // SAFETY: Read flags only on each retained live private descriptor.
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn private_pty() -> io::Result<(File, File)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "managed PTY ownership is not verified on this Unix platform",
    ))
}

pub(in crate::managed) struct ProcessGuard {
    master: Option<File>,
    group: libc::pid_t,
}

pub(in crate::managed) fn spawn(
    mut command: Command,
    helper: bool,
    lifetime: crate::managed::ManagedLifetime,
    io: crate::managed::process::ProcessIo,
) -> io::Result<(Child, ProcessGuard)> {
    command.stdin(if io.stdin_pipe {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    command.stdout(io.stdout.map_or_else(Stdio::null, Stdio::from));
    command.stderr(io.stderr.map_or_else(Stdio::null, Stdio::from));
    let (master, terminal) = if helper || lifetime == crate::managed::ManagedLifetime::CallerOwned {
        let (master, slave) = private_pty()?;
        // Helpers retain pipe stdin; their stderr supplies the private terminal.
        let terminal = if helper { 2 } else { 0 };
        if helper {
            command.stderr(Stdio::from(slave));
        } else {
            command.stdin(Stdio::from(slave));
        }
        (Some(master), Some(terminal))
    } else {
        (None, None)
    };
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
            if let Some(terminal) = terminal {
                if libc::ioctl(terminal, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    let group = child.id() as libc::pid_t;
    Ok((child, ProcessGuard { master, group }))
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
        #[cfg(target_os = "macos")]
        return macos_group_stopped(self.group);

        #[cfg(not(target_os = "macos"))]
        {
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
}

#[cfg(target_os = "macos")]
fn macos_group_stopped(group: libc::pid_t) -> io::Result<bool> {
    // Signal zero does not distinguish live members from exited kernel entries.
    // Query only this private group; zombies cannot execute or hold state files.
    // Treat incomplete/denied observations as errors, never as successful exit.
    const PROC_PGRP_ONLY: u32 = 2; // sys/proc_info.h
    let mut pids = [0_i32; 4096];
    let capacity = std::mem::size_of_val(&pids) as i32;
    // SAFETY: errno is thread-local; the initialized writable buffer is sized in
    // bytes as required by libproc. A zero result can otherwise mask an error.
    let bytes = unsafe {
        *libc::__error() = 0;
        libc::proc_listpids(
            PROC_PGRP_ONLY,
            group as u32,
            pids.as_mut_ptr().cast(),
            capacity,
        )
    };
    if bytes == 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(0) {
            Ok(true)
        } else {
            Err(error)
        };
    }
    if bytes < 0 || bytes >= capacity || bytes as usize % std::mem::size_of::<i32>() != 0 {
        return Err(io::Error::other("private group observation was incomplete"));
    }
    for pid in pids
        .iter()
        .take(bytes as usize / std::mem::size_of::<i32>())
        .copied()
        .filter(|pid| *pid > 0)
    {
        // SAFETY: proc_bsdinfo is a plain C output struct; its full byte size and
        // flavor match the native SDK. Inspect fields only on a complete result.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info) as i32;
        let read = unsafe {
            *libc::__error() = 0;
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        if read != size {
            let error = io::Error::last_os_error();
            if read == 0 && error.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(if read == 0 && error.raw_os_error() != Some(0) {
                error
            } else {
                io::Error::other("private member observation was incomplete")
            });
        }
        if info.pbi_pgid == group as u32 && info.pbi_status != libc::SZOMB {
            return Ok(false);
        }
    }
    Ok(true)
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

#[cfg(feature = "download")]
pub(in crate::managed) fn retain_private_directory(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    private_directory(path, &file.metadata()?)?;
    Ok(file)
}

fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .mode(0o600)
        // Do not block opening a substituted FIFO before the regular-file
        // check can reject it. O_NONBLOCK has no effect on ordinary files.
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
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
