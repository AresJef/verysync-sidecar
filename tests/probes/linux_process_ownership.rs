//! Exact private engine/state observation, including workers outside the root group.
#![allow(dead_code)]
use std::ffi::c_long;
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn geteuid() -> u32;
}

fn matches(pid: u32, binary: &Path, state: &Path) -> io::Result<bool> {
    let root = PathBuf::from("/proc").join(pid.to_string());
    // Read the public command-line selector first. Some unrelated same-user
    // runner processes prohibit exe/ptrace access; they are not this fixture.
    let args = match fs::read(root.join("cmdline")) {
        Ok(bytes) => bytes,
        Err(e) if matches!(e.raw_os_error(), Some(2 | 3)) => return Ok(false),
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!("native command selector for PID {pid}: {e}"),
            ))
        }
    };
    let args: Vec<_> = args.split(|b| *b == 0).collect();
    let home_matches = args
        .windows(2)
        .any(|pair| pair[0] == b"--home" && pair[1] == state.as_os_str().as_bytes());
    let race_matches = args.get(2).copied() == Some(state.as_os_str().as_bytes())
        && args.get(3).copied() == Some(b"race");
    if !home_matches && !race_matches {
        return Ok(false);
    }
    let executable = match fs::read_link(root.join("exe")) {
        Ok(path) => path,
        Err(e) if matches!(e.raw_os_error(), Some(2 | 3)) => return Ok(false),
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!("exact private executable query for PID {pid}: {e}"),
            ))
        }
    };
    Ok(executable == binary)
}

pub fn owned_pids(binary: &Path, state: &Path) -> io::Result<Vec<u32>> {
    let binary = fs::canonicalize(binary)?;
    let mut result = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        // Other users' processes cannot belong to this nonprivileged private
        // fixture. Same-user observation errors remain errors, never "gone".
        let metadata = match entry.metadata() {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if metadata.uid() != unsafe { geteuid() } {
            continue;
        }
        if matches(pid, &binary, state)? {
            result.push(pid);
            if result.len() > 256 {
                return Err(io::Error::other("private instance process bound exceeded"));
            }
        }
    }
    result.sort_unstable();
    Ok(result)
}

/// Fallback only. Callers must establish exclusive ownership of this synthetic
/// state; a same-state conflict challenger may never use this operation.
pub fn terminate_owned(binary: &Path, state: &Path) -> io::Result<()> {
    let binary = fs::canonicalize(binary)?;
    for pid in owned_pids(&binary, state)? {
        // SAFETY: Linux pidfd_open is 434 on the gated x86_64/aarch64 targets.
        // The returned handle prevents PID reuse from changing signal targets.
        let fd = unsafe { syscall(434, pid as c_long, 0 as c_long) };
        if fd < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(3) {
                continue;
            }
            return Err(e);
        }
        let handle = unsafe { File::from_raw_fd(fd as i32) };
        if !matches(pid, &binary, state)? {
            continue;
        }
        // SAFETY: Signal only the pidfd retained above after exact image/state
        // verification, never a name lookup or potentially reused bare PID.
        if unsafe {
            syscall(
                424,
                handle.as_raw_fd() as c_long,
                9 as c_long,
                0 as c_long,
                0 as c_long,
            )
        } < 0
        {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(3) {
                return Err(e);
            }
        }
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while !owned_pids(&binary, state)?.is_empty() {
        if Instant::now() >= deadline {
            return Err(io::Error::other(
                "private instance fallback did not stop every owned process",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}
