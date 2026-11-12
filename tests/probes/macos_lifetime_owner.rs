//! Standalone, explicitly compiled macOS lifetime investigation host.
//!
//! This is not a product supervisor or managed-instance implementation. The
//! outer probe supplies a verified engine and fresh private state, observes
//! outcomes independently, and performs separately reported fallback cleanup.
#![cfg(target_os = "macos")]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{c_char, c_int, c_ulong, c_void};
use std::fs::{self, File};
use std::io::{self, BufRead};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::ptr;
use std::time::{Duration, Instant};

// Darwin SDK sys/ttycom.h, sys/signal.h and sys/fcntl.h. All calls using
// process/session or signal state below run in the newly forked child only.
const TIOCSCTTY: c_ulong = 0x2000_7461;
const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;
const SIG_SETMASK: c_int = 3;
unsafe extern "C" {
    fn openpty(
        master: *mut c_int,
        slave: *mut c_int,
        name: *mut c_char,
        term: *const c_void,
        size: *const c_void,
    ) -> c_int;
    fn setsid() -> c_int;
    fn getpgid(pid: c_int) -> c_int;
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn kill(pid: c_int, signal: c_int) -> c_int;
    fn signal(number: c_int, handler: usize) -> usize;
    fn sigemptyset(set: *mut u32) -> c_int;
    fn sigaddset(set: *mut u32, number: c_int) -> c_int;
    fn sigprocmask(how: c_int, set: *const u32, old: *mut u32) -> c_int;
}

struct Owner {
    child: Option<Child>,
    group: c_int,
    master: Option<File>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if matches!(child.try_wait(), Ok(None)) {
                // SAFETY: A live unreaped exact child still owns this PID. Only
                // kill the group if it is the new session/group we created.
                if unsafe { getpgid(child.id() as c_int) } == self.group {
                    unsafe {
                        kill(-self.group, 9);
                    }
                }
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let binary = PathBuf::from(args.next().ok_or("explicit engine path required")?);
    let state = PathBuf::from(args.next().ok_or("explicit private state required")?);
    let mode = args.next().ok_or("base or pty required")?;
    if !binary.is_absolute() || !state.is_absolute() || args.next().is_some() {
        return Err("invalid explicit probe inputs".into());
    }
    let pty = match mode.to_str() {
        Some("base") => false,
        Some("pty") => true,
        _ => return Err("unknown probe mode".into()),
    };
    let inherited_hup = std::env::var("VERYSYNC_PROBE_HOST_SIGNAL_STATE")
        .ok()
        .as_deref()
        == Some("ignored-blocked");
    if inherited_hup {
        let mut blocked = 0u32;
        // SAFETY: This is the dedicated, short-lived test host, not the
        // controller or library caller. Simulate an inherited disposition and
        // thread mask so child-only reset can be investigated independently.
        if unsafe { signal(1, 1) } == usize::MAX
            || unsafe { sigemptyset(&mut blocked) } != 0
            || unsafe { sigaddset(&mut blocked, 1) } != 0
            || unsafe { sigprocmask(1, &blocked, ptr::null_mut()) } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
    }
    let (master, input) = if pty {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: Writable fd outputs; optional name/terminal/window settings
        // are null. Successful descriptors are transferred into unique Files.
        if unsafe {
            openpty(
                &mut master,
                &mut slave,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        // SAFETY: Live owned descriptor, valid Darwin fcntl commands. The
        // master must not survive exec into the engine or its descendants.
        let flags = unsafe { fcntl(master.as_raw_fd(), F_GETFD) };
        if flags < 0 || unsafe { fcntl(master.as_raw_fd(), F_SETFD, flags | FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        (Some(master), Stdio::from(slave))
    } else {
        (None, Stdio::null())
    };
    let master_cloexec = if let Some(master) = &master {
        // SAFETY: Read flags on the owned master before creating any child.
        let flags = unsafe { fcntl(master.as_raw_fd(), F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Some(flags & FD_CLOEXEC != 0)
    } else {
        None
    };

    let home = fs::canonicalize(&state)?;
    let quoted = format!(
        "\"{}\"",
        home.to_str()
            .ok_or("probe path must be UTF-8")?
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    );
    let profile = format!("(version 1)(allow default)(deny network-outbound (require-all (remote ip) (require-not (remote ip \"localhost:*\"))))(deny network-inbound (require-all (local ip) (require-not (local ip \"localhost:*\"))))(deny file-write* (require-not (require-any (subpath {quoted}) (literal \"/dev/null\"))))");
    let log = File::create(state.join(format!("owner-{}.engine.log", std::process::id())))?;
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .args(["-p", &profile])
        .arg(binary)
        .args(["serve", "--home"])
        .arg(&state)
        .args(["--no-browser", "--no-restart", "--no-upgrade"])
        .current_dir(&state)
        .env("TMPDIR", state.join("tmp"))
        .stdin(input)
        .stdout(log.try_clone()?)
        .stderr(log);
    // SAFETY: This closure runs only between fork and exec. It calls only
    // async-signal-safe native functions, uses stack values, and does not
    // allocate or touch the host's process/session/global signal state.
    unsafe {
        command.pre_exec(move || {
            if setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if signal(1, 0) == usize::MAX {
                return Err(io::Error::last_os_error());
            }
            let mut empty = 0u32;
            if sigemptyset(&mut empty) != 0
                || sigprocmask(SIG_SETMASK, &empty, ptr::null_mut()) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if pty && ioctl(0, TIOCSCTTY, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    drop(command);
    let group = child.id() as c_int;
    let mut owner = Owner {
        child: Some(child),
        group,
        master,
    };
    // SAFETY: Query only the exact child just spawned and retained above.
    if unsafe { getpgid(group) } != group {
        return Err("probe child did not enter its own process group".into());
    }
    fs::write(
        state.join(format!("owner-{}.meta.json", std::process::id())),
        format!(
            "{{\"master_cloexec\":{},\"host_hup_ignored_and_blocked\":{}}}",
            master_cloexec.map_or("null".to_owned(), |v| v.to_string()),
            inherited_hup
        ),
    )?;
    fs::write(
        state.join(format!("owner-{}.pid", std::process::id())),
        group.to_string(),
    )?;
    println!("owned_pid={group} owned_group={group} pty={pty}");
    let mut instruction = String::new();
    io::stdin().lock().read_line(&mut instruction)?;
    match instruction.trim() {
        "return" => return Ok(()),
        "close-pty" => {
            owner.master.take();
        }
        "wait" => {}
        _ => return Err("probe instruction must be return, wait, or close-pty".into()),
    }
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if let Some(status) = owner.child.as_mut().ok_or("lost exact child")?.try_wait()? {
            owner.child.take();
            fs::write(
                state.join(format!("owner-{}.exit.json", std::process::id())),
                format!(
                    "{{\"code\":{},\"signal\":{}}}",
                    status.code().map_or("null".to_owned(), |v| v.to_string()),
                    status.signal().map_or("null".to_owned(), |v| v.to_string())
                ),
            )?;
            println!("owned_child_exit={status}");
            return Ok(());
        }
        if Instant::now() >= deadline {
            fs::write(
                state.join(format!("owner-{}.timeout", std::process::id())),
                "child still live before probe host fallback guard",
            )?;
            return Err("probe child did not exit before deadline; fallback guard will clean only its owned group".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
