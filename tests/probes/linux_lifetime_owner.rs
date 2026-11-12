//! Standalone, explicitly compiled Linux lifetime investigation host.
//!
//! This is not a product supervisor or managed-instance implementation. The
//! outer probe supplies a verified engine and fresh private state, observes
//! outcomes independently, and performs separately reported fallback cleanup.
#![cfg(all(
    target_os = "linux",
    target_env = "gnu",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use std::fs::{self, File};
use std::io::{self, BufRead};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::ptr;
use std::time::{Duration, Instant};

// Linux UAPI constants and glibc ABI for the two explicitly gated targets.
// Other architectures require their own ABI validation. All calls using
// process/session or signal state below run in the newly forked child only.
const TIOCSCTTY: c_ulong = 0x540e;
const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;
const SIG_SETMASK: c_int = 2;
#[repr(C)]
struct Timespec {
    sec: c_long,
    nsec: c_long,
}

unsafe extern "C" {
    fn prctl(option: c_int, ...) -> c_int;
    fn getppid() -> c_int;
    fn getpid() -> c_int;
    fn fork() -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn write(fd: c_int, bytes: *const u8, count: usize) -> isize;
    fn pipe2(descriptors: *mut c_int, flags: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn read(fd: c_int, bytes: *mut u8, count: usize) -> isize;
    fn nanosleep(request: *const Timespec, remaining: *mut Timespec) -> c_int;
    fn _exit(status: c_int) -> !;
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
    fn sigemptyset(set: *mut [u64; 16]) -> c_int;
    fn sigaddset(set: *mut [u64; 16], number: c_int) -> c_int;
    fn sigprocmask(how: c_int, set: *const [u64; 16], old: *mut [u64; 16]) -> c_int;
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
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--primitive-child")) {
        args.next();
        let state = PathBuf::from(args.next().ok_or("private primitive state required")?);
        return primitive_child(state);
    }
    let binary = PathBuf::from(args.next().ok_or("explicit engine path required")?);
    let state = PathBuf::from(args.next().ok_or("explicit private state required")?);
    let mode = args.next().ok_or("base or pty required")?;
    if !binary.is_absolute() || !state.is_absolute() || args.next().is_some() {
        return Err("invalid explicit probe inputs".into());
    }
    let mode = mode.to_str().ok_or("ASCII probe mode required")?.to_owned();
    if mode == "primitive" {
        let mut command = Command::new(std::env::current_exe()?);
        command.arg("--primitive-child").arg(&state);
        // SAFETY: Child-only installation before exec; no host hooks.
        unsafe {
            command.pre_exec(|| {
                if prctl(1, 1 as c_long, 0 as c_long, 0 as c_long, 0 as c_long) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        if !command.status()?.success() {
            return Err("exec/fork primitive child failed".into());
        }
        return Ok(());
    }
    if ![
        "base",
        "pty",
        "pdeath-hup",
        "pdeath-kill",
        "thread-pdeath",
        "thread-pty",
        "race",
    ]
    .contains(&mode.as_str())
    {
        return Err("unknown explicit Linux investigation mode".into());
    }
    let pty = mode.contains("pty");
    let pdeath = mode.contains("pdeath") || mode == "race";
    let death_signal: c_long = if mode == "pdeath-kill" { 9 } else { 1 };
    let threaded = mode.starts_with("thread-");
    let race = mode == "race";
    let expected_parent = std::process::id() as c_int;
    let race_pid = File::create(state.join("race-child.pid.bin"))?;
    let race_result = File::create(state.join("race-rejected.bin"))?;
    let race_pid_fd = race_pid.as_raw_fd();
    let race_result_fd = race_result.as_raw_fd();
    let race_preinstall = File::create(state.join("race-parent-changed-before-install.bin"))?;
    let race_preinstall_fd = race_preinstall.as_raw_fd();
    let mut race_pipe = [-1; 2];
    let race_pipe_owner = if race {
        // SAFETY: Two writable descriptor slots; Linux O_CLOEXEC is 02000000.
        if unsafe { pipe2(race_pipe.as_mut_ptr(), 0o2000000) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Some((unsafe { File::from_raw_fd(race_pipe[0]) }, unsafe {
            File::from_raw_fd(race_pipe[1])
        }))
    } else {
        None
    };

    let inherited_hup = std::env::var("VERYSYNC_PROBE_HOST_SIGNAL_STATE")
        .ok()
        .as_deref()
        == Some("ignored-blocked");
    if inherited_hup {
        let mut blocked = [0u64; 16];
        // SAFETY: This is the dedicated, short-lived test host, not the
        // controller or library caller. Simulate an inherited disposition and
        // thread mask so child-only reset can be investigated independently.
        if unsafe { signal(1, 1) } == usize::MAX
            || unsafe { sigemptyset(&mut blocked) } != 0
            || unsafe { sigaddset(&mut blocked, 1) } != 0
            || unsafe { sigprocmask(0, &blocked, ptr::null_mut()) } != 0
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
        // SAFETY: Live owned descriptor, valid Linux fcntl commands. The
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

    // Fixed-version candidate: bypass the upstream restart monitor explicitly.
    // Its ordinary Linux worker can leave the monitor process group.
    let log = File::create(state.join(format!("owner-{}.engine.log", std::process::id())))?;
    let mut command = Command::new(&binary);
    command
        .env("VSMONITORED", "yes")
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
            let mut empty = [0u64; 16];
            if sigemptyset(&mut empty) != 0
                || sigprocmask(SIG_SETMASK, &empty, ptr::null_mut()) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if race {
                // SAFETY: Preopened private outputs, native PID bytes, and an
                // async-signal-safe pipe EOF deliberately exposes the race.
                // The creator host alone retains the writer after child close.
                let pid = getpid();
                if write(race_pid_fd, pid.to_ne_bytes().as_ptr(), 4) != 4 {
                    _exit(124);
                }
                close(race_pipe[1]);
                let mut byte = 0u8;
                if read(race_pipe[0], &mut byte, 1) != 0 {
                    _exit(123);
                }
                // EOF can precede exit_notify/reparenting on another CPU.
                // Wait for the actual parent transition before installing the
                // signal; the sleep is bounded polling, not an ordering guess.
                let pause = Timespec {
                    sec: 0,
                    nsec: 1_000_000,
                };
                let mut attempts = 0;
                while getppid() == expected_parent && attempts < 5000 {
                    nanosleep(&pause, ptr::null_mut());
                    attempts += 1;
                }
                if getppid() == expected_parent {
                    _exit(122);
                }
                if write(
                    race_preinstall_fd,
                    b"parent-changed-before-install".as_ptr(),
                    29,
                ) != 29
                {
                    _exit(121);
                }
            }
            if pdeath {
                if prctl(1, death_signal, 0 as c_long, 0 as c_long, 0 as c_long) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if getppid() != expected_parent {
                    if race {
                        write(race_result_fd, b"rejected-before-exec".as_ptr(), 20);
                    }
                    _exit(125);
                }
            }
            if pty && ioctl(0, TIOCSCTTY, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let _retained_race_pipe = race_pipe_owner;
    let mut creator_thread = None;
    let (child, creator_tid) = if threaded {
        let (sent, received) = std::sync::mpsc::sync_channel(1);
        let (release, held) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || -> io::Result<()> {
            let status = fs::read_to_string("/proc/thread-self/status")?;
            let tid = status
                .lines()
                .find_map(|line| line.strip_prefix("Pid:"))
                .ok_or_else(|| io::Error::other("creator thread ID unavailable"))?
                .trim()
                .to_owned();
            let child = command.spawn()?;
            drop(command);
            sent.send((child, tid))
                .map_err(|_| io::Error::other("probe owner disappeared"))?;
            let _ = held.recv();
            Ok(())
        });
        let child = received
            .recv()
            .map_err(|_| "creator thread failed to spawn exact child")?;
        creator_thread = Some((release, thread));
        child
    } else {
        let child = command.spawn()?;
        drop(command);
        (child, std::process::id().to_string())
    };
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
            "{{\"master_cloexec\":{},\"host_hup_ignored_and_blocked\":{},\"creator_tid\":{},\"host_pid\":{},\"pdeath_signal\":{},\"monitor_environment\":\"VSMONITORED=yes\"}}",
            master_cloexec.map_or("null".to_owned(), |v| v.to_string()),
            inherited_hup, creator_tid, std::process::id(), if pdeath { death_signal } else { 0 }
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
        "thread-exit" => {
            let (release, thread) = creator_thread.take().ok_or("no creator thread")?;
            release
                .send(())
                .map_err(|_| "creator thread ended prematurely")?;
            thread.join().map_err(|_| "creator thread panic")??;
            fs::write(
                state.join(format!("owner-{}.thread-ended", std::process::id())),
                "host still alive",
            )?;
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

fn primitive_child(state: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if !state.is_absolute() {
        return Err("absolute private state required".into());
    }
    let mut after_exec = -1;
    // SAFETY: Linux PR_GET_PDEATHSIG with a valid writable int pointer.
    if unsafe {
        prctl(
            2,
            &mut after_exec as *mut c_int,
            0 as c_long,
            0 as c_long,
            0 as c_long,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let output = File::create(state.join("fork-pdeath.bin"))?;
    let fd = output.as_raw_fd();
    // SAFETY: This standalone child has no auxiliary threads. The fork child
    // performs only native prctl/write/_exit and does not touch Rust allocation.
    let forked = unsafe { fork() };
    if forked < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if forked == 0 {
        let mut value: c_int = -1;
        unsafe {
            if prctl(
                2,
                &mut value as *mut c_int,
                0 as c_long,
                0 as c_long,
                0 as c_long,
            ) != 0
            {
                _exit(126);
            }
            if write(fd, value.to_ne_bytes().as_ptr(), 4) != 4 {
                _exit(127);
            }
            _exit(0);
        }
    }
    let mut status = -1;
    if unsafe { waitpid(forked, &mut status, 0) } != forked || status != 0 {
        return Err("owned fork primitive did not exit successfully".into());
    }
    let bytes: [u8; 4] = fs::read(state.join("fork-pdeath.bin"))?
        .try_into()
        .map_err(|_| "fork evidence malformed")?;
    fs::write(
        state.join("primitive.json"),
        format!(
            "{{\"pdeathsig_after_exec\":{after_exec},\"pdeathsig_after_fork\":{}}}",
            i32::from_ne_bytes(bytes)
        ),
    )?;
    Ok(())
}
