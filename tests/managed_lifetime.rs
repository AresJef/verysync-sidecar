//! Native public-API host exit regression. Separate test processes, never a service.
#![cfg(any(target_os = "macos", target_os = "linux", windows))]
#![allow(unsafe_code)]

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use verysync_sidecar::{LocalProgram, ManagedInstance, ManagedOptions, ManagementEndpoint};

#[cfg(windows)]
#[path = "common/managed_ui.rs"]
mod managed_ui;
#[cfg(windows)]
#[allow(dead_code)]
#[path = "common/windows_fixture.rs"]
mod windows_fixture;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const HOST_MODE: &str = "VERYSYNC_OWNED_TEST_HOST_MODE";
const HOST_ROOT: &str = "VERYSYNC_OWNED_TEST_HOST_ROOT";
#[cfg(unix)]
const CORE_FILE: &str = "private-core";
#[cfg(windows)]
const CORE_FILE: &str = "private-core.exe";

fn require(value: bool, message: &'static str) -> TestResult {
    if value {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn program(path: &Path) -> TestResult<LocalProgram> {
    let expected = std::env::var("VERYSYNC_TEST_BINARY_SHA256")?;
    require(expected.len() == 64, "explicit fixture checksum required")?;
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&expected[index * 2..index * 2 + 2], 16)?;
    }
    Ok(LocalProgram::new(path)?.expected_sha256(digest))
}

fn settings(binary: &Path, state: &Path) -> TestResult<ManagedOptions> {
    #[cfg(unix)]
    let endpoint = ManagementEndpoint::unix_socket(state.join("gui.sock"))?;
    #[cfg(windows)]
    let endpoint = {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        ManagementEndpoint::http(&format!("http://{}/", listener.local_addr()?))?
    };
    Ok(ManagedOptions::new(program(binary)?, state, endpoint)?
        .startup_timeout(Duration::from_secs(25))?)
}

fn identity_files(state: &Path) -> TestResult<Vec<Vec<u8>>> {
    ["key.pem", "cert.pem", ".verysync-sidecar-identity"]
        .iter()
        .map(|name| Ok(Sha256::digest(std::fs::read(state.join(name))?).to_vec()))
        .collect()
}

#[cfg(unix)]
fn ignored_blocked_hup(initialize: bool) -> std::io::Result<bool> {
    // This function initializes signals only in a separately launched test host.
    // The library and the parent test process never install a global handler.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&mut set) != 0 || libc::sigaddset(&mut set, libc::SIGHUP) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if initialize {
            if libc::signal(libc::SIGHUP, libc::SIG_IGN) == libc::SIG_ERR {
                return Err(std::io::Error::last_os_error());
            }
            let code = libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
            if code != 0 {
                return Err(std::io::Error::from_raw_os_error(code));
            }
        }
        let mut action: libc::sigaction = std::mem::zeroed();
        let mut mask: libc::sigset_t = std::mem::zeroed();
        if libc::sigaction(libc::SIGHUP, std::ptr::null(), &mut action) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let code = libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask);
        if code != 0 {
            return Err(std::io::Error::from_raw_os_error(code));
        }
        Ok(action.sa_sigaction == libc::SIG_IGN && libc::sigismember(&mask, libc::SIGHUP) == 1)
    }
}

fn host_command(root: &Path, mode: &str) -> TestResult<Command> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "owned_host_returns",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HOST_MODE, mode)
        .env(HOST_ROOT, root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
    }
    Ok(command)
}

async fn run_test_host() -> TestResult {
    let mode = std::env::var(HOST_MODE)?;
    let root = PathBuf::from(std::env::var_os(HOST_ROOT).ok_or("private host root required")?);
    if mode == "unrelated" {
        std::fs::write(root.join("unrelated-ready"), b"started")?;
        let deadline = Instant::now() + Duration::from_secs(90);
        while !root.join("unrelated-stop").try_exists()? {
            require(
                Instant::now() < deadline,
                "unrelated test exec was not explicitly stopped",
            )?;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        return Ok(());
    }
    #[cfg(unix)]
    let inherited = mode == "inherited";
    #[cfg(unix)]
    if inherited {
        require(
            ignored_blocked_hup(true)?,
            "test host HUP control not established",
        )?;
    }
    #[cfg(unix)]
    let environment_names = ["HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"];
    #[cfg(windows)]
    let environment_names = ["APPDATA", "LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP"];
    let environment_before: Vec<_> = environment_names.iter().map(std::env::var_os).collect();
    let state = root.join("state");
    let instance = ManagedInstance::start(settings(&root.join(CORE_FILE), &state)?).await?;
    #[cfg(unix)]
    if inherited {
        require(
            ignored_blocked_hup(false)?,
            "library changed its test caller's HUP state",
        )?;
    }
    require(
        environment_names
            .iter()
            .map(std::env::var_os)
            .collect::<Vec<_>>()
            == environment_before,
        "library changed caller environment",
    )?;
    std::fs::write(
        state.join("retained.bin"),
        b"synthetic host lifetime sample",
    )?;
    let mut unrelated = if mode == "exec" {
        Some(host_command(&root, "unrelated")?.spawn()?)
    } else {
        None
    };
    if let Some(child) = unrelated.as_mut() {
        std::fs::write(root.join("unrelated.pid"), child.id().to_string())?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !root.join("unrelated-ready").try_exists()? {
            require(
                child.try_wait()?.is_none(),
                "unrelated test exec ended before readiness",
            )?;
            require(
                Instant::now() < deadline,
                "unrelated test exec readiness deadline",
            )?;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    #[cfg(unix)]
    let inherited_hup_preserved = inherited && ignored_blocked_hup(false)?;
    #[cfg(windows)]
    let inherited_hup_preserved = false;
    let ready = json!({"pid":instance.process_id(), "identity":instance.client().instance().device_id.as_str(),
        "authenticated":instance.client().system_status().await?.device_id == instance.client().instance().device_id,
        "inherited_hup_preserved":inherited_hup_preserved,
        "unrelated_pid":unrelated.as_ref().map(Child::id)});
    std::fs::write(root.join("ready.tmp"), serde_json::to_vec(&ready)?)?;
    std::fs::rename(root.join("ready.tmp"), root.join("ready.json"))?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() == "exit" {
        std::process::exit(23);
    }
    require(input.trim() == "return", "unexpected test host instruction")?;
    // Ordinary return drops its real owner; forced/exit cases bypass this line.
    drop(instance);
    Ok(())
}

#[cfg(windows)]
fn process_birth(pid: u32) -> std::io::Result<Option<(u64, u64)>> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{
        ERROR_INVALID_PARAMETER, FILETIME, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE,
    };
    // SAFETY: Read-only rights for this fixture's recorded process; the owned
    // handle pins the native process object while observing exit and birth time.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if raw.is_null() {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    // SAFETY: A successful OpenProcess returned a newly owned handle.
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    // SAFETY: Query only, with a live process handle and zero timeout.
    match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
        WAIT_OBJECT_0 => return Ok(None),
        WAIT_TIMEOUT => (),
        _ => return Err(std::io::Error::last_os_error()),
    }
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: Four initialized, distinct FILETIME outputs and a live handle.
    if unsafe {
        GetProcessTimes(
            process.as_raw_handle(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Some((
        u64::from(creation.dwHighDateTime),
        u64::from(creation.dwLowDateTime),
    )))
}

#[cfg(target_os = "macos")]
fn process_birth(pid: u32) -> std::io::Result<Option<(u64, u64)>> {
    // SAFETY: Read only the independently created test process. A complete
    // native record binds its PID to start time, preventing PID-reuse confusion.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&info) as i32;
    let read = unsafe {
        *libc::__error() = 0;
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if read == size {
        return Ok((info.pbi_status != libc::SZOMB)
            .then_some((info.pbi_start_tvsec, info.pbi_start_tvusec)));
    }
    let error = std::io::Error::last_os_error();
    if read == 0 && error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(None);
    }
    Err(std::io::Error::other(
        "unrelated test process observation incomplete",
    ))
}

#[cfg(target_os = "linux")]
fn process_birth(pid: u32) -> std::io::Result<Option<(u64, u64)>> {
    use std::os::unix::fs::MetadataExt;
    let path = Path::new("/proc").join(pid.to_string());
    let text = match std::fs::read_to_string(path.join("stat")) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    // comm can contain spaces/parentheses. Fields after its final ')' begin
    // with field 3 (state); field 22 is the kernel process start tick.
    let fields: Vec<_> = text
        .rsplit_once(')')
        .ok_or_else(|| std::io::Error::other("incomplete private process stat"))?
        .1
        .split_whitespace()
        .collect();
    if fields.first() == Some(&"Z") {
        return Ok(None);
    }
    let start: u64 = fields
        .get(19)
        .ok_or_else(|| std::io::Error::other("missing private process start time"))?
        .parse()
        .map_err(|_| std::io::Error::other("invalid private process start time"))?;
    let inode = match std::fs::metadata(path) {
        Ok(metadata) => metadata.ino(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(Some((start, inode)))
}

async fn unrelated_finished(pid: u32, birth: (u64, u64)) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(8);
    while process_birth(pid)? == Some(birth) {
        require(
            Instant::now() < deadline,
            "unrelated test exec did not stop",
        )?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

struct Host(Child);
impl Drop for Host {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

async fn inventory(binary: &Path) -> TestResult<Vec<u32>> {
    let binary = binary.to_owned();
    tokio::task::spawn_blocking(move || -> TestResult<_> {
        let output = Command::new("python3")
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("scripts")
                    .join("prepare-test-engine.py"),
            )
            .arg("list-owned-processes")
            .env("VERYSYNC_TEST_BINARY", binary)
            .output()?;
        require(
            output.status.success(),
            "exact private process observation failed",
        )?;
        let value: Value = serde_json::from_slice(&output.stdout)?;
        value["pids"]
            .as_array()
            .ok_or("missing exact inventory")?
            .iter()
            .map(|pid| {
                pid.as_u64()
                    .and_then(|p| u32::try_from(p).ok())
                    .filter(|p| *p > 0)
                    .ok_or_else(|| "invalid exact private PID".into())
            })
            .collect()
    })
    .await?
}

async fn processes_gone(binary: &Path) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if inventory(binary).await?.is_empty() {
            return Ok(());
        }
        require(
            Instant::now() < deadline,
            "owned core survived host exit before any fallback",
        )?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(unix)]
async fn emergency_cleanup(binary: &Path, recorded_group: Option<u32>) -> TestResult {
    // This path never makes a failed lifetime case pass. Inspect exact copied
    // program membership before signalling only its private session/group.
    let pids = inventory(binary).await?;
    let mut groups = std::collections::BTreeSet::new();
    for pid in &pids {
        // SAFETY: Read-only lookup of exact private-image PIDs from this fixture.
        let group = unsafe { libc::getpgid(*pid as libc::pid_t) };
        if group > 1 && (pids.contains(&(group as u32)) || recorded_group == Some(group as u32)) {
            groups.insert(group);
        }
    }
    for group in groups {
        // SAFETY: A currently observed private image still belongs to this
        // independently established private group; never signal by program name.
        if unsafe { libc::kill(-group, libc::SIGKILL) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    processes_gone(binary).await
}

async fn exercise(mode: &'static str) -> TestResult {
    let root = tempfile::Builder::new().prefix("vsl-").tempdir()?.keep();
    let binary = root.join(CORE_FILE);
    let selected =
        PathBuf::from(std::env::var_os("VERYSYNC_TEST_BINARY").ok_or("explicit engine required")?);
    std::fs::copy(&selected, &binary)?;
    let mut canary = ManagedInstance::start(settings(&selected, &root.join("canary"))?).await?;
    let canary_id = canary.client().instance().device_id.clone();
    #[cfg(windows)]
    let baseline = if mode == "kill" {
        Some(managed_ui::observe(None, &root).await?)
    } else {
        None
    };
    let mut command = host_command(&root, mode)?;
    command.stdin(Stdio::piped());
    #[cfg(windows)]
    let outer = {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};
        command.creation_flags(CREATE_NO_WINDOW | CREATE_SUSPENDED);
        windows_fixture::Job::new()?
    };
    let mut host = Host(command.spawn()?);
    #[cfg(windows)]
    outer.assign_and_resume(&host.0)?;
    #[cfg(unix)]
    let mut group = None;
    let mut unrelated_identity = None;
    let result: TestResult = async {
        let deadline = Instant::now() + Duration::from_secs(30);
        let ready: Value = loop {
            if root.join("ready.json").try_exists()? {
                break serde_json::from_slice(&std::fs::read(root.join("ready.json"))?)?;
            }
            require(
                host.0.try_wait()?.is_none(),
                "test host exited before public API readiness",
            )?;
            require(Instant::now() < deadline, "test host readiness deadline")?;
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let pid = u32::try_from(ready["pid"].as_u64().ok_or("missing owned root")?)?;
        #[cfg(unix)]
        {
            group = Some(pid);
        }
        require(
            ready["authenticated"] == true,
            "host did not authenticate its real core",
        )?;
        require(
            inventory(&binary).await?.contains(&pid),
            "positive private core inventory missing",
        )?;
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::JobObjects::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let snapshot = outer.snapshot(&host.0)?;
            require(
                snapshot.root_in_job
                    && !snapshot.handle_inheritable
                    && snapshot.limit_flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0
                    && snapshot.process_ids.contains(&host.0.id())
                    && snapshot.process_ids.contains(&pid),
                "caller Job membership was not observed",
            )?;
            println!(
                "public owned host Job observation: {}",
                json!({"case": mode, "snapshot": snapshot})
            );
            if let Some(baseline) = &baseline {
                let observed = managed_ui::observe(Some(pid), &root).await?;
                managed_ui::assert_background(baseline, &observed)?;
                println!("public owned host UI observation: {observed}");
            }
        }
        if mode == "inherited" {
            require(
                ready["inherited_hup_preserved"] == true,
                "inherited HUP contract missing",
            )?;
        }
        if mode == "exec" {
            let other = u32::try_from(
                ready["unrelated_pid"]
                    .as_u64()
                    .ok_or("unrelated PID missing")?,
            )?;
            let birth = process_birth(other)?.ok_or("unrelated test exec not live")?;
            unrelated_identity = Some((other, birth));
        }
        let state = root.join("state");
        let identity = identity_files(&state)?;
        let sample = Sha256::digest(std::fs::read(state.join("retained.bin"))?);
        if matches!(mode, "kill" | "inherited" | "exec") {
            host.0.kill()?;
        } else {
            let input = host.0.stdin.as_mut().ok_or("test host input closed")?;
            writeln!(input, "{}", if mode == "exit" { "exit" } else { "return" })?;
            input.flush()?;
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = host.0.try_wait()? {
                break status;
            }
            require(Instant::now() < deadline, "retained test host did not exit")?;
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        if mode == "return" {
            require(status.success(), "ordinary test host return failed")?;
        } else if mode == "exit" {
            require(
                status.code() == Some(23),
                "explicit no-destructor exit not observed",
            )?;
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                require(
                    status.signal() == Some(libc::SIGKILL),
                    "actual forced host exit not observed",
                )?;
            }
            #[cfg(windows)]
            require(
                !status.success(),
                "actual forced Windows host exit not observed",
            )?;
        }
        processes_gone(&binary).await?;
        if let Some((other, birth)) = unrelated_identity {
            require(
                process_birth(other)? == Some(birth),
                "unrelated exec was not live after core exit",
            )?;
            std::fs::write(root.join("unrelated-stop"), b"stop")?;
            unrelated_finished(other, birth).await?;
        }
        #[cfg(windows)]
        {
            // Retain the outer Job until the SDK-owned inner Job has already
            // removed its core. Closing the observer cannot make this pass.
            let observer = outer.try_clone()?;
            tokio::task::spawn_blocking(move || observer.wait_empty(Duration::from_secs(8)))
                .await??;
        }
        require(
            canary.client().system_status().await?.device_id == canary_id,
            "other isolated instance affected",
        )?;
        require(
            identity_files(&state)? == identity,
            "identity changed on host exit",
        )?;
        require(
            Sha256::digest(std::fs::read(state.join("retained.bin"))?) == sample,
            "sample changed on host exit",
        )?;
        let mut restarted = ManagedInstance::start(settings(&binary, &state)?).await?;
        require(
            Some(restarted.client().instance().device_id.as_str()) == ready["identity"].as_str(),
            "explicit retry changed identity",
        )?;
        let exit = restarted.shutdown(Duration::from_secs(10)).await?;
        require(
            exit.code == Some(0) && exit.tree_stopped && !exit.forced,
            "retry did not normally finish",
        )?;
        processes_gone(&binary).await?;
        Ok(())
    }
    .await;
    drop(host);
    if mode == "exec" {
        std::fs::write(root.join("unrelated-stop"), b"stop")?;
        let identity = match unrelated_identity {
            Some(identity) => Some(identity),
            None => match std::fs::read_to_string(root.join("unrelated.pid")) {
                Ok(text) => {
                    let pid: u32 = text.parse()?;
                    process_birth(pid)?.map(|birth| (pid, birth))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            },
        };
        if let Some((pid, birth)) = identity {
            unrelated_finished(pid, birth).await?;
        }
    }
    if result.is_err() {
        std::fs::write(
            root.join("failed-before-fallback.json"),
            serde_json::to_vec(&json!({"mode":mode,"fallback_required":true}))?,
        )?;
        #[cfg(unix)]
        emergency_cleanup(&binary, group).await?;
        #[cfg(windows)]
        {
            let observer = outer.try_clone()?;
            tokio::task::spawn_blocking(move || observer.terminate_and_wait()).await??;
            processes_gone(&binary).await?;
        }
        return result;
    }
    canary.shutdown(Duration::from_secs(10)).await?;
    std::fs::remove_dir_all(&root)?;
    let mut evidence = json!({"case":mode,"actual_core_observed":true,
        "actual_host_exit_observed":true,"exact_core_exited_before_any_fallback":true,"identity_hashes_retained":true,
        "sample_sha_retained":true,"other_instance_untouched":true,"explicit_retry_same_identity_ready":true,
        "caller_environment_preserved":true});
    if mode == "inherited" {
        evidence["caller_ignored_blocked_hup_preserved"] = true.into();
    }
    if mode == "exec" {
        evidence["unrelated_exec_live_when_core_exited"] = true.into();
        evidence["unrelated_exec_explicitly_stopped_and_observed"] = true.into();
    }
    #[cfg(windows)]
    {
        evidence["core_exited_while_caller_job_retained"] = true.into();
    }
    println!("public owned host lifetime evidence: {evidence}");
    Ok(())
}

#[tokio::test]
async fn owned_host_returns() -> TestResult {
    if std::env::var_os(HOST_MODE).is_some() {
        run_test_host().await
    } else {
        exercise("return").await
    }
}
#[tokio::test]
async fn owned_host_exits_without_destructors() -> TestResult {
    exercise("exit").await
}
#[tokio::test]
async fn owned_host_is_forced_without_destructors() -> TestResult {
    exercise("kill").await
}
#[tokio::test]
#[cfg(unix)]
async fn owned_host_inherited_hup_is_only_reset_in_its_child() -> TestResult {
    exercise("inherited").await
}
#[tokio::test]
async fn owned_host_exit_does_not_wait_for_an_unrelated_exec() -> TestResult {
    exercise("exec").await
}
