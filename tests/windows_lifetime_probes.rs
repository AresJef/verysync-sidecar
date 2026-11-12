//! Explicit Windows Job investigations, separate from product runtime acceptance.
#![allow(unsafe_code)]

#[cfg(windows)]
#[allow(dead_code)]
#[path = "common/engine_fixture.rs"]
mod engine_fixture;
#[cfg(windows)]
#[allow(dead_code)]
#[path = "common/windows_fixture.rs"]
mod windows_fixture;

#[cfg(not(windows))]
#[test]
fn windows_lifetime_case() -> Result<(), &'static str> {
    Err("this explicitly requested investigation requires native Windows")
}

#[cfg(windows)]
mod windows {
    use super::engine_fixture::{EngineFixture, TestBinary, TestResult};
    use super::windows_fixture::Job;
    use std::fs::{self, File};
    use std::io::{self, BufRead, Write};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use reqwest::Method;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use verysync_sidecar::{ApiKey, Client, ConnectOptions, DeviceId, Error, ManagementEndpoint};
    use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, WaitForSingleObject, CREATE_NO_WINDOW,
        CREATE_SUSPENDED, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };

    struct HostEngine {
        child: Child,
        job: Option<Job>,
        duplicate: Option<Job>,
        state: PathBuf,
    }
    impl Drop for HostEngine {
        fn drop(&mut self) {
            // Closing the handles, not TerminateJobObject, is the mechanism
            // under investigation. A separately marked exact-child fallback
            // remains available if that kernel mechanism did not finish.
            self.job.take();
            self.duplicate.take();
            let deadline = Instant::now() + Duration::from_secs(3);
            while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            if matches!(self.child.try_wait(), Ok(None)) {
                let _ = fs::write(self.state.join("host-fallback"), "exact child still live");
                let _ = self.child.kill();
            }
            let _ = self.child.wait();
        }
    }

    /// This test is an explicitly filtered, short-lived child host. It never
    /// runs as part of the outer investigation's test-name filter.
    #[test]
    fn windows_probe_host() -> TestResult {
        let state = PathBuf::from(
            std::env::var_os("VERYSYNC_WINDOWS_PROBE_STATE")
                .ok_or("explicit private state required")?,
        );
        let mode = std::env::var("VERYSYNC_WINDOWS_PROBE_MODE")
            .map_err(|_| "explicit host mode required")?;
        if !state.is_absolute()
            || ![
                "normal",
                "forced-host",
                "last-handle",
                "persistent",
                "early",
                "auth-failure",
                "startup-failure",
            ]
            .contains(&mode.as_str())
        {
            return Err("invalid explicit Windows probe inputs".into());
        }
        let binary = TestBinary::from_env()?;
        let output = File::create(state.join("windows-probe-engine.log"))?;
        let mut command = Command::new(binary.path());
        command
            .args(["serve", "--home"])
            .arg(&state)
            .args(["--no-browser", "--no-restart", "--no-upgrade"])
            .current_dir(&state)
            .env("TMPDIR", state.join("tmp"))
            .env("TEMP", state.join("tmp"))
            .env("TMP", state.join("tmp"))
            .env("APPDATA", state.join("roaming"))
            .env("LOCALAPPDATA", state.join("local"))
            .env("USERPROFILE", state.join("profile"))
            .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(output.try_clone()?)
            .stderr(output);
        if mode == "startup-failure" {
            command.arg("--synthetic-unknown-probe-option");
        }
        let job = Job::new_with_kill_on_close(mode != "persistent")?;
        let child = command.spawn()?;
        let mut owned = HostEngine {
            child,
            job: Some(job),
            duplicate: None,
            state: state.clone(),
        };
        owned
            .job
            .as_ref()
            .ok_or("lost private Job")?
            .assign_and_resume(&owned.child)?;
        fs::write(
            state.join("windows-probe-root.pid"),
            owned.child.id().to_string(),
        )?;
        if mode == "startup-failure" {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(status) = owned.child.try_wait()? {
                    let snapshot = owned
                        .job
                        .as_ref()
                        .ok_or("lost Job")?
                        .snapshot(&owned.child)?;
                    fs::write(
                        state.join("startup-result.json"),
                        serde_json::to_vec(
                            &json!({"code":status.code(),"success":status.success(),"job":snapshot}),
                        )?,
                    )?;
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err("startup failure did not exit before deadline".into());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        if mode == "last-handle" {
            owned.duplicate = Some(owned.job.as_ref().ok_or("lost Job")?.try_clone()?);
        }
        let mut sequence = 0;
        for instruction in io::stdin().lock().lines() {
            match instruction?.trim() {
                "snapshot" => {
                    sequence += 1;
                    let job = owned
                        .job
                        .as_ref()
                        .or(owned.duplicate.as_ref())
                        .ok_or("no retained Job for snapshot")?;
                    fs::write(
                        state.join(format!("windows-job-{sequence}.json")),
                        serde_json::to_vec(&job.snapshot(&owned.child)?)?,
                    )?;
                }
                "close-primary" => {
                    owned.job.take();
                    fs::write(state.join("primary-closed"), "duplicate retained")?;
                }
                "close-final" => {
                    owned.duplicate.take();
                    owned.job.take();
                    fs::write(state.join("final-closed"), "last handle closed")?;
                }
                "return" => return Ok(()),
                "wait" => {
                    let deadline = Instant::now() + Duration::from_secs(12);
                    loop {
                        if let Some(status) = owned.child.try_wait()? {
                            fs::write(
                                state.join("windows-child-exit.json"),
                                serde_json::to_vec(
                                    &json!({"code":status.code(),"success":status.success()}),
                                )?,
                            )?;
                            return Ok(());
                        }
                        if Instant::now() >= deadline {
                            return Err("owned Windows child exit deadline exceeded".into());
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
                _ => return Err("unknown explicit Windows host instruction".into()),
            }
        }
        Err("explicit Windows host command pipe ended unexpectedly".into())
    }

    struct Process(OwnedHandle);
    impl Process {
        fn open(pid: u32, binary: &Path) -> TestResult<Self> {
            // SAFETY: Open only a PID supplied by the private Job while its
            // host is retained. This is a process handle, never a Job handle.
            let raw = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    0,
                    pid,
                )
            };
            if raw.is_null() {
                return Err(io::Error::last_os_error().into());
            }
            let process = Self(unsafe { OwnedHandle::from_raw_handle(raw) });
            let mut wide = vec![0u16; 32768];
            let mut size = wide.len() as u32;
            if unsafe {
                QueryFullProcessImageNameW(
                    process.0.as_raw_handle(),
                    0,
                    wide.as_mut_ptr(),
                    &mut size,
                )
            } == 0
            {
                return Err(io::Error::last_os_error().into());
            }
            let actual = PathBuf::from(String::from_utf16(&wide[..size as usize])?);
            if fs::canonicalize(actual)? != fs::canonicalize(binary)? {
                return Err(format!(
                    "private Job PID {pid} executable did not match the fixed engine"
                )
                .into());
            }
            Ok(process)
        }
        fn stopped(&self) -> TestResult<bool> {
            // SAFETY: Retained exact-process handle; PID reuse cannot change it.
            match unsafe { WaitForSingleObject(self.0.as_raw_handle(), 0) } {
                WAIT_OBJECT_0 => Ok(true),
                WAIT_TIMEOUT => Ok(false),
                _ => Err(io::Error::last_os_error().into()),
            }
        }
    }

    struct Owner {
        child: Child,
        outer_job: Job,
    }
    impl Drop for Owner {
        fn drop(&mut self) {
            // This outer containment is fallback only and remains open until
            // after the inner-Job verdict. It cannot mimic inner last-close.
            if let Err(error) = self.outer_job.terminate_and_wait() {
                eprintln!("private probe containment cleanup failed: {error}");
            }
            let _ = self.child.wait();
        }
    }
    impl Owner {
        fn start(state: &Path, case: &str) -> TestResult<Self> {
            let output = File::create(state.join("windows-probe-host.log"))?;
            let mut command = Command::new(std::env::current_exe()?);
            command
                .args([
                    "--exact",
                    "windows::windows_probe_host",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("VERYSYNC_WINDOWS_PROBE_STATE", state)
                .env("VERYSYNC_WINDOWS_PROBE_MODE", case)
                .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW)
                .stdin(Stdio::piped())
                .stdout(output.try_clone()?)
                .stderr(output);
            let outer_job = Job::new()?;
            let owner = Self {
                child: command.spawn()?,
                outer_job,
            };
            owner.outer_job.assign_and_resume(&owner.child)?;
            Ok(owner)
        }
        fn command(&mut self, value: &str) -> TestResult {
            let input = self
                .child
                .stdin
                .as_mut()
                .ok_or("probe host command pipe closed")?;
            writeln!(input, "{value}")?;
            input.flush()?;
            Ok(())
        }
        async fn wait(&mut self) -> TestResult<std::process::ExitStatus> {
            let deadline = Instant::now() + Duration::from_secs(16);
            loop {
                if let Some(status) = self.child.try_wait()? {
                    return Ok(status);
                }
                if Instant::now() >= deadline {
                    return Err("Windows test host exit deadline exceeded".into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }

    fn diagnostic(state: &Path, key: &str) -> String {
        let bytes = fs::read(state.join("windows-probe-host.log")).unwrap_or_default();
        String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(4096)..])
            .replace(key, "[REDACTED]")
    }

    async fn read_json(path: &Path, key: &str) -> TestResult<Value> {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            match fs::read(path) {
                Ok(bytes) => {
                    if let Ok(value) = serde_json::from_slice(&bytes) {
                        return Ok(value);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            if Instant::now() >= deadline {
                return Err(format!("private Windows evidence marker deadline exceeded; bounded Rust host diagnostic: {}", diagnostic(path.parent().ok_or("missing private state parent")?,key)).into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    async fn ready(fixture: &EngineFixture, wrong: bool) -> TestResult {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let options = ConnectOptions::new(
                ManagementEndpoint::http(&format!("http://{}", fixture.management_address()))?,
                ApiKey::new(if wrong {
                    "synthetic-wrong-Windows-probe-key"
                } else {
                    fixture.api_key()
                })?,
            )
            .expected_device_id(DeviceId::parse(fixture.device_id())?)
            .request_timeout(Duration::from_millis(500))?;
            match Client::connect(options).await {
                Ok(_) if !wrong => return Ok(()),
                Err(Error::AccessDenied { response }) if wrong && response.status() == 403 => {
                    return Ok(())
                }
                Ok(_) => return Err("wrong Windows probe key unexpectedly accepted".into()),
                Err(error) => {
                    if Instant::now() >= deadline {
                        return Err(error.into());
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }
    async fn all_stopped(processes: &[Process]) -> TestResult<bool> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut stopped = true;
            for process in processes {
                stopped &= process.stopped()?;
            }
            if stopped {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn windows_lifetime_case() -> TestResult {
        let case = std::env::var("VERYSYNC_LIFETIME_CASE")
            .map_err(|_| "explicit Windows lifetime case required")?;
        if ![
            "normal",
            "forced-host",
            "last-handle",
            "persistent",
            "early",
            "auth-failure",
            "startup-failure",
        ]
        .contains(&case.as_str())
        {
            return Err("unknown Windows lifetime case".into());
        }
        let evidence = PathBuf::from(
            std::env::var_os("VERYSYNC_LIFETIME_EVIDENCE")
                .ok_or("explicit private evidence file required")?,
        );
        if !evidence.is_absolute() {
            return Err("absolute evidence file required".into());
        }
        let mut artifact = File::options()
            .write(true)
            .create_new(true)
            .open(evidence)?;
        let binary = TestBinary::from_env()?;
        let mut fixture = EngineFixture::start().await?;
        fixture.shutdown().await?;
        let key = Sha256::digest(fs::read(fixture.state_dir().join("key.pem"))?);
        let mut owner = Owner::start(fixture.state_dir(), &case)?;
        let mut report = json!({"scope":"Windows mechanism investigation, not product managed-runtime acceptance","case":case,"observer_holds_inner_job_handle":false,"host_pid":owner.child.id(),"source_sha256":format!("{:x}",Sha256::digest(fs::read(Path::new(file!()))?)),"engine":"v2.33.2"});
        if case == "startup-failure" {
            let result = read_json(
                &fixture.state_dir().join("startup-result.json"),
                fixture.api_key(),
            )
            .await?;
            let host_exit = owner.wait().await?;
            report["host_exit"] = json!({"code":host_exit.code(),"success":host_exit.success()});
            report["startup_failure"] = result;
        } else {
            let root_path = fixture.state_dir().join("windows-probe-root.pid");
            let deadline = Instant::now() + Duration::from_secs(8);
            while !root_path.exists() {
                if owner.child.try_wait()?.is_some() || Instant::now() >= deadline {
                    return Err(format!("Windows host ownership marker unavailable; bounded Rust host diagnostic: {}",diagnostic(fixture.state_dir(),fixture.api_key())).into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            if case != "early" {
                ready(&fixture, case == "auth-failure").await?;
            }
            owner.command("snapshot")?;
            let snapshot = read_json(
                &fixture.state_dir().join("windows-job-1.json"),
                fixture.api_key(),
            )
            .await?;
            println!("private Job pre-observation snapshot: {snapshot}");
            let processes = snapshot["process_ids"]
                .as_array()
                .ok_or("missing private Job process IDs")?
                .iter()
                .map(|id| {
                    Process::open(
                        id.as_u64().ok_or("invalid Job PID")?.try_into()?,
                        binary.path(),
                    )
                })
                .collect::<TestResult<Vec<_>>>()?;
            if processes.is_empty() {
                return Err("private Job unexpectedly has no process".into());
            }
            report["job"] = snapshot;
            report["outer_containment"] =
                serde_json::to_value(owner.outer_job.snapshot(&owner.child)?)?;
            report["authenticated_expected_identity"] =
                if ["early", "auth-failure"].contains(&case.as_str()) {
                    Value::Null
                } else {
                    json!(true)
                };
            if case == "last-handle" {
                owner.command("close-primary")?;
                // A second snapshot can only be made through the retained
                // duplicate; no observer handle keeps the inner Job alive.
                owner.command("snapshot")?;
                report["retained_duplicate_job"] = read_json(
                    &fixture.state_dir().join("windows-job-2.json"),
                    fixture.api_key(),
                )
                .await?;
                ready(&fixture, false).await?;
                report["authenticated_after_primary_close"] = json!(true);
                owner.command("close-final")?;
                owner.command("wait")?;
                let status = owner.wait().await?;
                report["host_exit"] = json!({"code":status.code(),"success":status.success()});
            } else if case == "normal" {
                owner.command("return")?;
                let status = owner.wait().await?;
                report["host_exit"] = json!({"code":status.code(),"success":status.success()});
            } else {
                owner.child.kill()?;
                let status = owner.child.wait()?;
                report["host_exit"] = json!({"code":status.code(),"success":status.success()});
            }
            if case == "persistent" {
                ready(&fixture, false).await?;
                report["authenticated_after_host_termination"] = json!(true);
                let mut live = 0;
                for process in &processes {
                    if !process.stopped()? {
                        live += 1;
                    }
                }
                report["live_after_host_termination"] = json!(live);
                report["explicit_shutdown_acknowledged"] = json!(fixture
                    .request(Method::POST, "/rest/system/shutdown")?
                    .send()
                    .await?
                    .status()
                    .is_success());
            }
            let stopped = all_stopped(&processes).await?;
            report["all_recorded_process_handles_signalled_before_fallback"] = json!(stopped);
            let empty = owner.outer_job.wait_empty(Duration::from_secs(5)).is_ok();
            report["outer_job_empty_before_fallback"] = json!(empty);
            report["external_fallback_needed"] = json!(!stopped || !empty);
        }
        report["host_exact_child_fallback_used"] =
            json!(fixture.state_dir().join("host-fallback").exists());
        report["identity_key_unchanged"] =
            json!(Sha256::digest(fs::read(fixture.state_dir().join("key.pem"))?) == key);
        writeln!(artifact, "{}", serde_json::to_string_pretty(&report)?)?;
        Ok(())
    }
}
