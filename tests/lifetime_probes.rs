//! Explicit mechanism investigations, not production managed-runtime acceptance.
#![allow(unsafe_code)]

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(dead_code)] // Only the shared fixture methods needed by this probe run.
#[path = "common/engine_fixture.rs"]
mod engine_fixture;
#[cfg(target_os = "linux")]
#[path = "probes/linux_process_ownership.rs"]
mod linux_process_ownership;

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_lifetime_case() -> Result<(), &'static str> {
    Err("this explicitly requested investigation requires native macOS")
}

#[cfg(not(target_os = "linux"))]
#[test]
fn linux_lifetime_case() -> Result<(), &'static str> {
    Err("this explicitly requested investigation requires native Linux")
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod unix {
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use super::engine_fixture::{EngineFixture, TestBinary, TestResult};
    use reqwest::Method;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use verysync_sidecar::{ApiKey, Client, ConnectOptions, DeviceId, ManagementEndpoint};

    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }

    struct ProbeOwner {
        child: Child,
        state: PathBuf,
        engine: Option<u32>,
        binary: PathBuf,
        #[cfg(target_os = "linux")]
        state_cleanup_allowed: bool,
    }
    impl ProbeOwner {
        async fn start(helper: &Path, binary: &Path, state: &Path, mode: &str) -> TestResult<Self> {
            let state_cleanup_allowed = mode != "conflict-secondary";
            let mode = if state_cleanup_allowed { mode } else { "base" };
            let mut command = Command::new(helper);
            command.env_remove("VERYSYNC_PROBE_HOST_SIGNAL_STATE");
            if std::env::var("VERYSYNC_LIFETIME_CASE").ok().as_deref() == Some("inherited-pty") {
                command.env("VERYSYNC_PROBE_HOST_SIGNAL_STATE", "ignored-blocked");
            }
            let child = command
                .args([binary, state, Path::new(mode)])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let mut owner = Self {
                child,
                state: state.to_owned(),
                engine: None,
                binary: binary.to_owned(),
                #[cfg(target_os = "linux")]
                state_cleanup_allowed,
            };
            let marker = state.join(format!("owner-{}.pid", owner.child.id()));
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Ok(text) = fs::read_to_string(&marker) {
                    owner.engine = Some(text.parse()?);
                    return Ok(owner);
                }
                if owner.child.try_wait()?.is_some() {
                    return Err(
                        "explicit probe host exited before recording child ownership".into(),
                    );
                }
                if Instant::now() >= deadline {
                    return Err("probe host ownership marker deadline exceeded".into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        fn instruction(&mut self, value: &str) -> TestResult {
            let input = self
                .child
                .stdin
                .as_mut()
                .ok_or("probe command pipe closed")?;
            writeln!(input, "{value}")?;
            input.flush()?;
            Ok(())
        }
        async fn wait(&mut self) -> TestResult {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if self.child.try_wait()?.is_some() {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err("probe host exit deadline exceeded".into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        fn native_snapshot(&self) -> TestResult<String> {
            let pid = self.engine.ok_or("no recorded engine PID")?.to_string();
            let output = Command::new("/bin/ps")
                .args(["-p", &pid, "-o", "pid=,ppid=,pgid=,tpgid=,tty=,stat="])
                .output()?;
            if !output.status.success() && !output.stderr.is_empty() {
                return Err(
                    "native process observation failed; no stopped-process conclusion is available"
                        .into(),
                );
            }
            Ok(String::from_utf8(output.stdout)?.trim().to_owned())
        }
        fn live_group(&self) -> TestResult<Vec<String>> {
            #[cfg(target_os = "linux")]
            {
                let mut rows = Vec::new();
                for pid in super::linux_process_ownership::owned_pids(&self.binary, &self.state)? {
                    let output = Command::new("/bin/ps")
                        .args([
                            "-p",
                            &pid.to_string(),
                            "-o",
                            "pid=,ppid=,pgid=,tpgid=,tty=,stat=",
                        ])
                        .output()?;
                    if !output.status.success() && !output.stderr.is_empty() {
                        return Err("private Linux process observation failed".into());
                    }
                    let row = String::from_utf8(output.stdout)?;
                    if row
                        .split_whitespace()
                        .last()
                        .is_some_and(|s| !s.starts_with('Z'))
                    {
                        rows.push(row.trim().to_owned());
                    }
                }
                Ok(rows)
            }
            #[cfg(target_os = "macos")]
            {
                let pid = self.engine.ok_or("no recorded engine PID")?.to_string();
                let output = Command::new("/usr/bin/pgrep").args(["-g", &pid]).output()?;
                if !matches!(output.status.code(), Some(0 | 1)) {
                    return Err("native private-group observation failed".into());
                }
                let mut members = Vec::new();
                for member in String::from_utf8(output.stdout)?.lines() {
                    let output = Command::new("/bin/ps")
                        .args(["-p", member, "-o", "pid=,ppid=,pgid=,tpgid=,tty=,stat="])
                        .output()?;
                    if !output.status.success() && !output.stderr.is_empty() {
                        return Err("native private-group member observation failed".into());
                    }
                    let text = String::from_utf8(output.stdout)?;
                    if text
                        .split_whitespace()
                        .last()
                        .is_some_and(|s| !s.starts_with('Z'))
                    {
                        members.push(text.trim().to_owned());
                    }
                }
                Ok(members)
            }
        }
        fn engine_live(&self) -> TestResult<bool> {
            Ok(self
                .native_snapshot()?
                .split_whitespace()
                .last()
                .is_some_and(|state| !state.starts_with('Z')))
        }
        fn exit_metadata(&self) -> TestResult<Value> {
            Ok(serde_json::from_slice(&fs::read(
                self.state
                    .join(format!("owner-{}.exit.json", self.child.id())),
            )?)?)
        }
        fn fallback_cleanup(&mut self) {
            if matches!(self.child.try_wait(), Ok(None)) {
                let _ = self.instruction("return");
                let deadline = Instant::now() + Duration::from_secs(2);
                while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(20));
                }
                if matches!(self.child.try_wait(), Ok(None)) {
                    let _ = self.child.kill();
                }
            }
            let _ = self.child.wait();
            #[cfg(target_os = "linux")]
            if self.state_cleanup_allowed {
                if let Err(error) =
                    super::linux_process_ownership::terminate_owned(&self.binary, &self.state)
                {
                    eprintln!("exact private Linux instance fallback failed: {error}");
                }
                return;
            }
            if let Some(pid) = self.engine {
                // A fallback is reported separately. Verify every surviving
                // member's explicit binary/state before signalling this group.
                if let Ok(members) = self.live_group() {
                    let mut verified = false;
                    for member in members
                        .iter()
                        .filter_map(|line| line.split_whitespace().next())
                    {
                        let Ok(output) = Command::new("/bin/ps")
                            .args(["-ww", "-p", member, "-o", "command="])
                            .output()
                        else {
                            return;
                        };
                        let Ok(command) = String::from_utf8(output.stdout) else {
                            return;
                        };
                        let Some(binary) = self.binary.to_str() else {
                            return;
                        };
                        let Some(state) = self.state.to_str() else {
                            return;
                        };
                        if !command.trim_start().starts_with(binary) || !command.contains(state) {
                            return;
                        }
                        verified = true;
                    }
                    if verified {
                        // SAFETY: The group was created in the test child's own
                        // session; every currently present member was checked.
                        unsafe {
                            kill(-(pid as i32), 9);
                        }
                    }
                }
            }
        }
    }
    impl Drop for ProbeOwner {
        fn drop(&mut self) {
            self.fallback_cleanup();
        }
    }

    async fn ready(fixture: &EngineFixture) -> TestResult<Client> {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let options = ConnectOptions::new(
                ManagementEndpoint::unix_socket(fixture.state_dir().join("gui.sock"))?,
                ApiKey::new(fixture.api_key())?,
            )
            .expected_device_id(DeviceId::parse(fixture.device_id())?)
            .request_timeout(Duration::from_millis(500))?;
            match Client::connect(options).await {
                Ok(client) => return Ok(client),
                Err(error) => {
                    if Instant::now() >= deadline {
                        return Err(error.into());
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    }

    async fn authentication_rejected(fixture: &EngineFixture) -> TestResult {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let options = ConnectOptions::new(
                ManagementEndpoint::unix_socket(fixture.state_dir().join("gui.sock"))?,
                ApiKey::new("synthetic-wrong-probe-key")?,
            )
            .request_timeout(Duration::from_millis(500))?;
            match Client::connect(options).await {
                Err(verysync_sidecar::Error::Authentication { status: 403 }) => return Ok(()),
                Ok(_) => return Err("wrong probe credential unexpectedly accepted".into()),
                Err(error) => {
                    if Instant::now() >= deadline {
                        return Err(error.into());
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_lifetime_case() -> TestResult {
        run_case().await
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_lifetime_case() -> TestResult {
        run_case().await
    }

    async fn run_case() -> TestResult {
        let case = std::env::var("VERYSYNC_LIFETIME_CASE")
            .map_err(|_| "explicit VERYSYNC_LIFETIME_CASE is required")?;
        let mut cases = vec![
            "normal",
            "conflict",
            "forced-base",
            "forced-pty",
            "close-pty",
            "early-pty",
            "auth-failure-pty",
            "inherited-pty",
        ];
        if cfg!(target_os = "linux") {
            cases.extend([
                "pdeath-hup",
                "pdeath-kill",
                "thread-pdeath",
                "thread-pty",
                "install-race",
                "exec-fork",
            ]);
        }
        if !cases.contains(&case.as_str()) {
            return Err("unknown explicit lifetime case".into());
        }
        let rustc = PathBuf::from(
            std::env::var_os("VERYSYNC_PROBE_RUSTC")
                .ok_or("absolute VERYSYNC_PROBE_RUSTC is required")?,
        );
        let evidence = PathBuf::from(
            std::env::var_os("VERYSYNC_LIFETIME_EVIDENCE")
                .ok_or("absolute VERYSYNC_LIFETIME_EVIDENCE is required")?,
        );
        if !rustc.is_absolute() || !evidence.is_absolute() {
            return Err("probe compiler and evidence paths must be absolute".into());
        }
        let mut artifact = File::options()
            .write(true)
            .create_new(true)
            .open(&evidence)?;
        let binary = TestBinary::from_env()?;
        let mut fixture = EngineFixture::start().await?;
        fixture.shutdown().await?;
        let identity_hash = format!("{:x}", Sha256::digest(fixture.device_id().as_bytes()));
        let key_hash = Sha256::digest(fs::read(fixture.state_dir().join("key.pem"))?);
        let helper_dir = tempfile::Builder::new().prefix("vs-owner-").tempdir()?;
        let helper = helper_dir.path().join("unix-lifetime-owner");
        let helper_name = if cfg!(target_os = "linux") {
            "linux_lifetime_owner.rs"
        } else {
            "macos_lifetime_owner.rs"
        };
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("probes")
            .join(helper_name);
        let compiled = Command::new(&rustc)
            .args(["--edition=2021", "-Dwarnings"])
            .arg(&source)
            .arg("-o")
            .arg(&helper)
            .output()?;
        if !compiled.status.success() {
            return Err(
                "standalone Rust probe host failed compilation; no engine launched by it".into(),
            );
        }
        #[cfg(target_os = "linux")]
        if ["install-race", "exec-fork"].contains(&case.as_str()) {
            return linux_primitives(&case, &helper, &source, &binary, &fixture, &mut artifact)
                .await;
        }
        let mode = match case.as_str() {
            "pdeath-hup" | "pdeath-kill" | "thread-pdeath" | "thread-pty" => case.as_str(),
            _ if case.contains("pty") => "pty",
            _ => "base",
        };
        let mut owner =
            ProbeOwner::start(&helper, binary.path(), fixture.state_dir(), mode).await?;
        let connected = if ["early-pty", "auth-failure-pty"].contains(&case.as_str()) {
            None
        } else {
            Some(ready(&fixture).await?)
        };
        if case == "auth-failure-pty" {
            authentication_rejected(&fixture).await?;
        }
        let before = owner.native_snapshot()?;
        let host_meta: Value = serde_json::from_slice(&fs::read(
            fixture
                .state_dir()
                .join(format!("owner-{}.meta.json", owner.child.id())),
        )?)?;
        let mut report = json!({"scope":"native mechanism investigation, not product managed-runtime acceptance","case":case,"engine":"v2.33.2","identity_sha256":identity_hash,"before":before,"before_live_group_members":owner.live_group()?,"authenticated_expected_identity":connected.as_ref().map(|client|client.instance().device_id.as_str()==fixture.device_id()),"helper_source_sha256":format!("{:x}",Sha256::digest(fs::read(&source)?)),"controller_source_sha256":format!("{:x}",Sha256::digest(fs::read(Path::new(file!()))?)),"host_descriptor_and_signal_state":host_meta,"native_observation_seconds":5,"expected_authentication_rejection":case=="auth-failure-pty","readiness_not_requested":case=="early-pty"});
        if cfg!(target_os = "linux") {
            report["observation_scope"] = json!(
                "all exact private executable/--home processes, including groups outside root"
            );
        }
        drop(connected);
        if case == "conflict" {
            let mut second = ProbeOwner::start(
                &helper,
                binary.path(),
                fixture.state_dir(),
                "conflict-secondary",
            )
            .await?;
            second.instruction("wait")?;
            second.wait().await?;
            let timeout = fixture
                .state_dir()
                .join(format!("owner-{}.timeout", second.child.id()))
                .exists();
            let child_exit = second.exit_metadata().unwrap_or(Value::Null);
            let log = fs::read_to_string(
                fixture
                    .state_dir()
                    .join(format!("owner-{}.engine.log", second.child.id())),
            )?;
            let lower = log.to_ascii_lowercase();
            let rejection_lines: Vec<String> = log
                .lines()
                .filter(|line| {
                    let text = line.to_ascii_lowercase();
                    (text.contains("lock")
                        || text.contains("another instance")
                        || text.contains("address already in use"))
                        && !["password", "api key", "apikey", "private key", "token"]
                            .iter()
                            .any(|secret| text.contains(secret))
                })
                .take(3)
                .map(|line| {
                    line.replace(fixture.api_key(), "[REDACTED]")
                        .chars()
                        .take(512)
                        .collect()
                })
                .collect();
            report["second_child_exit"] = child_exit.clone();
            report["second_failed_without_probe_timeout"] =
                json!(!timeout && child_exit["code"].as_i64().is_some_and(|code| code != 0));
            report["upstream_lock_message_observed"] =
                json!(lower.contains("lock") || lower.contains("another verysync"));
            report["address_conflict_message_observed"] =
                json!(lower.contains("address already in use") || lower.contains("bind:"));
            report["bounded_rejection_context"] = json!(rejection_lines);
            report["probe_guard_timeout"] = json!(timeout);
            report["first_process_group_still_live"] = json!(!owner.live_group()?.is_empty());
            report["first_authenticated_endpoint_still_ready"] =
                json!(ready(&fixture).await.is_ok());
            owner.instruction("wait")?;
            let acknowledged = fixture
                .request(Method::POST, "/rest/system/shutdown")?
                .send()
                .await?
                .status()
                .is_success();
            owner.wait().await?;
            report["first_shutdown_acknowledged"] = json!(acknowledged);
            report["first_child_exit"] = owner.exit_metadata()?;
        } else if case == "normal" {
            owner.instruction("return")?;
            owner.wait().await?;
            report["normal_rust_guard_child_stopped"] = json!(!owner.engine_live()?);
            report["normal_rust_guard_live_group_members"] = json!(owner.live_group()?);
            owner.fallback_cleanup();
            let mut restarted =
                ProbeOwner::start(&helper, binary.path(), fixture.state_dir(), "base").await?;
            let connection = ready(&fixture).await?;
            report["same_state_identity_reused"] =
                json!(connection.instance().device_id.as_str() == fixture.device_id());
            restarted.instruction("wait")?;
            let acknowledged = fixture
                .request(Method::POST, "/rest/system/shutdown")?
                .send()
                .await?
                .status()
                .is_success();
            restarted.wait().await?;
            report["explicit_shutdown_acknowledged"] = json!(acknowledged);
            report["explicit_shutdown_child_exit"] = restarted.exit_metadata()?;
            report["explicit_shutdown_child_stopped"] = json!(!restarted.engine_live()?);
            report["explicit_shutdown_live_group_members"] = json!(restarted.live_group()?);
        } else {
            if case == "thread-pty" {
                owner.instruction("thread-exit")?;
                let marker = fixture
                    .state_dir()
                    .join(format!("owner-{}.thread-ended", owner.child.id()));
                let deadline = Instant::now() + Duration::from_secs(3);
                while !marker.exists() && Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                report["creator_thread_exited"] = json!(marker.exists());
                report["host_still_live_after_creator_thread_exit"] =
                    json!(owner.child.try_wait()?.is_none());
                report["engine_still_authenticated_after_creator_thread_exit"] =
                    json!(ready(&fixture).await.is_ok());
                owner.child.kill()?;
                owner.child.wait()?;
            } else if case == "thread-pdeath" {
                owner.instruction("thread-exit")?;
                let marker = fixture
                    .state_dir()
                    .join(format!("owner-{}.thread-ended", owner.child.id()));
                let deadline = Instant::now() + Duration::from_secs(3);
                while !marker.exists() && Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                report["creator_thread_exited"] = json!(marker.exists());
                report["host_recorded_after_creator_thread_exit"] = json!(marker.exists());
                report["host_still_live_at_observer_snapshot"] =
                    json!(owner.child.try_wait()?.is_none());
                // Leave the host alive while observing its exact child below.
            } else if ["close-pty", "early-pty", "auth-failure-pty"].contains(&case.as_str()) {
                owner.instruction("close-pty")?;
                owner.wait().await?;
                report["native_child_exit"] = owner.exit_metadata().unwrap_or(Value::Null);
            } else {
                owner.child.kill()?;
                owner.child.wait()?;
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while (owner.engine_live()? || !owner.live_group()?.is_empty())
                && Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            let alive = owner.engine_live()?;
            let group = owner.live_group()?;
            let probe_timeout = fixture
                .state_dir()
                .join(format!("owner-{}.timeout", owner.child.id()))
                .exists();
            report["native_child_stopped_before_external_cleanup"] = json!(!alive);
            report["native_live_group_members_before_cleanup"] = json!(group);
            report["probe_host_fallback_timeout"] = json!(probe_timeout);
            report["native_entire_group_stopped_before_any_fallback"] =
                json!(!alive && group.is_empty() && !probe_timeout);
            report["external_fallback_needed"] = json!(alive || !group.is_empty() || probe_timeout);
            report["after_before_fallback"] = json!(owner.native_snapshot()?);
            owner.fallback_cleanup();
        }
        report["identity_key_unchanged"] =
            json!(Sha256::digest(fs::read(fixture.state_dir().join("key.pem"))?) == key_hash);
        writeln!(artifact, "{}", serde_json::to_string_pretty(&report)?)?;
        println!("recorded native lifetime investigation case {case}; mechanism result is in the explicit evidence file");
        Ok(())
    }
    #[cfg(target_os = "linux")]
    async fn linux_primitives(
        case: &str,
        helper: &Path,
        source: &Path,
        binary: &TestBinary,
        fixture: &EngineFixture,
        artifact: &mut File,
    ) -> TestResult {
        let mut report = json!({"scope":"Linux primitive investigation, not product managed-runtime acceptance","case":case,"helper_source_sha256":format!("{:x}",Sha256::digest(fs::read(source)?))});
        if case == "exec-fork" {
            let result = Command::new(helper)
                .args([binary.path(), fixture.state_dir(), Path::new("primitive")])
                .output()?;
            if !result.status.success() {
                return Err("explicit exec/fork primitive failed".into());
            }
            report["primitive"] =
                serde_json::from_slice(&fs::read(fixture.state_dir().join("primitive.json"))?)?;
        } else {
            let child = Command::new(helper)
                .args([binary.path(), fixture.state_dir(), Path::new("race")])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let mut owner = ProbeOwner {
                child,
                state: fixture.state_dir().to_owned(),
                engine: None,
                binary: helper.to_owned(),
                state_cleanup_allowed: false,
            };
            let marker = fixture.state_dir().join("race-child.pid.bin");
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Ok(bytes) = fs::read(&marker) {
                    if let Ok(bytes) = <[u8; 4]>::try_from(bytes) {
                        owner.engine = Some(i32::from_ne_bytes(bytes).try_into()?);
                        break;
                    }
                }
                if owner.child.try_wait()?.is_some() || Instant::now() >= deadline {
                    return Err("pre-install child ownership marker unavailable".into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            report["before"] = json!(owner.native_snapshot()?);
            owner.child.kill()?;
            owner.child.wait()?;
            let deadline = Instant::now() + Duration::from_secs(5);
            while (owner.engine_live()? || !owner.live_group()?.is_empty())
                && Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            report["parent_changed_before_signal_installation"] = json!(
                fs::read(
                    fixture
                        .state_dir()
                        .join("race-parent-changed-before-install.bin")
                )? == b"parent-changed-before-install"
            );
            report["parent_changed_rejected_before_exec"] = json!(
                fs::read(fixture.state_dir().join("race-rejected.bin"))? == b"rejected-before-exec"
            );
            report["child_stopped_before_external_cleanup"] =
                json!(!owner.engine_live()? && owner.live_group()?.is_empty());
            report["live_group_before_cleanup"] = json!(owner.live_group()?);
            owner.fallback_cleanup();
        }
        writeln!(artifact, "{}", serde_json::to_string_pretty(&report)?)?;
        Ok(())
    }
}
