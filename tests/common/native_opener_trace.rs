//! Test-only, opt-in process-start tracing. No application/runtime SDK hook.
use std::{
    io::{BufRead, BufReader, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

/// Give only this exact test's child the owned SystemRoot used by native gopen.
pub(super) async fn run_owned_capture_child() -> super::TestResult<bool> {
    if std::env::var("VERYSYNC_TEST_OPENER_OWNED_CHILD").as_deref() == Ok("1") {
        return Ok(false);
    }
    let root = PathBuf::from(
        std::env::var_os("VERYSYNC_TEST_OPENER_SYSTEM_ROOT")
            .ok_or("explicit owned Windows opener root required")?,
    );
    let expected = root.join("System32").join("rundll32.exe");
    let executable = PathBuf::from(
        std::env::var_os("VERYSYNC_TEST_OPENER_EXECUTABLE")
            .ok_or("explicit owned opener executable required")?,
    );
    if !root.is_absolute() || expected != executable || !expected.symlink_metadata()?.is_file() {
        return Err("owned absolute Windows opener fixture required".into());
    }
    struct CaptureChild(Child);
    impl Drop for CaptureChild {
        fn drop(&mut self) {
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
    let mut child_output = tempfile::tempfile()?;
    let mut child = CaptureChild(
        Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "native_helper_effects::actual_native_folder_open_requests_capture_exact_owned_target_dispatch",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("SYSTEMROOT", &root)
            .env("VERYSYNC_TEST_OPENER_OWNED_CHILD", "1")
            // PowerShell needs the real Windows environment. Exact owned
            // argv capture replaces optional system-wide name observation.
            .env("VERYSYNC_TEST_OPENER_TRACE", "0")
            .stdin(Stdio::null())
            .stdout(child_output.try_clone()?)
            .stderr(child_output.try_clone()?)
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child.0.try_wait()? {
            // Preserve the child transcript without presenting its nested
            // harness as a second top-level execution to the evidence collector.
            child_output.seek(SeekFrom::Start(0))?;
            for line in BufReader::new(&mut child_output).lines() {
                eprintln!("owned Windows dispatch child: {}", line?);
            }
            if !status.success() {
                return Err("owned Windows native dispatch child failed".into());
            }
            eprintln!("native opener owned SystemRoot child=true exact_child_reaped=true original_dispatch_deadline_s=3 caller_environment_unchanged=true");
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Err("owned Windows dispatch child exceeded cleanup bound".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub(super) struct Trace {
    child: Child,
    directory: PathBuf,
    ready_before_request: bool,
}
impl Trace {
    pub(super) fn maybe_start(source_pid: u32, capture: &Path) -> Option<Self> {
        if std::env::var("VERYSYNC_TEST_OPENER_TRACE").as_deref() != Ok("1") {
            return None;
        }
        if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
            || std::env::var("RUNNER_OS").as_deref() != Ok("Windows")
        {
            eprintln!("native opener OS trace: scope_refused=true");
            return None;
        }
        let directory = capture.join("os-trace");
        if std::fs::create_dir(&directory).is_err() {
            eprintln!("native opener OS trace: evidence_directory_unavailable=true");
            return None;
        }
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scripts")
            .join("trace-native-folder-opener.ps1");
        let child = match Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(script)
            .arg("-SourcePid")
            .arg(source_pid.to_string())
            .arg("-EvidenceDirectory")
            .arg(&directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                eprintln!(
                    "native opener OS trace: spawn_error_kind={:?}",
                    error.kind()
                );
                let _ = std::fs::remove_dir(&directory);
                return None;
            }
        };
        let mut trace = Self {
            child,
            directory,
            ready_before_request: false,
        };
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if trace.directory.join("ready").is_file() {
                break;
            }
            match trace.child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => {}
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        trace.ready_before_request = trace.directory.join("ready").is_file();
        Some(trace)
    }
}
impl Drop for Trace {
    fn drop(&mut self) {
        let _ = std::fs::write(self.directory.join("stop"), b"stop");
        let deadline = Instant::now() + Duration::from_secs(4);
        let mut forced = false;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Err(_) => {
                    forced = true;
                    break;
                }
                Ok(None) => {}
            }
            if Instant::now() >= deadline {
                forced = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if forced {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        let ready = self.ready_before_request;
        let report = std::fs::File::open(self.directory.join("report.json"));
        match report {
            Ok(file) => {
                use std::io::Read;
                let mut bytes = Vec::new();
                match file.take(32769).read_to_end(&mut bytes) {
                    Ok(_) if bytes.len() <= 32768 => match serde_json::from_slice::<serde_json::Value>(&bytes) {
                        Ok(value) => eprintln!("native opener OS trace: ready_before_request={ready} forced_cleanup={forced} report={value}"),
                        Err(_) => eprintln!("native opener OS trace: invalid_report=true forced_cleanup={forced}"),
                    },
                    _ => eprintln!("native opener OS trace: bounded_report_unavailable=true forced_cleanup={forced}"),
                }
            }
            Err(_) => {
                eprintln!("native opener OS trace: report_unavailable=true forced_cleanup={forced}")
            }
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
