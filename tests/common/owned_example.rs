//! Actual compiled owned example, with containment retained by the test observer.
use super::{inventory, processes_gone, require, Host, TestResult, CORE_FILE};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Container {
    #[cfg(windows)]
    job: super::windows_fixture::Job,
}
impl Container {
    fn new() -> TestResult<Self> {
        Ok(Self {
            #[cfg(windows)]
            job: super::windows_fixture::Job::new()?,
        })
    }
    fn spawn(&self, command: &mut Command) -> TestResult<Host> {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};
            command.creation_flags(CREATE_NO_WINDOW | CREATE_SUSPENDED);
        }
        let host = Host(command.spawn()?);
        #[cfg(windows)]
        self.job.assign_and_resume(&host.0)?;
        Ok(host)
    }
    async fn empty(&self) -> TestResult {
        #[cfg(windows)]
        {
            let job = self.job.try_clone()?;
            tokio::task::spawn_blocking(move || job.wait_empty(Duration::from_secs(8))).await??;
        }
        Ok(())
    }
}

async fn invoke(
    container: &Container,
    executable: &Path,
    mode: &str,
    binary: &Path,
    state: &Path,
    address: &std::ffi::OsStr,
) -> TestResult<Value> {
    let capture_root = state.parent().ok_or("example capture parent missing")?;
    let stdout = tempfile::NamedTempFile::new_in(capture_root)?;
    let stderr = tempfile::NamedTempFile::new_in(capture_root)?;
    let mut command = Command::new(executable);
    command
        .arg(mode)
        .arg(binary)
        .arg(state)
        .arg(if cfg!(windows) { "http" } else { "socket" })
        .arg(address)
        .env(
            "VERYSYNC_EXAMPLE_PROGRAM_SHA256",
            std::env::var("VERYSYNC_TEST_BINARY_SHA256")?,
        )
        .stdin(Stdio::null())
        .stdout(stdout.as_file().try_clone()?)
        .stderr(stderr.as_file().try_clone()?);
    #[cfg(windows)]
    if mode == "persistent" {
        command.stdout(Stdio::piped());
    }
    let mut host = container.spawn(&mut command)?;
    eprintln!("compiled owned example stage: {mode} spawned");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if host.0.try_wait()?.is_some() {
            break;
        }
        require(Instant::now() < deadline, "compiled owned example deadline")?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    eprintln!("compiled owned example stage: {mode} caller exited");
    #[cfg(windows)]
    let pipe_bytes = if mode == "persistent" {
        Some(read_closed_caller_pipe(&mut host).await?)
    } else {
        None
    };
    #[cfg(not(windows))]
    let pipe_bytes: Option<Vec<u8>> = None;
    // Read a bounded regular file after this exact caller exits. A retained
    // Windows pipe writer can otherwise prevent EOF despite observed root exit.
    // This capture is independent of the native core-survival/exit verdicts.
    let output = tokio::task::spawn_blocking(move || -> TestResult<_> {
        use std::io::Read;
        let bytes = if let Some(bytes) = pipe_bytes {
            bytes
        } else {
            let mut bytes = Vec::new();
            stdout.reopen()?.take(8193).read_to_end(&mut bytes)?;
            bytes
        };
        require(
            bytes.len() <= 8192,
            "compiled owned example output exceeds its bound",
        )?;
        let status = host.0.wait()?;
        require(status.success(), "compiled owned example returned failure")?;
        Ok(serde_json::from_slice::<Value>(&bytes)?)
    })
    .await??;
    eprintln!("compiled owned example stage: {mode} output consumed");
    require(
        output["mode"] == mode,
        "compiled owned example mode mismatch",
    )?;
    Ok(output)
}

/// Poll only this private output pipe; EOF must precede any core cleanup.
#[cfg(windows)]
#[allow(unsafe_code)]
async fn read_closed_caller_pipe(host: &mut Host) -> TestResult<Vec<u8>> {
    use std::io::Read;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE;
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;
    let mut pipe = host
        .0
        .stdout
        .take()
        .ok_or("private caller stdout missing")?;
    let mut bytes = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut available = 0u32;
        // SAFETY: Only this retained private pipe handle and a writable output.
        // There is no concurrent reader or pending read on this handle.
        let result = unsafe {
            PeekNamedPipe(
                pipe.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if result == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                return Ok(bytes);
            }
            return Err(error.into());
        }
        require(
            (available as usize) <= 8192usize.saturating_sub(bytes.len()),
            "caller output exceeds bound",
        )?;
        if available != 0 {
            // Exactly this many bytes are already buffered and this is the sole
            // reader. The finite read never waits for an inherited writer's EOF.
            let start = bytes.len();
            bytes.resize(start + available as usize, 0);
            pipe.read_exact(&mut bytes[start..])?;
        }
        require(
            Instant::now() < deadline,
            "persistent core retained caller output pipe after caller exit",
        )?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn compiled_owned_example_persists_reconnects_stops_and_reuses_identity() -> TestResult {
    let directory = PathBuf::from(
        std::env::var_os("VERYSYNC_TEST_EXAMPLE_DIR")
            .ok_or("explicit compiled example directory required")?,
    );
    let mut executable = directory.join("manage_owned");
    if cfg!(windows) {
        executable.set_extension("exe");
    }
    let metadata = std::fs::symlink_metadata(&executable)?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "compiled owned example must be a regular file",
    )?;
    let root = tempfile::Builder::new()
        .prefix(if cfg!(windows) {
            "vsx 中文 spaces-"
        } else {
            "vsx-"
        })
        .tempdir()?
        .keep();
    let binary = root.join(CORE_FILE);
    std::fs::copy(
        std::env::var_os("VERYSYNC_TEST_BINARY").ok_or("explicit private core required")?,
        &binary,
    )?;
    let state = root.join("state");
    #[cfg(unix)]
    let address = state.join("gui.sock").into_os_string();
    #[cfg(windows)]
    let address = {
        let socket = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        std::ffi::OsString::from(format!("http://{}/", socket.local_addr()?))
    };
    let container = Container::new()?;
    #[cfg(unix)]
    let mut group = None;
    let result: TestResult = async {
        let started = invoke(
            &container,
            &executable,
            "persistent",
            &binary,
            &state,
            &address,
        )
        .await?;
        require(
            started["management_ready"] == true,
            "compiled persistent example not ready",
        )?;
        let pid = u32::try_from(
            started["process_id"]
                .as_u64()
                .ok_or("example root missing")?,
        )?;
        #[cfg(unix)]
        {
            group = Some(pid);
        }
        require(
            inventory(&binary).await?.contains(&pid),
            "compiled persistent example did not leave actual core alive",
        )?;
        let identity = super::identity_files(&state)?;
        std::fs::write(
            state.join("example-sample.bin"),
            b"synthetic compiled owned example sample",
        )?;
        let sample = Sha256::digest(std::fs::read(state.join("example-sample.bin"))?);
        let connected = invoke(
            &container,
            &executable,
            "connect",
            &binary,
            &state,
            &address,
        )
        .await?;
        require(
            connected["device_id"] == started["device_id"] && connected["management_ready"] == true,
            "compiled reconnect wrong identity",
        )?;
        require(
            inventory(&binary).await?.contains(&pid),
            "compiled borrowed exit stopped persistent core",
        )?;
        let shutdown = invoke(
            &container,
            &executable,
            "shutdown",
            &binary,
            &state,
            &address,
        )
        .await?;
        require(
            shutdown["shutdown_acknowledged"] == true,
            "compiled shutdown not acknowledged",
        )?;
        processes_gone(&binary).await?;
        eprintln!("compiled owned example stage: shutdown actual core exit");
        container.empty().await?;
        let owned = invoke(&container, &executable, "owned", &binary, &state, &address).await?;
        require(
            owned["device_id"] == started["device_id"]
                && owned["actual_tree_exit"] == true
                && owned["forced"] == false,
            "compiled owned normal exit missing",
        )?;
        processes_gone(&binary).await?;
        container.empty().await?;
        require(
            super::identity_files(&state)? == identity,
            "compiled example changed identity files",
        )?;
        require(
            Sha256::digest(std::fs::read(state.join("example-sample.bin"))?) == sample,
            "compiled example changed synthetic sample",
        )?;
        Ok(())
    }
    .await;
    if result.is_err() {
        std::fs::write(
            root.join("failed-before-fallback.json"),
            b"{\"compiled_owned_example_failed\":true}",
        )?;
        #[cfg(unix)]
        super::emergency_cleanup(&binary, group).await?;
        #[cfg(windows)]
        {
            let job = container.job.try_clone()?;
            tokio::task::spawn_blocking(move || job.terminate_and_wait()).await??;
            processes_gone(&binary).await?;
        }
        return result;
    }
    std::fs::remove_dir_all(&root)?;
    let mut evidence = json!({"persistent_example_executed":true,"actual_core_survived_example_exit":true,
        "connect_example_executed":true,"same_identity_authenticated":true,"borrowed_example_exit_leaves_core_alive":true,
        "shutdown_example_executed":true,"actual_core_exited_before_observer_cleanup":true,"owned_example_executed":true,
        "owned_normal_tree_exit":true,"identity_files_retained":true,"sample_sha_retained":true,"four_example_processes_reaped":true});
    if cfg!(windows) {
        evidence["caller_pipe_eof_before_core_shutdown"] = json!(true);
        evidence["native_paths_with_spaces_and_unicode"] = json!(true);
    }
    println!("compiled owned example evidence: {evidence}");
    Ok(())
}
