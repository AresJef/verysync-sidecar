//! Real pinned browser CLI with an explicitly owned desktop replacement.
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use verysync_sidecar::{
    Error, LocalProgram, ManagedInstance, ManagedOptions, ManagementEndpoint, NativeBrowserOutcome,
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Capture(PathBuf);
impl Capture {
    fn new() -> TestResult<Self> {
        let path = PathBuf::from(
            std::env::var_os("VERYSYNC_TEST_OPENER_CAPTURE_DIR")
                .ok_or("owned capture directory required")?,
        );
        let executable = PathBuf::from(
            std::env::var_os("VERYSYNC_TEST_OPENER_EXECUTABLE")
                .ok_or("owned executable required")?,
        );
        if !path.is_absolute()
            || !path.is_dir()
            || !executable.is_file()
            || std::env::var_os("BROWSER").as_deref() != Some(executable.as_os_str())
            || std::env::var("VERYSYNC_TEST_BROWSER_HOLD").as_deref() != Ok("1")
            || std::env::var("VERYSYNC_TEST_BROWSER_ISOLATION").as_deref()
                != Ok(if cfg!(target_os = "macos") {
                    "macos-seatbelt-fallback-v1"
                } else {
                    "linux-private-mount-fallback-v1"
                })
        {
            return Err("explicit isolated browser fixture required".into());
        }
        Ok(Self(path))
    }
    fn calls(&self) -> TestResult<Vec<PathBuf>> {
        let mut calls = Vec::new();
        for entry in fs::read_dir(&self.0)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "argv") {
                calls.push(path);
            }
        }
        Ok(calls)
    }
    async fn after_result(&self, previous: usize, url: &str) -> TestResult {
        let call = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let calls = self.calls()?;
                if calls.len() == previous + 1 {
                    let call = calls
                        .into_iter()
                        .find(|c| !c.with_extension("after-root").exists())
                        .ok_or("new owned call absent")?;
                    let bytes = fs::read(&call)?;
                    let mut expected = url.as_bytes().to_vec();
                    expected.push(0);
                    assert_eq!(
                        bytes, expected,
                        "native dispatch must preserve the exact owned URL"
                    );
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(call);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await??;
        fs::write(
            call.with_extension("after-root"),
            b"root result already received",
        )?;
        wait_file(&call.with_extension("alive")).await?;
        // The actor's live execution happens after the SDK returned, proving
        // successful root cleanup did not terminate desktop descendants.
        fs::write(call.with_extension("stop"), b"explicit test-owned stop")?;
        wait_file(&call.with_extension("finished")).await?;
        Ok(())
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        if let Ok(calls) = self.calls() {
            for call in calls {
                if !call.with_extension("must-exit").exists()
                    && !call.with_extension("detached").exists()
                {
                    let _ = fs::write(call.with_extension("stop"), b"test scope cleanup");
                }
            }
        }
    }
}
async fn wait_file(path: &Path) -> TestResult {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !path.is_file() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    Ok(())
}
struct InvalidOwnedOpener {
    path: PathBuf,
    backup: PathBuf,
}
impl InvalidOwnedOpener {
    fn install() -> TestResult<Self> {
        let path = PathBuf::from(
            std::env::var_os("VERYSYNC_TEST_OPENER_EXECUTABLE").ok_or("owned opener required")?,
        );
        let backup = path.with_extension("saved-valid-opener");
        let permissions = fs::metadata(&path)?.permissions();
        fs::rename(&path, &backup)?;
        let guard = Self { path, backup };
        fs::write(
            &guard.path,
            b"intentionally invalid owned executable; no interpreter header",
        )?;
        fs::set_permissions(&guard.path, permissions)?;
        Ok(guard)
    }
}
impl Drop for InvalidOwnedOpener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::rename(&self.backup, &self.path);
    }
}
fn private_program(root: &Path) -> TestResult<(PathBuf, [u8; 32])> {
    let source = PathBuf::from(
        std::env::var_os("VERYSYNC_TEST_BINARY").ok_or("fixed official program required")?,
    );
    let hex = std::env::var("VERYSYNC_TEST_BINARY_SHA256")?;
    if hex.len() != 64 {
        return Err("explicit pinned digest required".into());
    }
    let mut expected = [0; 32];
    for (i, b) in expected.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(fs::read(&source)?)),
        expected
    );
    let target = root.join(if cfg!(windows) {
        "owned-core.exe"
    } else {
        "owned-core"
    });
    fs::copy(source, &target)?;
    Ok((target, expected))
}
fn snapshot(state: &Path) -> TestResult<Vec<Vec<u8>>> {
    [
        "setting.dat",
        "key.pem",
        "cert.pem",
        ".verysync-sidecar-identity",
    ]
    .iter()
    .map(|p| fs::read(state.join(p)).map_err(Into::into))
    .collect()
}

#[tokio::test]
async fn actual_native_browser_preserves_primary_and_releases_only_successful_launcher(
) -> TestResult {
    let capture = Capture::new()?;
    let root = tempfile::Builder::new().prefix("vbrowser-").tempdir()?;
    let (program, expected) = private_program(root.path())?;
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let url = format!("http://{}/", listener.local_addr()?);
    assert_ne!(listener.local_addr()?.port(), 18886);
    let endpoint = ManagementEndpoint::http(&url)?;
    drop(listener);
    let state = root.path().join("primary");
    let helper = root.path().join("browser-helper");
    let mut core = ManagedInstance::start(
        ManagedOptions::new(
            LocalProgram::new(&program)?.expected_sha256(expected),
            &state,
            endpoint,
        )?
        .startup_timeout(Duration::from_secs(25))?,
    )
    .await?;
    let identity = core.client().instance().device_id.clone();
    let sentinel = state.join("caller-sentinel.bin");
    fs::write(&sentinel, b"primary caller data preserved")?;
    let before = snapshot(&state)?;
    for invalid in [
        state.clone(),
        state.join("nested-helper"),
        root.path().to_path_buf(),
    ] {
        assert!(matches!(
            core.request_native_browser(invalid, false, Duration::from_secs(10))
                .await,
            Err(Error::UnmanagedState)
        ));
    }
    assert!(matches!(
        core.request_native_browser(&helper, false, Duration::ZERO)
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(!helper.exists());
    assert_eq!(capture.calls()?.len(), 0);
    let first = core
        .request_native_browser(&helper, true, Duration::from_secs(15))
        .await?;
    assert_eq!(first.outcome, NativeBrowserOutcome::CommandSucceeded);
    assert_eq!(first.code, Some(0));
    assert!(
        first.native_verify_requested
            && first.authenticated_identity_checked
            && first.descendants_released
            && first.helper_state_released
    );
    assert_eq!(first.program.sha256, expected);
    assert!(first.helper_state_directory().ends_with("browser-helper"));
    capture.after_result(0, &url).await?;
    assert_eq!(snapshot(&state)?, before);
    assert_ne!(fs::read(helper.join("key.pem"))?, before[1]);
    assert_ne!(fs::read(helper.join("cert.pem"))?, before[2]);
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let helper_before = snapshot(&helper)?;
    let stopped = core.shutdown(Duration::from_secs(10)).await?;
    assert_eq!(stopped.code, Some(0));
    assert!(stopped.tree_stopped && !stopped.forced);
    let unreachable_helper = root.path().join("unreachable-target-helper");
    assert!(core
        .request_native_browser(&unreachable_helper, true, Duration::from_secs(3))
        .await
        .is_err());
    assert!(!unreachable_helper.exists());
    assert_eq!(capture.calls()?.len(), 1);
    let expired_helper = root.path().join("expired-helper");
    assert!(matches!(
        core.request_native_browser(&expired_helper, false, Duration::from_nanos(1))
            .await,
        Err(Error::Timeout { .. })
    ));
    assert!(!expired_helper.exists());
    let second = core
        .request_native_browser(&helper, false, Duration::from_secs(15))
        .await?;
    assert_eq!(second.outcome, NativeBrowserOutcome::CommandSucceeded);
    assert!(second.descendants_released && second.helper_state_released);
    assert!(!second.authenticated_identity_checked && !second.native_verify_requested);
    capture.after_result(1, &url).await?;
    assert_eq!(snapshot(&state)?, before);
    assert_eq!(snapshot(&helper)?, helper_before);
    let invalid_opener = InvalidOwnedOpener::install()?;
    let failed = core
        .request_native_browser(&helper, false, Duration::from_secs(10))
        .await?;
    assert_eq!(failed.outcome, NativeBrowserOutcome::NativeFailure);
    assert_eq!(failed.code, Some(1));
    assert!(!failed.descendants_released && failed.helper_state_released);
    assert_eq!(capture.calls()?.len(), 2);
    drop(invalid_opener);
    let role = helper.join(".verysync-sidecar-browser-helper");
    let original_role = fs::read(&role)?;
    fs::write(&role, b"corrupted test role")?;
    let refused = core
        .request_native_browser(&helper, false, Duration::from_secs(10))
        .await;
    assert!(matches!(refused, Err(Error::UnmanagedState)));
    assert_eq!(fs::read(&role)?, b"corrupted test role");
    fs::write(&role, original_role)?;
    assert_eq!(capture.calls()?.len(), 2);
    assert_eq!(fs::read(&sentinel)?, b"primary caller data preserved");
    let original = fs::read(&program)?;
    fs::write(
        &program,
        b"deliberately corrupted owned program copy; must never execute",
    )?;
    let rejected = core
        .request_native_browser(&helper, false, Duration::from_secs(10))
        .await;
    fs::write(&program, original)?;
    assert!(matches!(rejected, Err(Error::ProgramRejected { .. })));
    assert_eq!(capture.calls()?.len(), 2);
    assert_eq!(snapshot(&state)?, before);
    assert_eq!(snapshot(&helper)?, helper_before);
    {
        fs::write(
            capture.0.join("hold-native-root"),
            b"test-only bounded cancellation point",
        )?;
        let cancelled_helper = root.path().join("cancelled-helper");
        let mut request = Box::pin(core.request_native_browser(
            &cancelled_helper,
            false,
            Duration::from_secs(15),
        ));
        tokio::select! {
            _=&mut request => return Err("native request finished before the controlled cancellation point".into()),
            ready=tokio::time::timeout(Duration::from_secs(10),async {
                while !capture.0.join("native-root-held").is_file() || capture.calls()?.len()!=3 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
            }) => ready??,
        }
        let cancelled_call = capture
            .calls()?
            .into_iter()
            .find(|p| !p.with_extension("after-root").exists())
            .ok_or("cancelled native argv absent")?;
        let mut expected_url = url.as_bytes().to_vec();
        expected_url.push(0);
        assert_eq!(fs::read(cancelled_call)?, expected_url);
        let cancelled_before = snapshot(&cancelled_helper)?;
        drop(request);
        let fence = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(cancelled_helper.join(".verysync-sidecar-lease"))?;
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match fs2::FileExt::try_lock_exclusive(&fence) {
                    Ok(()) => break,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(10)).await
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok::<_, std::io::Error>(())
        })
        .await??;
        assert_eq!(snapshot(&cancelled_helper)?, cancelled_before);
        assert_eq!(snapshot(&state)?, before);
        assert_eq!(snapshot(&helper)?, helper_before);
        assert_eq!(fs::read(&sentinel)?, b"primary caller data preserved");
        assert_eq!(capture.calls()?.len(), 3);
        // The outer wrapper must independently observe the exact native CLI PID
        // dead before any cleanup markers. macOS additionally requires the
        // cancellation actor dead; Linux records whether its native detached
        // opener and actor outlive that root, then explicitly stops the fixture.
        drop(fence);
        eprintln!("native browser evidence: exact_owned_url_calls=3 successful_root_receipts=2 native_failed_opener_code=1 failure_never_releases_descendants=true cancellation_after_native_root_and_actor_started=true cancellation_lease_released=true cancelled_helper_bytes_preserved=true verify_live_identity=true verify_false_after_normal_stop=true desktop_actor_executed_after_each_success_result=true cancellation_native_root_exit_before_outer_cleanup_required=true cancellation_desktop_exit_is_platform_specific=true independent_helper_keys=true primary_config_keys_data_preserved=true helper_reused=true overlap_refused=true program_drift_refused=true real_desktop_opened=false");
    }
    Ok(())
}
