//! Actual public managed startup, isolated state reuse and conflict protection.

use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;
use verysync_sidecar::{
    Error, LocalProgram, ManagedInstance, ManagedOptions, ManagementEndpoint, RawMethod,
    RawRequest, RequestEffect,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn source() -> TestResult<LocalProgram> {
    let path = PathBuf::from(
        std::env::var_os("VERYSYNC_TEST_BINARY")
            .ok_or("explicit private test binary is required")?,
    );
    let hex = std::env::var("VERYSYNC_TEST_BINARY_SHA256")?;
    if hex.len() != 64 {
        return Err("explicit executable SHA-256 is required".into());
    }
    let mut sha = [0; 32];
    for (index, byte) in sha.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)?;
    }
    Ok(LocalProgram::new(path)?.expected_sha256(sha))
}

fn options(program: LocalProgram, path: &std::path::Path) -> TestResult<ManagedOptions> {
    #[cfg(unix)]
    let endpoint = ManagementEndpoint::unix_socket(path.join("gui.sock"))?;
    #[cfg(windows)]
    let endpoint = {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        ManagementEndpoint::http(&format!("http://{}", listener.local_addr()?))?
    };
    Ok(ManagedOptions::new(program, path, endpoint)?.startup_timeout(Duration::from_secs(25))?)
}

async fn start_checked(settings: ManagedOptions) -> verysync_sidecar::Result<ManagedInstance> {
    let state = settings.state_directory().to_owned();
    match ManagedInstance::start(settings).await {
        Ok(instance) => Ok(instance),
        Err(error) => {
            if let Error::ManagedProcessExited {
                operation,
                diagnostic: Some(diagnostic),
                ..
            } = &error
            {
                let mut text = String::from_utf8_lossy(diagnostic.body_bytes()).into_owned();
                if let Ok(bytes) = std::fs::read(state.join("setting.dat")) {
                    if let Ok(config) = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes)) {
                        for field in ["4", "6"] {
                            if let Some(secret) = config["4"][field]
                                .as_str()
                                .filter(|value| !value.is_empty())
                            {
                                text = text.replace(secret, "[REDACTED]");
                            }
                        }
                    }
                }
                // This fixture owns only synthetic state. Mask long opaque tokens
                // as well as known GUI credentials before CI diagnostics appear.
                let safe = text
                    .split_whitespace()
                    .map(|part| {
                        if part.len() > 24 {
                            "[REDACTED-TOKEN]"
                        } else {
                            part
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                eprintln!(
                    "private test startup stage {operation}: {}",
                    safe.chars().take(8192).collect::<String>()
                );
            }
            Err(error)
        }
    }
}

async fn stop_via_explicit_management(instance: &mut ManagedInstance) -> TestResult {
    let request = RawRequest::new(
        RawMethod::Post,
        ["rest", "system", "shutdown"],
        RequestEffect::MayModify,
    )?;
    let response = instance.client().raw_request(&request).await?;
    assert!((200..300).contains(&response.status()));
    let exit = tokio::time::timeout(Duration::from_secs(12), instance.wait_for_exit()).await??;
    assert_eq!(exit.code, Some(0));
    assert!(!exit.forced);
    Ok(())
}

#[tokio::test]
async fn start_authenticate_reuse_identity_and_reject_state_conflict() -> TestResult {
    let binary = source()?;
    #[cfg(unix)]
    let root = tempfile::Builder::new().prefix("vsm-").tempdir_in("/tmp")?;
    #[cfg(windows)]
    let root = tempfile::Builder::new().prefix("vsm-").tempdir()?;
    let path = root.path().join("state");
    let settings = options(binary, &path)?;
    let mut instance = start_checked(settings.clone()).await?;
    let identity = instance.client().instance().device_id.clone();
    assert_eq!(instance.client().version().await?.version, "v2.33.2");
    assert_eq!(instance.program_info().version, "v2.33.2");
    let status = instance.client().system_status().await?;
    assert_eq!(status.device_id, identity);
    assert_eq!(
        instance.program_info().sha256,
        <[u8; 32]>::from(Sha256::digest(std::fs::read(source()?.path())?))
    );
    let upstream_lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path.join("verysync.lock"))?;
    assert!(fs2::FileExt::try_lock_exclusive(&upstream_lock).is_err());
    let sample = path.join("managed-sample");
    std::fs::create_dir(&sample)?;
    std::fs::write(
        sample.join("retained.txt"),
        b"synthetic persistent managed data",
    )?;
    let sample_hash = Sha256::digest(std::fs::read(sample.join("retained.txt"))?);
    let folder_id = verysync_sidecar::FolderId::parse("managed-state-reuse")?;
    instance
        .client()
        .create_folder(
            &verysync_sidecar::CreateFolderOptions::new(
                folder_id.clone(),
                verysync_sidecar::TargetPath::local(&sample),
            )
            .paused(true),
        )
        .await?;
    let config_request =
        RawRequest::new(RawMethod::Get, ["rest", "config"], RequestEffect::ReadOnly)?;
    let original_config: serde_json::Value = serde_json::from_slice(
        instance
            .client()
            .raw_request(&config_request)
            .await?
            .body_bytes(),
    )?;
    let key_hash = Sha256::digest(std::fs::read(path.join("key.pem"))?);
    let cert_hash = Sha256::digest(std::fs::read(path.join("cert.pem"))?);
    assert!(matches!(
        ManagedInstance::start(settings.clone()).await,
        Err(Error::ManagedStateInUse)
    ));
    instance.client().system_status().await?;
    stop_via_explicit_management(&mut instance).await?;
    drop(instance);
    println!(
        "official lock pathname removed after clean exit: {}",
        !path.join("verysync.lock").exists()
    );
    drop(upstream_lock);
    // The official process removes its lock pathname on clean exit. Open the
    // current pathname again; locking its old unlinked inode proves nothing.
    let upstream_lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path.join("verysync.lock"))?;
    fs2::FileExt::try_lock_exclusive(&upstream_lock)?;
    let config_before_rejection = Sha256::digest(std::fs::read(path.join("setting.dat"))?);
    assert!(matches!(
        ManagedInstance::start(settings.clone()).await,
        Err(Error::ManagedStateInUse)
    ));
    assert_eq!(
        Sha256::digest(std::fs::read(path.join("key.pem"))?),
        key_hash
    );
    assert_eq!(
        Sha256::digest(std::fs::read(path.join("setting.dat"))?),
        config_before_rejection
    );
    fs2::FileExt::unlock(&upstream_lock)?;
    drop(upstream_lock);
    let mut second = start_checked(settings).await?;
    assert_eq!(second.client().instance().device_id, identity);
    assert_eq!(
        Sha256::digest(std::fs::read(path.join("key.pem"))?),
        key_hash
    );
    assert_eq!(
        Sha256::digest(std::fs::read(path.join("cert.pem"))?),
        cert_hash
    );
    let reused_config: serde_json::Value = serde_json::from_slice(
        second
            .client()
            .raw_request(&config_request)
            .await?
            .body_bytes(),
    )?;
    assert_eq!(reused_config["devices"], original_config["devices"]);
    assert_eq!(reused_config["options"], original_config["options"]);
    assert_eq!(second.client().folder(&folder_id).await?.id, folder_id);
    assert_eq!(
        Sha256::digest(std::fs::read(sample.join("retained.txt"))?),
        sample_hash
    );
    stop_via_explicit_management(&mut second).await?;
    println!("public managed start evidence: {{\"fixed_program_checked\":true,\"authenticated_identity\":true,\"conflict_rejected\":true,\"first_instance_untouched\":true,\"identity_reused\":true,\"key_sha_unchanged\":true,\"cert_sha_unchanged\":true,\"actual_zero_exit\":true,\"upstream_lock_rejected_before_configuration\":true,\"folder_and_options_retained\":true,\"sample_sha_unchanged\":true}}");
    Ok(())
}

#[tokio::test]
async fn start_wrong_executable_checksum_never_generates_identity() -> TestResult {
    let binary = source()?.expected_sha256([0; 32]);
    #[cfg(unix)]
    let root = tempfile::Builder::new().prefix("vsm-").tempdir_in("/tmp")?;
    #[cfg(windows)]
    let root = tempfile::tempdir()?;
    let path = root.path().join("state");
    assert!(matches!(
        ManagedInstance::start(options(binary, &path)?).await,
        Err(Error::ProgramRejected { .. })
    ));
    assert!(!path.join("key.pem").exists());
    assert!(!path.join("cert.pem").exists());
    Ok(())
}

#[tokio::test]
async fn start_refuses_existing_application_state_without_rewriting_files() -> TestResult {
    let binary = source()?;
    #[cfg(unix)]
    let root = tempfile::Builder::new().prefix("vsm-").tempdir_in("/tmp")?;
    #[cfg(windows)]
    let root = tempfile::tempdir()?;
    let path = root.path();
    let canary = path.join("setting.dat");
    std::fs::write(
        &canary,
        b"synthetic existing application state; must stay untouched",
    )?;
    let before = Sha256::digest(std::fs::read(&canary)?);
    let result = ManagedInstance::start(options(binary, path)?).await;
    assert!(matches!(
        result,
        Err(Error::UnmanagedState | Error::LocalIo { .. })
    ));
    assert_eq!(Sha256::digest(std::fs::read(&canary)?), before);
    assert!(!path.join(".verysync-sidecar-state").exists());
    assert!(!path.join(".verysync-sidecar-lease").exists());
    assert!(!path.join("key.pem").exists());
    Ok(())
}

#[path = "common/managed_pause.rs"]
mod managed_pause;

fn lifecycle_root() -> TestResult<tempfile::TempDir> {
    #[cfg(unix)]
    {
        Ok(tempfile::Builder::new().prefix("vss-").tempdir_in("/tmp")?)
    }
    #[cfg(windows)]
    {
        Ok(tempfile::Builder::new().prefix("vss-").tempdir()?)
    }
}

#[tokio::test]
async fn shutdown_confirms_exit_keeps_files_and_another_instance() -> TestResult {
    let root = lifecycle_root()?;
    let path_a = root.path().join("a");
    let path_b = root.path().join("b");
    let settings_a = options(source()?, &path_a)?;
    let mut first = start_checked(settings_a.clone()).await?;
    let mut other = start_checked(options(source()?, &path_b)?).await?;
    std::fs::write(path_a.join("retained.bin"), b"synthetic shutdown sample")?;
    let before = Sha256::digest(std::fs::read(path_a.join("retained.bin"))?);
    let identity = first.client().instance().device_id.clone();
    let exit = match first.shutdown(Duration::from_secs(10)).await {
        Ok(exit) => exit,
        Err(error) => {
            print_owned_group(first.process_id());
            return Err(error.into());
        }
    };
    assert_eq!(exit.code, Some(0));
    assert!(!exit.forced);
    assert!(exit.tree_stopped);
    assert_eq!(
        Sha256::digest(std::fs::read(path_a.join("retained.bin"))?),
        before
    );
    other.client().system_status().await?;
    let already = first.shutdown(Duration::from_secs(1)).await?;
    assert_eq!(already.code, Some(0));
    let mut reused = start_checked(settings_a).await?;
    assert_eq!(reused.client().instance().device_id, identity);
    if let Err(error) = reused.shutdown(Duration::from_secs(10)).await {
        print_owned_group(reused.process_id());
        return Err(error.into());
    }
    let other_pid = other.process_id();
    let forced = match other.force_stop(Duration::from_secs(10)).await {
        Ok(exit) => exit,
        Err(error) => {
            print_owned_group(other_pid);
            return Err(error.into());
        }
    };
    assert!(forced.forced && forced.tree_stopped);
    println!("public managed shutdown evidence: {{\"api_then_actual_zero_exit\":true,\"sample_sha_unchanged\":true,\"other_instance_untouched\":true,\"already_exited_observed\":true,\"state_lease_released\":true,\"identity_reused\":true,\"explicit_force_confirmed\":true}}");
    Ok(())
}

#[tokio::test]
async fn shutdown_timeout_retains_owner_until_the_real_root_resumes() -> TestResult {
    let root = lifecycle_root()?;
    let settings = options(source()?, &root.path().join("state"))?;
    let mut instance = start_checked(settings.clone()).await?;
    let paused = managed_pause::PausedRoot::new(instance.process_id())?;
    let start = std::time::Instant::now();
    let result = instance.shutdown(Duration::from_millis(300)).await;
    assert!(matches!(result, Err(Error::Timeout { .. })), "{result:?}");
    assert!(start.elapsed() < Duration::from_secs(3));
    assert!(paused.is_paused()?);
    assert!(matches!(
        ManagedInstance::start(settings).await,
        Err(Error::ManagedStateInUse)
    ));
    drop(paused);
    // Linux's validated inner-process mode freezes the API itself. The other
    // baselines freeze the monitor while its worker acknowledges shutdown.
    #[cfg(target_os = "linux")]
    let exit = instance.shutdown(Duration::from_secs(10)).await?;
    #[cfg(not(target_os = "linux"))]
    let exit = tokio::time::timeout(Duration::from_secs(10), instance.wait_for_exit()).await??;
    assert_eq!(exit.code, Some(0));
    assert!(!exit.forced && exit.tree_stopped);
    println!("public managed shutdown timeout evidence: {{\"real_root_suspended\":true,\"deadline_returned\":true,\"no_implicit_force\":true,\"state_still_exclusive\":true,\"resume_then_actual_zero_exit\":true}}");
    Ok(())
}

#[tokio::test]
async fn shutdown_transport_failure_does_not_force_the_owned_instance() -> TestResult {
    let root = lifecycle_root()?;
    let settings = options(source()?, &root.path().join("state"))?;
    let mut instance = start_checked(settings.clone()).await?;
    let query = RawRequest::new(
        RawMethod::Get,
        ["rest", "config", "gui"],
        RequestEffect::ReadOnly,
    )?;
    let response = instance.client().raw_request(&query).await?;
    assert!((200..300).contains(&response.status()));
    let mut gui: serde_json::Value = serde_json::from_slice(response.body_bytes())?;
    assert_eq!(gui["enabled"], true);
    // Deliberately remove this test instance's management endpoint, then prove
    // a failed normal shutdown cannot silently acquire permission to kill it.
    gui["enabled"] = false.into();
    let patch = RawRequest::new(
        RawMethod::Patch,
        ["rest", "config", "gui"],
        RequestEffect::MayModify,
    )?
    .json_body(&gui)?;
    let response = instance.client().raw_request(&patch).await?;
    assert!((200..300).contains(&response.status()));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match instance.client().version().await {
            Err(Error::Transport { .. }) => break,
            Ok(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await
            }
            other => {
                return Err(
                    format!("management endpoint did not become unavailable: {other:?}").into(),
                )
            }
        }
    }
    let paused = managed_pause::PausedRoot::new(instance.process_id())?;
    let result = instance.shutdown(Duration::from_secs(2)).await;
    assert!(matches!(result, Err(Error::Transport { .. })), "{result:?}");
    assert!(paused.is_paused()?);
    assert!(matches!(
        ManagedInstance::start(settings).await,
        Err(Error::ManagedStateInUse)
    ));
    assert!(instance.force_stop(Duration::ZERO).await.is_err());
    assert!(paused.is_paused()?);
    drop(paused);
    let exit = instance.force_stop(Duration::from_secs(10)).await?;
    assert!(exit.forced && exit.tree_stopped);
    println!("public managed shutdown failure evidence: {{\"actual_management_endpoint_disabled\":true,\"typed_transport_failure\":true,\"retained_root_still_alive\":true,\"state_still_exclusive\":true,\"invalid_deadline_did_not_stop\":true,\"force_requires_explicit_call\":true}}");
    Ok(())
}

#[cfg(unix)]
fn print_owned_group(pid: u32) {
    if let Ok(output) = std::process::Command::new("/bin/ps")
        .args(["-A", "-o", "pid=,ppid=,pgid=,stat=,comm="])
        .output()
    {
        if !output.status.success() {
            eprintln!(
                "own ps observation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        for row in String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| {
                line.split_whitespace()
                    .nth(2)
                    .and_then(|value| value.parse::<u32>().ok())
                    == Some(pid)
            })
        {
            eprintln!("owned exit group observation: {row}");
        }
    }
}
#[cfg(not(unix))]
fn print_owned_group(_pid: u32) {}
