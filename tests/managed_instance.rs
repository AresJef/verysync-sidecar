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
    let mut instance = ManagedInstance::start(settings.clone()).await?;
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
    let mut second = ManagedInstance::start(settings).await?;
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
