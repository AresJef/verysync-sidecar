//! Real cancellation boundaries, independent inventory and explicit recovery.

use super::{lifecycle_root, options, source, start_checked, TestResult};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use verysync_sidecar::{LocalProgram, ManagedInstance, ManagedOptions, ManagementEndpoint};

struct StartupCase {
    // Keep failures private for diagnosis. Successful cases explicitly remove
    // only their own temp root after exact-program exit has been confirmed.
    root: PathBuf,
    binary: PathBuf,
    state: PathBuf,
    settings: ManagedOptions,
    blocker: Option<TcpListener>,
}

impl StartupCase {
    fn blocked() -> TestResult<Self> {
        let root = lifecycle_root()?.keep();
        #[cfg(windows)]
        let binary = root.join("cancel-engine.exe");
        #[cfg(unix)]
        let binary = root.join("cancel-engine");
        std::fs::copy(source()?.path(), &binary)?;
        let sha: [u8; 32] = Sha256::digest(std::fs::read(&binary)?).into();
        let blocker = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let endpoint = ManagementEndpoint::http(&format!("http://{}", blocker.local_addr()?))?;
        let state = root.join("state");
        let settings = ManagedOptions::new(
            LocalProgram::new(&binary)?.expected_sha256(sha),
            &state,
            endpoint,
        )?
        .startup_timeout(Duration::from_secs(25))?;
        Ok(Self {
            root,
            binary,
            state,
            settings,
            blocker: Some(blocker),
        })
    }

    fn unblock(&mut self) {
        self.blocker.take();
    }

    async fn cleanup(self) -> TestResult {
        wait_no_processes(&self.binary).await?;
        std::fs::remove_dir_all(self.root)?;
        Ok(())
    }
}

fn inventory_blocking(binary: &Path) -> TestResult<Vec<u32>> {
    #[cfg(windows)]
    let python = "python";
    #[cfg(unix)]
    let python = "python3";
    let output = Command::new(python)
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("scripts")
                .join("prepare-test-engine.py"),
        )
        .arg("list-owned-processes")
        .env("VERYSYNC_TEST_BINARY", binary)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "exact private process inventory failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    value["pids"]
        .as_array()
        .ok_or("process list missing")?
        .iter()
        .map(|pid| {
            pid.as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .filter(|value| *value != 0)
                .ok_or_else(|| "process ID invalid".into())
        })
        .collect()
}

pub(super) async fn inventory(binary: &Path) -> TestResult<Vec<u32>> {
    let binary = binary.to_owned();
    tokio::task::spawn_blocking(move || inventory_blocking(&binary)).await?
}

async fn core_created(binary: &Path, state: &Path) -> TestResult<Vec<u32>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        // A fresh case's core capture is created only after all metadata helpers
        // completed. A real exact-image PID then proves a core was created.
        if state.join(".verysync-sidecar-core.log").try_exists()? {
            let pids = inventory(binary).await?;
            if !pids.is_empty() {
                return Ok(pids);
            }
        }
        if Instant::now() >= deadline {
            return Err("actual core was not observed before readiness".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_no_processes(binary: &Path) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if inventory(binary).await?.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("cancelled startup left an exact private program process alive".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_state_available(state: &Path) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(state.join(".verysync-sidecar-lease"))?;
        if fs2::FileExt::try_lock_exclusive(&lease).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("cleanup did not release its private state lease".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn private_identity(state: &Path) -> TestResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    Ok((
        std::fs::read(state.join(".verysync-sidecar-identity"))?,
        Sha256::digest(std::fs::read(state.join("key.pem"))?).to_vec(),
        Sha256::digest(std::fs::read(state.join("cert.pem"))?).to_vec(),
    ))
}

#[tokio::test]
async fn cancelled_start_after_actual_core_creation_cleans_and_retries_same_identity() -> TestResult
{
    let mut case = StartupCase::blocked()?;
    let canary_root = lifecycle_root()?;
    let mut canary = start_checked(options(source()?, &canary_root.path().join("state"))?).await?;
    let canary_id = canary.client().instance().device_id.clone();
    let mut pending = Box::pin(ManagedInstance::start(case.settings.clone()));
    let seen = tokio::select! {
        result = &mut pending => return Err(format!("startup ended before the actual cancellation boundary: {result:?}").into()),
        pids = core_created(&case.binary, &case.state) => pids?,
    };
    assert!(!seen.is_empty());
    let identity = private_identity(&case.state)?;
    let sample = case.state.join("retained-sample.bin");
    std::fs::write(&sample, b"synthetic startup cancellation sample")?;
    let sample_sha = Sha256::digest(std::fs::read(&sample)?);
    drop(pending);
    wait_no_processes(&case.binary).await?;
    wait_state_available(&case.state).await?;
    assert_eq!(private_identity(&case.state)?, identity);
    assert_eq!(Sha256::digest(std::fs::read(&sample)?), sample_sha);
    assert_eq!(canary.client().system_status().await?.device_id, canary_id);
    case.unblock();
    let mut retried = start_checked(case.settings.clone()).await?;
    assert!(inventory(&case.binary)
        .await?
        .contains(&retried.process_id()));
    assert_eq!(
        retried.client().instance().device_id.as_str().as_bytes(),
        identity.0
    );
    assert_eq!(private_identity(&case.state)?, identity);
    assert_eq!(Sha256::digest(std::fs::read(&sample)?), sample_sha);
    retried.shutdown(Duration::from_secs(10)).await?;
    canary.shutdown(Duration::from_secs(10)).await?;
    case.cleanup().await?;
    println!("public cancelled startup evidence: {{\"actual_private_core_pids_observed\":true,\"future_dropped_before_readiness\":true,\"independent_exact_processes_gone\":true,\"identity_key_certificate_retained\":true,\"sample_sha_retained\":true,\"other_instance_untouched\":true,\"explicit_retry_authenticated_same_identity\":true}}");
    Ok(())
}

#[tokio::test]
async fn cancelled_start_by_caller_deadline_releases_actual_created_processes() -> TestResult {
    let mut case = StartupCase::blocked()?;
    let mut pending = Box::pin(ManagedInstance::start(case.settings.clone()));
    tokio::select! {
        result = &mut pending => return Err(format!("startup ended before the caller deadline boundary: {result:?}").into()),
        pids = core_created(&case.binary, &case.state) => assert!(!pids?.is_empty()),
    }
    let identity = private_identity(&case.state)?;
    // Owning the future matters: timeout drops it, rather than merely ceasing to
    // await a detached JoinHandle whose task would still own its startup.
    let timed = tokio::time::timeout(Duration::from_millis(150), pending).await;
    assert!(
        timed.is_err(),
        "startup unexpectedly completed before the caller deadline"
    );
    wait_no_processes(&case.binary).await?;
    wait_state_available(&case.state).await?;
    assert_eq!(private_identity(&case.state)?, identity);
    case.unblock();
    let mut retried = start_checked(case.settings.clone()).await?;
    assert!(inventory(&case.binary)
        .await?
        .contains(&retried.process_id()));
    assert_eq!(
        retried.client().instance().device_id.as_str().as_bytes(),
        identity.0
    );
    retried.shutdown(Duration::from_secs(10)).await?;
    case.cleanup().await?;
    println!("public caller startup deadline evidence: {{\"actual_core_observed\":true,\"owned_future_deadline_elapsed\":true,\"independent_process_exit_confirmed\":true,\"partial_state_retained\":true,\"explicit_retry_ready\":true}}");
    Ok(())
}

#[tokio::test]
async fn cancelled_start_by_sdk_deadline_cleans_an_observed_process() -> TestResult {
    let mut case = StartupCase::blocked()?;
    let settings = case
        .settings
        .clone()
        .startup_timeout(Duration::from_secs(12))?;
    let mut pending = Box::pin(ManagedInstance::start(settings));
    let seen = tokio::select! {
        result = &mut pending => return Err(format!("startup ended before its observed deadline boundary: {result:?}").into()),
        pids = core_created(&case.binary, &case.state) => pids?,
    };
    let root = super::managed_pause::startup_root(&seen)?;
    let paused = super::managed_pause::PausedRoot::new(root)?;
    assert!(paused.is_paused()?);
    paused.leave_paused();
    let identity = private_identity(&case.state)?;
    let result = pending.await;
    assert!(
        matches!(result, Err(verysync_sidecar::Error::Timeout { .. })),
        "{result:?}"
    );
    wait_no_processes(&case.binary).await?;
    wait_state_available(&case.state).await?;
    case.unblock();
    let mut retried = start_checked(case.settings.clone()).await?;
    assert_eq!(private_identity(&case.state)?, identity);
    assert!(inventory(&case.binary)
        .await?
        .contains(&retried.process_id()));
    retried.shutdown(Duration::from_secs(10)).await?;
    case.cleanup().await?;
    println!("public SDK startup deadline evidence: {{\"actual_core_observed\":true,\"actual_retained_root_frozen\":true,\"typed_sdk_timeout\":true,\"independent_process_exit_confirmed\":true,\"lease_released_separately\":true,\"explicit_retry_same_identity\":true}}");
    Ok(())
}

#[tokio::test]
async fn cancelled_start_by_runtime_shutdown_keeps_cleanup_independent() -> TestResult {
    let mut case = StartupCase::blocked()?;
    let binary = case.binary.clone();
    let state = case.state.clone();
    let settings = case.settings.clone();
    let canary_root = lifecycle_root()?;
    let mut canary = start_checked(options(source()?, &canary_root.path().join("state"))?).await?;
    let canary_id = canary.client().instance().device_id.clone();
    let identity = tokio::task::spawn_blocking(move || -> TestResult<_> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let pending = runtime.spawn(ManagedInstance::start(settings));
        runtime.block_on(core_created(&binary, &state))?;
        assert!(!pending.is_finished());
        let identity = private_identity(&state)?;
        // No explicit abort or instance Drop: runtime shutdown drops its actual
        // pending startup task. The native owner thread must finish independently.
        drop(runtime);
        drop(pending);
        Ok(identity)
    })
    .await??;
    wait_no_processes(&case.binary).await?;
    wait_state_available(&case.state).await?;
    assert_eq!(private_identity(&case.state)?, identity);
    assert_eq!(canary.client().system_status().await?.device_id, canary_id);
    case.unblock();
    let mut retried = start_checked(case.settings.clone()).await?;
    assert_eq!(private_identity(&case.state)?, identity);
    assert!(inventory(&case.binary)
        .await?
        .contains(&retried.process_id()));
    retried.shutdown(Duration::from_secs(10)).await?;
    canary.shutdown(Duration::from_secs(10)).await?;
    case.cleanup().await?;
    println!("public runtime startup cancellation evidence: {{\"actual_core_observed\":true,\"pending_runtime_dropped\":true,\"native_cleanup_without_runtime\":true,\"other_instance_untouched\":true,\"identity_retained\":true,\"explicit_retry_ready\":true}}");
    Ok(())
}

#[tokio::test]
async fn cancelled_start_partial_identity_and_configuration_require_explicit_repair() -> TestResult
{
    let mut case = StartupCase::blocked()?;
    case.unblock();
    let mut first = start_checked(case.settings.clone()).await?;
    assert!(inventory(&case.binary).await?.contains(&first.process_id()));
    let identity = private_identity(&case.state)?;
    let sample = case.state.join("partial-state-sample.bin");
    std::fs::write(&sample, b"synthetic partial state must remain")?;
    let sample_sha = Sha256::digest(std::fs::read(&sample)?);
    first.shutdown(Duration::from_secs(10)).await?;
    wait_no_processes(&case.binary).await?;
    let cert_path = case.state.join("cert.pem");
    let certificate = std::fs::read(&cert_path)?;
    let permissions = std::fs::metadata(&cert_path)?.permissions();
    std::fs::remove_file(&cert_path)?;
    let incomplete = ManagedInstance::start(case.settings.clone()).await;
    assert!(
        matches!(
            incomplete,
            Err(verysync_sidecar::Error::ManagedFailure { .. })
        ),
        "{incomplete:?}"
    );
    wait_no_processes(&case.binary).await?;
    assert!(!cert_path.exists());
    assert_eq!(
        Sha256::digest(std::fs::read(case.state.join("key.pem"))?).as_slice(),
        identity.1
    );
    assert_eq!(
        std::fs::read(case.state.join(".verysync-sidecar-identity"))?,
        identity.0
    );
    assert_eq!(Sha256::digest(std::fs::read(&sample)?), sample_sha);
    // The caller explicitly restores its own original certificate; startup must
    // not silently invent another identity to conceal the incomplete state.
    std::fs::write(&cert_path, certificate)?;
    std::fs::set_permissions(&cert_path, permissions)?;
    #[cfg(unix)]
    {
        let original = case.root.join("original-test-certificate");
        std::fs::rename(&cert_path, &original)?;
        let original_sha = Sha256::digest(std::fs::read(&original)?);
        std::os::unix::fs::symlink(&original, &cert_path)?;
        let aliased = ManagedInstance::start(case.settings.clone()).await;
        assert!(
            matches!(aliased, Err(verysync_sidecar::Error::LocalIo { .. })),
            "{aliased:?}"
        );
        wait_no_processes(&case.binary).await?;
        assert_eq!(Sha256::digest(std::fs::read(&original)?), original_sha);
        assert!(std::fs::symlink_metadata(&cert_path)?
            .file_type()
            .is_symlink());
        std::fs::remove_file(&cert_path)?;
        std::fs::rename(&original, &cert_path)?;
    }
    let config_path = case.state.join("setting.dat");
    let original_config = std::fs::read(&config_path)?;
    let saved = case.root.join("explicit-configuration-backup");
    std::fs::rename(&config_path, &saved)?;
    let missing_config = ManagedInstance::start(case.settings.clone()).await;
    assert!(
        matches!(
            missing_config,
            Err(verysync_sidecar::Error::ManagedFailure { .. })
        ),
        "{missing_config:?}"
    );
    wait_no_processes(&case.binary).await?;
    assert!(!config_path.exists());
    assert_eq!(private_identity(&case.state)?, identity);
    assert_eq!(std::fs::read(&saved)?, original_config);
    std::fs::rename(&saved, &config_path)?;
    #[cfg(unix)]
    {
        let original = case.root.join("original-test-configuration");
        std::fs::rename(&config_path, &original)?;
        assert!(Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&config_path)
            .status()?
            .success());
        let special = tokio::time::timeout(
            Duration::from_secs(5),
            ManagedInstance::start(case.settings.clone()),
        )
        .await?;
        assert!(
            matches!(special, Err(verysync_sidecar::Error::LocalIo { .. })),
            "{special:?}"
        );
        wait_no_processes(&case.binary).await?;
        assert_eq!(std::fs::read(&original)?, original_config);
        std::fs::remove_file(&config_path)?;
        std::fs::rename(&original, &config_path)?;
    }
    let backup = case.root.join("explicit-identity-backup");
    std::fs::create_dir(&backup)?;
    let names = [
        "key.pem",
        "cert.pem",
        ".verysync-sidecar-identity",
        ".verysync-sidecar-configured",
    ];
    for name in names {
        std::fs::rename(case.state.join(name), backup.join(name))?;
    }
    let orphaned = ManagedInstance::start(case.settings.clone()).await;
    assert!(
        matches!(
            orphaned,
            Err(verysync_sidecar::Error::ManagedFailure { .. })
        ),
        "{orphaned:?}"
    );
    wait_no_processes(&case.binary).await?;
    assert_eq!(std::fs::read(&config_path)?, original_config);
    for name in names {
        assert!(!case.state.join(name).exists());
        std::fs::rename(backup.join(name), case.state.join(name))?;
    }
    assert_eq!(private_identity(&case.state)?, identity);
    std::fs::write(&config_path, b"synthetic invalid MessagePack configuration")?;
    let malformed = ManagedInstance::start(case.settings.clone()).await;
    assert!(
        matches!(
            malformed,
            Err(verysync_sidecar::Error::ManagedFailure { .. })
        ),
        "{malformed:?}"
    );
    wait_no_processes(&case.binary).await?;
    assert_eq!(
        std::fs::read(&config_path)?,
        b"synthetic invalid MessagePack configuration"
    );
    assert_eq!(private_identity(&case.state)?, identity);
    assert_eq!(Sha256::digest(std::fs::read(&sample)?), sample_sha);
    std::fs::write(&config_path, original_config)?;
    let mut restored = start_checked(case.settings.clone()).await?;
    assert_eq!(private_identity(&case.state)?, identity);
    assert!(inventory(&case.binary)
        .await?
        .contains(&restored.process_id()));
    restored.shutdown(Duration::from_secs(10)).await?;
    case.cleanup().await?;
    #[cfg(unix)]
    println!("public private resource admission evidence: {{\"certificate_alias_rejected\":true,\"external_synthetic_target_unchanged\":true,\"link_preserved_for_explicit_repair\":true,\"fifo_configuration_rejected_without_blocking\":true}}");
    println!("public partial startup state evidence: {{\"missing_certificate_not_regenerated\":true,\"missing_configuration_not_regenerated\":true,\"orphan_configuration_not_reset\":true,\"missing_identity_not_regenerated_over_configuration\":true,\"private_key_identity_retained\":true,\"malformed_config_not_reset\":true,\"sample_sha_unchanged\":true,\"explicit_repair_same_identity_ready\":true,\"independent_process_cleanup\":true}}");
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn cancelled_start_dangling_control_links_are_not_fresh_state() -> TestResult {
    for (index, name) in [
        "verysync.lock",
        "setting.dat",
        "key.pem",
        "cert.pem",
        ".verysync-sidecar-identity",
        ".verysync-sidecar-configured",
    ]
    .iter()
    .enumerate()
    {
        let mut case = StartupCase::blocked()?;
        case.unblock();
        // Public checksum rejection admits a new private state but executes no
        // helper or identity generation. This models an interrupted early start.
        let seed = ManagedOptions::new(
            LocalProgram::new(&case.binary)?.expected_sha256([0; 32]),
            &case.state,
            case.settings.management_endpoint().clone(),
        )?;
        assert!(matches!(
            ManagedInstance::start(seed).await,
            Err(verysync_sidecar::Error::ProgramRejected { .. })
        ));
        wait_state_available(&case.state).await?;
        let sample = case.state.join("retained.bin");
        std::fs::write(&sample, b"synthetic cold-state sample")?;
        let target = case.root.join("must-not-be-created");
        let alias = case.state.join(name);
        std::os::unix::fs::symlink(&target, &alias)?;
        let result = ManagedInstance::start(case.settings.clone()).await;
        let kind = match result {
            Err(verysync_sidecar::Error::LocalIo { .. }) => "local_io",
            Err(_) => "other_error",
            Ok(mut instance) => {
                instance.force_stop(Duration::from_secs(10)).await?;
                "accepted"
            }
        };
        wait_no_processes(&case.binary).await?;
        println!(
            "private cold-link control: name={name} result={kind} target_created={} key_created={}",
            target.exists(),
            case.state.join("key.pem").is_file()
        );
        assert_eq!(kind, "local_io");
        assert!(!target.exists());
        for resource in ["key.pem", "cert.pem", ".verysync-sidecar-identity"] {
            assert!(!case.state.join(resource).is_file());
        }
        assert!(std::fs::symlink_metadata(&alias)?.file_type().is_symlink());
        assert_eq!(std::fs::read(&sample)?, b"synthetic cold-state sample");
        std::fs::remove_file(&alias)?;
        if index == 0 {
            let mut repaired = start_checked(case.settings.clone()).await?;
            assert!(inventory(&case.binary)
                .await?
                .contains(&repaired.process_id()));
            assert_eq!(std::fs::read(&sample)?, b"synthetic cold-state sample");
            repaired.shutdown(Duration::from_secs(10)).await?;
        }
        case.cleanup().await?;
    }
    println!("public dangling private resource evidence: {{\"six_control_aliases_exercised\":true,\"typed_rejection_before_generation\":true,\"external_synthetic_targets_not_created\":true,\"identity_not_regenerated\":true,\"sample_unchanged\":true,\"explicit_repair_ready\":true,\"independent_process_exit\":true}}");
    Ok(())
}
