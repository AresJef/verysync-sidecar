//! Synthetic server-key observations in a fresh test subprocess, never host trust.
use super::{execute, options, storage_service, TestResult};
use std::{
    fs::File,
    io::Write,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};
use verysync_sidecar::{
    CreateLocalSyncJob, Error, LocalSyncMode, ManagedInstance, StorageEndpoint, StorageProtocol,
    TargetPath,
};

const WORKER: &str = "VERYSYNC_SYNTHETIC_SFTP_IDENTITY_WORKER";
const TEST: &str = "public_sftp_server_identity_reports_actual_wrong_and_matching_host_policies";
const RECEIPT: &str = "public SFTP server identity boundary evidence: ";

fn public_key(path: &Path) -> TestResult<String> {
    let python = std::env::var_os("VERYSYNC_STORAGE_TEST_PYTHON")
        .ok_or("explicit private peer interpreter required")?;
    let output = Command::new(python)
        .args(["-c", "import paramiko,sys; k=paramiko.RSAKey.from_private_key_file(sys.argv[1]); print(k.get_name()+' '+k.get_base64())"])
        .arg(path)
        .output()?;
    if !output.status.success() || output.stdout.len() > 8192 {
        return Err("synthetic public-key extraction failed".into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn native_outcome<T>(result: &verysync_sidecar::Result<T>) -> TestResult<serde_json::Value> {
    let Err(mut error) = result.as_ref() else {
        return Ok(serde_json::json!({"accepted":true}));
    };
    while let Error::MutationOutcomeUnknown { source, .. } = error {
        error = source.as_ref();
    }
    let response = match error {
        Error::Api { response, .. }
        | Error::Http { response }
        | Error::InvalidResponse { response, .. } => response,
        _ => return Err("server-key observation did not receive an actual native response".into()),
    };
    // The private peer uses synthetic credentials. Retain the native response,
    // without interpreting an arbitrary HTTP refusal as verified SSH identity.
    Ok(
        serde_json::json!({"accepted":false,"status":response.status(),
        "native_body":String::from_utf8_lossy(response.body_bytes()),
        "verified_host_identity_claimed":false}),
    )
}

async fn worker(root: &Path) -> TestResult {
    let known = root.join("explicit-known-hosts");
    if !root.is_absolute()
        || std::fs::read(root.join("owned-worker-marker"))? != b"owned synthetic SFTP worker"
        || std::env::var_os("RCLONE_SFTP_KNOWN_HOSTS_FILE").as_deref() != Some(known.as_os_str())
        || known.exists()
    {
        return Err("explicit fresh owned worker and trust-file path required".into());
    }
    let mut peer = storage_service::Service::start(StorageProtocol::Sftp, root, Duration::ZERO)?;
    let result = async {
        let wrong = public_key(&root.join("synthetic-client-key.pem"))?;
        let matching = public_key(&root.join("synthetic-host-key.pem"))?;
        assert_ne!(wrong, matching);
        let endpoint = peer.endpoint.clone().insecure_tls(false)?;
        std::fs::write(
            peer.share.join("sentinel.bin"),
            b"retained destination-only bytes",
        )?;
        let mut records = Vec::new();
        let mut identities = Vec::new();
        for (kind, key, fill) in [("wrong", wrong, 0x35), ("matching", matching, 0xa1)] {
            let policy = format!("* {key}\n");
            std::fs::write(&known, &policy)?;
            let state = root.join(format!("state-{kind}"));
            let mut core = ManagedInstance::start(
                options(&state)?.management_request_timeout(Duration::from_secs(30))?,
            )
            .await?;
            let identity = core.client().instance().device_id.clone();
            assert!(
                !identities.contains(&identity),
                "separate owned states reused an identity"
            );
            identities.push(identity.clone());
            let effect = async {
                // ManagedInstance creates this owned profile. Populate only its
                // disposable trust candidate before the first SFTP connection.
                let profile = state.join("profile").join(".ssh");
                std::fs::create_dir_all(&profile)?;
                std::fs::write(profile.join("known_hosts"), &policy)?;
                let probe = core.client().probe_storage_endpoint(&endpoint).await;
                let browse = core.client().browse_storage_endpoint(&endpoint, "").await;
                let probe_outcome = native_outcome(&probe)?;
                let browse_outcome = native_outcome(&browse)?;
                if kind == "matching" {
                    assert!(probe.is_ok(), "matching synthetic policy probe failed");
                    assert!(browse.is_ok(), "matching synthetic policy browse failed");
                }
                let mut copied = false;
                if browse.is_ok() {
                    let source = root.join(format!("source-{kind}"));
                    std::fs::create_dir(&source)?;
                    let name = format!("{kind} 中文 %.bin");
                    let payload = vec![fill; 128 * 1024 + 43];
                    std::fs::write(source.join(&name), &payload)?;
                    let job = core
                        .client()
                        .create_local_sync_job(
                            &CreateLocalSyncJob::new(
                                format!("synthetic {kind} host policy"),
                                StorageEndpoint::local(TargetPath::local(&source))?,
                                endpoint.clone(),
                                LocalSyncMode::MirrorAToB,
                            )?
                            .ignore_permissions(true),
                        )
                        .await?;
                    execute(&core, &job.job_id).await?;
                    assert_eq!(std::fs::read(peer.share.join(&name))?, payload);
                    assert_eq!(std::fs::read(source.join(&name))?, payload);
                    core.client().delete_local_sync_job(&job.job_id).await?;
                    assert_eq!(std::fs::read(peer.share.join(&name))?, payload);
                    copied = true;
                }
                assert_eq!(
                    std::fs::read(peer.share.join("sentinel.bin"))?,
                    b"retained destination-only bytes"
                );
                assert_eq!(std::fs::read(&known)?, policy.as_bytes());
                assert_eq!(
                    std::fs::read(profile.join("known_hosts"))?,
                    policy.as_bytes()
                );
                assert_eq!(core.client().system_status().await?.device_id, identity);
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(serde_json::json!({
                    "policy":kind,"probe":probe_outcome,"browse":browse_outcome,
                    "actual_copy_and_all_bytes":copied,"unregister_preserves_files":copied,
                    "target_only_sentinel_retained":true,"identity_retained":true,
                    "both_owned_trust_candidates_unchanged":true,
                    "verified_server_identity_claimed":false
                }))
            }
            .await;
            let exit = core.shutdown(Duration::from_secs(15)).await?;
            assert_eq!(exit.code, Some(0));
            assert!(!exit.forced && exit.tree_stopped && exit.state_released);
            let mut record = effect?;
            record["normal_tree_and_state_exit"] = true.into();
            records.push(record);
        }
        assert_eq!(identities.len(), 2);
        std::fs::remove_file(&known)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(records)
    }
    .await;
    peer.stop()?;
    let records = result?;
    println!(
        "{RECEIPT}{}",
        serde_json::json!({"records":records,
        "only_fresh_test_subprocess_environment":true,"two_fresh_owned_generations":true,
        "two_distinct_native_device_identities":true,
        "distinct_synthetic_keys":true,"insecure_tls_false":true,"system_trust_unchanged":true,
        "explicit_trust_file_removed":!known.exists(),"peer_stopped":true,
        "verified_server_identity_claimed":false})
    );
    Ok(())
}

pub async fn run() -> TestResult {
    if let Some(root) = std::env::var_os(WORKER) {
        return worker(Path::new(&root)).await;
    }
    let root = tempfile::Builder::new()
        .prefix("vs-sftp-host-")
        .tempdir()?
        .keep();
    std::fs::write(
        root.join("owned-worker-marker"),
        b"owned synthetic SFTP worker",
    )?;
    // Set policy only on a new child. Never mutate this process's environment,
    // the controller's SSH files, or the environment of unrelated tests.
    let stdout_path = root.join("worker.stdout.log");
    let stderr_path = root.join("worker.stderr.log");
    let mut child = Command::new(std::env::current_exe()?)
        .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
        .env(WORKER, &root)
        .env(
            "RCLONE_SFTP_KNOWN_HOSTS_FILE",
            root.join("explicit-known-hosts"),
        )
        .stdout(File::create(&stdout_path)?)
        .stderr(File::create(&stderr_path)?)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err(
                "owned SFTP identity worker exceeded its explicit 120-second deadline".into(),
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    for path in [&stdout_path, &stderr_path] {
        if std::fs::metadata(path)?.len() > 1024 * 1024 {
            return Err("owned SFTP worker diagnostic output exceeded its bound".into());
        }
    }
    let stdout = std::fs::read_to_string(&stdout_path)?;
    std::io::stdout().write_all(stdout.as_bytes())?;
    std::io::stderr().write_all(&std::fs::read(&stderr_path)?)?;
    assert!(status.success(), "owned SFTP identity worker failed");
    let receipts: Vec<_> = stdout
        .lines()
        .filter_map(|line| {
            line.find(RECEIPT)
                .map(|offset| &line[offset + RECEIPT.len()..])
        })
        .collect();
    assert_eq!(
        receipts.len(),
        1,
        "exactly one actual native receipt required"
    );
    let receipt: serde_json::Value = serde_json::from_str(receipts[0])?;
    assert_eq!(
        receipt["records"].as_array().ok_or("records absent")?.len(),
        2
    );
    assert_eq!(receipt["peer_stopped"], true);
    assert_eq!(receipt["explicit_trust_file_removed"], true);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
