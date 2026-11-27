//! Native same-attempt upgrade witnesses. Requests use task-owned loopback peers.
use super::{baseline_asset, bounded_request_head, exact_program_pids, options, upgrade_source};
use crate::TestResult;
use sha2::{Digest, Sha256};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use verysync_sidecar::{
    ApiKey, ConnectOptions, Error, KernelUpgradeCommand, LocalProgram, ManagedInstance,
    ManagedOptions, ManagementEndpoint, UpgradeDispatch, UpgradeOutcome, UpgradeProgramMatch,
    UpgradeProgramUncertainty, UpgradeReceipt, VersionPolicy,
};

async fn owned_old(
    root: &Path,
    tcp: bool,
) -> TestResult<(ManagedInstance, ManagedOptions, PathBuf)> {
    let source = upgrade_source()?;
    let program = root.join(
        source
            .path()
            .file_name()
            .ok_or("old executable basename missing")?,
    );
    std::fs::copy(source.path(), &program)?;
    let previous = hash(source.path())?;
    assert_eq!(hash(&program)?, previous);
    let base = options(&root.join("c"))?;
    let endpoint = if tcp {
        let reserved = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        ManagementEndpoint::http(&format!("http://{}/", reserved.local_addr()?))?
    } else {
        base.management_endpoint().clone()
    };
    let config = ManagedOptions::new(
        LocalProgram::new(&program)?.expected_sha256(previous),
        base.state_directory(),
        endpoint,
    )?
    .version_policy(VersionPolicy::AllowUnverified);
    let core = ManagedInstance::start(config.clone()).await?;
    assert_eq!(core.program_info().version, "v2.33.1");
    Ok((core, config, program))
}

fn hash(path: &Path) -> TestResult<[u8; 32]> {
    let mut hasher = Sha256::new();
    io::copy(&mut std::fs::File::open(path)?, &mut hasher)?;
    Ok(hasher.finalize().into())
}

fn hex(hash: [u8; 32]) -> String {
    hash.into_iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now() -> TestResult<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .try_into()?)
}

fn receipt_event(name: &str, stage: &str, detail: serde_json::Value) -> TestResult {
    println!(
        "s29-upgrade {}",
        serde_json::json!({
            "case": name, "stage": stage, "unix_ns": now()?, "pid": std::process::id(),
            "detail": detail
        })
    );
    Ok(())
}

fn pinned_program() -> TestResult<PathBuf> {
    let value =
        PathBuf::from(std::env::var_os("VERYSYNC_TEST_BINARY").ok_or("fixed engine missing")?);
    let actual = hex(hash(&value)?);
    assert_eq!(actual, std::env::var("VERYSYNC_TEST_BINARY_SHA256")?);
    Ok(value)
}

fn original_receipt(name: &str, receipt: &UpgradeReceipt, error: &Error) -> TestResult {
    use std::error::Error as _;
    assert_eq!(receipt.outcome(), UpgradeOutcome::Unknown);
    receipt_event(
        name,
        "original-receipt",
        serde_json::json!({
            "receipt": receipt,
            "top": format!("{error}"), "origin": error.source().map(ToString::to_string),
        }),
    )
}

// Libtest's listing mode runs no tests and creates no engine state. It gives
// the external observer a real short-lived child on both sides of the window.
fn calibrate_process_creation(name: &str, stage: &str) -> TestResult {
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .arg("--list")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let id = child.id();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait()? {
            assert!(status.success(), "libtest list mode failed");
            return receipt_event(name, stage, serde_json::json!({"pid": id}));
        }
        if std::time::Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("the isolated calibration child exceeded its deadline".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

async fn verify_comparison(
    name: &str,
    core: &ManagedInstance,
    receipt: &UpgradeReceipt,
    program: &Path,
    expected: UpgradeProgramMatch,
    digest: [u8; 32],
    requests: &AtomicUsize,
) -> TestResult {
    let data = program.with_file_name("retained-s29.txt");
    let configuration = core.state_directory().join("setting.dat");
    let before = (hash(&data)?, hash(&configuration)?);
    assert_eq!(hash(program)?, digest);
    assert_eq!(receipt.outcome(), UpgradeOutcome::Unknown);
    let seen = requests.load(Ordering::SeqCst);
    calibrate_process_creation(name, "calibration-child")?;
    receipt_event(
        name,
        "begin-recovery",
        serde_json::json!({
            "operation_id": receipt.operation_id(), "requests_seen": seen
        }),
    )?;
    let result = core
        .observe_upgrade_program(receipt, Duration::from_secs(8))
        .await?;
    receipt_event(
        name,
        "end-recovery",
        serde_json::json!({
            "operation_id": result.operation_id,
            "comparison": format!("{:?}", result.comparison),
            "original_outcome": format!("{:?}", result.original_outcome),
            "sdk_sha256": result.current_sha256.map(hex), "true_sha256": hex(digest),
            "requests_seen": requests.load(Ordering::SeqCst)
        }),
    )?;
    calibrate_process_creation(name, "calibration-after")?;
    assert_eq!(result.comparison, expected, "{:?}", result.source);
    assert_eq!(result.original_outcome, UpgradeOutcome::Unknown);
    assert_eq!(result.operation_id, receipt.operation_id());
    assert_eq!(result.current_sha256, Some(digest));
    assert_eq!(hash(program)?, digest);
    assert_eq!((hash(&data)?, hash(&configuration)?), before);
    assert_eq!(requests.load(Ordering::SeqCst), seen);
    Ok(())
}

#[tokio::test]
async fn native_same_attempt_observes_previous_after_partial_cli_archive() -> TestResult {
    let root = tempfile::Builder::new().prefix("u2c").tempdir()?;
    let (mut core, settings, program) = owned_old(root.path(), false).await?;
    let identity = core.client().instance().device_id.clone();
    let old = hash(&program)?;
    let fixed = pinned_program()?;
    let target = hash(&fixed)?;
    let asset = baseline_asset()?;
    std::fs::write(
        program.with_file_name("retained-s29.txt"),
        b"s29 synthetic old sample",
    )?;
    let premature = core
        .run_cli_upgrade_with_receipt(KernelUpgradeCommand::Provider, Duration::from_secs(1))
        .await?;
    assert_eq!(premature.receipt.outcome(), UpgradeOutcome::NotSubmitted);
    assert_eq!(premature.receipt.dispatch(), UpgradeDispatch::Preparing);
    assert!(matches!(
        premature.result,
        Err(Error::ManagedFailure { .. })
    ));
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));

    let file =
        std::fs::read(std::env::var_os("VERYSYNC_TEST_ARCHIVE").ok_or("fixed archive missing")?)?;
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&file)),
        asset.archive_sha256()
    );
    let archive = asset.archive_filename().to_owned();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = url::Url::parse(&format!("http://{}/{}", listener.local_addr()?, archive))?;
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        assert!(bounded_request_head(&mut stream)
            .await?
            .starts_with(&format!("GET /{archive} ")));
        counted.fetch_add(1, Ordering::SeqCst);
        receipt_event(
            "cli-partial",
            "archive-get",
            serde_json::json!({"partial_bytes":65536}),
        )?;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                    file.len()
                )
                .as_bytes(),
            )
            .await?;
        stream.write_all(&file[..65536]).await?;
        let mut byte = [0];
        match stream.read(&mut byte).await {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) => {}
            other => {
                return Err(format!(
                    "expected the original partial archive stream to close: {other:?}"
                )
                .into())
            }
        }
        receipt_event(
            "cli-partial",
            "archive-closed",
            serde_json::json!({"complete": false}),
        )?;
        // Continue to observe the same URL until after the recovery window.
        loop {
            let (mut next, _) = listener.accept().await?;
            counted.fetch_add(1, Ordering::SeqCst);
            let _ = next.shutdown().await;
        }
        #[allow(unreachable_code)]
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    receipt_event(
        "cli-partial",
        "before-dispatch",
        serde_json::json!({"old_sha256":hex(old), "target_sha256":hex(target), "owned_device":identity}),
    )?;
    let attempt = core
        .run_cli_upgrade_with_target_receipt(
            KernelUpgradeCommand::FromUrl(url),
            &asset,
            Duration::from_secs(25),
        )
        .await?;
    let error = attempt
        .result
        .expect_err("partial archive unexpectedly produced CLI completion");
    assert!(
        matches!(error, Error::MutationOutcomeUnknown { .. }),
        "expected a contained modifying CLI timeout: error={error:?}, receipt={:?}",
        attempt.receipt
    );
    assert_eq!(attempt.receipt.dispatch(), UpgradeDispatch::CliStarted);
    assert_eq!(attempt.receipt.previous_program_sha256(), Some(old));
    assert_eq!(attempt.receipt.target_program_sha256(), Some(target));
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    original_receipt("cli-partial", &attempt.receipt, &error)?;
    verify_comparison(
        "cli-partial",
        &core,
        &attempt.receipt,
        &program,
        UpgradeProgramMatch::Previous,
        old,
        &requests,
    )
    .await?;
    assert!(exact_program_pids(&program).await?.is_empty());

    // Deliberate negative changes are confined to this fixture after the
    // original case. The original receipt is reused without any upgrade call.
    drop(std::fs::File::open(&program)?);
    let saved = program.with_file_name("original-s29-program");
    std::fs::rename(&program, &saved)?;
    for (present, expected) in [
        (
            false,
            UpgradeProgramMatch::Unconfirmed(UpgradeProgramUncertainty::FileUnverified),
        ),
        (true, UpgradeProgramMatch::Other),
    ] {
        if present {
            std::fs::write(&program, b"synthetic third program content")?;
        }
        let observed = core
            .observe_upgrade_program(&attempt.receipt, Duration::from_secs(5))
            .await?;
        assert_eq!(observed.comparison, expected);
        receipt_event(
            "cli-partial",
            "unconfirmed-control",
            serde_json::json!({
                "present":present, "comparison":format!("{:?}", observed.comparison), "operation_id":observed.operation_id
            }),
        )?;
    }
    std::fs::remove_file(&program)?;
    std::fs::rename(saved, &program)?;
    core.restart(Duration::from_secs(25)).await?;
    assert_eq!(core.client().instance().device_id, identity);
    let changed = core
        .observe_upgrade_program(&attempt.receipt, Duration::from_secs(1))
        .await?;
    assert_eq!(
        changed.comparison,
        UpgradeProgramMatch::Unconfirmed(UpgradeProgramUncertainty::OwnerChanged)
    );
    receipt_event(
        "cli-partial",
        "changed-owner-control",
        serde_json::json!({"rejected":true}),
    )?;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    assert!(exact_program_pids(&program).await?.is_empty());
    assert_eq!(hash(&program)?, old);
    assert_eq!(
        std::fs::canonicalize(core.state_directory())?,
        std::fs::canonicalize(settings.state_directory())?
    );
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    server.abort();
    assert!(server.await.is_err_and(|e| e.is_cancelled()));
    root.close()?;
    receipt_event(
        "cli-partial",
        "cleanup",
        serde_json::json!({"removed":true,"owned_program_pids":0}),
    )
}

async fn forwards_until_native_upload_reply(
    mut client: TcpStream,
    native: SocketAddr,
    seen: Arc<AtomicUsize>,
) -> TestResult {
    let head = bounded_request_head(&mut client).await?;
    let method = head
        .lines()
        .next()
        .ok_or("missing private witness request")?;
    let upload = method.starts_with("POST /rest/system/upgrade/upload ");
    let upgrade_route = method
        .split_whitespace()
        .nth(1)
        .is_some_and(|path| path.starts_with("/rest/system/upgrade"));
    if upgrade_route {
        let previous = seen.fetch_add(1, Ordering::SeqCst);
        assert_eq!(previous, 0, "only one upgrade request is allowed");
        assert!(
            upload,
            "the original fixture only dispatches a fixed archive"
        );
    }
    assert!(upload || method.starts_with("GET "));
    let mut upstream = TcpStream::connect(native).await?;
    let rewritten = head
        .lines()
        .filter(|line| !line.is_empty() && !line.to_ascii_lowercase().starts_with("connection:"))
        .collect::<Vec<_>>()
        .join("\r\n")
        + "\r\nConnection: close\r\n\r\n";
    upstream.write_all(rewritten.as_bytes()).await?;
    if !upload {
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        return Ok(());
    }
    let length: u64 = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim())
        })
        .ok_or("missing fixed upload length")?
        .parse()?;
    assert!((1..=128 * 1024 * 1024).contains(&length));
    let transferred = tokio::io::copy(&mut (&mut client).take(length), &mut upstream).await?;
    assert_eq!(transferred, length);
    let mut reply = Vec::new();
    upstream.take(65537).read_to_end(&mut reply).await?;
    assert!(!reply.is_empty() && reply.len() <= 65536);
    let http = std::str::from_utf8(&reply)?;
    assert!(http.starts_with("HTTP/1.1 200 ") && http.contains("restarting"));
    receipt_event(
        "upload-drop",
        "native-response-withheld",
        serde_json::json!({
            "upstream_status":200, "forwarded_body_bytes":transferred, "downstream_bytes":0,
            "native_response_sha256":hex(Sha256::digest(&reply).into())
        }),
    )?;
    client.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn native_same_attempt_observes_replacement_after_upload_reply_loss() -> TestResult {
    let root = tempfile::Builder::new().prefix("u2h").tempdir()?;
    let (mut core, settings, program) = owned_old(root.path(), true).await?;
    let real_endpoint = settings
        .management_endpoint()
        .http_url()
        .ok_or("TCP endpoint missing")?;
    let native: SocketAddr = format!(
        "127.0.0.1:{}",
        real_endpoint.port().ok_or("private port missing")?
    )
    .parse()?;
    let old = hash(&program)?;
    let target = hash(&pinned_program()?)?;
    let asset = baseline_asset()?;
    let archive =
        PathBuf::from(std::env::var_os("VERYSYNC_TEST_ARCHIVE").ok_or("fixed archive missing")?);
    let identity = core.client().instance().device_id.clone();
    std::fs::write(
        program.with_file_name("retained-s29.txt"),
        b"s29 synthetic replacement sample",
    )?;
    let data = std::fs::read(settings.state_directory().join("setting.dat"))?;
    let parsed = rmpv::decode::read_value(&mut std::io::Cursor::new(data))?;
    let key = ApiKey::new(
        parsed["4"]["6"]
            .as_str()
            .ok_or("private fixture credential missing")?,
    )?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy = ManagementEndpoint::http(&format!("http://{}/", listener.local_addr()?))?;
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    let mut server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await?;
            forwards_until_native_upload_reply(stream, native, counted.clone()).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    core.reconnect_management(
        ConnectOptions::new(proxy, key)
            .version_policy(VersionPolicy::AllowUnverified)
            .expected_device_id(identity.clone())
            .request_timeout(Duration::from_secs(30))?,
    )
    .await?;
    receipt_event(
        "upload-drop",
        "before-dispatch",
        serde_json::json!({"old_sha256":hex(old), "target_sha256":hex(target), "owned_device":identity}),
    )?;
    let pending =
        core.upload_kernel_upgrade_with_target_receipt(archive, &asset, Duration::from_secs(30));
    let attempt = tokio::select! {
        result = pending => result?,
        end = &mut server => { end??; return Err("private witness stopped before caller returned".into()); }
    };
    let error = attempt
        .result
        .expect_err("caller unexpectedly received the native acknowledgement");
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    assert_eq!(
        attempt.receipt.dispatch(),
        UpgradeDispatch::Http {
            status: None,
            complete: false
        }
    );
    assert_eq!(attempt.receipt.previous_program_sha256(), Some(old));
    assert_eq!(attempt.receipt.target_program_sha256(), Some(target));
    original_receipt("upload-drop", &attempt.receipt, &error)?;
    let exit = tokio::time::timeout(Duration::from_secs(20), core.wait_for_exit()).await??;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced);
    receipt_event(
        "upload-drop",
        "original-native-exit",
        serde_json::json!({"code":exit.code,"tree_stopped":exit.tree_stopped,"state_released":exit.state_released}),
    )?;
    assert!(exact_program_pids(&program).await?.is_empty());
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    verify_comparison(
        "upload-drop",
        &core,
        &attempt.receipt,
        &program,
        UpgradeProgramMatch::Target,
        target,
        &requests,
    )
    .await?;
    drop(core);
    let mut updated = ManagedInstance::start(ManagedOptions::new(
        LocalProgram::new(&program)?.expected_sha256(target),
        settings.state_directory(),
        settings.management_endpoint().clone(),
    )?)
    .await?;
    assert_eq!(updated.program_info().version, "v2.33.2");
    assert_eq!(updated.client().instance().device_id, identity);
    let exit = updated.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    assert!(exact_program_pids(&program).await?.is_empty());
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    server.abort();
    assert!(server.await.is_err_and(|e| e.is_cancelled()));
    root.close()?;
    receipt_event(
        "upload-drop",
        "cleanup",
        serde_json::json!({"removed":true,"owned_program_pids":0}),
    )
}

#[tokio::test]
async fn stopped_cli_blocked_check_preserves_actual_nonzero_exit_with_no_installation() -> TestResult
{
    let root = tempfile::Builder::new().prefix("u1c").tempdir()?;
    let (mut core, settings, program) = owned_old(root.path(), false).await?;
    let digest = hash(&program)?;
    let original = core.client().instance().device_id.clone();
    let ended = core.shutdown(Duration::from_secs(10)).await?;
    assert!(ended.tree_stopped && ended.state_released && !ended.forced && ended.code == Some(0));
    let before = hash(&settings.state_directory().join("setting.dat"))?;
    let attempt = core
        .run_cli_upgrade_with_receipt(KernelUpgradeCommand::Check, Duration::from_secs(20))
        .await?;
    let exit = attempt.result?;
    assert_eq!(exit.code, Some(1));
    assert!(!exit.release_unavailable);
    assert_eq!(attempt.receipt.outcome(), UpgradeOutcome::QueryFailed);
    assert_eq!(
        attempt.receipt.dispatch(),
        UpgradeDispatch::CliExited {
            code: Some(1),
            tree_stopped: true
        }
    );
    assert_eq!(attempt.receipt.previous_program_sha256(), Some(digest));
    assert_eq!(hash(&program)?, digest);
    assert_eq!(
        hash(&settings.state_directory().join("setting.dat"))?,
        before
    );
    let refused = core
        .run_cli_upgrade_with_receipt(KernelUpgradeCommand::Provider, Duration::from_secs(3))
        .await?;
    assert_eq!(refused.receipt.outcome(), UpgradeOutcome::NotSubmitted);
    assert!(matches!(refused.result, Err(Error::ManagedFailure { .. })));
    receipt_event(
        "blocked-cli-check",
        "receipt",
        serde_json::json!({
            "check":attempt.receipt, "provider_after_check":refused.receipt,
            "check_empty_selection": String::from_utf8_lossy(exit.diagnostic.body_bytes()).contains("no version to select"),
            "program_and_configuration_unchanged":true, "no_retry_after_lost_backup_eligibility":true
        }),
    )?;
    core.restart(Duration::from_secs(25)).await?;
    assert_eq!(core.client().instance().device_id, original);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    assert!(exact_program_pids(&program).await?.is_empty());
    root.close()?;
    receipt_event(
        "blocked-cli-check",
        "cleanup",
        serde_json::json!({"removed":true,"owned_program_pids":0}),
    )
}
