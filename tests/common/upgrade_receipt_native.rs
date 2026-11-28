//! Native same-attempt upgrade witnesses. Requests use task-owned loopback peers.
use super::{baseline_asset, bounded_request_head, exact_program_pids, options, upgrade_source};
use crate::TestResult;
use sha2::{Digest, Sha256};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, CreateFolderOptions, Error, FolderId,
    KernelInstallationOutcome, KernelReadinessOutcome, KernelUpgradeCommand, LocalProgram,
    ManagedInstance, ManagedOptions, ManagementEndpoint, OperationOptions, TargetPath,
    UpgradeCheckpointStage, UpgradeDispatch, UpgradeOutcome, UpgradeProgramMatch,
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
    .version_policy(VersionPolicy::AllowUnverified)
    .with_transient_read_retries();
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
        "{}-upgrade {}",
        if name.starts_with("s30-") {
            "s30"
        } else {
            "s29"
        },
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

// The fixture brackets real calls with a separate process that reads native
// accounting. No environment switch affects the candidate SDK operation.
async fn process_observer_barrier(case: &str, phase: &str) -> TestResult {
    let Some(root) = std::env::var_os("VERYSYNC_S29_PHASE_DIR").map(PathBuf::from) else {
        return Ok(());
    };
    tokio::time::timeout(Duration::from_secs(12), async {
        while !root.join("attached").is_file() {
            if root.join("unavailable").is_file() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let stem = root.join(format!("{case}-{phase}"));
        std::fs::File::create_new(stem.with_extension("request"))?;
        while !stem.with_extension("response").is_file() {
            if root.join("unavailable").is_file() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

async fn await_process_observer() -> TestResult {
    let Some(root) = std::env::var_os("VERYSYNC_S29_PHASE_DIR").map(PathBuf::from) else {
        return Ok(());
    };
    tokio::time::timeout(Duration::from_secs(12), async {
        while !root.join("attached").is_file() && !root.join("unavailable").is_file() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    Ok(())
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
    process_observer_barrier(name, "before-control").await?;
    calibrate_process_creation(name, "calibration-child")?;
    process_observer_barrier(name, "begin").await?;
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
    process_observer_barrier(name, "end").await?;
    calibrate_process_creation(name, "calibration-after")?;
    process_observer_barrier(name, "after-control").await?;
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
    await_process_observer().await?;
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

    let locked = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(core.state_directory().join(".verysync-sidecar-lease"))?;
    fs2::FileExt::try_lock_exclusive(&locked)?;
    let busy = core
        .observe_upgrade_program(&attempt.receipt, Duration::from_secs(2))
        .await?;
    assert_eq!(
        busy.comparison,
        UpgradeProgramMatch::Unconfirmed(UpgradeProgramUncertainty::WriterNotFinished)
    );
    fs2::FileExt::unlock(&locked)?;
    drop(locked);
    receipt_event(
        "cli-partial",
        "busy-writer-control",
        serde_json::json!({"rejected":true}),
    )?;
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
    forward_native_management(client, native, head, upload, "upload-drop").await
}

async fn forward_native_management(
    mut client: TcpStream,
    native: SocketAddr,
    head: String,
    upload: bool,
    case: &str,
) -> TestResult {
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
    let length = fixed_upload_length(&head)?;
    let transferred = tokio::io::copy(&mut (&mut client).take(length), &mut upstream).await?;
    assert_eq!(transferred, length);
    let mut reply = Vec::new();
    upstream.take(65537).read_to_end(&mut reply).await?;
    assert!(!reply.is_empty() && reply.len() <= 65536);
    let http = std::str::from_utf8(&reply)?;
    assert!(http.starts_with("HTTP/1.1 200 ") && http.contains("restarting"));
    receipt_event(
        case,
        "native-response-withheld",
        serde_json::json!({
            "upstream_status":200, "forwarded_body_bytes":transferred, "downstream_bytes":0,
            "native_response_sha256":hex(Sha256::digest(&reply).into())
        }),
    )?;
    client.shutdown().await?;
    Ok(())
}

fn fixed_upload_length(head: &str) -> TestResult<u64> {
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim())
        })
        .ok_or("missing fixed upload length")?
        .parse()?;
    assert!((1..=128 * 1024 * 1024).contains(&length));
    Ok(length)
}

#[tokio::test]
async fn native_business_install_reports_verified_target_after_lost_reply() -> TestResult {
    await_process_observer().await?;
    let root = tempfile::Builder::new().prefix("u30h").tempdir()?;
    let (mut core, settings, program) = owned_old(root.path(), true).await?;
    let native = settings
        .management_endpoint()
        .http_url()
        .and_then(|value| value.port())
        .map(|p| SocketAddr::from((Ipv4Addr::LOCALHOST, p)))
        .ok_or("private native port missing")?;
    let old = hash(&program)?;
    let target = hash(&pinned_program()?)?;
    let asset = baseline_asset()?;
    let archive =
        PathBuf::from(std::env::var_os("VERYSYNC_TEST_ARCHIVE").ok_or("fixed archive missing")?);
    let identity = core.client().instance().device_id.clone();
    let sample = root.path().join("s30-retained.txt");
    std::fs::write(
        &sample,
        b"s30 synthetic content retained across installation",
    )?;
    let before = hash(&sample)?;
    let state_file = settings.state_directory().join("setting.dat");
    let parsed = rmpv::decode::read_value(&mut std::fs::File::open(&state_file)?)?;
    let key = ApiKey::new(parsed["4"]["6"].as_str().ok_or("private key missing")?)?;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy = ManagementEndpoint::http(&format!("http://{}/", listener.local_addr()?))?;
    let armed = Arc::new(AtomicBool::new(false));
    let apply_faults = Arc::clone(&armed);
    let (requests, mut witnessed) = tokio::sync::mpsc::unbounded_channel();
    let mut server = tokio::spawn(async move {
        let mut versions = 0;
        loop {
            let (mut stream, _) = listener.accept().await?;
            let head = bounded_request_head(&mut stream).await?;
            let line = head.lines().next().ok_or("missing private request")?;
            let mut fields = line.split_whitespace();
            let routed = (
                fields.next().ok_or("missing method")?,
                fields.next().ok_or("missing path")?,
            );
            let upload = routed == ("POST", "/rest/system/upgrade/upload");
            if apply_faults.load(Ordering::SeqCst) {
                requests.send((routed.0.to_owned(), routed.1.to_owned()))?;
                if routed == ("GET", "/rest/system/version") {
                    versions += 1;
                    if versions == 1 {
                        // The normally polled connection is silent until the
                        // SDK closes this timed-out first request.
                        let _ = stream.read_u8().await;
                        continue;
                    }
                }
            }
            forward_native_management(stream, native, head, upload, "s30-install-drop").await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    core.reconnect_management(
        ConnectOptions::new(proxy, key)
            .version_policy(VersionPolicy::AllowUnverified)
            .expected_device_id(identity.clone())
            .request_timeout(Duration::from_secs(35))?,
    )
    .await?;
    let tracing = std::env::var_os("VERYSYNC_S29_PHASE_DIR").is_some()
        || std::env::var_os("VERYSYNC_S30_TRACE").is_some();
    if tracing {
        process_observer_barrier("s30-install-drop", "before-control").await?;
        calibrate_process_creation("s30-install-drop", "calibration-child")?;
        process_observer_barrier("s30-install-drop", "begin").await?;
        receipt_event(
            "s30-install-drop",
            "begin-business-operation",
            serde_json::json!({}),
        )?;
    }
    armed.store(true, Ordering::SeqCst);
    let job = core.install_kernel_upgrade(
        archive,
        &asset,
        OperationOptions::new(Duration::from_secs(45)),
    );
    let report = tokio::select! {
        result = job => result?,
        end = &mut server => { end??; return Err("native witness stopped before the report".into()); }
    };
    if tracing {
        receipt_event(
            "s30-install-drop",
            "end-business-operation",
            serde_json::json!({
                "operation_id":report.installation.receipt.operation_id()
            }),
        )?;
        process_observer_barrier("s30-install-drop", "end").await?;
        calibrate_process_creation("s30-install-drop", "calibration-after")?;
        process_observer_barrier("s30-install-drop", "after-control").await?;
    }
    let actual: Vec<_> = std::iter::from_fn(|| witnessed.try_recv().ok()).collect();
    let routes: Vec<_> = actual
        .iter()
        .map(|(method, path)| (method.as_str(), path.as_str()))
        .collect();
    assert_eq!(
        routes,
        [
            ("GET", "/rest/system/version"),
            ("GET", "/rest/system/version"),
            ("GET", "/rest/system/status"),
            ("POST", "/rest/system/upgrade/upload"),
        ]
    );
    assert_eq!(report.outcome, KernelInstallationOutcome::Installed);
    assert_eq!(report.admission_attempts, 2);
    assert!(matches!(
        report.first_admission_failure,
        Some(Error::Timeout { .. })
    ));
    assert_eq!(
        report.installation.receipt.outcome(),
        UpgradeOutcome::Unknown
    );
    assert_eq!(
        report.installation.receipt.dispatch(),
        UpgradeDispatch::Http {
            status: None,
            complete: false
        }
    );
    assert!(matches!(
        report.installation.result,
        Err(Error::MutationOutcomeUnknown { .. })
    ));
    assert_eq!(
        report.installation.receipt.previous_program_sha256(),
        Some(old)
    );
    assert_eq!(
        report.installation.receipt.target_program_sha256(),
        Some(target)
    );
    let disk = report.disk.ok_or("missing observed disk effect")?;
    assert_eq!(disk.comparison, UpgradeProgramMatch::Target);
    assert_eq!(disk.current_sha256, Some(target));
    assert_eq!(
        disk.operation_id,
        report.installation.receipt.operation_id()
    );
    assert_eq!(hash(&program)?, target);
    assert_eq!(hash(&sample)?, before);
    let exit = report
        .original_exit
        .ok_or("missing original process exit")?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced);
    assert!(exact_program_pids(&program).await?.is_empty());
    receipt_event(
        "s30-install-drop",
        "verified-within-original-call",
        serde_json::json!({
            "routes": actual, "native_exit":exit.code,"target_sha256":hex(target),
            "previous_sha256":hex(old), "payload_preserved":true,
            "original_reply_unknown":true, "sdk_result":report.outcome.to_string(),
            "observed_disk_sha256":disk.current_sha256.map(hex),
            "operation_id":report.installation.receipt.operation_id()
        }),
    )?;
    server.abort();
    assert!(server.await.is_err_and(|e| e.is_cancelled()));
    drop(core);
    root.close()?;
    receipt_event(
        "s30-install-drop",
        "cleanup",
        serde_json::json!({
            "removed":true,"owned_program_pids":0
        }),
    )
}

#[tokio::test]
async fn native_business_install_reports_previous_after_unanswered_upload() -> TestResult {
    verify_non_target_after_unanswered_upload(false).await
}

#[tokio::test]
async fn native_business_install_preserves_unknown_when_program_file_is_unavailable() -> TestResult
{
    verify_non_target_after_unanswered_upload(true).await
}

async fn verify_non_target_after_unanswered_upload(remove_program: bool) -> TestResult {
    let case = if remove_program {
        "s30-install-missing"
    } else {
        "s30-install-previous"
    };
    let root = tempfile::Builder::new().prefix("u30d").tempdir()?;
    let (mut core, settings, program) = owned_old(root.path(), true).await?;
    let old = hash(&program)?;
    let target = baseline_asset()?;
    let archive =
        PathBuf::from(std::env::var_os("VERYSYNC_TEST_ARCHIVE").ok_or("fixed archive missing")?);
    let identity = core.client().instance().device_id.clone();
    let state = settings.state_directory().join("setting.dat");
    let parsed = rmpv::decode::read_value(&mut std::fs::File::open(&state)?)?;
    let key = ApiKey::new(
        parsed["4"]["6"]
            .as_str()
            .ok_or("private fixture key missing")?,
    )?;
    let fixture_control = Client::connect(
        ConnectOptions::new(settings.management_endpoint().clone(), key.clone())
            .version_policy(VersionPolicy::AllowUnverified)
            .expected_device_id(identity.clone()),
    )
    .await?;
    let native_port = settings
        .management_endpoint()
        .http_url()
        .and_then(|url| url.port())
        .ok_or("private native port missing")?;
    let native = SocketAddr::from((Ipv4Addr::LOCALHOST, native_port));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let endpoint = ManagementEndpoint::http(&format!("http://{}/", listener.local_addr()?))?;
    let (requests, mut observed) = tokio::sync::mpsc::unbounded_channel();
    let position = program.clone();
    let restored = program.with_file_name("owned-old-preserved");
    let displaced = restored.clone();
    let mut witness = tokio::spawn(async move {
        loop {
            let (mut conn, _) = listener.accept().await?;
            let head = bounded_request_head(&mut conn).await?;
            if !head.starts_with("POST /rest/system/upgrade/upload ") {
                assert!(head.starts_with("GET "));
                forward_native_management(conn, native, head, false, case).await?;
                continue;
            }
            let length = fixed_upload_length(&head)?;
            let received =
                tokio::io::copy(&mut (&mut conn).take(length), &mut tokio::io::sink()).await?;
            assert_eq!(received, length);
            requests.send(received)?;
            // Model an unanswered request which did not reach the engine; stop
            // the fixture separately so the SDK can observe a settled program.
            // This independent fixture client has its own mutation lock.
            fixture_control.request_shutdown().await?;
            tokio::time::timeout(Duration::from_secs(8), async {
                while !exact_program_pids(&position).await?.is_empty() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            })
            .await??;
            if remove_program {
                std::fs::rename(&position, &displaced)?;
            }
            receipt_event(
                case,
                "controlled-no-upstream-upload",
                serde_json::json!({
                    "sdk_uploads":1,"forwarded_uploads":0,"fixture_shutdowns":1,
                    "input_bytes_consumed":received,"program_temporarily_unavailable":remove_program
                }),
            )?;
            conn.shutdown().await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    core.reconnect_management(
        ConnectOptions::new(endpoint, key)
            .version_policy(VersionPolicy::AllowUnverified)
            .expected_device_id(identity),
    )
    .await?;
    let run = core.install_kernel_upgrade(
        archive,
        &target,
        OperationOptions::new(Duration::from_secs(30)),
    );
    let report = tokio::select! {
        result = run => result?,
        end = &mut witness => { end??; return Err("controlled witness stopped early".into()); }
    };
    assert!(matches!(
        report.installation.result,
        Err(Error::MutationOutcomeUnknown { .. })
    ));
    assert_eq!(
        report.installation.receipt.outcome(),
        UpgradeOutcome::Unknown
    );
    assert_eq!(report.admission_attempts, 1);
    let disk = report.disk.ok_or("expected SDK disk observation")?;
    if remove_program {
        assert_eq!(report.outcome, KernelInstallationOutcome::Unconfirmed);
        assert_eq!(
            disk.comparison,
            UpgradeProgramMatch::Unconfirmed(UpgradeProgramUncertainty::FileUnverified)
        );
        assert!(disk.current_sha256.is_none());
        std::fs::rename(restored, &program)?;
    } else {
        assert_eq!(
            report.outcome,
            KernelInstallationOutcome::PreviousProgramRemains
        );
        assert_eq!(disk.comparison, UpgradeProgramMatch::Previous);
        assert_eq!(disk.current_sha256, Some(old));
    }
    assert!(observed.try_recv()? > target.archive_bytes());
    assert!(observed.try_recv().is_err());
    assert_eq!(hash(&program)?, old);
    let ended = report.original_exit.ok_or("missing owned exit")?;
    assert!(ended.tree_stopped && ended.state_released && !ended.forced);
    assert!(exact_program_pids(&program).await?.is_empty());
    witness.abort();
    assert!(witness.await.is_err_and(|error| error.is_cancelled()));
    drop(core);
    root.close()?;
    receipt_event(
        case,
        "result-and-cleanup",
        serde_json::json!({
            "original_unknown":true, "later_comparison":format!("{:?}", disk.comparison),
            "final_report":report.outcome.to_string(), "native_exit_code":ended.code,
            "owned_program_pids":0, "removed":true
        }),
    )
}

#[tokio::test]
async fn native_business_upgrade_and_ready_reuses_owned_data_and_same_device() -> TestResult {
    let root = tempfile::Builder::new().prefix("u30r").tempdir()?;
    let (mut core, _, program) = owned_old(root.path(), true).await?;
    let previous = core.control_generation();
    let device = core.client().instance().device_id.clone();
    let target = baseline_asset()?;
    let archive =
        PathBuf::from(std::env::var_os("VERYSYNC_TEST_ARCHIVE").ok_or("fixed archive missing")?);
    let path = root.path().join("retained");
    std::fs::create_dir(&path)?;
    let sample = path.join("synthetic.bin");
    std::fs::write(&sample, b"owned upgrade data on disk")?;
    let saved = hash(&sample)?;
    let id = FolderId::parse("s30-upgrade-retained")?;
    core.client()
        .create_folder(&CreateFolderOptions::new(
            id.clone(),
            TargetPath::local(&path),
        ))
        .await?;
    let before = core.client().folder(&id).await?;
    let prep_file = root.path().join("prepared-storage-1.json");
    let path_for_storage = prep_file.clone();
    let options = OperationOptions::new(Duration::from_secs(45)).save_upgrade_checkpoints(
        move |checkpoint| {
            let output = path_for_storage.clone();
            async move {
                match checkpoint.stage {
                    UpgradeCheckpointStage::BeforeUpload => {
                        let bytes = checkpoint.receipt.encode().map_err(io::Error::other)?;
                        tokio::fs::write(output, bytes).await
                    }
                    UpgradeCheckpointStage::RequestFinished => Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "synthetic final receipt storage refusal",
                    )),
                    _ => Err(io::Error::other("unexpected test checkpoint stage")),
                }
            }
        },
    );
    let report = core
        .upgrade_kernel_and_wait_ready(archive, &target, options.clone())
        .await?;
    assert_eq!(report.outcome, KernelReadinessOutcome::Ready, "{report:?}");
    assert!(report.sdk_start_attempted);
    assert_eq!(
        report.installation.outcome,
        KernelInstallationOutcome::Installed
    );
    assert!(matches!(
        report.installation.persistence_error,
        Some(Error::LocalIo { .. })
    ));
    let durable = UpgradeReceipt::decode(&std::fs::read(&prep_file)?)?;
    assert_eq!(
        durable.operation_id(),
        report.installation.installation.receipt.operation_id()
    );
    assert_eq!(durable.dispatch(), UpgradeDispatch::Preparing);
    assert_eq!(
        report.installation.installation.receipt.outcome(),
        UpgradeOutcome::Acknowledged
    );
    let transition = report
        .transition
        .ok_or("missing authenticated transition")?;
    assert!(transition.previous_exit.tree_stopped && transition.previous_exit.state_released);
    assert_eq!(transition.current_program.sha256, hash(&pinned_program()?)?);
    assert_eq!(hash(&program)?, transition.current_program.sha256);
    assert_ne!(core.control_generation(), previous);
    assert_eq!(core.client().instance().device_id, device);
    assert_eq!(
        core.client().version().await?.version,
        target.version().as_str()
    );
    let after = core.client().folder(&id).await?;
    assert_eq!(after.id, before.id);
    assert_eq!(after.path, before.path);
    assert_eq!(hash(&sample)?, saved);
    let ready = core.control_generation();
    let zero = core
        .upgrade_kernel_and_wait_ready(
            root.path().join("unneeded-archive.zip"),
            &target,
            OperationOptions::new(Duration::from_secs(45)),
        )
        .await?;
    assert_eq!(zero.outcome, KernelReadinessOutcome::AlreadyReady);
    assert_eq!(
        zero.installation.installation.receipt.dispatch(),
        UpgradeDispatch::Preparing
    );
    assert!(!zero.sdk_start_attempted);
    assert_eq!(core.control_generation(), ready);
    let ended = core.shutdown(Duration::from_secs(15)).await?;
    assert!(ended.tree_stopped && ended.state_released && !ended.forced);
    assert!(exact_program_pids(&program).await?.is_empty());
    drop(core);
    root.close()?;
    receipt_event(
        "s30-ready",
        "result-and-cleanup",
        serde_json::json!({
            "disk_target":true, "authenticated_target_generation":true, "original_device":true,
            "folder_and_bytes_retained":true, "already_ready_without_upload_or_restart":true,
            "original_native_exit":transition.previous_exit.code, "sdk_start_attempted":true,
        "final_storage_failure_separate_from_installed_and_ready":true,
            "owned_program_pids":0, "removed":true
        }),
    )
}

#[tokio::test]
async fn native_business_install_timed_out_checkpoint_cannot_replace_the_final_receipt(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("u30s").tempdir()?;
    let (mut core, settings, program) = owned_old(root.path(), true).await?;
    let previous = core.control_generation();
    let digest = hash(&program)?;
    let identity = core.client().instance().device_id.clone();
    let asset = baseline_asset()?;
    let archive =
        PathBuf::from(std::env::var_os("VERYSYNC_TEST_ARCHIVE").ok_or("fixed archive missing")?);
    let parsed = rmpv::decode::read_value(&mut std::fs::File::open(
        settings.state_directory().join("setting.dat"),
    )?)?;
    let key = ApiKey::new(
        parsed["4"]["6"]
            .as_str()
            .ok_or("private fixture key missing")?,
    )?;
    let port = settings
        .management_endpoint()
        .http_url()
        .and_then(|url| url.port())
        .ok_or("private port missing")?;
    let native = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let endpoint = ManagementEndpoint::http(&format!("http://{}/", proxy.local_addr()?))?;
    let uploads = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&uploads);
    let mut relay = tokio::spawn(async move {
        loop {
            let (mut stream, _) = proxy.accept().await?;
            let head = bounded_request_head(&mut stream).await?;
            let upgrade = head.starts_with("POST /rest/system/upgrade/upload ");
            if upgrade {
                seen.fetch_add(1, Ordering::SeqCst);
                return Err("upload reached the witness after a failed write checkpoint".into());
            }
            forward_native_management(stream, native, head, false, "s30-storage").await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    core.reconnect_management(
        ConnectOptions::new(endpoint, key)
            .version_policy(VersionPolicy::AllowUnverified)
            .expected_device_id(identity),
    )
    .await?;

    let prepared = root.path().join("before-upload.json");
    let finished = root.path().join("request-finished.json");
    let (release_late_save, wait_for_release) = std::sync::mpsc::channel();
    let held = Arc::new(Mutex::new(Some(wait_for_release)));
    let (late_saved, confirmed_late) = tokio::sync::oneshot::channel();
    let acknowledged = Arc::new(Mutex::new(Some(late_saved)));
    let began_storage = Arc::new(AtomicBool::new(false));
    let options = OperationOptions::new(Duration::from_secs(30)).save_upgrade_checkpoints({
        let prepared = prepared.clone();
        let finished = finished.clone();
        let began_storage = Arc::clone(&began_storage);
        move |checkpoint| {
            let prepared = prepared.clone();
            let finished = finished.clone();
            let held = Arc::clone(&held);
            let acknowledged = Arc::clone(&acknowledged);
            let began_storage = Arc::clone(&began_storage);
            async move {
                let bytes = checkpoint.receipt.encode().map_err(io::Error::other)?;
                match checkpoint.stage {
                    UpgradeCheckpointStage::BeforeUpload => {
                        assert!(!began_storage.swap(true, Ordering::SeqCst));
                        let receiver =
                            held.lock().unwrap().take().ok_or_else(|| {
                                io::Error::other("duplicate pre-upload checkpoint")
                            })?;
                        tokio::task::spawn_blocking(move || {
                            receiver
                                .recv_timeout(Duration::from_secs(45))
                                .map_err(io::Error::other)?;
                            std::fs::write(prepared, bytes)?;
                            let sender = acknowledged
                                .lock()
                                .unwrap()
                                .take()
                                .ok_or_else(|| io::Error::other("duplicate late write"))?;
                            let _ = sender.send(());
                            Ok::<(), io::Error>(())
                        })
                        .await
                        .map_err(io::Error::other)?
                    }
                    UpgradeCheckpointStage::RequestFinished => {
                        tokio::fs::write(finished, bytes).await
                    }
                    _ => Err(io::Error::other("unexpected test checkpoint stage")),
                }
            }
        }
    });
    let result = core.install_kernel_upgrade(archive, &asset, options);
    let report = tokio::select! {
        result = result => result?,
        end = &mut relay => { end??; return Err("private relay finished early".into()); }
    };
    assert_eq!(report.outcome, KernelInstallationOutcome::NotInstalled);
    assert!(began_storage.load(Ordering::SeqCst), "{report:?}");
    assert!(matches!(
        report.installation.result,
        Err(Error::Timeout {
            operation: "save the private upgrade checkpoint"
        })
    ));
    assert_eq!(
        report.installation.receipt.outcome(),
        UpgradeOutcome::NotSubmitted
    );
    assert_eq!(
        report.installation.receipt.dispatch(),
        UpgradeDispatch::Preparing
    );
    assert!(report.persistence_error.is_none(), "{report:?}");
    assert!(!prepared.exists());
    let original_final_bytes = std::fs::read(&finished)?;
    release_late_save.send(())?;
    tokio::time::timeout(Duration::from_secs(4), confirmed_late).await??;
    assert_eq!(std::fs::read(&finished)?, original_final_bytes);
    assert_ne!(std::fs::read(&prepared)?, original_final_bytes);
    let child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "upgrade_receipt_native::reopen_private_upgrade_receipt_child",
            "--ignored",
            "--nocapture",
        ])
        .env("VERYSYNC_S30_FINAL_TEST_RECEIPT", &finished)
        .env("VERYSYNC_S30_BEFORE_TEST_RECEIPT", &prepared)
        .output()?;
    assert!(child.status.success());
    assert!(
        std::str::from_utf8(&child.stdout)?.contains("s30-second-process-private-receipts-read")
    );
    assert_eq!(uploads.load(Ordering::SeqCst), 0);
    assert_eq!(core.control_generation(), previous);
    assert_eq!(hash(&program)?, digest);
    let ended = core.shutdown(Duration::from_secs(10)).await?;
    assert!(ended.tree_stopped && ended.state_released && !ended.forced);
    assert!(exact_program_pids(&program).await?.is_empty());
    relay.abort();
    assert!(relay.await.is_err_and(|error| error.is_cancelled()));
    drop(core);
    root.close()?;
    receipt_event(
        "s30-storage",
        "result-and-cleanup",
        serde_json::json!({
            "upload_requests":0, "prewrite_timed_out":true, "late_write_completed":true,
            "final_receipt_unchanged":true, "second_process_reopened_both_slots":true,
            "owned_program_pids":0, "removed":true
        }),
    )
}

#[test]
#[ignore = "subprocess of the private checkpoint timing fixture"]
fn reopen_private_upgrade_receipt_child() -> TestResult {
    let final_path =
        std::env::var_os("VERYSYNC_S30_FINAL_TEST_RECEIPT").ok_or("missing final fixture")?;
    let before_path =
        std::env::var_os("VERYSYNC_S30_BEFORE_TEST_RECEIPT").ok_or("missing before fixture")?;
    let final_bytes = std::fs::read(final_path)?;
    let final_receipt = UpgradeReceipt::decode(&final_bytes)?;
    let before = UpgradeReceipt::decode(&std::fs::read(before_path)?)?;
    assert_eq!(final_receipt.operation_id(), before.operation_id());
    assert_eq!(final_receipt.dispatch(), UpgradeDispatch::Preparing);
    assert_eq!(final_receipt.outcome(), UpgradeOutcome::NotSubmitted);
    assert_eq!(final_receipt.encode()?, final_bytes);
    let mut malformed: serde_json::Value = serde_json::from_slice(&final_bytes)?;
    malformed["schema_version"] = 77.into();
    assert!(UpgradeReceipt::decode(&serde_json::to_vec(&malformed)?).is_err());
    println!("s30-second-process-private-receipts-read");
    Ok(())
}

#[tokio::test]
async fn native_same_attempt_observes_replacement_after_upload_reply_loss() -> TestResult {
    await_process_observer().await?;
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
    let equal = updated
        .run_cli_upgrade_with_target_receipt(
            KernelUpgradeCommand::Provider,
            &asset,
            Duration::from_secs(2),
        )
        .await?;
    assert!(matches!(
        equal.result,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert_eq!(equal.receipt.dispatch(), UpgradeDispatch::Preparing);
    assert_eq!(equal.receipt.outcome(), UpgradeOutcome::NotSubmitted);
    receipt_event(
        "upload-drop",
        "identical-target-control",
        serde_json::json!({"rejected_before_dispatch":true}),
    )?;
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
#[ignore = "requires the isolated provider-blocked receipt job"]
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
