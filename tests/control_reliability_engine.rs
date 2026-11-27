//! Native listener migration exercised through independently built application processes.
#![cfg(feature = "engine-tests")]

#[path = "common/control_fault_origin.rs"]
mod control_fault_origin;
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[path = "common/control_loopback_capture.rs"]
mod control_loopback_capture;
#[path = "common/control_native_request_log.rs"]
mod control_native_request_log;
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
#[cfg(feature = "tls")]
#[path = "common/management_service.rs"]
#[allow(dead_code)] // This target uses only the TLS origin and its observation feed.
mod management_service;
#[path = "../examples/common/owned_shutdown.rs"]
mod owned_shutdown;

use control_fault_origin::{
    assert_read_only, Delivery, Method, Origin, Phase, Request, Response, Route, TestResult,
    Witness,
};
use serde_json::{json, Value};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, CreateFolderOptions, DeviceId, FolderId,
    ManagedGenerationStatus, ManagedInstance, ManagedOptions, ManagementEndpoint, TargetPath,
};

const SHORT_WAIT: Duration = Duration::from_secs(10);
const PROGRAM_WAIT: Duration = Duration::from_secs(30);
const RETAINED_FILE: &[u8] = b"independent listener migration keeps the synthetic file\n";
const FIXTURE_KEY: &str = "fixture-only-control-service-key";
const FIXTURE_DEVICE: &str = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";
const ALTERNATE_DEVICE: &str = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
const CONTROLLED_BEFORE: &str = "127.0.0.1:44001";
const CONTROLLED_AFTER: &str = "127.0.0.1:44002";
const READ_PATHS: [Route; 6] = [
    Route::Version,
    Route::Identity,
    Route::Identity,
    Route::Gui,
    Route::Version,
    Route::Identity,
];

struct AppProcess(Option<Child>);

impl Drop for AppProcess {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            if child.try_wait().is_ok_and(|status| status.is_none()) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

struct AppResult {
    code: i32,
    output: Value,
}

impl AppResult {
    fn operation_id(&self) -> TestResult<&str> {
        self.output["operation_id"]
            .as_str()
            .filter(|id| {
                id.len() <= 128 && !id.is_empty() && id.bytes().all(|v| v.is_ascii_hexdigit())
            })
            .ok_or_else(|| "expected a bounded opaque operation ID in application output".into())
    }
}

fn app_executable() -> TestResult<PathBuf> {
    let value = std::env::var_os("VERYSYNC_TEST_RECOVERY_EXAMPLE")
        .ok_or("set VERYSYNC_TEST_RECOVERY_EXAMPLE to the explicitly built package consumer")?;
    let path = PathBuf::from(value);
    if !path.is_absolute() || !path.is_file() {
        return Err("the compiled package consumer must be an explicit absolute path".into());
    }
    Ok(path)
}

async fn launch_app(
    executable: &Path,
    verb: &str,
    journal: &Path,
    input: &Value,
) -> TestResult<AppResult> {
    let mut app = AppProcess(Some(
        Command::new(executable)
            .args([std::ffi::OsStr::new(verb), journal.as_os_str()])
            .current_dir(journal)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    ));
    let child = app.0.as_mut().ok_or("application child absent")?;
    let mut stdin = child.stdin.take().ok_or("application stdin absent")?;
    serde_json::to_writer(&mut stdin, input)?;
    stdin.write_all(b"\n")?;
    drop(stdin);
    let deadline = Instant::now() + PROGRAM_WAIT;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            return Err("package consumer process exceeded its deadline".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let output = app
        .0
        .take()
        .ok_or("application child disappeared")?
        .wait_with_output()?;
    if output.stdout.len() > 8192 || output.stderr.len() > 8192 {
        return Err("package consumer exceeded its diagnostic output bound".into());
    }
    let secret = input["api_key"].as_str().ok_or("test API key absent")?;
    for output in [&output.stdout, &output.stderr] {
        let printable = String::from_utf8_lossy(output);
        assert!(
            !printable.contains(secret),
            "application output leaked the test credential"
        );
        if let Some(endpoint) = input["endpoint"].as_str() {
            assert!(
                !printable.contains(endpoint),
                "application output leaked the endpoint"
            );
        }
        if let Some(bind) = input["bind"].as_str() {
            assert!(
                !printable.contains(bind),
                "application output leaked the bind authority"
            );
        }
    }
    Ok(AppResult {
        code: output
            .status
            .code()
            .ok_or("application did not exit with a code")?,
        output: serde_json::from_slice(&output.stdout)
            .map_err(|_| "application did not emit a bounded JSON result")?,
    })
}

fn forward_http() -> TestResult<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(SHORT_WAIT)
        .build()?)
}

async fn forward_to_owned(
    client: reqwest::Client,
    backend: SocketAddr,
    request: Request,
    lose_reply: bool,
) -> TestResult<Response> {
    if backend.ip() != Ipv4Addr::LOCALHOST || backend.port() == 18886 {
        return Err("explicit isolated loopback backend required".into());
    }
    let path = if let Some(peer) = request.peer.as_ref() {
        format!("/rest/config/devices/{}", peer.as_str())
    } else {
        request
            .route
            .path()
            .ok_or("unknown backend route")?
            .to_owned()
    };
    let uri = format!("http://{backend}{path}");
    let mut outgoing = match request.method {
        Method::Patch => client
            .patch(&uri)
            .header("content-type", "application/json")
            .body(request.body),
        Method::Get => client.get(&uri),
        Method::Delete => client.delete(&uri),
        Method::Post if request.route == Route::Shutdown => client.post(&uri),
        _ => return Err("fixture does not forward this request method".into()),
    };
    if let Some(key) = request.credential {
        outgoing = outgoing.header("x-api-key", key);
    }
    let result = outgoing.send().await;
    if lose_reply {
        return Ok(match result {
            Ok(received) => Response::drop_reply(Some(received.status().as_u16())),
            Err(_) => Response::backend_disconnected(),
        });
    }
    let mut response = result.map_err(|_| "owned fixture backend did not return HTTP headers")?;
    let status = response.status().as_u16();
    let mut data = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "owned fixture backend response was incomplete")?
    {
        if data.len() + chunk.len() > 1024 * 1024 {
            return Err("owned fixture response exceeded its bound".into());
        }
        data.extend_from_slice(&chunk);
    }
    Ok(Response::forwarded(status, data))
}

fn reserved() -> TestResult<TcpListener> {
    let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    if reserved.local_addr()?.port() == 18886 {
        return Err("test must avoid the default port".into());
    }
    Ok(reserved)
}

fn endpoint(address: SocketAddr) -> verysync_sidecar::Result<ManagementEndpoint> {
    ManagementEndpoint::http(&format!("http://{address}/"))
}

fn options(
    address: SocketAddr,
    key: ApiKey,
    expected: DeviceId,
) -> verysync_sidecar::Result<ConnectOptions> {
    ConnectOptions::new(endpoint(address)?, key)
        .expected_device_id(expected)
        .request_timeout(Duration::from_secs(2))
}

fn private_tree() -> TestResult<tempfile::TempDir> {
    #[cfg(unix)]
    let root = tempfile::Builder::new()
        .prefix("vs-control-")
        .tempdir_in("/tmp")?;
    #[cfg(windows)]
    let root = tempfile::Builder::new().prefix("vs-control-").tempdir()?;
    Ok(root)
}

fn journal_path(root: &Path) -> TestResult<PathBuf> {
    let journal = root.join("app");
    std::fs::create_dir(&journal)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(journal)
}

async fn owned_core(root: &Path, address: SocketAddr) -> TestResult<ManagedInstance> {
    let fixture = managed_fixture::options(&root.join("core"))?;
    let options = ManagedOptions::new(
        fixture.program().clone(),
        fixture.state_directory(),
        endpoint(address)?,
    )?
    .startup_timeout(PROGRAM_WAIT)?;
    Ok(ManagedInstance::start(options).await?)
}

async fn await_listener(
    address: SocketAddr,
    key: ApiKey,
    expected: &DeviceId,
) -> TestResult<Client> {
    let deadline = Instant::now() + SHORT_WAIT;
    loop {
        match Client::connect(options(address, key.clone(), expected.clone())?).await {
            Ok(client) => return Ok(client),
            Err(verysync_sidecar::Error::IdentityMismatch { .. }) => {
                return Err("isolated native address was taken by an unexpected device".into());
            }
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await
            }
            Err(_) => return Err("isolated native listener did not become reachable".into()),
        }
    }
}

async fn confirmed_exit(core: &mut ManagedInstance) -> TestResult {
    let exit = core.shutdown(SHORT_WAIT).await?;
    assert_eq!(exit.code, Some(0));
    assert!(exit.tree_stopped && exit.state_released && !exit.forced);
    Ok(())
}

#[tokio::test]
async fn native_migration_keeps_one_submission_and_new_process_recovers_read_only() -> TestResult {
    let executable = app_executable()?;
    let root = private_tree()?;
    let before_reservation = reserved()?;
    let after_reservation = reserved()?;
    let before = before_reservation.local_addr()?;
    let after = after_reservation.local_addr()?;
    assert_ne!(before, after);
    drop(before_reservation);

    let mut core = owned_core(root.path(), before).await?;
    let expected = core.client().instance().device_id.clone();
    let initial_pid = core.process_id();
    let original_generation = core.control_generation();
    let credential = core.client().gui_authentication().await?.api_key()?;
    let original_configuration = core.client().configuration().await?;

    // The fixture owns this randomly generated management key. It passes it to
    // each process through stdin and never emits it to the evidence stream.
    let api_key = original_configuration.native_document()["gui"]["apiKey"]
        .as_str()
        .ok_or("isolated API key absent")?;
    let data = root.path().join("synthetic-data");
    std::fs::create_dir(&data)?;
    let sample = data.join("retained.txt");
    std::fs::write(&sample, RETAINED_FILE)?;
    let folder = FolderId::parse("control-migration-fixture")?;
    core.client()
        .create_folder(
            &CreateFolderOptions::new(folder.clone(), TargetPath::local(&data)).paused(true),
        )
        .await?;
    assert!(core.client().folder(&folder).await?.paused);

    let journal = journal_path(root.path())?;
    let witness = Witness::new();
    let forwarder = forward_http()?;
    let old_gate = Origin::start("a", witness.clone(), move |_, request: Request| {
        let lose_reply = request.method == Method::Patch;
        forward_to_owned(forwarder.clone(), before, request, lose_reply)
    })
    .await?;

    // Keep the selected new port reserved until just before the explicit write.
    drop(after_reservation);
    let mut adopted = false;
    let outcome: TestResult<Value> = async {
        let submitted = launch_app(&executable, "submit", &journal, &json!({
            "endpoint": old_gate.url(), "api_key": api_key, "expected_device_id": expected.as_str(),
            "bind": after.to_string(), "event_log": true
        })).await?;
        assert_eq!(submitted.code, 2, "loss case must report uncertainty");
        assert_eq!(submitted.output["submission"], "possibly_submitted");
        let operation_id = submitted.operation_id()?.to_owned();
        let first_evidence = witness.rows()?;
        let native_writes: Vec<_> = first_evidence
            .iter()
            .filter(|row| row.method == Method::Patch)
            .collect();
        assert_eq!(native_writes.len(), 1);
        assert_eq!(native_writes[0].phase, Phase::Submission);
        assert_eq!(native_writes[0].route, Route::Gui);
        assert!(native_writes[0].credential_header);
        assert!(matches!(
            native_writes[0].delivery,
            Delivery::DroppedAfterBackendResponse | Delivery::BackendDisconnected
        ));
        if let Some(status) = native_writes[0].backend_status {
            assert!((200..300).contains(&status));
        }

        // The first application process has already exited. The observer and
        // owner stay alive and the engine is reachable at its native B socket.
        let native_b = await_listener(after, credential.clone(), &expected).await?;
        let actual = native_b.gui_listener().await?;
        assert_eq!(
            actual.address.tcp_authority(),
            Some(after.to_string().as_str())
        );
        assert_eq!(native_b.system_status().await?.device_id, expected);
        assert_eq!(core.process_id(), initial_pid);
        assert_eq!(
            core.check_control_generation(&original_generation),
            ManagedGenerationStatus::Current
        );

        let receipt_file = journal.join("receipt.json");
        let saved = std::fs::read(&receipt_file)?;
        assert!(saved.len() <= 16 * 1024);
        assert!(!String::from_utf8_lossy(&saved).contains(api_key));
        control_native_request_log::enable(&native_b).await?;
        let native_log_calibration =
            calibrate_native_request_log(core.state_directory(), after, api_key).await?;
        witness.recovery()?;
        let native_log =
            control_native_request_log::LogWindow::new(core.state_directory(), after, api_key)?;
        native_log.open().await?;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let direct_capture = control_loopback_capture::DirectCapture::start(after.port())?;
        let recovered_direct = launch_app(
            &executable,
            "observe",
            &journal,
            &json!({
                "endpoint": format!("http://{after}/"), "api_key": api_key,
                "expected_device_id": expected.as_str()
            }),
        )
        .await?;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let direct_b_wire = direct_capture
            .map(|observer| observer.finish())
            .transpose()?;
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let direct_b_wire: Option<Value> = None;
        let direct_b_evidence = native_log.close().await?;
        assert_eq!(direct_b_evidence["ordered_reads"], json!(READ_PATHS));
        check_recovered(&recovered_direct, &operation_id)?;
        assert_eq!(std::fs::read(&receipt_file)?, saved);

        // The same persisted receipt is replayed in a third application. This
        // guarded route witnesses each actual HTTP request independently. The
        // direct B application above never uses this guard.
        let forwarder = forward_http()?;
        let b_gate = Origin::start("b_guard", witness.clone(), move |_, request| {
            forward_to_owned(forwarder.clone(), after, request, false)
        })
        .await?;
        let witnessed_b = launch_app(&executable, "observe", &journal, &json!({
            "endpoint": b_gate.url(), "api_key": api_key, "expected_device_id": expected.as_str()
        })).await?;
        check_recovered(&witnessed_b, &operation_id)?;
        assert_eq!(std::fs::read(&receipt_file)?, saved);
        let rows = witness.rows()?;
        let recovery: Vec<_> = rows
            .iter()
            .filter(|row| row.phase == Phase::Recovery)
            .cloned()
            .collect();
        assert_read_only(&recovery)?;
        assert!(recovery
            .iter()
            .all(|row| row.origin == "b_guard" && row.credential_header));
        assert_eq!(
            recovery.iter().map(|item| item.route).collect::<Vec<_>>(),
            READ_PATHS
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row.method == Method::Patch)
                .count(),
            1
        );

        assert!(native_b.folder(&folder).await?.paused);
        assert_eq!(std::fs::read(&sample)?, RETAINED_FILE);
        core.reconnect_management(options(after, credential.clone(), expected.clone())?)
            .await?;
        adopted = true;
        Ok(json!({
            "scenario":"native_listener_change_reply_lost",
            "operation_id":operation_id,
            "direct_b_confirmed":true,
            "direct_b_application_exited":true,
            "direct_b_requests_independently_counted":true,
            "direct_b_request_witness":direct_b_evidence,
            "direct_b_packet_witness":direct_b_wire,
            "native_request_log_calibration":native_log_calibration,
            "guarded_b_read_requests":recovery.len(),
            "guarded_b_modifications":0,
            "submission_patch":1,
            "native_b_actual_bind_and_identity":true,
            "original_outcome":"possibly_submitted",
            "borrowed_process_generation":"unknown",
            "real_registered_folder_and_sample_preserved":true,
            "witnesses":rows
        }))
    }
    .await;
    if !adopted
        && await_listener(after, credential.clone(), &expected)
            .await
            .is_ok()
    {
        let _ = core
            .reconnect_management(options(after, credential, expected)?)
            .await;
    }
    let exit = confirmed_exit(&mut core).await;
    let mut report = outcome?;
    exit?;
    report["owned_normal_exit_and_state_release"] = true.into();
    assert_eq!(std::fs::read(sample)?, RETAINED_FILE);
    println!("control reliability native evidence {report}");
    Ok(())
}

async fn calibrate_native_request_log(
    state: &Path,
    address: SocketAddr,
    api_key: &str,
) -> TestResult<Value> {
    use control_native_request_log::LogWindow;
    let http = forward_http()?;
    let positive = LogWindow::new(state, address, api_key)?;
    positive.open().await?;
    let reply = http
        .get(format!("http://{address}/rest/system/version"))
        .header("x-api-key", api_key)
        .send()
        .await?;
    assert_eq!(reply.status(), 200);
    let body = reply.json::<Value>().await?;
    assert_eq!(body["version"], "v2.33.2");
    let positive_log = positive.close().await?;
    assert_eq!(positive_log["ordered_reads"], json!([Route::Version]));
    for (method, path, expected_error) in [
        (
            reqwest::Method::HEAD,
            "/rest/system/version",
            "native recovery handled a request whose method was not GET",
        ),
        (
            reqwest::Method::GET,
            "/rest/system/ping?test_control_unexpected=marker-control",
            "native recovery handled a route outside the read-only allowlist",
        ),
    ] {
        let negative = LogWindow::new(state, address, api_key)?;
        negative.open().await?;
        // Both methods exercise read endpoints on the synthetic native core.
        // The expected rejection is from the independent observer.
        let reply = http
            .request(method, format!("http://{address}{path}"))
            .header("x-api-key", api_key)
            .send()
            .await?;
        let _ = reply.bytes().await?;
        assert_eq!(
            negative.close().await.unwrap_err().to_string(),
            expected_error
        );
    }
    Ok(json!({
        "confirmed_expected_read":true,
        "detected_non_get_method":true,
        "detected_unexpected_get_route":true
    }))
}

fn check_recovered(result: &AppResult, id: &str) -> TestResult {
    check_observation(result, id, "possibly_submitted", true)
}

fn check_observation(result: &AppResult, id: &str, submission: &str, matches: bool) -> TestResult {
    assert_eq!(result.code, 0);
    assert_eq!(result.operation_id()?, id);
    assert_eq!(result.output["submission"], submission);
    assert_eq!(result.output["requested_fields_match"], matches);
    assert!(result.output["observed_at_unix_ms"]
        .as_u64()
        .is_some_and(|value| value > 0));
    assert_eq!(result.output["process_generation"], "unknown");
    Ok(())
}

struct ControlledDevice {
    id: &'static str,
    applied: AtomicBool,
    apply_on_patch: bool,
    return_reply: bool,
}

impl ControlledDevice {
    fn request(&self, request: Request) -> TestResult<Response> {
        assert_eq!(
            request
                .credential
                .as_ref()
                .and_then(|key| key.to_str().ok()),
            Some(FIXTURE_KEY)
        );
        match (request.method, request.route) {
            (Method::Get, Route::Version) => Response::json(&json!({
                "version": "v2.33.2", "os": "linux", "arch": "amd64"
            })),
            (Method::Get, Route::Identity) => Response::json(&json!({"myID": self.id})),
            (Method::Get, Route::Gui) => Response::json(&json!({
                "enabled": true, "authMode": "static", "user": "", "password": "",
                "apiKey": FIXTURE_KEY, "useTLS": false, "unixSocketPermissions": "",
                "address": if self.applied.load(Ordering::SeqCst) {
                    CONTROLLED_AFTER
                } else {
                    CONTROLLED_BEFORE
                }
            })),
            (Method::Patch, Route::Gui) => {
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body)?,
                    json!({"address": CONTROLLED_AFTER})
                );
                self.applied.store(self.apply_on_patch, Ordering::SeqCst);
                if self.return_reply {
                    Response::json(&json!({}))
                } else {
                    Ok(Response::drop_reply(Some(200)))
                }
            }
            _ => Err("controlled device received an unsupported request".into()),
        }
    }
}

async fn controlled_origin(
    label: &'static str,
    witness: &Witness,
    device: &Arc<ControlledDevice>,
) -> TestResult<Origin> {
    let device = Arc::clone(device);
    Origin::start(label, witness.clone(), move |_, request| {
        let device = Arc::clone(&device);
        async move { device.request(request) }
    })
    .await
}

fn simulator(id: &'static str, apply_on_patch: bool, return_reply: bool) -> Arc<ControlledDevice> {
    Arc::new(ControlledDevice {
        id,
        applied: AtomicBool::new(false),
        apply_on_patch,
        return_reply,
    })
}

fn app_connection(endpoint: &str) -> Value {
    json!({
        "endpoint": endpoint,
        "api_key": FIXTURE_KEY,
        "expected_device_id": FIXTURE_DEVICE
    })
}

fn app_submission(endpoint: &str) -> Value {
    let mut input = app_connection(endpoint);
    input["bind"] = CONTROLLED_AFTER.into();
    input
}

fn assert_application_failure(result: &AppResult, failure: &str) {
    assert_eq!(result.code, 1);
    assert_eq!(result.output["failure"], failure);
    assert!(result.output.get("requested_fields_match").is_none());
}

#[tokio::test]
async fn package_consumer_distinguishes_acknowledgement_loss_and_later_changes() -> TestResult {
    let executable = app_executable()?;
    for (name, apply, acknowledge, external_change) in [
        ("applied_unanswered", true, false, false),
        ("unapplied_unanswered", false, false, false),
        ("acknowledged_and_applied", true, true, false),
        (
            "acknowledged_then_overwritten_independently",
            true,
            true,
            true,
        ),
        ("acknowledged_with_failed_diagnostic_log", true, true, false),
    ] {
        let root = private_tree()?;
        let journal = journal_path(root.path())?;
        let witness = Witness::new();
        let device = simulator(FIXTURE_DEVICE, apply, acknowledge);
        let first = controlled_origin("a", &witness, &device).await?;
        let second = controlled_origin("b", &witness, &device).await?;
        let mut submit = app_submission(&first.url());
        if name == "acknowledged_with_failed_diagnostic_log" {
            submit["event_log"] = true.into();
            std::fs::create_dir(journal.join("events.jsonl"))?;
        }
        let result = launch_app(&executable, "submit", &journal, &submit).await?;
        let operation = result.operation_id()?;
        let submission = if acknowledge {
            assert_eq!(result.code, 0);
            assert_eq!(result.output["http_status"], 200);
            "acknowledged"
        } else {
            assert_eq!(result.code, 2);
            assert_eq!(result.output["failure"], "mutation_outcome_unknown");
            assert_eq!(result.output["final_receipt_saved"], true);
            "possibly_submitted"
        };
        assert_eq!(result.output["submission"], submission);
        assert_eq!(device.applied.load(Ordering::SeqCst), apply);
        if external_change {
            device.applied.store(false, Ordering::SeqCst);
        }
        let saved = std::fs::read(journal.join("receipt.json"))?;
        witness.recovery()?;
        let observed = launch_app(
            &executable,
            "observe",
            &journal,
            &app_connection(&second.url()),
        )
        .await?;
        check_observation(&observed, operation, submission, apply && !external_change)?;
        assert_eq!(std::fs::read(journal.join("receipt.json"))?, saved);
        let rows = witness.rows()?;
        let patches: Vec<_> = rows
            .iter()
            .filter(|row| row.method == Method::Patch)
            .collect();
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].phase, Phase::Submission);
        assert_eq!(patches[0].origin, "a");
        let reads: Vec<_> = rows
            .iter()
            .filter(|row| row.phase == Phase::Recovery)
            .cloned()
            .collect();
        assert_read_only(&reads)?;
        assert!(reads
            .iter()
            .all(|row| row.origin == "b" && row.credential_header));
        assert_eq!(
            reads.iter().map(|row| row.route).collect::<Vec<_>>(),
            READ_PATHS
        );
        println!(
            "control reliability controlled evidence {}",
            json!({
                "scenario":name, "operation_id":operation, "submission":submission,
                "observed_at_unix_ms":observed.output["observed_at_unix_ms"],
                "requested_fields_match":observed.output["requested_fields_match"],
                "fixture_external_overwrite":external_change, "submission_patch":1,
                "recovery_modifications":0, "witnesses":rows
            })
        );
    }
    Ok(())
}

#[tokio::test]
async fn package_consumer_rejects_input_without_sending_a_new_change() -> TestResult {
    let executable = app_executable()?;
    let root = private_tree()?;
    let journal = journal_path(root.path())?;
    let witness = Witness::new();
    let device = simulator(FIXTURE_DEVICE, true, true);
    let first = controlled_origin("a", &witness, &device).await?;

    let receipt = journal.join("receipt.json");
    std::fs::create_dir(&receipt)?;
    let denied = launch_app(
        &executable,
        "submit",
        &journal,
        &app_submission(&first.url()),
    )
    .await?;
    assert_application_failure(&denied, "receipt_storage");
    assert_eq!(denied.output["submission"], "not_submitted");
    assert!(!device.applied.load(Ordering::SeqCst));
    let denied_id = denied.operation_id()?;
    let initial_requests = witness.rows()?;
    assert!(initial_requests.iter().all(|request| {
        request.phase == Phase::Submission
            && request.method == Method::Get
            && request.route.path().is_some()
            && request.delivery == Delivery::ResponseSent
    }));
    witness.recovery()?;

    std::fs::remove_dir(&receipt)?;
    std::fs::write(&receipt, b"{broken receipt}")?;
    let corrupt = launch_app(
        &executable,
        "observe",
        &journal,
        &app_connection(&first.url()),
    )
    .await?;
    assert_application_failure(&corrupt, "invalid_receipt");
    assert_eq!(witness.rows()?.len(), initial_requests.len());
    assert!(!device.applied.load(Ordering::SeqCst));
    let unchanged = Client::connect(options(
        first.address(),
        ApiKey::new(FIXTURE_KEY)?,
        DeviceId::parse(FIXTURE_DEVICE)?,
    )?)
    .await?;
    assert_eq!(
        unchanged.gui_listener().await?.address.tcp_authority(),
        Some(CONTROLLED_BEFORE)
    );
    let requests = witness.rows()?;
    assert_read_only(&requests[initial_requests.len()..])?;
    println!(
        "control reliability controlled evidence {}",
        json!({
            "scenario":"receipt_storage_failed_and_invalid_readback",
            "operation_id":denied_id,
            "preflight_submission":"not_submitted", "preflight_patch":0,
            "invalid_receipt_requests":0, "old_configuration_still_present":true,
            "witnesses":requests
        })
    );
    Ok(())
}

async fn seed_unanswered_receipt(
    executable: &Path,
    journal: &Path,
) -> TestResult<(String, Witness, Origin)> {
    let witness = Witness::new();
    let origin = controlled_origin("a", &witness, &simulator(FIXTURE_DEVICE, false, false)).await?;
    let submitted = launch_app(
        executable,
        "submit",
        journal,
        &app_submission(&origin.url()),
    )
    .await?;
    assert_eq!(submitted.code, 2);
    assert_eq!(submitted.output["submission"], "possibly_submitted");
    let previous = witness.rows()?;
    assert_eq!(
        previous
            .iter()
            .filter(|request| request.method == Method::Patch)
            .count(),
        1
    );
    witness.recovery()?;
    Ok((submitted.operation_id()?.to_owned(), witness, origin))
}

#[tokio::test]
async fn package_consumer_preserves_uncertainty_for_wrong_and_unreachable_targets() -> TestResult {
    let executable = app_executable()?;
    let root = private_tree()?;
    let journal = journal_path(root.path())?;
    let (operation, witness, old) = seed_unanswered_receipt(&executable, &journal).await?;
    let saved = std::fs::read(journal.join("receipt.json"))?;
    let alternate = simulator(ALTERNATE_DEVICE, false, false);
    let wrong = controlled_origin("wrong_b", &witness, &alternate).await?;
    let rejected = launch_app(
        &executable,
        "observe",
        &journal,
        &app_connection(&wrong.url()),
    )
    .await?;
    assert_application_failure(&rejected, "identity_mismatch");
    assert_eq!(rejected.operation_id()?, operation);
    assert_eq!(rejected.output["submission"], "possibly_submitted");
    let before = witness.rows()?;
    let reads: Vec<_> = before
        .iter()
        .filter(|row| row.phase == Phase::Recovery)
        .cloned()
        .collect();
    assert_read_only(&reads)?;
    assert_eq!(
        reads.iter().map(|row| row.route).collect::<Vec<_>>(),
        [Route::Version, Route::Identity]
    );
    assert!(reads.iter().all(|row| row.origin == "wrong_b"));
    assert!(!alternate.applied.load(Ordering::SeqCst));

    // The caller explicitly makes two attempts using isolated bound sockets
    // which never answer an HTTP request. There is no automatic endpoint fallback.
    let a_unreachable = reserved()?;
    let b_unreachable = reserved()?;
    for unreachable in [&a_unreachable, &b_unreachable] {
        let mut input = app_connection(&format!("http://{}/", unreachable.local_addr()?));
        input["timeout_ms"] = 250.into();
        let result = launch_app(&executable, "observe", &journal, &input).await?;
        assert_application_failure(&result, "transport");
        assert_eq!(result.operation_id()?, operation);
        assert_eq!(result.output["submission"], "possibly_submitted");
    }
    assert_eq!(witness.rows()?.len(), before.len());
    assert_eq!(std::fs::read(journal.join("receipt.json"))?, saved);
    drop(old);
    println!(
        "control reliability controlled evidence {}",
        json!({
            "scenario":"wrong_identity_and_two_unreachable_targets", "operation_id":operation,
            "wrong_identity_requests":reads.len(), "wrong_identity_gui_reads":0,
            "two_explicit_transport_failures":true, "observed_result":"possibly_submitted",
            "guarded_origin_modifications":0, "witnesses":before
        })
    );
    Ok(())
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn package_consumer_refuses_wrong_tls_name_before_sending_http_credentials() -> TestResult {
    let executable = app_executable()?;
    let root = private_tree()?;
    let journal = journal_path(root.path())?;
    let (operation, witness, backend) = seed_unanswered_receipt(&executable, &journal).await?;
    let mut tls = management_service::ManagementService::start(
        &root.path().join("explicit-tls"),
        backend.address().port(),
    )?;
    let endpoint = tls.endpoint(false)?;
    let mut input = app_connection(endpoint.http_url().ok_or("TLS endpoint absent")?.as_str());
    input["ca_pem"] = String::from_utf8(tls.pem()?)?.into();
    let denied = launch_app(&executable, "observe", &journal, &input).await?;
    assert_application_failure(&denied, "tls_certificate_rejected");
    assert_eq!(denied.operation_id()?, operation);
    assert_eq!(denied.output["submission"], "possibly_submitted");
    let observations = tls.observations()?;
    assert_eq!(
        observations
            .iter()
            .filter(|item| item["operation"] == "tls_rejected")
            .count(),
        1
    );
    assert!(observations
        .iter()
        .all(|item| item["operation"] != "http_forward"));
    assert!(witness
        .rows()?
        .iter()
        .all(|row| row.phase == Phase::Submission));
    tls.stop()?;
    println!(
        "control reliability controlled evidence {}",
        json!({
            "scenario":"named_tls_refused_before_http", "operation_id":operation,
            "tls_handshake_rejections":1, "forwarded_http_requests":0,
            "credential_requests":0, "plain_http_fallback":false, "fixture_cleaned":true
        })
    );
    Ok(())
}

#[tokio::test]
async fn native_old_owner_generation_cannot_shutdown_restarted_same_device() -> TestResult {
    let root = private_tree()?;
    let reservation = reserved()?;
    let address = reservation.local_addr()?;
    drop(reservation);
    let mut core = owned_core(root.path(), address).await?;
    let original_pid = core.process_id();
    let device = core.client().instance().device_id.clone();
    let key = core.client().gui_authentication().await?.api_key()?;
    let old_generation = core.control_generation();
    core.restart(PROGRAM_WAIT).await?;
    let restarted_pid = core.process_id();
    assert_ne!(original_pid, restarted_pid);
    assert_eq!(core.client().endpoint(), &endpoint(address)?);
    assert_eq!(core.client().instance().device_id, device);
    let new_generation = core.control_generation();
    assert!(old_generation != new_generation);

    let witness = Witness::new();
    witness.recovery()?;
    let upstream = forward_http()?;
    let observing_gate = Origin::start("generation_guard", witness.clone(), move |_, request| {
        forward_to_owned(upstream.clone(), address, request, false)
    })
    .await?;
    assert!(observing_gate.address().ip().is_loopback());

    let checked: TestResult<Value> = async {
        core.reconnect_management(options(
            observing_gate.address(),
            key.clone(),
            device.clone(),
        )?)
        .await?;
        assert_eq!(
            core.check_control_generation(&old_generation),
            ManagedGenerationStatus::Replaced
        );
        assert_eq!(
            core.check_control_generation(&new_generation),
            ManagedGenerationStatus::Current
        );
        assert!(core
            .shutdown_control_generation(&old_generation, SHORT_WAIT)
            .await
            .is_err());
        let current = core.client().observe_control_identity().await?;
        assert_eq!(current.device_id(), &device);
        assert!(current.process_generation().is_none());
        let owned = core.observe_owned_control_identity().await?;
        assert_eq!(owned.device_id(), &device);
        assert_eq!(owned.process_generation(), Some(&new_generation));
        assert_eq!(core.process_id(), restarted_pid);
        let rows = witness.rows()?;
        assert_read_only(&rows)?;
        Ok(json!({
            "scenario":"same_device_and_address_new_owned_generation",
            "owned_process_instances_differ":true,
            "original_handle_rejected":true,
            "replacement_device_identity_matches":true,
            "owned_observation_matches_replacement_generation":true,
            "borrowed_process_generation":"unknown",
            "recovery_modifications":0,
            "witnesses":rows
        }))
    }
    .await;
    core.reconnect_management(options(address, key, device)?)
        .await?;
    let exit = confirmed_exit(&mut core).await;
    let mut report = checked?;
    exit?;
    report["owned_normal_exit_and_state_release"] = true.into();
    println!("control reliability native evidence {report}");
    Ok(())
}

#[tokio::test]
async fn native_delete_reply_loss_and_reregistration_are_separate_facts() -> TestResult {
    use control_native_request_log::LogWindow;
    use verysync_sidecar::{
        CreateDeviceOptions, DevicePatch, RawMethod, RawRequest, RequestEffect,
    };

    let executable = app_executable()?;
    let root = private_tree()?;
    let owner_port = reserved()?;
    let peer_port = reserved()?;
    let owner_address = owner_port.local_addr()?;
    let peer_address = peer_port.local_addr()?;
    drop(owner_port);
    drop(peer_port);
    let mut owner = owned_core(root.path(), owner_address).await?;
    let peer_fixture = root.path().join("owned-peer");
    std::fs::create_dir(&peer_fixture)?;
    let mut peer_owner = owned_core(&peer_fixture, peer_address).await?;
    let peer = peer_owner.client().instance().device_id.clone();
    confirmed_exit(&mut peer_owner).await?;

    let report: TestResult<Value> = async {
        let id = owner.client().instance().device_id.clone();
        let before_generation = owner.control_generation();
        let configuration = owner.client().configuration().await?;
        let key = configuration.native_document()["gui"]["apiKey"]
            .as_str()
            .ok_or("isolated native key absent")?;
        let data = root.path().join("retained-device-files");
        std::fs::create_dir(&data)?;
        let sample = data.join("fixture.txt");
        std::fs::write(&sample, RETAINED_FILE)?;
        let folder = FolderId::parse("device-recovery-fixture")?;
        let registration =
            CreateDeviceOptions::new(peer.clone()).settings(DevicePatch::default().paused(true));
        owner.client().create_device(&registration).await?;
        let created = owner
            .client()
            .create_folder(
                &CreateFolderOptions::new(folder.clone(), TargetPath::local(&data)).paused(true),
            )
            .await?;
        let mut devices = created.extra["devices"]
            .as_array()
            .cloned()
            .ok_or("native folder associations absent")?;
        devices.push(json!({"deviceID": peer.as_str()}));
        let attach = RawRequest::new(
            RawMethod::Patch,
            ["rest", "config", "folders", folder.as_str()],
            RequestEffect::MayModify,
        )?
        .json_body(&json!({"devices":devices}))?;
        let result = owner.client().raw_request(&attach).await?;
        assert!((200..300).contains(&result.status()));

        let journal = journal_path(root.path())?;
        let witness = Witness::new();
        let forwarder = forward_http()?;
        let origin = Origin::start_for_peer(
            "device_a",
            witness.clone(),
            Some(peer.clone()),
            move |_, request: Request| {
                let lose_reply = request.method == Method::Delete;
                forward_to_owned(forwarder.clone(), owner_address, request, lose_reply)
            },
        )
        .await?;
        let removed = launch_app(
            &executable,
            "remove-device",
            &journal,
            &json!({
                "endpoint": origin.url(), "api_key": key, "expected_device_id": id.as_str(),
                "peer_id": peer.as_str(), "event_log": true
            }),
        )
        .await?;
        assert_eq!(removed.code, 2);
        assert_eq!(removed.output["submission"], "possibly_submitted");
        assert!(!owner
            .client()
            .devices()
            .await?
            .iter()
            .any(|item| item.device_id == peer));
        assert_eq!(std::fs::read(&sample)?, RETAINED_FILE);

        owner.restart(PROGRAM_WAIT).await?;
        assert_eq!(owner.client().instance().device_id, id);
        assert_ne!(owner.control_generation(), before_generation);
        control_native_request_log::enable(owner.client()).await?;
        witness.recovery()?;
        let observe_input = json!({
            "endpoint": format!("http://{owner_address}/"), "api_key": key,
            "expected_device_id": id.as_str()
        });
        let checkpoint = std::fs::read(journal.join("receipt.json"))?;
        let window = LogWindow::new(owner.state_directory(), owner_address, key)?;
        window.open().await?;
        let absent = launch_app(&executable, "observe-device", &journal, &observe_input).await?;
        let first_reads = window.close().await?;
        assert_eq!(absent.code, 0);
        assert_eq!(absent.operation_id()?, removed.operation_id()?);
        assert_eq!(absent.output["submission"], "possibly_submitted");
        assert_eq!(absent.output["configuration_absent"], true);
        assert_eq!(absent.output["remaining_folder_count"], 0);

        // An independent owner action registers the same ID again outside both
        // observation windows. An old receipt must report the new live state.
        owner.client().create_device(&registration).await?;
        let window = LogWindow::new(owner.state_directory(), owner_address, key)?;
        window.open().await?;
        let returned = launch_app(&executable, "observe-device", &journal, &observe_input).await?;
        let second_reads = window.close().await?;
        assert_eq!(returned.code, 0);
        assert_eq!(returned.operation_id()?, removed.operation_id()?);
        assert_eq!(returned.output["submission"], "possibly_submitted");
        assert_eq!(returned.output["configuration_absent"], false);
        assert_eq!(std::fs::read(journal.join("receipt.json"))?, checkpoint);
        for observation in [&first_reads, &second_reads] {
            assert_eq!(
                observation["ordered_reads"],
                json!([
                    Route::Version,
                    Route::Identity,
                    Route::Identity,
                    Route::RegistrationConfig,
                    Route::Version,
                    Route::Identity
                ])
            );
            assert_eq!(observation["modifications_received"], 0);
        }
        let rows = witness.rows()?;
        let changes = rows
            .iter()
            .filter(|row| row.method != Method::Get)
            .collect::<Vec<_>>();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].method, Method::Delete);
        assert_eq!(changes[0].route, Route::Peer);
        assert_eq!(changes[0].phase, Phase::Submission);
        assert_eq!(changes[0].delivery, Delivery::DroppedAfterBackendResponse);
        assert!(changes[0]
            .backend_status
            .is_some_and(|status| (200..300).contains(&status)));
        assert!(owner.client().folder(&folder).await?.paused);
        assert_eq!(std::fs::read(&sample)?, RETAINED_FILE);
        Ok(json!({
            "scenario":"native_device_removal_reply_lost", "operation_id": removed.operation_id()?,
            "delete_requests": 1, "absence_verified_after_core_restart": true,
            "later_registration_detected": true, "original_outcome": "possibly_submitted",
            "recovery_observations": [first_reads, second_reads],
            "bytes_and_folder_preserved": true, "witnesses": rows
        }))
    }
    .await;
    let exit = confirmed_exit(&mut owner).await;
    let mut report = report?;
    exit?;
    report["owned_cleanup_verified"] = true.into();
    println!("control reliability native evidence {report}");
    Ok(())
}

#[tokio::test]
async fn native_shutdown_once_observes_late_exit_or_expiry_of_the_same_generation() -> TestResult {
    use std::sync::atomic::AtomicUsize;
    use verysync_sidecar::{Error, ManagedExitObservationOutcome};

    for forward in [true, false] {
        let root = private_tree()?;
        let reservation = reserved()?;
        let address = reservation.local_addr()?;
        drop(reservation);
        let mut owner = owned_core(root.path(), address).await?;
        let original_pid = owner.process_id();
        let generation = owner.control_generation();
        let device = owner.client().instance().device_id.clone();
        let key = owner.client().gui_authentication().await?.api_key()?;
        let witness = Witness::new();
        let forwarded = Arc::new(AtomicUsize::new(0));
        let count = forwarded.clone();
        let upstream = forward_http()?;
        let origin = Origin::start_shutdown(witness.clone(), move |_, request| {
            let client = upstream.clone();
            let count = count.clone();
            async move {
                if request.route != Route::Shutdown {
                    return forward_to_owned(client, address, request, false).await;
                }
                // The proxy receives the actual request within the first
                // wait. Only the task-owned HTTP peer delays forwarding it.
                tokio::time::sleep(Duration::from_millis(1500)).await;
                if forward {
                    count.fetch_add(1, Ordering::SeqCst);
                    forward_to_owned(client, address, request, true).await
                } else {
                    Ok(Response::drop_reply(None))
                }
            }
        })
        .await?;
        owner
            .reconnect_management(options(origin.address(), key.clone(), device.clone())?)
            .await?;
        let first = Duration::from_secs(1);
        let total = if forward {
            Duration::from_secs(8)
        } else {
            Duration::from_millis(1250)
        };
        let report = owned_shutdown::shutdown_once_observing_exit(&mut owner, first, total).await;
        assert!(matches!(report.original, Err(Error::Timeout { .. })));
        let later = report.later.ok_or("no remaining-time observation")??;
        assert_eq!(later.generation, generation);
        assert!(later.waited <= total);
        let later_kind = match later.outcome {
            ManagedExitObservationOutcome::Exited(exit) if forward => {
                assert!(
                    exit.tree_stopped
                        && exit.state_released
                        && !exit.forced
                        && exit.code == Some(0)
                );
                "original_generation_exited"
            }
            ManagedExitObservationOutcome::TimedOut if !forward => {
                assert_eq!(owner.process_id(), original_pid);
                assert_eq!(
                    owner.check_control_generation(&generation),
                    ManagedGenerationStatus::Current
                );
                "observation_expired"
            }
            other => return Err(format!("wrong later outcome: {other:?}").into()),
        };
        // A live-case proxy handler is deliberately still pending after the
        // observation. Wait for its witness before the independent teardown.
        let rows = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(rows) = witness.rows() {
                    break rows;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        assert_eq!(
            rows.iter().filter(|row| row.method != Method::Get).count(),
            1
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row.method == Method::Post && row.route == Route::Shutdown)
                .count(),
            1
        );
        assert_eq!(forwarded.load(Ordering::SeqCst), usize::from(forward));
        println!(
            "s29-shutdown {}",
            json!({
                "original":"timeout", "later":later_kind, "owned_process_id":original_pid,
                "observed_at_unix_ms":later.observed_at.duration_since(std::time::UNIX_EPOCH)?.as_millis(),
                "observation_ms":later.waited.as_millis(), "original_request_count":1,
                "forwarded_original_requests":forwarded.load(Ordering::SeqCst), "observation_requests":0,
                "request_witness":rows,
            })
        );
        if !forward {
            owner
                .reconnect_management(options(address, key, device)?)
                .await?;
            let exit = owner.shutdown(SHORT_WAIT).await?;
            assert!(
                exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0)
            );
            println!("s29-shutdown cleanup used the fixture's explicit normal stop after the observation");
        }
        drop(owner);
        root.close()?;
    }
    Ok(())
}
