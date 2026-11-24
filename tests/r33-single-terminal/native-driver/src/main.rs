mod audit_case;
mod audit_files;
mod audit_history;
mod case_receipts;
mod local_api_probe;
mod schedule;
mod selective_case;

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env,
    io::{self, BufRead, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use verysync_sidecar::{
    LicenseEntries, LicenseExpiry, LocalProgram, ManagedInstance, ManagedOptions,
    ManagementEndpoint, OfficialAccountCredentials, OfficialAccountState,
};

const ENGINE_VERSION: &str = "2.33.2";
const ENGINE_HASH: [u8; 32] = [
    0xf8, 0xe9, 0xbd, 0x67, 0xbe, 0x3f, 0xb1, 0xb4, 0x5e, 0xaf, 0xea, 0x79, 0x40, 0x08, 0xc4, 0xdf,
    0xae, 0x24, 0xae, 0xc4, 0xe1, 0x77, 0x61, 0x75, 0x78, 0xb2, 0x68, 0x59, 0x8b, 0xf1, 0x22, 0x74,
];
const START: Duration = Duration::from_secs(20);
const STOP: Duration = Duration::from_secs(10);
const RESTART: Duration = Duration::from_secs(32);
const FRAME_LIMIT: u64 = 4096;

type Stage<T> = Result<T, &'static str>;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Request {
    Login {
        username: String,
        password: String,
    },
    Inspect,
    RefreshPaid,
    RestartObservation,
    Schedule {
        trigger: schedule::Trigger,
        step: schedule::Step,
        request: String,
    },
    Audit {
        step: audit_case::Step,
        request: String,
    },
    Selective {
        step: selective_case::Step,
        request: String,
    },
    CaseReadback {
        request: String,
    },
    Logout,
    End,
}

fn record(result: Value) -> Stage<()> {
    let mut buffer = io::stdout().lock();
    serde_json::to_writer(&mut buffer, &result).map_err(|_| "receipt-unavailable")?;
    buffer.write_all(b"\n").map_err(|_| "receipt-unavailable")?;
    buffer.flush().map_err(|_| "receipt-unavailable")
}

fn private_input() -> mpsc::Receiver<Request> {
    let (tx, rx) = mpsc::channel(1);
    std::thread::spawn(move || {
        let mut reader = io::stdin().lock();
        loop {
            let mut line = Vec::new();
            let Ok(count) = reader
                .by_ref()
                .take(FRAME_LIMIT + 1)
                .read_until(b'\n', &mut line)
            else {
                return;
            };
            if count == 0 || count as u64 > FRAME_LIMIT || !line.ends_with(b"\n") {
                return;
            }
            let request = serde_json::from_slice(&line);
            line.fill(0);
            let Ok(request) = request else {
                return;
            };
            if tx.blocking_send(request).is_err() {
                return;
            }
        }
    });
    rx
}

async fn start(engine: PathBuf, root: &Path) -> Stage<ManagedInstance> {
    let state = root.join("state");
    let endpoint = ManagementEndpoint::unix_socket(state.join("gui.sock"))
        .map_err(|_| "private-endpoint-invalid")?;
    let engine = LocalProgram::new(engine)
        .map_err(|_| "engine-path-invalid")?
        .expected_sha256(ENGINE_HASH);
    let settings = ManagedOptions::new(engine, &state, endpoint)
        .and_then(|options| options.startup_timeout(START))
        .and_then(|options| options.management_request_timeout(Duration::from_secs(14)))
        .map_err(|_| "private-engine-options-invalid")?;
    ManagedInstance::start(settings)
        .await
        .map_err(|_| "private-engine-start-failed")
}

async fn end(core: &mut ManagedInstance) -> bool {
    match core.shutdown(STOP).await {
        Ok(result) => {
            result.code == Some(0) && !result.forced && result.tree_stopped && result.state_released
        }
        Err(_) => {
            let _ = core.force_stop(STOP).await;
            false
        }
    }
}

fn device_alias(core: &ManagedInstance, run: &str) -> String {
    format!(
        "{:x}",
        Sha256::new()
            .chain_update(run.as_bytes())
            .chain_update(core.client().instance().device_id.to_string().as_bytes())
            .finalize(),
    )
}

async fn inspect(core: &ManagedInstance, run: &str) -> Stage<Value> {
    let client = core.client();
    let info = client.instance();
    let reported_version = &info.version.version;
    if reported_version != ENGINE_VERSION && reported_version != "v2.33.2" {
        return Err("unexpected-engine-version");
    }
    let device = device_alias(core, run);
    let account = client
        .official_account_status()
        .await
        .map_err(|_| "official-account-read-failed")?;
    let state = match account.state() {
        OfficialAccountState::LoggedIn => "logged-in",
        OfficialAccountState::LoggedOut => "logged-out",
        OfficialAccountState::Unknown => "unknown",
    };
    let mut licenses = Vec::new();
    if let Ok(status) = client.license_status().await {
        let observed = match status.licenses() {
            Some(LicenseEntries::List(items)) => Some(items.iter().collect::<Vec<_>>()),
            Some(LicenseEntries::Map(items)) => Some(items.values().collect::<Vec<_>>()),
            _ => None,
        };
        if let Some(items) = observed {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "clock-unavailable")?;
            let now = i64::try_from(now.as_secs()).map_err(|_| "clock-unavailable")?;
            for item in items.into_iter().filter(|item| item.is_pro()) {
                licenses.push(json!({
                    "reported_trial": item.trial(),
                    "reported_expiry_unix_seconds": item.expires_unix_seconds(),
                    "expiry_observation": match item.expiry_at(now) {
                        Some(LicenseExpiry::Perpetual) => "perpetual",
                        Some(LicenseExpiry::NotExpired) => "not-expired",
                        Some(LicenseExpiry::Expired) => "expired",
                        None => "unreported",
                    },
                }));
            }
        }
    }
    Ok(json!({
        "ok": true, "account": state, "device": device, "version": ENGINE_VERSION,
        "arch": env::consts::ARCH, "pro_observations": licenses,
    }))
}

async fn paid_native_permission(core: &ManagedInstance, run: &str) -> Stage<()> {
    let observed = inspect(core, run).await?;
    if observed["account"] != "logged-in" {
        return Err("dedicated-official-session-not-confirmed");
    }
    let valid = observed["pro_observations"]
        .as_array()
        .is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry["reported_trial"] == false
                    && matches!(
                        entry["expiry_observation"].as_str(),
                        Some("perpetual" | "not-expired")
                    )
            })
        });
    if !valid {
        return Err("dedicated-paid-license-not-confirmed");
    }
    Ok(())
}

async fn refresh_paid(core: &ManagedInstance, root: &Path, run: &str) -> Stage<Value> {
    let before = inspect(core, run).await?;
    if before["account"] != "logged-in" {
        return Err("dedicated-paid-account-not-signed-in");
    }
    schedule::check_authorization(&root.join(schedule::GRANT_REVOKED))?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("paid-fetch-submitted"))
        .and_then(|receipt| receipt.sync_all())
        .map_err(|_| "paid-refresh-already-submitted")?;
    let sentinel = b"R33 owned paid license persistence sample\\n";
    std::fs::write(root.join("paid-sentinel"), sentinel).map_err(|_| "sentinel-setup-failed")?;
    let acknowledged = core.client().fetch_licenses().await.is_ok();
    let after = inspect(core, run).await?;
    Ok(json!({"ok":acknowledged,"device":after["device"],
              "refresh_acknowledged":acknowledged,
              "previous_pro_observations":before["pro_observations"],
              "actual_pro_observations":after["pro_observations"],
              "native_fields_read_independently":true}))
}

async fn restart_observation(core: &mut ManagedInstance, root: &Path, run: &str) -> Stage<Value> {
    let before = inspect(core, run).await?;
    if before["account"] != "logged-in" {
        return Err("dedicated-paid-account-not-signed-in");
    }
    let sentinel = root.join("paid-sentinel");
    let data = std::fs::read(&sentinel).map_err(|_| "paid-sentinel-missing")?;
    let process = core.process_id();
    core.restart(RESTART)
        .await
        .map_err(|_| "native-restart-failed")?;
    let after = inspect(core, run).await?;
    let retained = std::fs::read(&sentinel).is_ok_and(|bytes| bytes == data);
    Ok(
        json!({"ok":before["device"]==after["device"] && retained && process!=core.process_id(),
              "device":after["device"],"new_process":process!=core.process_id(),
              "same_device":before["device"]==after["device"],
              "sentinel_preserved":retained,"account_after_restart":after["account"],
              "before":before["pro_observations"],"after":after["pro_observations"]}),
    )
}

async fn logout(core: &mut ManagedInstance) -> Stage<Value> {
    let device = core.client().instance().device_id.clone();
    let acknowledged = core
        .client()
        .logout_official_account()
        .await
        .is_ok_and(|change| change.expected_state_matches);
    let retained = if acknowledged && core.restart(RESTART).await.is_ok() {
        core.client().instance().device_id == device
            && core
                .client()
                .official_account_status()
                .await
                .is_ok_and(|status| status.state() == OfficialAccountState::LoggedOut)
    } else {
        false
    };
    Ok(json!({"ok": acknowledged && retained,
              "native_logout_readback": acknowledged, "persisted_after_restart": retained}))
}

async fn serve(engine: PathBuf, root: &Path, run: &str) -> Stage<()> {
    let mut audit_case = audit_case::AuditCase::new(&engine, root);
    let mut selective = selective_case::LicensedCase::new(&engine, root);
    let mut core = start(engine, root).await?;
    let mut requests = private_input();
    let initial = inspect(&core, run).await;
    if let Err(reason) = initial {
        let normal_exit = end(&mut core).await;
        record(json!({"ok": false,"code": reason,"normal_owned_exit": normal_exit}))?;
        return Ok(());
    }
    let mut login_submitted = false;
    let mut retained_result = None;
    let mut scheduler = schedule::Scheduler::new(root);
    let case_receipts = case_receipts::Receipts::new(root);
    if record(initial?).is_ok() {
        while let Some(request) = requests.recv().await {
            let result = match request {
                Request::Login { username, password } if !login_submitted => {
                    login_submitted = true;
                    let outcome = match OfficialAccountCredentials::new(username, password) {
                        Ok(credentials) => core
                            .client()
                            .login_official_account(&credentials)
                            .await
                            .is_ok_and(|change| change.expected_state_matches),
                        Err(_) => false,
                    };
                    inspect(&core, run).await.map(|mut read| {
                        read["login_acknowledged"] = json!(outcome);
                        read
                    })
                }
                Request::Login { .. } => Err("login-already-submitted"),
                Request::Inspect => inspect(&core, run).await,
                Request::RefreshPaid => refresh_paid(&core, root, run).await,
                Request::RestartObservation => restart_observation(&mut core, root, run).await,
                Request::Schedule {
                    trigger,
                    step,
                    request,
                } => {
                    let authorization =
                        if matches!(step, schedule::Step::Prepare | schedule::Step::Seed) {
                            paid_native_permission(&core, run).await
                        } else {
                            Ok(())
                        };
                    let observed = if let Err(code) = authorization {
                        Err(code)
                    } else if !case_receipts.valid(&request) {
                        Err("owned-case-request-invalid")
                    } else if matches!(step, schedule::Step::Observe) {
                        scheduler.run(core.client(), trigger, step, &request).await
                    } else if let Err(code) = case_receipts.begin(&request) {
                        Err(code)
                    } else {
                        let result = scheduler
                            .run(core.client(), trigger, step, &request)
                            .await
                            .unwrap_or_else(|code| json!({"ok":false,"code":code}));
                        case_receipts.finish(&request, &result).map(|()| result)
                    };
                    observed.map(|mut value| {
                        value["device"] = json!(device_alias(&core, run));
                        value["native_core_pid"] = json!(core.process_id());
                        value
                    })
                }
                Request::Audit { step, request } => {
                    let authorization = if matches!(
                        step,
                        audit_case::Step::Prepare
                            | audit_case::Step::Record
                            | audit_case::Step::Reset
                    ) {
                        paid_native_permission(&core, run).await
                    } else {
                        Ok(())
                    };
                    let observed = if let Err(code) = authorization {
                        Err(code)
                    } else if !case_receipts.valid(&request) {
                        Err("owned-case-request-invalid")
                    } else if matches!(step, audit_case::Step::Observe) {
                        audit_case.apply(step, &core, run).await
                    } else if let Err(code) = case_receipts.begin(&request) {
                        Err(code)
                    } else {
                        let result = audit_case
                            .apply(step, &core, run)
                            .await
                            .unwrap_or_else(|code| json!({"ok":false,"code":code}));
                        case_receipts.finish(&request, &result).map(|()| result)
                    };
                    observed.map(|mut value| {
                        value["device"] = json!(device_alias(&core, run));
                        value["native_core_pid"] = json!(core.process_id());
                        value
                    })
                }
                Request::Selective { step, request } => {
                    let authorization = if step == selective_case::Step::Finish {
                        Ok(())
                    } else {
                        paid_native_permission(&core, run).await
                    };
                    let observed = if let Err(code) = authorization {
                        Err(code)
                    } else if !case_receipts.valid(&request) {
                        Err("owned-case-request-invalid")
                    } else if let Err(code) = case_receipts.begin(&request) {
                        Err(code)
                    } else {
                        let result = selective
                            .apply(step, &core, run)
                            .await
                            .unwrap_or_else(|code| json!({"ok":false,"code":code}));
                        case_receipts.finish(&request, &result).map(|()| result)
                    };
                    observed.map(|mut value| {
                        value["device"] = json!(device_alias(&core, run));
                        value["native_core_pid"] = json!(core.process_id());
                        value
                    })
                }
                Request::CaseReadback { request } => case_receipts.read(&request),
                Request::Logout => {
                    let schedules = scheduler.cleanup(core.client()).await;
                    let audit = audit_case.cleanup(core.client()).await;
                    let peer = selective.cleanup(core.client()).await;
                    logout(&mut core).await.map(|mut observed| {
                        if let Err(code) = schedules.and(audit).and(peer) {
                            observed["ok"] = json!(false);
                            observed["fixture_cleanup"] = json!(code);
                        }
                        observed
                    })
                }
                Request::End => {
                    let audit_stopped = audit_case.stop_peer().await.is_ok();
                    let peer_stopped =
                        selective.cleanup(core.client()).await.is_ok() && audit_stopped;
                    retained_result = Some(end(&mut core).await && peer_stopped);
                    break;
                }
            };
            let observed = result.unwrap_or_else(|code| json!({"ok":false,"code":code}));
            if record(observed).is_err() {
                break;
            }
        }
    }
    // On parent death or pipe loss stop only the owned instance. Its private
    // state remains for operator recovery if the cloud session is unconfirmed.
    let normal_exit = match retained_result {
        Some(result) => result,
        None => {
            let audit_stopped = audit_case.stop_peer().await.is_ok();
            let peer_stopped = selective.cleanup(core.client()).await.is_ok() && audit_stopped;
            end(&mut core).await && peer_stopped
        }
    };
    if retained_result.is_some() {
        record(json!({"ok":normal_exit, "normal_owned_exit":normal_exit}))?;
    }
    Ok(())
}

async fn audit_archive_control(engine: &Path, root: &Path, run: &str) -> Stage<()> {
    let mut receiver = start(engine.to_path_buf(), root).await?;
    let evidence = async {
        let before = inspect(&receiver, run).await?;
        let audit = receiver
            .client()
            .audit_history_settings()
            .await
            .map_err(|_| "control-audit-configuration-unavailable")?;
        if audit.enabled || before["account"] != "logged-out" {
            return Err("audit-archive-control-requires-a-free-isolated-instance");
        }
        let mut witness =
            audit_files::ArchiveWitness::prepare(engine, root, &receiver, run).await?;
        let pair = async {
            let first = witness.archive_revisions(receiver.client()).await?;
            witness.quiesce(receiver.client()).await?;
            let repeated = witness.snapshot(receiver.client()).await?;
            if first != repeated {
                return Err("audit-archive-census-changed-after-peer-stop");
            }
            let page = audit_history::empty_view(receiver.client()).await?;
            let no_owned_history = audit_history::owned_pages(
                receiver.client(),
                witness.folder_id(),
                witness.named_samples(),
            )
            .await;
            if no_owned_history != Err("audit-native-more-than-one-page-unverified") {
                return Err("audit-archive-control-found-unexpected-audit-history");
            }
            Ok(
                json!({"ok":true, "folder":"synthetic-two-peer-archive", "native":before,
                     "owned_registered_samples":witness.named_samples(),
                     "archive_census_before_source_stop":first,
                     "archive_census_after_source_stop":repeated,
                     "source_normal_owned_exit":true,"free_audit_page":page,
                     "positive_audit_gate_refused_without_nonempty_native_records":true}),
            )
        }
        .await;
        witness.stop_source().await?;
        pair
    }
    .await;
    let stopped = end(&mut receiver).await;
    if !stopped {
        return Err("audit-receiver-normal-owned-exit-unverified");
    }
    let mut evidence = evidence?;
    evidence["receiver_normal_owned_exit"] = json!(true);
    record(evidence)
}

fn network_control(allowed: &str, forbidden: &str) -> Stage<()> {
    let socket = |port: &str| {
        port.parse::<u16>()
            .map(|port| SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .map_err(|_| "network-check-argument-invalid")
    };
    let permitted = TcpStream::connect_timeout(&socket(allowed)?, Duration::from_secs(2)).is_ok();
    let protected =
        TcpStream::connect_timeout(&socket(forbidden)?, Duration::from_secs(2)).is_err();
    if !permitted || !protected {
        return Err("isolated-network-control-failed");
    }
    record(json!({"ok":true,"fixed_egress_control":true}))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [operation, allowed, forbidden] if operation == "net-check" => {
            network_control(&allowed.to_string_lossy(), &forbidden.to_string_lossy())
        }
        [operation, engine, root, run] if operation == "audit-archive-control" => {
            match run.to_str() {
                Some(run) if run.len() == 32 && run.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    audit_archive_control(Path::new(engine), Path::new(root), run).await
                }
                _ => Err("audit-owned-run-invalid"),
            }
        }
        [operation, engine, root, run]
            if operation == "selective-free-control"
                || operation == "selective-audit-transition-control" =>
        {
            match run.to_str() {
                Some(run) if run.len() == 32 && run.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    selective_case::free_native_control(
                        Path::new(engine),
                        Path::new(root),
                        run,
                        operation == "selective-audit-transition-control",
                    )
                    .await
                }
                _ => Err("selective-owned-run-invalid"),
            }
        }
        [operation, engine, root, run] if operation == "local-api-free-control" => {
            match run.to_str() {
                Some(run) if run.len() == 32 && run.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    local_api_probe::signed_out_control(Path::new(engine), Path::new(root), run)
                        .await
                }
                _ => Err("local-api-owned-run-invalid"),
            }
        }
        [operation, engine, root, run] if operation == "serve" => {
            serve(
                PathBuf::from(engine),
                Path::new(root),
                &run.to_string_lossy(),
            )
            .await
        }
        _ => Err("private-driver-arguments-invalid"),
    };
    if let Err(code) = result {
        let _ = record(json!({"ok":false,"code":code}));
        std::process::exit(2);
    }
}
