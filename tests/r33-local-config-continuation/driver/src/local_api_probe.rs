//! Evidence-only Local-API qualification for the fixed native instance.

use crate::{
    check_authorization, end, inspect, logout, paid_native_permission, private_input, record,
    refresh_paid, Request, Stage, ENGINE_HASH, START,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};
use verysync_sidecar::{
    CreateFolderOptions, DeviceId, Error, FolderId, LocalApiClient, LocalApiConnectOptions,
    LocalProgram, ManagedInstance, ManagedOptions, ManagementEndpoint, OfficialAccountCredentials,
    TargetPath,
};

mod configuration;
#[path = "r33_local_api_qualification.rs"]
mod qualification;

async fn folder_qualification(
    local: &LocalApiClient,
    folder: &FolderId,
    path: &TargetPath,
) -> Value {
    use qualification::Qualification;
    match qualification::observe(local, folder, path).await {
        Qualification::Eligible => {
            json!({"route":"LA-012","state":"exact-folder-readback","exact_id":true,"exact_path":true})
        }
        Qualification::ReadbackMismatch {
            exact_id,
            exact_path,
        } => {
            json!({"route":"LA-012","state":"readback-mismatch","exact_id":exact_id,"exact_path":exact_path})
        }
        Qualification::LicenseRequired { code, http } => {
            json!({"route":"LA-012","state":"license-required","code":code,"http":http})
        }
        Qualification::HttpFailure { http } => {
            json!({"route":"LA-012","state":"http-failure","http":http})
        }
        Qualification::Unconfirmed => json!({"route":"LA-012","state":"typed-read-failed"}),
    }
}

pub(crate) fn owned_endpoint() -> Stage<ManagementEndpoint> {
    let port = env::var("R33_LOCAL_API_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|&port| port >= 1024 && port != 18886)
        .ok_or("local-api-needs-an-explicit-owned-loopback-port")?;
    ManagementEndpoint::http(&format!(
        "http://{}/",
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    ))
    .map_err(|_| "local-api-test-endpoint-invalid")
}

pub(crate) async fn start(
    engine: &Path,
    root: &Path,
) -> Stage<(ManagedInstance, ManagementEndpoint)> {
    let endpoint = owned_endpoint()?;
    let program = LocalProgram::new(engine.to_path_buf())
        .map_err(|_| "local-api-fixed-engine-path-unavailable")?
        .expected_sha256(ENGINE_HASH);
    let settings = ManagedOptions::new(program, root.join("state"), endpoint.clone())
        .and_then(|options| options.startup_timeout(START))
        .and_then(|options| options.management_request_timeout(Duration::from_secs(14)))
        .and_then(|options| options.local_api_enabled(true))
        .map_err(|_| "local-api-fixed-native-options-unavailable")?;
    let core = ManagedInstance::start(settings)
        .await
        .map_err(|_| "local-api-owned-start-failed")?;
    Ok((core, endpoint))
}

async fn qualify(
    root: &Path,
    core: &ManagedInstance,
    endpoint: ManagementEndpoint,
    run: &str,
) -> Stage<(Value, Option<DeviceId>)> {
    check_authorization(root)?;
    let account = paid_native_permission(core, run).await?;
    let managed = core.client();
    if !managed
        .folders()
        .await
        .map_err(|_| "local-api-owned-registry-unavailable")?
        .is_empty()
    {
        return Err("local-api-test-needs-an-empty-owned-native-registry");
    }
    let selected = root.join("synthetic");
    fs::create_dir(&selected).map_err(|_| "local-api-private-fixture-unavailable")?;
    let input = selected.join("read-qualification.bin");
    let outside = root.join("untouched-control.bin");
    fs::write(&input, format!("local API qualification {run}\n"))
        .map_err(|_| "local-api-fixture-file-unavailable")?;
    fs::write(&outside, b"unrelated synthetic local API sentinel")
        .map_err(|_| "local-api-control-file-unavailable")?;
    let snapshot =
        || -> Stage<Vec<Value>> {
            [&input, &outside].iter().map(|path| {
            let bytes = fs::read(path).map_err(|_| "local-api-private-sample-read-unavailable")?;
            Ok(json!({"bytes":bytes.len(),"sha256":format!("{:x}", Sha256::digest(&bytes))}))
        }).collect()
        };
    let before = snapshot()?;
    let folder = FolderId::parse(configuration::FIRST_ID)
        .map_err(|_| "local-api-owned-folder-id-invalid")?;
    managed
        .create_folder(
            &CreateFolderOptions::new(folder.clone(), TargetPath::local(&selected)).paused(true),
        )
        .await
        .map_err(|_| "local-api-owned-folder-preparation-failed")?;

    let expected = managed.instance().device_id.clone();
    let local = LocalApiClient::connect(
        LocalApiConnectOptions::new(endpoint)
            .map_err(|_| "local-api-ordinary-options-unavailable")?
            .expected_device_id(expected.clone()),
    )
    .await
    .map_err(|_| "local-api-ordinary-handshake-failed")?;
    let status = local
        .system_status()
        .await
        .map_err(|_| "local-api-ordinary-status-unavailable")?;
    let version = local
        .version()
        .await
        .map_err(|_| "local-api-ordinary-version-unavailable")?;
    let ordinary = local
        .folders()
        .await
        .map_err(|_| "local-api-ordinary-folders-unavailable")?;
    if status.device_id != expected {
        return Err("local-api-ordinary-device-identity-unconfirmed");
    }
    if version.version != verysync_sidecar::BASELINE_ENGINE_VERSION {
        return Err("local-api-ordinary-engine-version-unconfirmed");
    }
    if ordinary.len() != 1 || ordinary[0].id != folder {
        return Err("local-api-ordinary-folder-projection-unconfirmed");
    }
    check_authorization(root)?;
    let primary = folder_qualification(&local, &folder, &TargetPath::local(&selected)).await;
    let after_account = paid_native_permission(core, run).await?;
    let after = snapshot()?;
    if before != after {
        return Err("local-api-read-qualification-affected-sample-data");
    }
    let same_device = account["device"] == after_account["device"];
    let config_device =
        (same_device && primary["state"] == "exact-folder-readback").then_some(expected);
    Ok((
        json!({"ok":true,"fixed_native_account_observation":account,
              "ordinary_status_and_folder_projection":true,"protected_read_routes":[primary],
              "original_files":before,"files_after_actual_reads":after,"protected_writes":0,
              "same_paid_device_after_read":same_device}),
        config_device,
    ))
}

#[cfg(target_os = "linux")]
fn private_linux_namespace() -> Stage<()> {
    use std::os::unix::fs::MetadataExt;

    let own = fs::metadata("/proc/self/ns/net").map_err(|_| "private-network-identity-missing")?;
    let outer = env::var("R33_OUTER_NETWORK_INODE")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|inode| *inode > 0)
        .ok_or("outer-network-identity-missing")?;
    let proc = fs::metadata("/proc/self").map_err(|_| "private-worker-identity-missing")?;
    let interfaces =
        fs::read_to_string("/proc/net/dev").map_err(|_| "private-network-inventory-missing")?;
    let names = interfaces
        .lines()
        .skip(2)
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim()))
        .collect::<Vec<_>>();
    if own.ino() == outer || proc.uid() == 0 || names != ["lo"] {
        return Err("licensed-local-api-needs-private-linux-loopback");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn private_linux_namespace() -> Stage<()> {
    Err("licensed-local-api-needs-private-linux-loopback")
}

pub(crate) async fn serve_qualification(
    engine: &Path,
    root: &Path,
    run: &str,
    control: bool,
) -> Stage<()> {
    if !control {
        private_linux_namespace()?;
    }
    let (mut core, endpoint) = start(engine, root).await?;
    let processing: Stage<Value> = async {
        let initial = inspect(&core, run).await?;
        if initial["account"] != "logged-out" {
            return Err("local-api-start-did-not-confirm-an-empty-account");
        }
        record(initial)?;
        let mut incoming = private_input();
        let mut login_submitted = false;
        let mut operation_consumed = false;
        let mut config_device = None;
        let mut native_logout = None;
        while let Some(request) = incoming.recv().await {
            let observed = match request {
                Request::Inspect => inspect(&core, run).await,
                Request::Login { username, password } if !control && !login_submitted => {
                    login_submitted = true;
                    let (acknowledged, outcome) = match OfficialAccountCredentials::new(username, password) {
                        Ok(credentials) => match core.client().login_official_account(&credentials).await {
                            Ok(result) => (result.expected_state_matches,json!({"stage":"native-acknowledgment"})),
                            Err(Error::OfficialAccountRejected {code,response}) =>
                                (false,json!({"stage":"native-rejection","code":code,"http":response.status()})),
                            Err(Error::MutationOutcomeUnknown {..}) => (false,json!({"stage":"outcome-unknown"})),
                            Err(_) => (false,json!({"stage":"management-failure"})),
                        },
                        Err(_) => (false,json!({"stage":"input-unavailable"})),
                    };
                    inspect(&core, run).await.map(|mut current| {
                        current["login_acknowledged"] = json!(acknowledged);
                        current["login_native_result"] = outcome;
                        current
                    })
                }
                Request::RefreshPaid if login_submitted && native_logout.is_none() => {
                    refresh_paid(&core, root, run).await
                }
                Request::LocalApiQualify if !operation_consumed => {
                    // The target and protected route are fixed inside qualify.
                    // An uncertain response must never dispatch this step again.
                    operation_consumed = true;
                    qualify(root, &core, endpoint.clone(), run).await.map(|(receipt, device)| {
                        config_device = device;
                        receipt
                    })
                }
                Request::LocalApiConfigVerify if !control && login_submitted && native_logout.is_none() => {
                    match config_device.take() {
                        Some(device) => configuration::verify(
                            root, &mut core, endpoint.clone(), run, &device
                        ).await,
                        None => Err("local-api-exact-qualification-required"),
                    }
                }
                Request::Logout if login_submitted && native_logout.is_none() => {
                    let outcome = logout(&mut core).await;
                    native_logout = Some(outcome.clone());
                    outcome
                }
                Request::End => break,
                _ => Err("operation-outside-the-licensed-local-api-scope"),
            };
            let safe = observed.unwrap_or_else(|reason| json!({"ok":false,"reason":reason}));
            if record(safe).is_err() {
                break;
            }
        }
        if login_submitted && native_logout.is_none() {
            native_logout = Some(logout(&mut core).await);
        }
        Ok(
            json!({"login_submitted":login_submitted,"native_logout":native_logout.transpose()?,
                  "qualification_consumed":operation_consumed}),
        )
    }
    .await;
    let stopped = end(&mut core).await;
    if !stopped {
        return Err("local-api-normal-owned-exit-unconfirmed");
    }
    let mut result = processing?;
    result["ok"] = json!(true);
    result["normal_owned_exit"] = json!(true);
    record(result)
}
