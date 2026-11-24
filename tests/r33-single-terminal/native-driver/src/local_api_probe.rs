//! Evidence-only Local-API qualification for the fixed native instance.

use crate::{end, inspect, record, Stage, ENGINE_HASH, START};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};
use verysync_sidecar::{
    CreateFolderOptions, Error, FolderId, LocalApiClient, LocalApiConnectOptions, LocalProgram,
    ManagedInstance, ManagedOptions, ManagementEndpoint, TargetPath,
};

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

fn read_result<T>(
    route: &str,
    value: verysync_sidecar::Result<T>,
    examine: impl FnOnce(T) -> Value,
) -> Value {
    match value {
        Ok(native) => json!({"route":route,"state":"native-value","readback":examine(native)}),
        Err(Error::LicenseRequired { code, response }) => {
            json!({"route":route,"state":"license-required","code":code,"http":response.status()})
        }
        Err(Error::Http { response }) => {
            json!({"route":route,"state":"http-failure","http":response.status()})
        }
        Err(_) => json!({"route":route,"state":"typed-read-failed"}),
    }
}

async fn qualify(
    root: &Path,
    core: &ManagedInstance,
    endpoint: ManagementEndpoint,
    run: &str,
) -> Stage<Value> {
    let account = inspect(core, run).await?;
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
    let folder = FolderId::parse("r33-local-api-read-qualification")
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
    let protected = [
        read_result(
            "LA-008",
            local.folder_summaries().await,
            |values| json!({"owned_folder_present":values.contains_key(&folder),"entries":values.len()}),
        ),
        read_result(
            "LA-012",
            local.folder_configuration(&folder).await,
            |configuration| {
                json!({"exact_requested_id":configuration.id==folder,
                   "exact_requested_path":configuration.path.to_protocol().is_ok_and(|actual|
                       selected.to_str().is_some_and(|path| actual==path))})
            },
        ),
        read_result(
            "LA-019",
            local.connections().await,
            |connections| json!({"reported_peer_count":connections.connections.len()}),
        ),
    ];
    let after = snapshot()?;
    if before != after {
        return Err("local-api-read-qualification-affected-sample-data");
    }
    Ok(json!({"ok":true,"fixed_native_account_observation":account,
              "ordinary_status_and_folder_projection":true,"protected_read_routes":protected,
              "original_files":before,"files_after_actual_reads":after,"protected_writes":0}))
}

pub(crate) async fn signed_out_control(engine: &Path, root: &Path, run: &str) -> Stage<()> {
    let (mut core, endpoint) = start(engine, root).await?;
    let observation = qualify(root, &core, endpoint, run).await;
    let shut_down = end(&mut core).await;
    let mut receipt = observation?;
    let expected_denials = receipt["protected_read_routes"]
        .as_array()
        .is_some_and(|routes| {
            routes.len() == 3
                && routes.iter().all(|route| {
                    route["state"] == "license-required"
                        && route["code"] == 3001
                        && route["http"] == 200
                })
        });
    let scope = &receipt["fixed_native_account_observation"];
    let confirmed = shut_down
        && expected_denials
        && scope["account"] == "logged-out"
        && scope["pro_observations"] == json!([]);
    receipt["normal_owned_exit"] = json!(shut_down);
    receipt["ok"] = json!(confirmed);
    record(receipt)?;
    if confirmed {
        Ok(())
    } else {
        Err("local-api-native-signed-out-controls-unconfirmed")
    }
}
