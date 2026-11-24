use std::{
    env, fs, io,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use serde_json::json;
use sha2::{Digest, Sha256};
use verysync_sidecar::{
    CreateFolderOptions, Error, FolderId, LocalApiClient, LocalApiConnectOptions, LocalProgram,
    ManagedInstance, ManagedOptions, ManagementEndpoint, TargetPath,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn digest(path: &Path) -> TestResult<String> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}

async fn observe(root: &Path, endpoint: ManagementEndpoint, core: &ManagedInstance) -> TestResult {
    let manager = core.client();
    let identity = manager.instance().device_id.clone();
    let id = FolderId::parse("r33-private-loopback-native")?;
    let directory = root.join("samples");
    fs::create_dir(&directory)?;
    let sample = directory.join("sample.txt");
    let control = root.join("control.txt");
    fs::write(
        &sample,
        b"An isolated synthetic fixture for native Local-API.",
    )?;
    fs::write(&control, b"An unrelated control outside the shared folder.")?;
    let hashes = [digest(&sample)?, digest(&control)?];
    manager
        .create_folder(
            &CreateFolderOptions::new(id.clone(), TargetPath::local(&directory)).paused(true),
        )
        .await?;
    let local = LocalApiClient::connect(
        LocalApiConnectOptions::new(endpoint)?.expected_device_id(identity.clone()),
    )
    .await?;
    let snapshot = local.system_status().await?;
    assert_eq!(snapshot.device_id, identity);
    assert_eq!(
        local.version().await?.version,
        verysync_sidecar::BASELINE_ENGINE_VERSION
    );
    assert_eq!(
        local
            .folders()
            .await?
            .into_iter()
            .map(|row| row.id)
            .collect::<Vec<_>>(),
        [id.clone()]
    );
    assert_eq!(
        manager.official_account_status().await?.state(),
        verysync_sidecar::OfficialAccountState::LoggedOut,
    );
    for result in [
        local.folder_summaries().await.unwrap_err(),
        local.folder_configuration(&id).await.unwrap_err(),
        local.connections().await.unwrap_err(),
    ] {
        assert!(
            matches!(result, Error::LicenseRequired { code: 3001, response }
                         if response.status() == 200)
        );
    }
    let alias = format!("{:x}", Sha256::digest(identity.to_string().as_bytes()));
    println!(
        "R33_NATIVE_PRIVATE_READY {}",
        json!({
            "core_pid":core.process_id(),"namespace":env::var("R33_LOOPBACK_NAMESPACE")?,
            "logged_out":true,"protected_read_denials":3,"protected_writes":0,
            "fixed_version":verysync_sidecar::BASELINE_ENGINE_VERSION,
            "ordinary_inside_status":200,"ordinary_inside_identity_matched":true,"device_alias":alias,
        })
    );
    let mut instruction = String::new();
    io::stdin().read_line(&mut instruction)?;
    assert_eq!(instruction.trim(), "STOP");
    assert_eq!([digest(&sample)?, digest(&control)?], hashes);
    println!(
        "R33_NATIVE_PRIVATE_DATA {}",
        json!({"sample_sha256":hashes[0],
             "sample_bytes":fs::metadata(&sample)?.len(),"control_sha256":hashes[1],
             "control_bytes":fs::metadata(&control)?.len(),"read_back_after_test":true})
    );
    Ok(())
}

#[tokio::test]
async fn r33_native_private_local_api() -> TestResult {
    let program = PathBuf::from(env::var_os("R33_LOOPBACK_ENGINE").ok_or("Engine path missing.")?);
    let engine_hash = env::var("R33_LOOPBACK_ENGINE_SHA256")?;
    if engine_hash.len() != 64 || !engine_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Native executable SHA-256 is invalid.".into());
    }
    let mut expected_digest = [0_u8; 32];
    for (position, pair) in engine_hash.as_bytes().chunks_exact(2).enumerate() {
        expected_digest[position] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    let root = PathBuf::from(env::var_os("R33_LOOPBACK_STATE").ok_or("Fixture path missing.")?);
    let port = env::var("R33_LOOPBACK_PORT")?.parse::<u16>()?;
    let endpoint = ManagementEndpoint::http(&format!(
        "http://{}/",
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
    ))?;
    let options = ManagedOptions::new(
        LocalProgram::new(program)?.expected_sha256(expected_digest),
        root.join("state"),
        endpoint.clone(),
    )?
    .startup_timeout(Duration::from_secs(20))?
    .local_api_enabled(true)?;
    let mut core = ManagedInstance::start(options).await?;
    let result = observe(&root, endpoint, &core).await;
    let stopped = core.shutdown(Duration::from_secs(15)).await?;
    assert!(
        stopped.code == Some(0)
            && stopped.state_released
            && !stopped.forced
            && stopped.tree_stopped
    );
    println!(
        "R33_NATIVE_PRIVATE_EXIT {}",
        json!({"normal_owned_exit":true,"exact_state_released":true})
    );
    result
}
