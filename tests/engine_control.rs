//! Public management API tests and explicitly separated fixture contracts.

#[path = "common/engine_fixture.rs"]
mod engine_fixture;

use engine_fixture::{EngineFixture, TestBinary, TestResult};
use reqwest::{Method, StatusCode};
use verysync_sidecar::{ApiKey, Client, ConnectOptions, DeviceId, Error, ManagementEndpoint};

fn endpoint(instance: &EngineFixture) -> verysync_sidecar::Result<ManagementEndpoint> {
    #[cfg(unix)]
    {
        ManagementEndpoint::unix_socket(instance.state_dir().join("gui.sock"))
    }
    #[cfg(windows)]
    {
        ManagementEndpoint::http(&format!("http://{}", instance.management_address()))
    }
}

#[tokio::test]
async fn connect_auth_version_and_identity_through_the_public_api() -> TestResult {
    let mut instance = EngineFixture::start().await?;
    let identity = DeviceId::parse(instance.device_id())?;
    let options = ConnectOptions::new(endpoint(&instance)?, ApiKey::new(instance.api_key())?)
        .expected_device_id(identity.clone());
    let client = Client::connect(options).await?;
    let info = client.instance();
    assert_eq!(info.device_id, identity);
    assert_eq!(
        info.compatibility,
        verysync_sidecar::VersionCompatibility::ValidatedBaseline
    );
    assert_eq!(
        info.version.os,
        if cfg!(target_os = "macos") {
            "darwin"
        } else {
            std::env::consts::OS
        }
    );
    assert_eq!(
        info.version.arch,
        if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "amd64"
        }
    );
    assert_eq!(
        info.version.version,
        verysync_sidecar::BASELINE_ENGINE_VERSION
    );
    assert!(!format!("{client:?}").contains(instance.api_key()));
    drop(client);
    // A management connection does not own the serving process.
    assert_eq!(
        instance.read_json("/rest/system/status").await?["myID"],
        instance.device_id()
    );

    let wrong_key =
        ConnectOptions::new(endpoint(&instance)?, ApiKey::new("synthetic-invalid-key")?);
    assert!(matches!(
        Client::connect(wrong_key).await,
        Err(Error::Authentication { status: 403 })
    ));

    let wrong_id =
        DeviceId::parse("AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA")?;
    assert_ne!(wrong_id.as_str(), instance.device_id());
    let wrong_identity =
        ConnectOptions::new(endpoint(&instance)?, ApiKey::new(instance.api_key())?)
            .expected_device_id(wrong_id);
    assert!(matches!(
        Client::connect(wrong_identity).await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert_eq!(
        instance.read_json("/rest/system/status").await?["myID"],
        instance.device_id()
    );
    assert!(instance.shutdown().await?.success());
    assert!(instance.has_reaped_process());
    Ok(())
}

#[test]
fn missing_test_program_or_checksum_is_an_error() -> TestResult {
    let path = std::env::current_exe()?;
    for (path, checksum) in [
        (None, None),
        (Some(path), None),
        (None, Some("0".repeat(64))),
    ] {
        assert!(TestBinary::new(path, checksum).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn checksum_mismatch_is_rejected_before_starting_an_engine() -> TestResult {
    let source = TestBinary::from_env()?;
    let invalid = TestBinary::new(Some(source.path().to_owned()), Some("0".repeat(64)))?;
    let result = EngineFixture::start_from(invalid).await;
    assert!(matches!(result, Err(error) if error.to_string().contains("checksum")));
    Ok(())
}

#[tokio::test]
async fn two_private_instances_have_separate_identity_authentication_and_cleanup() -> TestResult {
    let mut first = EngineFixture::start().await?;
    let mut second = EngineFixture::start().await?;

    assert_ne!(first.state_dir(), second.state_dir());
    assert_ne!(first.device_id(), second.device_id());
    assert_ne!(first.management_address(), second.management_address());
    assert!(
        first.api_key() != second.api_key(),
        "fixtures must not share API keys"
    );

    let helper = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("prepare-test-engine.py");
    let python = if cfg!(windows) { "python" } else { "python3" };
    let cleanup_probe = std::process::Command::new(python)
        .arg(helper)
        .arg("check-cleanup")
        .output()?;
    assert!(!cleanup_probe.status.success());
    assert!(String::from_utf8(cleanup_probe.stderr)?
        .contains("task-owned test engine processes remain"));

    let wrong_key = first
        .request_with_key(Method::GET, "/rest/system/version", "invalid-test-key")?
        .send()
        .await?;
    assert_eq!(wrong_key.status(), StatusCode::FORBIDDEN);

    for instance in [&first, &second] {
        let version = instance.read_json("/rest/system/version").await?;
        let expected_os = if cfg!(target_os = "macos") {
            "darwin"
        } else {
            std::env::consts::OS
        };
        let expected_arch = match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "amd64",
            other => {
                return Err(
                    format!("fixture architecture mapping not yet verified: {other}").into(),
                )
            }
        };
        assert_eq!(version["os"], expected_os);
        assert_eq!(version["arch"], expected_arch);
        let config = instance.read_json("/rest/config").await?;
        assert!(config["folders"].as_array().is_some_and(Vec::is_empty));
        for key in [
            "globalAnnounceEnabled",
            "localAnnounceEnabled",
            "relaysEnabled",
            "natEnabled",
            "udpEnabled",
            "startBrowser",
            "systrayEnabled",
            "trackerEnabled",
        ] {
            assert_eq!(
                config["options"][key], false,
                "unsafe fixture option: {key}"
            );
        }
        assert_eq!(config["relayServer"]["enabled"], false);
        assert_eq!(config["options"]["autoUpgradeIntervalH"], 0);
        assert!(config["options"]["globalAnnounceServers"]
            .as_array()
            .is_some_and(Vec::is_empty));
        assert!(instance.private_resources_are_protected()?);
    }

    let first_pid = first.pid();
    assert!(first.shutdown().await?.success());
    assert!(first.has_reaped_process());
    let version = second.read_json("/rest/system/version").await?;
    assert_eq!(
        version["version"],
        verysync_sidecar::BASELINE_ENGINE_VERSION
    );
    assert!(second.shutdown().await?.success());
    assert!(second.has_reaped_process());
    println!(
        "fixture cleanup confirmed for owned PIDs {first_pid} and {}",
        second.pid()
    );
    Ok(())
}
