//! Actual TLS and explicit proxy behavior against a separate official core.
use super::*;
#[path = "management_service.rs"]
mod management_service;

#[cfg(feature = "tls")]
#[tokio::test]
async fn trusted_management_tls_and_explicit_proxies_preserve_authentication_and_real_data(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-management-tls-")
        .tempdir()?
        .keep();
    let defaults = options(&root.join("core"))?;
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    assert_ne!(address.port(), 18886);
    drop(listener);
    let mut core = ManagedInstance::start(
        ManagedOptions::new(
            defaults.program().clone(),
            defaults.state_directory(),
            ManagementEndpoint::http(&format!("http://{address}/"))?,
        )?
        .startup_timeout(Duration::from_secs(25))?,
    )
    .await?;
    let identity = core.client().instance().device_id.clone();
    let key = core.client().gui_authentication().await?.api_key()?;
    let credentials =
        GuiCredentials::new("synthetic-management-gui", "synthetic-private-gui-password")?;
    core.client()
        .set_local_gui_credentials(&credentials, Duration::from_secs(10))
        .await?;
    let mut peer =
        management_service::ManagementService::start(&root.join("peer"), address.port())?;
    let endpoint = peer.endpoint(true)?;
    let options =
        || ConnectOptions::new(endpoint.clone(), key.clone()).expected_device_id(identity.clone());
    assert!(matches!(
        Client::connect(options()).await,
        Err(Error::Transport { .. })
    ));
    let trust = ManagementTransport::default().trusted_certificates_pem(&peer.pem()?)?;
    assert!(matches!(
        Client::connect(
            ConnectOptions::new(peer.endpoint(false)?, key.clone()).transport(trust.clone())
        )
        .await,
        Err(Error::Transport { .. })
    ));
    assert!(!peer
        .observations()?
        .iter()
        .any(|v| v["operation"] == "http_forward"));
    let secure = Client::connect(options().transport(trust.clone())).await?;
    assert_eq!(secure.system_status().await?.device_id, identity);
    let data = root.join("synthetic-files");
    std::fs::create_dir(&data)?;
    let sentinel = data.join("retained.txt");
    std::fs::write(&sentinel, b"TLS management retains exact synthetic bytes")?;
    let folder = FolderId::parse("synthetic-tls-management")?;
    let created = secure
        .create_folder(
            &CreateFolderOptions::new(folder.clone(), TargetPath::local(data)).paused(true),
        )
        .await?;
    assert_eq!(created.id, folder);
    assert!(created.paused);
    assert!(core.client().folder(&folder).await?.paused);
    for (encrypted_target, encrypted_proxy) in [(false, false), (true, false), (true, true)] {
        let target = if encrypted_target {
            endpoint.clone()
        } else {
            core.client().endpoint().clone()
        };
        let transport = if encrypted_proxy {
            ManagementTransport::default().trusted_certificate_der(&peer.der()?)?
        } else {
            trust.clone()
        }
        .proxy(peer.proxy(encrypted_proxy)?);
        let before = peer
            .observations()?
            .iter()
            .filter(|v| v["operation"] == "proxy_auth" && v["matched"] == true)
            .count();
        let client = Client::connect(
            ConnectOptions::new(target, key.clone())
                .expected_device_id(identity.clone())
                .transport(transport),
        )
        .await?;
        assert_eq!(client.system_status().await?.device_id, identity);
        let reconnected = client.reconnect_with_api_key(key.clone()).await?;
        assert!(reconnected.folder(&folder).await?.paused);
        let after = peer
            .observations()?
            .iter()
            .filter(|v| v["operation"] == "proxy_auth" && v["matched"] == true)
            .count();
        assert!(
            after > before,
            "explicit proxy did not observe management traffic"
        );
    }
    let before = peer
        .observations()?
        .iter()
        .filter(|v| v["operation"] == "http_forward")
        .count();
    let rejected = ManagementTransport::default().proxy(
        peer.proxy(false)?
            .basic_auth("isolated-proxy-user", "wrong-private-proxy-password")?,
    );
    assert!(Client::connect(
        ConnectOptions::new(core.client().endpoint().clone(), key.clone()).transport(rejected)
    )
    .await
    .is_err());
    let after = peer
        .observations()?
        .iter()
        .filter(|v| v["operation"] == "http_forward")
        .count();
    assert_eq!(
        before, after,
        "failed proxy authentication forwarded or fell back"
    );
    let redirected = Client::connect(
        ConnectOptions::new(peer.redirect_endpoint()?, key.clone()).transport(trust.clone()),
    )
    .await;
    assert!(redirected.is_err());
    assert!(peer
        .observations()?
        .iter()
        .any(|v| v["operation"] == "redirect"));
    let session = GuiSession::login(
        GuiLoginOptions::new(endpoint, credentials)
            .expected_device_id(identity.clone())
            .transport(trust.proxy(peer.proxy(true)?)),
    )
    .await?;
    assert_eq!(session.system_status().await?.device_id, identity);
    assert!(session.logout().await?.session_rejected);
    assert!(
        secure
            .remove_folder_keep_files(&folder)
            .await?
            .configuration_absent
    );
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"TLS management retains exact synthetic bytes"
    );
    let observations = peer.observations()?;
    assert!(observations
        .iter()
        .any(|v| v["operation"] == "proxy_auth" && v["matched"] == false));
    assert!(observations.iter().any(|v| v["role"] == "https_proxy"
        && v["operation"] == "connect_complete"
        && v["bytes"].as_u64().is_some_and(|n| n > 0)));
    for v in observations
        .iter()
        .filter(|v| v["operation"] == "http_forward")
    {
        assert_eq!(v["forwarded_proxy_authorization"], false);
        assert_eq!(v["target_authorization"], false);
        if v["role"] == "origin" {
            assert_eq!(v["received_proxy_authorization"], false);
        }
    }
    peer.stop()?;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    println!("native_management_tls_effects=24 tls_frontend=controlled_reverse_proxy real_core_backend=true system_trust_unchanged=true helper_platform={}", peer.python_platform);
    Ok(())
}
