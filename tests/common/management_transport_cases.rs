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

async fn connect_listener(options: ConnectOptions) -> TestResult<Client> {
    Ok(tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            match Client::connect(options.clone()).await {
                Ok(client) => return Ok::<_, Error>(client),
                Err(Error::Transport { .. } | Error::Timeout { .. }) => {
                    tokio::time::sleep(Duration::from_millis(25)).await
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await??)
}

#[tokio::test]
async fn native_listener_tls_address_and_disable_effects_keep_explicit_owner_control() -> TestResult
{
    let root = tempfile::Builder::new()
        .prefix("vs-listener-")
        .tempdir()?
        .keep();
    let base = options(&root.join("core"))?;
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let initial = listener.local_addr()?;
    assert_ne!(initial.port(), 18886);
    drop(listener);
    let mut core = ManagedInstance::start(ManagedOptions::new(
        base.program().clone(),
        base.state_directory(),
        ManagementEndpoint::http(&format!("http://{initial}/"))?,
    )?)
    .await?;
    let id = core.client().instance().device_id.clone();
    let key = core.client().gui_authentication().await?.api_key()?;
    let before = core.client().configuration().await?.native_document()["gui"].clone();
    let sentinel = root.join("sentinel.bin");
    std::fs::write(&sentinel, b"native listener changes retain caller data")?;
    let mut certificates =
        management_service::ManagementService::start(&root.join("peer"), initial.port())?;
    let ca = certificates.pem()?;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::write(
        core.state_directory().join("https-cert.pem"),
        std::fs::read(root.join("peer/server.pem"))?,
    )?;
    std::fs::write(
        core.state_directory().join("https-key.pem"),
        std::fs::read(root.join("peer/server.key"))?,
    )?;
    certificates.stop()?;
    core.restart(Duration::from_secs(30)).await?;
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let changed = listener.local_addr()?;
    assert_ne!(changed.port(), 18886);
    drop(listener);
    let update = core
        .client()
        .update_gui_listener(
            &GuiListenerPatch::default()
                .address(GuiListenAddress::tcp(&changed.to_string())?)
                .use_tls(true),
        )
        .await?;
    println!("native_gui_listener_stage=tls_reconnect");
    assert_eq!(
        update.previous_configuration.address.tcp_authority(),
        Some(initial.to_string().as_str())
    );
    let tls = connect_listener(
        ConnectOptions::new(
            ManagementEndpoint::http(&format!("https://localhost:{}/", changed.port()))?,
            key.clone(),
        )
        .expected_device_id(id.clone())
        .transport(ManagementTransport::default().trusted_certificates_pem(&ca)?)
        .request_timeout(Duration::from_secs(2))?,
    )
    .await?;
    assert!(update.requested_fields_match(&tls.gui_listener().await?));
    assert_eq!(tls.system_status().await?.device_id, id);
    println!("native_gui_listener_stage=http_restore");
    let initial_guard = std::net::TcpListener::bind(initial)?;
    drop(initial_guard);
    let restore = tls
        .update_gui_listener(
            &GuiListenerPatch::default()
                .address(GuiListenAddress::tcp(&initial.to_string())?)
                .use_tls(false),
        )
        .await?;
    let http = connect_listener(
        ConnectOptions::new(core.client().endpoint().clone(), key.clone())
            .expected_device_id(id.clone())
            .request_timeout(Duration::from_secs(2))?,
    )
    .await?;
    println!("native_gui_listener_stage=disable_management");
    assert!(restore.requested_fields_match(&http.gui_listener().await?));
    assert!(
        http.configuration().await?.native_document()["gui"] == before,
        "listener update changed unrelated GUI configuration"
    );
    let disabled = http
        .update_gui_listener(&GuiListenerPatch::default().enabled(false))
        .await?;
    assert!(disabled.previous_configuration.enabled);
    println!("native_gui_listener_stage=wait_released_address");
    // Passively bind the exact released owned address; do not probe any endpoint
    // that might have been reused by another process after the listener closes.
    let guard = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            match std::net::TcpListener::bind(initial) {
                Ok(listener) => return Ok::<_, std::io::Error>(listener),
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::time::sleep(Duration::from_millis(25)).await
                }
                Err(e) => return Err(e),
            }
        }
    })
    .await??;
    println!("native_gui_listener_stage=explicit_force_cleanup");
    // Disabling management is not process exit. Explicit forced cleanup is a
    // separate caller choice for this synthetic fixture, never a library fallback.
    let forced = core.force_stop(Duration::from_secs(10)).await?;
    assert!(forced.forced && forced.tree_stopped && forced.state_released);
    let native = rmpv::decode::read_value(&mut std::io::Cursor::new(std::fs::read(
        core.state_directory().join("setting.dat"),
    )?))?;
    assert_eq!(native["4"]["1"].as_bool(), Some(false));
    drop(guard);
    core.restart(Duration::from_secs(30)).await?;
    assert!(core.client().gui_listener().await?.enabled);
    assert_eq!(core.client().instance().device_id, id);
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"native listener changes retain caller data"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    println!("native_gui_listener_effects=18 direct_native_tls=true disable_is_not_process_exit=true explicit_force_cleanup_separate=true");
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn native_gui_socket_modes_are_observed_on_the_actual_owned_socket() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::Builder::new()
        .prefix("vs-mode-")
        .tempdir()?
        .keep();
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let id = core.client().instance().device_id.clone();
    let key = core.client().gui_authentication().await?.api_key()?;
    let before = core.client().gui_listener().await?;
    let path = core.state_directory().join("gui.sock");
    // Both names are known local paths in this owned fixture. Keep the native
    // configuration spelling intact; compare filesystem identity via Path APIs.
    let reported = std::path::Path::new(
        before
            .address
            .socket_path()
            .ok_or("native socket path missing")?
            .to_protocol()?,
    );
    assert_eq!(
        std::fs::canonicalize(reported)?,
        std::fs::canonicalize(&path)?
    );
    let mode = std::fs::metadata(&path)?.permissions().mode() & 0o7777;
    for permissions in [
        GuiSocketPermissions::Mode(0o600),
        GuiSocketPermissions::Mode(0o660),
        before.unix_socket_permissions,
    ] {
        let update = core
            .client()
            .update_gui_listener(&GuiListenerPatch::default().unix_socket_permissions(permissions))
            .await?;
        let client = connect_listener(
            ConnectOptions::new(core.client().endpoint().clone(), key.clone())
                .expected_device_id(id.clone())
                .request_timeout(Duration::from_secs(2))?,
        )
        .await?;
        let actual = client.gui_listener().await?;
        assert!(update.requested_fields_match(&actual));
        let expected = match actual.unix_socket_permissions {
            GuiSocketPermissions::Mode(v) => u32::from(v),
            GuiSocketPermissions::NativeDefault => mode,
            _ => return Err("unexpected native socket mode".into()),
        };
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if std::fs::metadata(&path)?.permissions().mode() & 0o7777 == expected {
                    return Ok::<_, std::io::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await??;
    }
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    println!("native_gui_socket_mode_effects=8");
    Ok(())
}

#[tokio::test]
async fn owned_https_adoption_restart_and_existing_connection_retain_identity_and_trust(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-owned-tls-")
        .tempdir()?
        .keep();
    let base = options(&root.join("core"))?;
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let initial = listener.local_addr()?;
    assert_ne!(initial.port(), 18886);
    drop(listener);
    let base = ManagedOptions::new(
        base.program().clone(),
        base.state_directory(),
        ManagementEndpoint::http(&format!("http://{initial}/"))?,
    )?;
    let mut core = ManagedInstance::start(base.clone()).await?;
    let id = core.client().instance().device_id.clone();
    let key = core.client().gui_authentication().await?.api_key()?;
    let sentinel = root.join("sentinel.bin");
    std::fs::write(&sentinel, b"owned HTTPS transitions retain original data")?;
    let mut certificates =
        management_service::ManagementService::start(&root.join("peer"), initial.port())?;
    let trust = ManagementTransport::default().trusted_certificates_pem(&certificates.pem()?)?;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::write(
        core.state_directory().join("https-cert.pem"),
        std::fs::read(root.join("peer/native-server.pem"))?,
    )?;
    std::fs::write(
        core.state_directory().join("https-key.pem"),
        std::fs::read(root.join("peer/server.key"))?,
    )?;
    certificates.stop()?;
    core.restart(Duration::from_secs(30)).await?;
    let first_tls = ManagementEndpoint::http(&format!("https://{initial}/"))?;
    let mut foreign = id.as_str().as_bytes().to_vec();
    foreign[0] = if foreign[0] == b'A' { b'B' } else { b'A' };
    let foreign = DeviceId::parse(std::str::from_utf8(&foreign)?)?;
    assert!(matches!(
        core.reconnect_management(
            ConnectOptions::new(core.client().endpoint().clone(), key.clone())
                .expected_device_id(foreign)
        )
        .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        core.reconnect_management(ConnectOptions::new(
            ManagementEndpoint::http("http://192.0.2.10:42391/")?,
            key.clone()
        ))
        .await,
        Err(Error::InvalidConfiguration { .. })
    ));

    let wrong_key = ConnectOptions::new(
        core.client().endpoint().clone(),
        ApiKey::new("synthetic-wrong-owned-management-key")?,
    );
    assert!(core.reconnect_management(wrong_key).await.is_err());
    assert_eq!(core.client().system_status().await?.device_id, id);
    core.client()
        .update_gui_listener(&GuiListenerPatch::default().use_tls(true))
        .await?;
    let adoption_pid = core.process_id();
    let options = ConnectOptions::new(first_tls.clone(), key.clone()).transport(trust.clone());
    // The caller selects the new endpoint explicitly after its single write.
    // This bounded readiness loop repeats only read-only reconnection attempts.
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            match core.reconnect_management(options.clone()).await {
                Ok(()) => return Ok::<_, Error>(()),
                Err(Error::Transport { .. } | Error::Timeout { .. }) => {
                    tokio::time::sleep(Duration::from_millis(25)).await
                }
                Err(e) => return Err(e),
            }
        }
    })
    .await??;
    assert_eq!(core.process_id(), adoption_pid);
    assert_eq!(core.client().endpoint(), &first_tls);
    assert!(core.client().gui_listener().await?.use_tls);
    let before_pid = core.process_id();
    core.restart(Duration::from_secs(30)).await?;
    assert_ne!(core.process_id(), before_pid);
    assert_eq!(core.client().endpoint(), &first_tls);
    assert!(core.client().gui_listener().await?.use_tls);
    assert_eq!(core.client().instance().device_id, id);
    let existing = ManagedOptions::new(
        base.program().clone(),
        base.state_directory(),
        first_tls.clone(),
    )?
    .management_transport(trust.clone());
    assert_eq!(existing.connect_existing().await?.instance().device_id, id);
    assert!(
        matches!(
            base.connect_existing().await,
            Err(Error::InvalidConfiguration { .. })
        ),
        "plaintext selection accepted persisted native TLS policy"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    let mut secure = ManagedInstance::start(existing).await?;
    assert_eq!(secure.client().instance().device_id, id);
    assert!(secure.client().gui_listener().await?.use_tls);
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"owned HTTPS transitions retain original data"
    );
    let exit = secure.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    assert!(matches!(
        secure
            .reconnect_management(ConnectOptions::new(first_tls, key))
            .await,
        Err(Error::ManagedFailure { .. })
    ));
    println!("native_owned_https_effects=20 normal_tls_start_stop_restart_and_existing=true");
    Ok(())
}
