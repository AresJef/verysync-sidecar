//! Actual management credential changes and explicit owned-client recovery.
#[path = "common/ldap_service.rs"]
mod ldap_service;
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::*;

#[tokio::test]
async fn native_tunnel_permissions_negative_probe_and_restart_preserve_owned_data() -> TestResult {
    fn loopback(v: &serde_json::Value) -> Option<String> {
        match v {
            serde_json::Value::String(s) => s
                .strip_prefix("tcp://")
                .and_then(|v| v.parse::<std::net::SocketAddr>().ok())
                .filter(|a| {
                    a.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) && a.port() != 0
                })
                .map(|_| s.clone()),
            serde_json::Value::Array(v) => v.iter().find_map(loopback),
            serde_json::Value::Object(v) => v.values().find_map(loopback),
            _ => None,
        }
    }
    async fn address(c: &Client) -> TestResult<String> {
        Ok(tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(a) = c
                    .system_status()
                    .await?
                    .extra
                    .get("connectionServiceStatus")
                    .and_then(loopback)
                {
                    return Ok::<_, Error>(a);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await??)
    }
    let root = tempfile::Builder::new()
        .prefix("vs-tunnel-")
        .tempdir()?
        .keep();
    let sentinel = root.join("sentinel.bin");
    std::fs::write(&sentinel, b"remote configuration keeps caller bytes")?;
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let b_default = options(&root.join("b"))?;
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let b_addr = listener.local_addr()?;
    assert_ne!(b_addr.port(), 18886);
    drop(listener);
    let b_options = ManagedOptions::new(
        b_default.program().clone(),
        b_default.state_directory(),
        ManagementEndpoint::http(&format!("http://{b_addr}/"))?,
    )?
    .startup_timeout(Duration::from_secs(25))?;
    let mut b = ManagedInstance::start(b_options).await?;
    let aid = a.client().instance().device_id.clone();
    let bid = b.client().instance().device_id.clone();
    let aa = address(a.client()).await?;
    let ba = address(b.client()).await?;
    let template = a
        .client()
        .update_device_defaults(
            &DevicePatch::default()
                .allow_tunnel(false)
                .remote_gui_port(b_addr.port())?,
        )
        .await?;
    assert!(template.requested_fields_match);
    assert_eq!(template.configuration.allow_tunnel, Some(false));
    assert_eq!(template.configuration.remote_gui_port, Some(b_addr.port()));
    for (client, peer, addr) in [(a.client(), &bid, ba), (b.client(), &aid, aa)] {
        let patch = DevicePatch::default().addresses(vec![addr]).paused(false);
        let patch = if *peer == bid {
            patch
        } else {
            patch.allow_tunnel(false).remote_gui_port(b_addr.port())?
        };
        assert!(
            client
                .create_device(&CreateDeviceOptions::new(peer.clone()).settings(patch))
                .await?
                .requested_fields_match
        );
    }
    let defaults = a.client().device_defaults().await?;
    let original = a.client().device(&bid).await?;
    assert_eq!(original.allow_tunnel, Some(false));
    assert_eq!(original.remote_gui_port, Some(b_addr.port()));
    let denied = a.client().probe_device_tunnel(&bid).await?;
    assert_eq!(denied.device_id(), &bid);
    assert!(!denied.tunnel_available());
    assert_eq!(denied.native_error(), Some("no authorization"));
    for (client, peer) in [(a.client(), &bid), (b.client(), &aid)] {
        assert!(
            client
                .update_device(peer, &DevicePatch::default().allow_tunnel(true))
                .await?
                .requested_fields_match
        );
    }
    let changed = a.client().device(&bid).await?;
    assert_eq!(changed.remote_gui_port, Some(b_addr.port()));
    assert_eq!(changed.addresses, original.addresses);
    assert_eq!(changed.compression, original.compression);
    assert!(
        changed.extra == original.extra,
        "unrelated device settings changed"
    );
    let probe = a.client().probe_device_tunnel(&bid).await?;
    assert_eq!(probe.device_id(), &bid);
    if probe.tunnel_available() {
        assert!(probe.native_error().is_none_or(str::is_empty));
    } else {
        assert!(probe.native_error().is_some_and(|v| !v.is_empty()));
    }
    println!(
        "native granted tunnel_available={} licensed_session_not_attempted=true",
        probe.tunnel_available()
    );
    assert!(a.client().license_status().await?.licenses().is_none());
    assert!(
        serde_json::to_value(a.client().device_defaults().await?)?
            == serde_json::to_value(defaults)?,
        "device defaults changed"
    );
    a.restart(Duration::from_secs(30)).await?;
    let persisted = a.client().device(&bid).await?;
    assert_eq!(persisted.allow_tunnel, Some(true));
    assert_eq!(persisted.remote_gui_port, Some(b_addr.port()));
    assert_eq!(a.client().system_status().await?.device_id, aid);
    assert_eq!(b.client().system_status().await?.device_id, bid);
    for (client, peer) in [(a.client(), &bid), (b.client(), &aid)] {
        assert!(
            client
                .update_device(peer, &DevicePatch::default().allow_tunnel(false))
                .await?
                .requested_fields_match
        );
    }
    let revoked = a.client().probe_device_tunnel(&bid).await?;
    assert!(!revoked.tunnel_available());
    assert_eq!(revoked.native_error(), Some("no authorization"));
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"remote configuration keeps caller bytes"
    );
    // Probe observations are not a paid native gateway session. Do not open a
    // gateway with these unlicensed synthetic instances or infer entitlement.
    for core in [&mut b, &mut a] {
        let exit = core.shutdown(Duration::from_secs(30)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    println!("native_remote_tunnel_effects=20 licensed_gateway_session_pending=true");
    Ok(())
}

#[tokio::test]
async fn native_empty_license_metadata_and_uncertain_fetch_preserve_the_owned_instance(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-license-metadata-")
        .tempdir()?
        .keep();
    let sentinel = root.join("sentinel.bin");
    std::fs::write(&sentinel, b"license requests retain local data")?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let pid = core.process_id();
    let before = core.client().configuration().await?;
    let licenses = core.client().license_status().await?;
    assert!(licenses.licenses().is_none() && licenses.extra().is_empty());
    assert_eq!(
        core.client().official_account_status().await?.state(),
        OfficialAccountState::LoggedOut
    );
    // On the unlicensed/unlogged fixed baseline, a single explicit fetch has
    // no complete management response. Preserve that actual uncertainty rather
    // than reporting successful refresh or guessing an account prerequisite.
    let failure = core
        .client()
        .fetch_licenses()
        .await
        .err()
        .ok_or("native uncertain fetch expected")?;
    assert!(
        matches!(failure, Error::MutationOutcomeUnknown { source, .. } if matches!(*source, Error::Transport { .. }))
    );
    let after = core.client().license_status().await?;
    assert!(after.licenses().is_none() && after.extra().is_empty());
    assert_eq!(
        core.client().official_account_status().await?.state(),
        OfficialAccountState::LoggedOut
    );
    assert_eq!(core.client().system_status().await?.device_id, identity);
    assert_eq!(core.process_id(), pid);
    let unchanged = core.client().configuration().await?;
    assert!(
        unchanged.native_document() == before.native_document(),
        "license request changed configuration"
    );
    core.restart(Duration::from_secs(30)).await?;
    let persisted = core.client().license_status().await?;
    assert!(persisted.licenses().is_none() && persisted.extra().is_empty());
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"license requests retain local data"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    println!("native_license_metadata_effects=10 trial_not_invoked=true licensed_positive_effects_pending=true");
    Ok(())
}

#[tokio::test]
async fn official_account_empty_logout_and_upstream_failure_preserve_gui_and_identity() -> TestResult
{
    let root = tempfile::Builder::new()
        .prefix("vs-official-account-")
        .tempdir()?
        .keep();
    let sentinel = root.join("sentinel.bin");
    std::fs::write(&sentinel, b"official account calls retain caller data")?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let pid = core.process_id();
    let before = core.client().configuration().await?;
    let state = core.client().official_account_status().await?;
    assert_eq!(state.state(), OfficialAccountState::LoggedOut);
    assert_eq!(state.user_id(), None);
    assert!(state.extra().is_empty());
    let logout = core.client().logout_official_account().await?;
    assert!(logout.expected_state_matches);
    assert_eq!(logout.status.state(), OfficialAccountState::LoggedOut);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(logout.acknowledgement.body_bytes())?,
        serde_json::json!({})
    );
    // The isolation wrapper refuses external forwarding. This establishes a
    // native upstream service failure, not rejection of an incorrect password
    // by the real account service and not a successful authenticated session.
    let credentials = OfficialAccountCredentials::new(
        "synthetic-account@example.invalid",
        "synthetic-never-real-password",
    )?;
    let error = core
        .client()
        .login_official_account(&credentials)
        .await
        .err()
        .ok_or("native upstream rejection expected")?;
    assert!(!format!("{error:?} {credentials:?}").contains("synthetic-never-real-password"));
    let Error::OfficialAccountRejected { code, response } = error else {
        return Err("native official account rejection category differs".into());
    };
    assert_eq!(code, 5000);
    assert_eq!(response.status(), 200);
    let envelope: serde_json::Value = serde_json::from_slice(response.body_bytes())?;
    assert_eq!(envelope["error"]["code"], 5000);
    assert!(envelope["error"]["message"].is_string());
    assert_eq!(
        core.client().official_account_status().await?.state(),
        OfficialAccountState::LoggedOut
    );
    assert_eq!(core.process_id(), pid);
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let after = core.client().configuration().await?;
    for section in [
        "gui",
        "ldap",
        "folders",
        "devices",
        "defaults",
        "options",
        "relayServer",
    ] {
        assert!(
            before.native_document()[section] == after.native_document()[section],
            "official account call changed unrelated configuration"
        );
    }
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(
        core.client().official_account_status().await?.state(),
        OfficialAccountState::LoggedOut
    );
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"official account calls retain caller data"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    println!("native_official_account_effects=12 successful_cloud_login_and_authenticated_logout_pending=true");
    Ok(())
}

#[tokio::test]
async fn gui_preferences_reload_preserve_credentials_and_control_actual_metrics_and_frame_headers(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-gui-preferences-")
        .tempdir()?
        .keep();
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let pid = core.process_id();
    let before = core.client().configuration().await?;
    let before_auth = core.client().gui_authentication().await?;
    let original_key = before_auth.api_key()?;
    let endpoint = core.client().endpoint().clone();
    let builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(3));
    #[cfg(unix)]
    let builder = match endpoint.socket_path() {
        Some(path) => builder.unix_socket(path),
        None => builder,
    };
    let http = builder.build()?;
    let base = endpoint
        .http_url()
        .cloned()
        .unwrap_or(url::Url::parse("http://localhost/")?);
    let metrics_before = http
        .get(base.join("metrics")?)
        .send()
        .await?
        .status()
        .as_u16();
    assert!(matches!(metrics_before, 401 | 403));
    let frame_before = http
        .get(base.clone())
        .send()
        .await?
        .headers()
        .get("x-frame-options")
        .is_some();
    assert!(frame_before);
    let enabled = core
        .update_gui_preferences(
            &GuiPreferencesPatch::default().metrics_without_auth(true),
            Duration::from_secs(10),
        )
        .await?;
    assert!(enabled.requested_fields_match && enabled.configuration.metrics_without_auth);
    let mut metrics = http.get(base.join("metrics")?).send().await?;
    assert_eq!(metrics.status().as_u16(), 200);
    let mut bytes = Vec::new();
    while let Some(chunk) = metrics.chunk().await? {
        assert!(
            bytes.len() + chunk.len() <= 1024 * 1024,
            "native metrics exceeded private observation bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    let text = std::str::from_utf8(&bytes)?;
    assert!(
        text.lines().any(|l| l.starts_with("# HELP "))
            && text.lines().any(|l| l.starts_with("# TYPE "))
    );
    let changed = core
        .update_gui_preferences(
            &GuiPreferencesPatch::default()
                .metrics_without_auth(false)
                .theme("dark")
                .debugging(false)
                .allow_frame_loading(true)
                .send_basic_auth_prompt(true)
                .session_cookie_duration_seconds(600)
                .session_cookie_path("/"),
            Duration::from_secs(10),
        )
        .await?;
    assert!(changed.requested_fields_match);
    assert_eq!(core.process_id(), pid);
    assert!(!http
        .get(base)
        .send()
        .await?
        .headers()
        .contains_key("x-frame-options"));
    assert!(matches!(
        http.get(
            endpoint
                .http_url()
                .cloned()
                .unwrap_or(url::Url::parse("http://localhost/")?)
                .join("metrics")?
        )
        .send()
        .await?
        .status()
        .as_u16(),
        401 | 403
    ));
    let fresh = Client::connect(
        ConnectOptions::new(endpoint, original_key).expected_device_id(identity.clone()),
    )
    .await?;
    assert_eq!(fresh.system_status().await?.device_id, identity);
    let after = core.client().configuration().await?;
    for section in [
        "folders",
        "devices",
        "options",
        "defaults",
        "ldap",
        "relayServer",
    ] {
        assert!(
            before.native_document()[section] == after.native_document()[section],
            "unrelated configuration section changed"
        );
    }
    for field in [
        "user", "password", "apiKey", "authMode", "address", "enabled", "useTLS",
    ] {
        assert!(
            before.native_document()["gui"][field] == after.native_document()["gui"][field],
            "GUI connection or credential changed"
        );
    }
    core.restart(Duration::from_secs(30)).await?;
    let persisted = core.client().gui_preferences().await?;
    assert!(
        persisted.theme() == "dark"
            && persisted.insecure_allow_frame_loading
            && !persisted.metrics_without_auth
    );
    assert_eq!(persisted.session_cookie_duration_seconds, 600);
    assert!(persisted.session_cookie_path() == "/");
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    println!("native_gui_preferences_effects=15");
    Ok(())
}

#[tokio::test]
async fn native_ldap_search_filter_requires_a_matching_directory_entry() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-ldap-search-")
        .tempdir()?
        .keep();
    let mut peer = ldap_service::LdapService::start(&root)?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let login = GuiLoginOptions::new(core.client().endpoint().clone(), peer.credentials.clone())
        .expected_device_id(identity.clone())
        .request_timeout(Duration::from_secs(3))?;
    assert!(
        core.client()
            .update_ldap_configuration(
                &LdapPatch::default()
                    .address(peer.address.clone())
                    .bind_dn("uid=%s,dc=example,dc=test")
                    .transport(LdapTransport::Plain)
                    .insecure_skip_verify(false)
                    .search_base_dn("dc=example,dc=test")
                    .search_filter("(uid=%s)")
            )
            .await?
            .requested_fields_match
    );
    core.set_gui_auth_mode(&GuiAuthMode::Ldap, Duration::from_secs(10))
        .await?;
    let session = GuiSession::login(login.clone()).await?;
    assert_eq!(session.system_status().await?.device_id, identity);
    assert!(session.logout().await?.session_rejected);
    for patch in [
        LdapPatch::default().search_filter("(uid=missing-entry)"),
        LdapPatch::default()
            .search_filter("(uid=%s)")
            .search_base_dn("dc=missing,dc=test"),
    ] {
        core.set_gui_auth_mode(&GuiAuthMode::Static, Duration::from_secs(10))
            .await?;
        assert!(
            core.client()
                .update_ldap_configuration(&patch)
                .await?
                .requested_fields_match
        );
        core.set_gui_auth_mode(&GuiAuthMode::Ldap, Duration::from_secs(10))
            .await?;
        assert_login_denied(GuiSession::login(login.clone()).await);
        assert_eq!(core.client().system_status().await?.device_id, identity);
    }
    let observations = peer.observations()?;
    assert!(observations
        .iter()
        .any(|r| r["operation"] == "searchRequest" && r["entries"] == 1 && r["result_code"] == 0));
    assert!(observations
        .iter()
        .any(|r| r["operation"] == "searchRequest"
            && r["filter_matches"] == false
            && r["entries"] == 0));
    assert!(observations
        .iter()
        .any(|r| r["operation"] == "searchRequest"
            && r["base_matches"] == false
            && r["entries"] == 0));
    peer.stop()?;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    println!(
        "native_ldap_search_effects=9 helper_platform={}",
        peer.python_platform
    );
    Ok(())
}

#[tokio::test]
async fn native_ldap_tls_requires_explicit_self_signed_certificate_policy() -> TestResult {
    ldap_encrypted_authentication("tls", LdapTransport::Tls).await
}

#[tokio::test]
async fn native_ldap_starttls_upgrades_before_sending_bind_credentials() -> TestResult {
    ldap_encrypted_authentication("starttls", LdapTransport::StartTls).await
}

fn assert_login_denied(result: Result<GuiSession>) {
    assert!(
        matches!(&result,Err(Error::AccessDenied{response}) if response.status()==403)
            || matches!(&result, Err(Error::Authentication { status: 401 }))
    );
}

async fn ldap_encrypted_authentication(
    transport_name: &str,
    transport: LdapTransport,
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-ldap-encrypted-")
        .tempdir()?
        .keep();
    let mut peer = ldap_service::LdapService::start_transport(&root, transport_name)?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let login = GuiLoginOptions::new(core.client().endpoint().clone(), peer.credentials.clone())
        .expected_device_id(identity.clone())
        .request_timeout(Duration::from_secs(3))?;
    assert!(
        core.client()
            .update_ldap_configuration(
                &LdapPatch::default()
                    .address(peer.address.clone())
                    .bind_dn("uid=%s,dc=example,dc=test")
                    .transport(transport)
                    .insecure_skip_verify(false)
                    .search_base_dn("")
                    .search_filter("")
            )
            .await?
            .requested_fields_match
    );
    core.set_gui_auth_mode(&GuiAuthMode::Ldap, Duration::from_secs(10))
        .await?;
    assert_login_denied(GuiSession::login(login.clone()).await);
    let strict = peer.observations()?;
    assert!(strict
        .iter()
        .any(|r| r["operation"] == "tlsHandshakeRejected"));
    assert!(!strict.iter().any(|r| r["operation"] == "bindRequest"));
    core.set_gui_auth_mode(&GuiAuthMode::Static, Duration::from_secs(10))
        .await?;
    assert!(
        core.client()
            .update_ldap_configuration(&LdapPatch::default().insecure_skip_verify(true))
            .await?
            .requested_fields_match
    );
    core.set_gui_auth_mode(&GuiAuthMode::Ldap, Duration::from_secs(10))
        .await?;
    let session = GuiSession::login(login).await?;
    assert_eq!(session.system_status().await?.device_id, identity);
    assert_login_denied(
        GuiSession::login(
            GuiLoginOptions::new(
                core.client().endpoint().clone(),
                GuiCredentials::new("ldap-test-user", "deliberately-wrong-password")?,
            )
            .expected_device_id(identity.clone())
            .request_timeout(Duration::from_secs(3))?,
        )
        .await,
    );
    let observed = peer.observations()?;
    assert!(observed
        .iter()
        .any(|r| r["operation"] == "tlsHandshake" && r["encrypted"] == true));
    assert!(observed.iter().any(|r| r["operation"] == "bindRequest"
        && r["result_code"] == 0
        && r["encrypted"] == true));
    assert!(observed.iter().any(|r| r["operation"] == "bindRequest"
        && r["result_code"] == 49
        && r["encrypted"] == true));
    assert!(!observed
        .iter()
        .any(|r| r["operation"] == "bindRequest" && r["encrypted"] == false));
    if transport_name == "starttls" {
        assert!(observed
            .iter()
            .any(|r| r["operation"] == "startTls" && r["result_code"] == 0));
    }
    assert!(session.logout().await?.session_rejected);
    assert_eq!(core.client().system_status().await?.device_id, identity);
    peer.stop()?;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    println!(
        "native_ldap_encrypted_effects=12 transport={transport_name} helper_platform={}",
        peer.python_platform
    );
    Ok(())
}

#[tokio::test]
async fn native_ldap_bind_and_authentication_failure_preserve_api_management() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-ldap-")
        .tempdir()?
        .keep();
    let mut peer = ldap_service::LdapService::start(&root)?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let endpoint = core.client().endpoint().clone();
    let configured = core
        .client()
        .update_ldap_configuration(
            &LdapPatch::default()
                .address(peer.address.clone())
                .bind_dn("uid=%s,dc=example,dc=test")
                .transport(LdapTransport::Plain)
                .insecure_skip_verify(false)
                .search_base_dn("")
                .search_filter(""),
        )
        .await?;
    assert!(configured.requested_fields_match);
    assert_eq!(configured.configuration.transport, LdapTransport::Plain);
    assert!(!configured.configuration.insecure_skip_verify);
    let mode = core
        .set_gui_auth_mode(&GuiAuthMode::Ldap, Duration::from_secs(10))
        .await?;
    assert!(mode.requested_mode_matches);
    let login = GuiLoginOptions::new(endpoint.clone(), peer.credentials.clone())
        .expected_device_id(identity.clone())
        .request_timeout(Duration::from_secs(3))?;
    let session = GuiSession::login(login).await?;
    assert_eq!(session.system_status().await?.device_id, identity);
    for credentials in [
        GuiCredentials::new("ldap-test-user", "deliberately-wrong-password")?,
        peer.unknown_user()?,
    ] {
        let denied = GuiSession::login(
            GuiLoginOptions::new(endpoint.clone(), credentials)
                .expected_device_id(identity.clone())
                .request_timeout(Duration::from_secs(3))?,
        )
        .await;
        assert!(
            matches!(&denied,Err(Error::AccessDenied{response}) if response.status()==403)
                || matches!(&denied, Err(Error::Authentication { status: 401 }))
        );
    }
    let observations = peer.observations()?;
    assert!(observations.iter().any(|r| r["dn_matches"] == true
        && r["password_matches"] == true
        && r["result_code"] == 0));
    assert!(observations.iter().any(|r| r["dn_matches"] == true
        && r["password_matches"] == false
        && r["result_code"] == 49));
    assert!(observations
        .iter()
        .any(|r| r["dn_matches"] == false && r["result_code"] == 49));
    peer.stop()?;
    assert_eq!(session.system_status().await?.device_id, identity);
    assert_eq!(core.client().system_status().await?.device_id, identity);
    assert!(session.logout().await?.session_rejected);
    let mode = core
        .set_gui_auth_mode(&GuiAuthMode::Static, Duration::from_secs(10))
        .await?;
    assert!(mode.requested_mode_matches);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    println!(
        "native_ldap_effects=12 helper_platform={}",
        peer.python_platform
    );
    Ok(())
}

#[tokio::test]
async fn gui_password_sessions_logout_and_api_key_management_are_independent() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-gui-auth-")
        .tempdir()?
        .keep();
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let endpoint = core.client().endpoint().clone();
    let identity = core.client().instance().device_id.clone();
    let mut entropy = [0u8; 24];
    getrandom::fill(&mut entropy)?;
    let password: String = entropy.iter().map(|b| format!("{b:02x}")).collect();
    let credentials = GuiCredentials::new("synthetic-gui-user", password.clone())?;
    let changed = core
        .set_local_gui_credentials(&credentials, Duration::from_secs(10))
        .await?;
    assert!(changed.username_matches && changed.configuration.password_is_set());
    assert!(matches!(changed.configuration.mode, GuiAuthMode::Static));
    let configured = core.client().configuration().await?;
    assert!(configured.native_document()["gui"]["password"]
        .as_str()
        .is_some_and(|s| s.starts_with("$2") && s != password));
    let login =
        GuiLoginOptions::new(endpoint.clone(), credentials).expected_device_id(identity.clone());
    let session = GuiSession::login(login.clone()).await?;
    let second = GuiSession::login(login).await?;
    assert_eq!(session.system_status().await?.device_id, identity);
    assert_eq!(session.version().await?.version, "v2.33.2");
    let obtained = session.gui_authentication().await?.api_key()?;
    assert_eq!(
        Client::connect(
            ConnectOptions::new(endpoint.clone(), obtained).expected_device_id(identity.clone())
        )
        .await?
        .instance()
        .device_id,
        identity
    );
    let wrong = GuiSession::login(
        GuiLoginOptions::new(
            endpoint,
            GuiCredentials::new("synthetic-gui-user", "wrong-private-test-password")?,
        )
        .expected_device_id(identity.clone()),
    )
    .await;
    assert!(
        matches!(&wrong,Err(Error::AccessDenied{response}) if response.status()==403)
            || matches!(&wrong, Err(Error::Authentication { status: 401 }))
    );
    let stale = session.clone();
    assert!(session.logout().await?.session_rejected);
    let denied = stale.system_status().await;
    assert!(
        matches!(&denied,Err(Error::AccessDenied{response}) if response.status()==403)
            || matches!(&denied, Err(Error::Authentication { status: 401 }))
    );
    assert_eq!(second.system_status().await?.device_id, identity);
    assert_eq!(core.client().system_status().await?.device_id, identity);
    assert!(second.logout().await?.session_rejected);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    println!("native_gui_authentication_effects=14");
    Ok(())
}

#[tokio::test]
async fn key_rotation_reauthenticates_owner_retains_files_and_rejects_old_key() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-auth-")
        .tempdir()?
        .keep();
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let mut other = ManagedInstance::start(options(&root.join("other"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let other_identity = other.client().instance().device_id.clone();
    let other_gui = other.client().configuration().await?.native_document()["gui"].clone();
    let gui_before = core.client().configuration().await?.native_document()["gui"].clone();
    let pid = core.process_id();
    let old_client = core.client().clone();
    let old_key = core.client().gui_authentication().await?.api_key()?;
    let new_key = ApiKey::generate()?;
    let data = root.join("synthetic-data");
    std::fs::create_dir(&data)?;
    let sentinel = data.join("retained.txt");
    std::fs::write(&sentinel, b"credential change retains synthetic bytes")?;
    let folder = FolderId::parse("synthetic-authentication")?;
    core.client()
        .create_folder(
            &CreateFolderOptions::new(folder.clone(), TargetPath::local(data)).paused(true),
        )
        .await?;
    let rotated = core
        .rotate_api_key(new_key.clone(), Duration::from_secs(10))
        .await?;
    assert!(rotated.requested_key_matches && rotated.previous_key_rejected);
    assert_eq!(rotated.client.system_status().await?.device_id, identity);
    assert_eq!(core.client().system_status().await?.device_id, identity);
    assert_eq!(core.process_id(), pid);
    let mut gui_after = core.client().configuration().await?.native_document()["gui"].clone();
    gui_after["apiKey"] = gui_before["apiKey"].clone();
    assert!(gui_after == gui_before, "unrelated GUI settings changed");
    let denied = old_client.reconnect_with_api_key(old_key.clone()).await;
    assert!(
        matches!(&denied, Err(Error::AccessDenied { response }) if response.status() == 403)
            || matches!(&denied, Err(Error::Authentication { status: 401 }))
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(core.client().instance().device_id, identity);
    assert!(core.client().folder(&folder).await?.paused);
    assert!(core
        .client()
        .reconnect_with_api_key(new_key.clone())
        .await
        .is_ok());
    let denied = old_client.reconnect_with_api_key(old_key).await;
    assert!(
        matches!(&denied, Err(Error::AccessDenied { response }) if response.status() == 403)
            || matches!(&denied, Err(Error::Authentication { status: 401 }))
    );
    assert_eq!(
        other.client().system_status().await?.device_id,
        other_identity
    );
    assert!(
        other.client().configuration().await?.native_document()["gui"] == other_gui,
        "other instance GUI settings changed"
    );
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"credential change retains synthetic bytes"
    );
    // A separately borrowed client can rotate; the owner explicitly adopts the
    // supplied new key before using its own subsequent lifecycle operations.
    let borrowed = core.client().clone();
    let next_key = ApiKey::generate()?;
    let rotation = borrowed
        .rotate_api_key(next_key.clone(), Duration::from_secs(10))
        .await?;
    assert!(rotation.requested_key_matches && rotation.previous_key_rejected);
    core.reconnect_with_api_key(next_key).await?;
    assert_eq!(core.client().system_status().await?.device_id, identity);
    assert!(
        core.client()
            .remove_folder_keep_files(&folder)
            .await?
            .configuration_absent
    );
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"credential change retains synthetic bytes"
    );
    for owned in [&mut core, &mut other] {
        let exit = owned.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    println!("management_key_rotation_effects=20");
    Ok(())
}
