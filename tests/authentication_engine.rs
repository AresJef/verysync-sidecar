//! Actual management credential changes and explicit owned-client recovery.
#[path = "common/ldap_service.rs"]
mod ldap_service;
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::*;

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
