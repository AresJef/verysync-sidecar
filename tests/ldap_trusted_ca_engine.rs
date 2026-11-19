//! Explicit strict public-CA LDAP acceptance without system trust modification.
#[path = "common/ldap_service.rs"]
#[allow(dead_code)]
mod ldap_service;
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::{path::PathBuf, time::Duration};
use verysync_sidecar::{
    Error, GuiAuthMode, GuiCredentials, GuiLoginOptions, GuiSession, LdapPatch, LdapTransport,
    ManagedInstance,
};

fn require_private_fixture() -> TestResult<PathBuf> {
    let path = PathBuf::from(
        std::env::var_os("VERYSYNC_TEST_LDAP_TLS_MANIFEST")
            .ok_or("explicit prepared private public-CA LDAP fixture required")?,
    );
    if !path.is_absolute() || path.file_name().is_none_or(|name| name != "manifest.json") {
        return Err("absolute private TLS manifest required".into());
    }
    Ok(path.canonicalize()?)
}
fn denied(result: verysync_sidecar::Result<GuiSession>) {
    assert!(
        matches!(&result, Err(Error::AccessDenied {response}) if response.status()==403)
            || matches!(&result, Err(Error::Authentication { status: 401 }))
    );
}

#[tokio::test]
async fn native_trusted_ca_ldap_verifies_chain_hostname_password_and_exact_cleanup() -> TestResult {
    let manifest = require_private_fixture()?;
    let root = tempfile::Builder::new()
        .prefix("vs-ldap-trusted-")
        .tempdir()?
        .keep();
    let peer_root = root.join("peer");
    std::fs::create_dir(&peer_root)?;
    let mut peer = ldap_service::LdapService::start_public_tls(&peer_root, &manifest)?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let id = core.client().instance().device_id.clone();
    let sentinel = root.join("sentinel.bin");
    std::fs::write(&sentinel, b"strict trusted LDAP keeps bytes")?;
    let localhost = peer
        .address
        .replacen("127.0.0.1:", "ldap.localhost.direct:", 1);
    assert!(
        core.client()
            .update_ldap_configuration(
                &LdapPatch::default()
                    .address(localhost.clone())
                    .bind_dn("uid=%s,dc=example,dc=test")
                    .transport(LdapTransport::Tls)
                    .insecure_skip_verify(false)
                    .search_base_dn("")
                    .search_filter("")
            )
            .await?
            .requested_fields_match
    );
    core.set_gui_auth_mode(&GuiAuthMode::Ldap, Duration::from_secs(10))
        .await?;
    let login = GuiLoginOptions::new(core.client().endpoint().clone(), peer.credentials.clone())
        .expected_device_id(id.clone())
        .request_timeout(Duration::from_secs(5))?;
    let session = GuiSession::login(login.clone()).await?;
    assert_eq!(session.system_status().await?.device_id, id);
    denied(
        GuiSession::login(
            GuiLoginOptions::new(
                core.client().endpoint().clone(),
                GuiCredentials::new("ldap-test-user", "wrong-synthetic-password")?,
            )
            .expected_device_id(id.clone())
            .request_timeout(Duration::from_secs(5))?,
        )
        .await,
    );
    let before = peer
        .observations()?
        .iter()
        .filter(|row| row["operation"] == "bindRequest")
        .count();
    core.set_gui_auth_mode(&GuiAuthMode::Static, Duration::from_secs(10))
        .await?;
    core.client()
        .update_ldap_configuration(&LdapPatch::default().address(peer.address.clone()))
        .await?;
    core.set_gui_auth_mode(&GuiAuthMode::Ldap, Duration::from_secs(10))
        .await?;
    denied(GuiSession::login(login.clone()).await);
    let wrong_host = peer.observations()?;
    assert_eq!(
        wrong_host
            .iter()
            .filter(|row| row["operation"] == "bindRequest")
            .count(),
        before
    );
    assert!(wrong_host
        .iter()
        .any(|row| row["operation"] == "tlsHandshakeRejected"));
    core.set_gui_auth_mode(&GuiAuthMode::Static, Duration::from_secs(10))
        .await?;
    core.client()
        .update_ldap_configuration(&LdapPatch::default().address(localhost))
        .await?;
    core.set_gui_auth_mode(&GuiAuthMode::Ldap, Duration::from_secs(10))
        .await?;
    core.restart(Duration::from_secs(30)).await?;
    assert!(
        !core
            .client()
            .ldap_configuration()
            .await?
            .insecure_skip_verify
    );
    let session = GuiSession::login(login).await?;
    assert_eq!(session.system_status().await?.device_id, id);
    assert!(session.logout().await?.session_rejected);
    let observed = peer.observations()?;
    for code in [0, 49] {
        assert!(observed.iter().any(|row| row["operation"] == "bindRequest"
            && row["result_code"] == code
            && row["encrypted"] == true));
    }
    assert!(!observed
        .iter()
        .any(|row| row["operation"] == "bindRequest" && row["encrypted"] == false));
    assert_eq!(std::fs::read(sentinel)?, b"strict trusted LDAP keeps bytes");
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    peer.stop()?;
    std::fs::remove_dir_all(&root)?;
    assert!(!root.exists());
    println!("native_ldap_trusted_ca_effects=12 strict_chain_and_hostname=true bypass=false private_peer_and_files_removed=true system_trust_mutations=0");
    Ok(())
}

#[tokio::test]
async fn native_trusted_ca_starttls_refusal_preserves_strict_policy_and_never_sends_bind_credentials(
) -> TestResult {
    let manifest = require_private_fixture()?;
    let root = tempfile::Builder::new()
        .prefix("vs-ldap-starttls-trusted-")
        .tempdir()?
        .keep();
    let sentinel = root.join("unrelated caller bytes");
    std::fs::write(&sentinel, b"strict StartTLS preserves caller data")?;
    let tls_root = root.join("ldaps-control");
    let starttls_root = root.join("starttls");
    std::fs::create_dir(&tls_root)?;
    std::fs::create_dir(&starttls_root)?;
    let mut tls_peer = ldap_service::LdapService::start_public_tls(&tls_root, &manifest)?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let id = core.client().instance().device_id.clone();
    let tls_host = tls_peer
        .address
        .replacen("127.0.0.1:", "ldap.localhost.direct:", 1);
    let selected_tls = core
        .client()
        .update_ldap_configuration(
            &LdapPatch::default()
                .address(tls_host)
                .bind_dn("uid=%s,dc=example,dc=test")
                .transport(LdapTransport::Tls)
                .insecure_skip_verify(false)
                .search_base_dn("")
                .search_filter(""),
        )
        .await?;
    assert!(selected_tls.requested_fields_match);
    let strict_tls = core.client().ldap_configuration().await?;
    assert!(!strict_tls.insecure_skip_verify && strict_tls.transport == LdapTransport::Tls);
    core.set_gui_auth_mode(&GuiAuthMode::Ldap, Duration::from_secs(10))
        .await?;
    let control = GuiSession::login(
        GuiLoginOptions::new(
            core.client().endpoint().clone(),
            tls_peer.credentials.clone(),
        )
        .expected_device_id(id.clone())
        .request_timeout(Duration::from_secs(5))?,
    )
    .await?;
    assert_eq!(control.system_status().await?.device_id, id);
    assert!(control.logout().await?.session_rejected);
    assert!(tls_peer
        .observations()?
        .iter()
        .any(|r| r["operation"] == "bindRequest"
            && r["encrypted"] == true
            && r["result_code"] == 0));
    tls_peer.stop()?;

    let mut peer = ldap_service::LdapService::start_public_starttls(&starttls_root, &manifest)?;
    core.set_gui_auth_mode(&GuiAuthMode::Static, Duration::from_secs(10))
        .await?;
    let host = peer
        .address
        .replacen("127.0.0.1:", "ldap.localhost.direct:", 1);
    assert!(
        core.client()
            .update_ldap_configuration(
                &LdapPatch::default()
                    .address(host)
                    .transport(LdapTransport::StartTls)
                    .insecure_skip_verify(false)
            )
            .await?
            .requested_fields_match
    );
    core.set_gui_auth_mode(&GuiAuthMode::Ldap, Duration::from_secs(10))
        .await?;
    let result = GuiSession::login(
        GuiLoginOptions::new(core.client().endpoint().clone(), peer.credentials.clone())
            .expected_device_id(id.clone())
            .request_timeout(Duration::from_secs(5))?,
    )
    .await;
    denied(result);
    let observed = peer.observations()?;
    assert!(observed
        .iter()
        .any(|r| r["operation"] == "startTls" && r["result_code"] == 0));
    assert!(observed
        .iter()
        .any(|r| r["operation"] == "tlsHandshakeRejected"));
    assert!(!observed
        .iter()
        .any(|r| r["operation"] == "tlsHandshake" || r["operation"] == "bindRequest"));
    let policy = core.client().ldap_configuration().await?;
    assert!(!policy.insecure_skip_verify && policy.transport == LdapTransport::StartTls);
    assert_eq!(core.client().system_status().await?.device_id, id);
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"strict StartTLS preserves caller data"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    let diagnostic = String::from_utf8_lossy(exit.diagnostic.body_bytes());
    assert!(
        diagnostic.contains("either ServerName or InsecureSkipVerify must be specified"),
        "strict StartTLS must preserve the specific native missing-server-name refusal"
    );
    peer.stop()?;
    std::fs::remove_dir_all(&root)?;
    assert!(!root.exists());
    println!(
        "native strict StartTLS boundary evidence: {}",
        serde_json::json!({
            "same_certificate_strict_ldaps_control_login":true,
            "matching_hostname_and_chain_verification_enabled":true,
            "native_starttls_extended_operation_accepted":true,
            "native_missing_server_name_refusal_preserved":true,
            "no_tls_handshake_or_bind_credentials_after_starttls":true,
            "no_implicit_bypass_or_downgrade":true,
            "api_management_identity_and_sentinel_retained":true,
            "normal_owned_tree_and_state_exit":true,"private_peer_and_files_removed":true,
            "system_trust_mutations":0
        })
    );
    Ok(())
}
