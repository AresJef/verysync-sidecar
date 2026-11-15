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
