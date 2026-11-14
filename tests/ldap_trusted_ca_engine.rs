//! Explicit trusted-CA native acceptance on disposable GitHub-hosted VMs only.
#[path = "common/ldap_service.rs"]
#[allow(dead_code)]
mod ldap_service;
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::{
    fs::OpenOptions,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use verysync_sidecar::{
    Error, GuiAuthMode, GuiCredentials, GuiLoginOptions, GuiSession, LdapPatch, LdapTransport,
    ManagedInstance,
};

struct TemporaryTrust {
    certificate: PathBuf,
    fingerprint: Option<String>,
    active: bool,
}
impl TemporaryTrust {
    fn command(&self, action: &str) -> TestResult<String> {
        let parent = self
            .certificate
            .parent()
            .ok_or("owned CA directory missing")?;
        let error = OpenOptions::new()
            .create(true)
            .append(true)
            .open(parent.join("private-ca-helper-stderr.log"))?;
        let python = std::env::var_os("VERYSYNC_STORAGE_TEST_PYTHON")
            .ok_or("explicit private test Python required")?;
        let output = Command::new(python)
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/ephemeral-ci-trust.py"))
            .arg(action)
            .arg("--certificate")
            .arg(&self.certificate)
            .arg("--allow-ephemeral-runner-system-trust")
            .stdin(Stdio::null())
            .stderr(error)
            .output()?;
        if !output.status.success() || output.stdout.len() > 4096 {
            let mut bytes = Vec::new();
            let _ = std::fs::File::open(parent.join("ephemeral-ca-command-results.jsonl"))
                .and_then(|file| file.take(8192).read_to_end(&mut bytes));
            let native: Vec<_> = String::from_utf8_lossy(&bytes)
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .collect();
            eprintln!(
                "ephemeral CA helper failure: {}",
                serde_json::json!({
                "action":action,"helper_code":output.status.code(),"native_commands":native})
            );
            return Err("ephemeral CA helper failed; inspect private test diagnostics".into());
        }
        let response: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        if response["completed"] != true
            || response["ephemeral_runner_only"] != true
            || response["action"] != action
        {
            return Err("ephemeral CA helper outcome differs".into());
        }
        let fingerprint = response["ca_sha256"]
            .as_str()
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or("CA fingerprint missing")?;
        Ok(fingerprint.to_owned())
    }
    fn install(certificate: PathBuf) -> TestResult<Self> {
        let mut trust = Self {
            certificate,
            fingerprint: None,
            active: true,
        };
        trust.fingerprint = Some(trust.command("install")?);
        Ok(trust)
    }
    fn remove(&mut self) -> TestResult<()> {
        let observed = self.command("remove")?;
        if self
            .fingerprint
            .as_ref()
            .is_some_and(|value| value != &observed)
        {
            return Err("CA cleanup fingerprint differs".into());
        }
        self.active = false;
        Ok(())
    }
}
impl Drop for TemporaryTrust {
    fn drop(&mut self) {
        if self.active {
            let _ = self.remove();
        }
    }
}

fn require_ephemeral_runner() -> TestResult<PathBuf> {
    for (key, expected) in [
        ("CI", "true"),
        ("GITHUB_ACTIONS", "true"),
        ("RUNNER_ENVIRONMENT", "github-hosted"),
        ("VERYSYNC_TEST_EPHEMERAL_CA_TRUST", "selected"),
    ] {
        if std::env::var(key).ok().as_deref() != Some(expected) {
            return Err(
                "trusted-CA native target requires explicitly selected disposable GitHub-hosted VM"
                    .into(),
            );
        }
    }
    Ok(
        PathBuf::from(std::env::var_os("RUNNER_TEMP").ok_or("runner private directory required")?)
            .canonicalize()?,
    )
}
fn denied(result: verysync_sidecar::Result<GuiSession>) {
    assert!(
        matches!(&result, Err(Error::AccessDenied {response}) if response.status()==403)
            || matches!(&result, Err(Error::Authentication { status: 401 }))
    );
}

#[tokio::test]
async fn native_trusted_ca_ldap_verifies_chain_hostname_password_and_exact_cleanup() -> TestResult {
    let parent = require_ephemeral_runner()?;
    let root = tempfile::Builder::new()
        .prefix("vs-ldap-trusted-")
        .tempdir_in(parent)?
        .keep();
    let peer_root = root.join("peer");
    std::fs::create_dir(&peer_root)?;
    let mut peer = ldap_service::LdapService::start_trusted_tls(&peer_root)?;
    let mut trust = TemporaryTrust::install(peer_root.join("synthetic-ldap-ca.pem"))?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let id = core.client().instance().device_id.clone();
    let sentinel = root.join("sentinel.bin");
    std::fs::write(&sentinel, b"strict trusted LDAP keeps bytes")?;
    let localhost = peer.address.replacen("127.0.0.1:", "localhost:", 1);
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
    trust.remove()?;
    assert!(!peer_root.join(".ephemeral-ci-ca-lease.json").exists());
    std::fs::remove_dir_all(root)?;
    println!("native_ldap_trusted_ca_effects=12 strict_chain_and_hostname=true bypass=false exact_ca_cleanup=true ephemeral_ci_vm_only=true");
    Ok(())
}
