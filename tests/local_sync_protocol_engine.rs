//! Actual native protocol traffic and data effects, with synthetic owned peers.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
#[path = "common/sftp_identity_cases.rs"]
mod sftp_identity_cases;
#[path = "common/storage_diagnostic.rs"]
mod storage_diagnostic;
#[path = "common/storage_service.rs"]
mod storage_service;
use managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::{
    CreateLocalSyncJob, LocalSyncJobId, LocalSyncMode, LocalSyncRun, ManagedInstance,
    StorageEndpoint, StorageProtocol, TargetPath,
};

#[tokio::test]
async fn public_sftp_server_identity_reports_actual_wrong_and_matching_host_policies() -> TestResult
{
    sftp_identity_cases::run().await
}

async fn execute(core: &ManagedInstance, id: &LocalSyncJobId) -> TestResult<LocalSyncRun> {
    let operation = core.client().start_local_sync_preview(id).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status = core.client().local_sync_status(id).await?;
            assert_eq!(status.operation_id.as_ref(), Some(&operation.id));
            assert!(status.last_error.as_deref().unwrap_or_default().is_empty());
            if status.state == "idle" {
                break Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    let preview = core.client().local_sync_preview(id).await?;
    assert_eq!(preview.operation_id, operation.id);
    assert!(preview.count > 0);
    let receipt = core
        .client()
        .run_local_sync_preview_all(id, &preview.id)
        .await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let run = core.client().local_sync_run(id).await?;
            assert_eq!(run.id, receipt.id);
            if !run.finished.starts_with("0001-") {
                assert_eq!(run.summary.failed, 0);
                return Ok(run);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?
}
async fn protocol_effects(protocol: StorageProtocol) -> TestResult {
    let root = tempfile::Builder::new().prefix("vsp-").tempdir()?.keep();
    let source = root.join("source");
    std::fs::create_dir_all(source.join("nested"))?;
    let payload = b"actual VerySync native protocol payload";
    std::fs::write(source.join("nested").join("payload 中文 %.txt"), payload)?;
    let mut server = storage_service::Service::start(protocol, &root, Duration::ZERO)?;
    std::fs::write(
        server.share.join("sentinel.bin"),
        b"protocol destination-only sentinel",
    )?;
    // rclone v1.69.3 SFTP getSftpConnection retries authentication failures
    // through its native pacer. Explicitly budget this observed native work;
    // the library's ten-second default remains unchanged. A deadline error
    // must never be reported as a completed authentication refusal.
    let request_seconds = if protocol == StorageProtocol::Sftp {
        30
    } else {
        10
    };
    let settings = options(&root.join("core"))?
        .management_request_timeout(Duration::from_secs(request_seconds))?;
    let mut core = ManagedInstance::start(settings).await?;
    let identity = core.client().instance().device_id.clone();
    let authentication_started = std::time::Instant::now();
    let bad = core
        .client()
        .probe_storage_endpoint(&server.bad_endpoint)
        .await;
    let error = bad.expect_err("native core accepted incorrect remote credentials");
    let cause = match &error {
        verysync_sidecar::Error::MutationOutcomeUnknown { source, .. } => source.as_ref(),
        other => other,
    };
    assert!(
        matches!(
            cause,
            verysync_sidecar::Error::Api { .. }
                | verysync_sidecar::Error::Http { .. }
                | verysync_sidecar::Error::AccessDenied { .. }
        ),
        "incorrect credentials did not produce an actual native rejection: {cause:?}"
    );
    let authentication_refusal_elapsed_ms = authentication_started.elapsed().as_millis();
    let probe = core
        .client()
        .probe_storage_endpoint(&server.endpoint)
        .await?;
    assert!(!probe.time_precision.is_empty());
    core.client()
        .create_storage_directory(&server.endpoint, "", "created 中文 %")
        .await?;
    assert!(server.share.join("created 中文 %").is_dir());
    let listed = core
        .client()
        .browse_storage_endpoint(&server.endpoint, "")
        .await?;
    assert!(listed
        .entries
        .iter()
        .any(|e| e.path == "created 中文 %" && e.directory));
    let local = StorageEndpoint::local(TargetPath::local(&source))?;
    let options = CreateLocalSyncJob::new(
        "Explicit synthetic protocol job",
        local,
        server.endpoint.clone(),
        LocalSyncMode::MirrorAToB,
    )?
    .ignore_permissions(true);
    let job = core.client().create_local_sync_job(&options).await?;
    let completed = match execute(&core, &job.job_id).await {
        Ok(run) => run,
        Err(error) => {
            if let Some(native) = error.downcast_ref::<verysync_sidecar::Error>() {
                storage_diagnostic::native_rejection(native, &server.endpoint, &root);
            }
            return Err(error);
        }
    };
    assert_eq!(
        std::fs::read(server.share.join("nested").join("payload 中文 %.txt"))?,
        payload
    );
    assert_eq!(
        std::fs::read(source.join("nested").join("payload 中文 %.txt"))?,
        payload
    );
    assert_eq!(
        std::fs::read(server.share.join("sentinel.bin"))?,
        b"protocol destination-only sentinel"
    );
    let results = core
        .client()
        .local_sync_run_results(&job.job_id, &completed.id, 0, 100)
        .await?;
    assert!(results
        .iter()
        .any(|r| r.path == "nested/payload 中文 %.txt" && r.bytes == Some(payload.len() as u64)));
    core.client().delete_local_sync_job(&job.job_id).await?;
    assert_eq!(
        std::fs::read(server.share.join("nested").join("payload 中文 %.txt"))?,
        payload
    );
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let core_arch = core.client().instance().version.arch.clone();
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    server.stop()?;
    println!(
        "public storage protocol evidence: {}",
        serde_json::json!({
        "protocol":format!("{protocol:?}"),"explicit_management_request_seconds":request_seconds,"authentication_refusal_elapsed_ms":authentication_refusal_elapsed_ms,"native_rust_test_arch":std::env::consts::ARCH,
        "native_core_reported_arch":core_arch,"protocol_peer_python_platform":server.python_platform,
        "actual_incorrect_credentials_refused":true,"actual_native_probe":true,
        "actual_protocol_directory_creation_and_listing":true,"actual_exact_preview_operation":true,
        "actual_explicit_native_protocol_run":true,"actual_payload_and_source_bytes":true,
        "actual_destination_only_sentinel_preserved":true,"actual_result_payload_byte_count":true,
        "actual_registration_removal_preserves_data":true,"actual_same_identity":true,
        "actual_normal_core_tree_exit":true,"actual_exact_protocol_peer_stopped":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test]
async fn public_ftp_uses_the_native_core_for_actual_authenticated_data_effects() -> TestResult {
    protocol_effects(StorageProtocol::Ftp).await
}
#[tokio::test]
async fn public_sftp_uses_the_native_core_for_actual_authenticated_data_effects() -> TestResult {
    protocol_effects(StorageProtocol::Sftp).await
}
#[tokio::test]
async fn public_webdav_uses_the_native_core_for_actual_authenticated_data_effects() -> TestResult {
    protocol_effects(StorageProtocol::WebDav).await
}
#[tokio::test]
async fn public_smb_uses_the_native_core_for_actual_authenticated_data_effects() -> TestResult {
    protocol_effects(StorageProtocol::Smb).await
}

#[tokio::test]
async fn public_ftp_anonymous_authentication_has_actual_refusal_and_data_effects() -> TestResult {
    use verysync_sidecar::Error;
    let root = tempfile::Builder::new()
        .prefix("vs-ftp-anonymous-")
        .tempdir()?
        .keep();
    let source = root.join("source");
    std::fs::create_dir(&source)?;
    let payload = vec![0x5d; 131072];
    std::fs::write(source.join("anonymous %.bin"), &payload)?;
    let mut peer = storage_service::Service::start_anonymous_ftp(&root)?;
    std::fs::write(peer.share.join("sentinel.bin"), b"anonymous target-only")?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let denied = core
        .client()
        .browse_storage_endpoint(&peer.bad_endpoint, "")
        .await
        .expect_err("anonymous-only peer must refuse an ordinary named user");
    let cause = match &denied {
        Error::MutationOutcomeUnknown { source, .. } => source.as_ref(),
        other => other,
    };
    assert!(
        matches!(
            cause,
            Error::Api { .. } | Error::Http { .. } | Error::AccessDenied { .. }
        ),
        "actual native authentication refusal, not a timeout, required"
    );
    core.client().probe_storage_endpoint(&peer.endpoint).await?;
    let listing = core
        .client()
        .browse_storage_endpoint(&peer.endpoint, "")
        .await?;
    assert!(listing.entries.iter().any(|x| x.path == "sentinel.bin"));
    let job = core
        .client()
        .create_local_sync_job(
            &CreateLocalSyncJob::new(
                "explicit anonymous FTP",
                StorageEndpoint::local(TargetPath::local(&source))?,
                peer.endpoint.clone(),
                LocalSyncMode::MirrorAToB,
            )?
            .ignore_permissions(true),
        )
        .await?;
    let first = execute(&core, &job.job_id).await?;
    assert_eq!(first.summary.failed, 0);
    assert_eq!(std::fs::read(peer.share.join("anonymous %.bin"))?, payload);
    core.restart(Duration::from_secs(30)).await?;
    let retained = core.client().local_sync_job(&job.job_id).await?;
    assert_eq!(retained.side_b.extra()["user"], "anonymous");
    let next = vec![0x36; 65536];
    std::fs::write(source.join("after-restart.bin"), &next)?;
    let second = execute(&core, &job.job_id).await?;
    assert_ne!(first.id, second.id);
    assert_eq!(second.summary.failed, 0);
    for path in [&source, &peer.share] {
        assert_eq!(std::fs::read(path.join("anonymous %.bin"))?, payload);
        assert_eq!(std::fs::read(path.join("after-restart.bin"))?, next);
    }
    assert_eq!(
        std::fs::read(peer.share.join("sentinel.bin"))?,
        b"anonymous target-only"
    );
    core.client().delete_local_sync_job(&job.job_id).await?;
    assert_eq!(std::fs::read(peer.share.join("after-restart.bin"))?, next);
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    peer.stop()?;
    let observations = std::fs::read_to_string(&peer.observation_log)?
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .collect::<Vec<_>>();
    assert!(
        observations
            .iter()
            .any(|v| v["owned_ftp_event"] == "anonymous_authentication"
                && v["anonymous_user"] == true)
    );
    std::fs::remove_dir_all(&root)?;
    assert!(!root.exists());
    println!(
        "public anonymous FTP authentication evidence: {}",
        serde_json::json!({
        "actual_named_user_refused":true,"actual_anonymous_peer_identity_observed":true,
        "actual_probe_and_browse":true,"actual_two_explicit_previews_and_runs":true,
        "actual_exact_source_and_destination_bytes":true,"actual_same_identity_restart_and_credentials":true,
        "actual_sentinel_and_removal_retention":true,"actual_normal_tree_state_and_peer_cleanup":true,
        "ftp_tls_or_server_identity_claimed":false})
    );
    Ok(())
}

#[tokio::test]
async fn public_https_webdav_rejects_untrusted_certificate_and_requires_explicit_bypass_for_data(
) -> TestResult {
    use sha2::{Digest, Sha256};
    use verysync_sidecar::Error;
    let root = tempfile::Builder::new()
        .prefix("vs-dav-tls-")
        .tempdir()?
        .keep();
    let source = root.join("source");
    std::fs::create_dir(&source)?;
    let payload = vec![0x7b; 262144];
    std::fs::write(source.join("tls-payload.bin"), &payload)?;
    let mut peer = storage_service::Service::start_https(&root)?;
    std::fs::write(peer.share.join("sentinel.bin"), b"TLS target-only")?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let checked = peer.endpoint.clone().insecure_tls(false)?;
    let refused = core
        .client()
        .probe_storage_endpoint(&checked)
        .await
        .unwrap_err();
    let Error::MutationOutcomeUnknown {
        source: refusal, ..
    } = refused
    else {
        return Err("expected a completed native TLS refusal, not a management timeout".into());
    };
    let response = match refusal.as_ref() {
        Error::Api { response, .. } | Error::Http { response } => response,
        error => return Err(format!("expected native TLS response, observed {error:?}").into()),
    };
    let text = String::from_utf8_lossy(response.body_bytes()).to_ascii_lowercase();
    assert!(
        text.contains("certificate")
            && (text.contains("unknown authority") || text.contains("untrusted"))
    );
    assert!(!peer.share.join("tls-payload.bin").exists());
    let permitted = checked.insecure_tls(true)?;
    core.client().probe_storage_endpoint(&permitted).await?;
    let credentials_error = core
        .client()
        .probe_storage_endpoint(&peer.bad_endpoint.clone().insecure_tls(true)?)
        .await
        .expect_err("TLS bypass must not bypass authentication");
    let credentials_cause = match &credentials_error {
        Error::MutationOutcomeUnknown { source, .. } => source.as_ref(),
        error => error,
    };
    assert!(
        matches!(
            credentials_cause,
            Error::Api { .. } | Error::Http { .. } | Error::AccessDenied { .. }
        ),
        "expected a completed authentication refusal, observed {credentials_cause:?}"
    );
    let job = core
        .client()
        .create_local_sync_job(
            &CreateLocalSyncJob::new(
                "explicit synthetic TLS",
                StorageEndpoint::local(TargetPath::local(&source))?,
                permitted,
                LocalSyncMode::MirrorAToB,
            )?
            .ignore_permissions(true),
        )
        .await?;
    let run = execute(&core, &job.job_id).await?;
    assert_eq!(run.summary.failed, 0);
    assert_eq!(std::fs::read(peer.share.join("tls-payload.bin"))?, payload);
    assert_eq!(std::fs::read(source.join("tls-payload.bin"))?, payload);
    assert_eq!(
        std::fs::read(peer.share.join("sentinel.bin"))?,
        b"TLS target-only"
    );
    core.client().delete_local_sync_job(&job.job_id).await?;
    assert_eq!(std::fs::read(peer.share.join("tls-payload.bin"))?, payload);
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    peer.stop()?;
    println!(
        "public HTTPS storage boundary evidence: {}",
        serde_json::json!({"actual_private_tls_listener":true,"actual_unknown_certificate_refused":true,"actual_no_copy_before_explicit_choice":true,"actual_explicit_insecure_probe_succeeds":true,"actual_wrong_credentials_still_refused":true,"actual_exact_native_preview_and_run":true,"actual_all_source_and_target_payload_bytes":true,"actual_target_only_sentinel_retained":true,"actual_registration_removal_keeps_data":true,"actual_same_identity_and_normal_owned_exit":true,"certificate_pem_sha256":format!("{:x}",Sha256::digest(std::fs::read(root.join("synthetic-webdav-cert.pem"))?)),"trusted_identity_positive_claimed":false,"system_trust_modified":false})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn public_smb_domain_ntlm_and_guest_selection_have_actual_peer_and_data_effects() -> TestResult
{
    use verysync_sidecar::Error;
    for mode in ["domain", "guest"] {
        let root = tempfile::Builder::new()
            .prefix("vs-smb-auth-")
            .tempdir()?
            .keep();
        let source = root.join("source");
        std::fs::create_dir(&source)?;
        let payload = b"actual SMB selected authentication payload";
        std::fs::write(source.join("auth.bin"), payload)?;
        let mut peer = storage_service::Service::start_smb_auth(&root, mode)?;
        std::fs::write(
            peer.share.join("sentinel.bin"),
            b"authentication target-only",
        )?;
        let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
        let identity = core.client().instance().device_id.clone();
        let bad = if mode == "domain" {
            peer.endpoint.clone().smb_domain("WRONG-SYNTHETIC")?
        } else {
            peer.bad_endpoint.clone().smb_guest(false)?
        };
        let refusal = core
            .client()
            .probe_storage_endpoint(&bad)
            .await
            .expect_err("private SMB authentication policy was ignored");
        let cause = match &refusal {
            Error::MutationOutcomeUnknown { source, .. } => source.as_ref(),
            error => error,
        };
        assert!(
            matches!(
                cause,
                Error::Api { .. } | Error::Http { .. } | Error::AccessDenied { .. }
            ),
            "expected native refusal rather than timeout: {cause:?}"
        );
        if mode == "domain" {
            let wrong_password = peer.bad_endpoint.clone().smb_domain("VS-SYNTHETIC")?;
            let error = core
                .client()
                .probe_storage_endpoint(&wrong_password)
                .await
                .expect_err("domain selection must not replace password verification");
            let cause = match &error {
                Error::MutationOutcomeUnknown { source, .. } => source.as_ref(),
                error => error,
            };
            assert!(matches!(
                cause,
                Error::Api { .. } | Error::Http { .. } | Error::AccessDenied { .. }
            ));
        }
        core.client().probe_storage_endpoint(&peer.endpoint).await?;
        let job = core
            .client()
            .create_local_sync_job(
                &CreateLocalSyncJob::new(
                    "explicit SMB authentication",
                    StorageEndpoint::local(TargetPath::local(&source))?,
                    peer.endpoint.clone(),
                    LocalSyncMode::MirrorAToB,
                )?
                .ignore_permissions(true),
            )
            .await?;
        execute(&core, &job.job_id).await?;
        assert_eq!(std::fs::read(peer.share.join("auth.bin"))?, payload);
        assert_eq!(std::fs::read(source.join("auth.bin"))?, payload);
        assert_eq!(
            std::fs::read(peer.share.join("sentinel.bin"))?,
            b"authentication target-only"
        );
        assert_eq!(core.client().system_status().await?.device_id, identity);
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
        peer.stop()?;
        let records = std::fs::read_to_string(root.join("smb-auth-observations.jsonl"))?
            .lines()
            .map(serde_json::from_str::<serde_json::Value>)
            .collect::<Result<Vec<_>, _>>()?;
        assert!(records
            .iter()
            .any(|r| r["policy_matched"] == false && r["status"] == 0xC000006Du64));
        assert!(records
            .iter()
            .any(|r| r["policy_matched"] == true && r["status"] == 0));
        if mode == "domain" {
            assert!(records
                .iter()
                .any(|r| r["policy_matched"] == true && r["status"] == 0xC000006Du64));
            assert!(records
                .iter()
                .any(|r| r["status"] == 0 && r["user_present"] == true && r["session_flags"] == 0));
        } else {
            assert!(records.iter().any(|r| r["status"] == 0
                && r["user_present"] == false
                && r["session_flags"] == 1));
        }
        println!(
            "public SMB authentication boundary evidence: {}",
            serde_json::json!({"mode":mode,"actual_wrong_policy_refused":true,"actual_native_authentication_fields_observed":true,"actual_native_probe_and_explicit_copy":true,"actual_source_and_target_payload_bytes":true,"actual_target_only_sentinel_retained":true,"actual_same_identity_and_normal_owned_exit":true,"peer_observations":records,"active_directory_or_kerberos_claimed":false})
        );
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[tokio::test]
async fn public_sftp_inline_key_copies_real_bytes_and_preserves_native_probe_boundary() -> TestResult
{
    use verysync_sidecar::Error;
    let root = tempfile::Builder::new()
        .prefix("vs-sftp-inline-")
        .tempdir()?
        .keep();
    let source = root.join("source");
    std::fs::create_dir(&source)?;
    let bytes = b"actual inline SFTP key authenticated payload";
    std::fs::write(source.join("key-auth.bin"), bytes)?;
    let mut peer = storage_service::Service::start(StorageProtocol::Sftp, &root, Duration::ZERO)?;
    std::fs::write(
        peer.share.join("sentinel.bin"),
        b"retained destination bytes",
    )?;
    let user = peer.endpoint.extra()["user"]
        .as_str()
        .ok_or("synthetic user absent")?;
    let base = peer.endpoint.clone().credentials(user, "")?;
    let good = base.clone().private_key_pem(std::fs::read_to_string(
        root.join("synthetic-client-key.pem"),
    )?)?;
    let wrong = base.private_key_pem(std::fs::read_to_string(
        root.join("synthetic-host-key.pem"),
    )?)?;
    let mut core = ManagedInstance::start(
        options(&root.join("core"))?.management_request_timeout(Duration::from_secs(30))?,
    )
    .await?;
    let identity = core.client().instance().device_id.clone();
    let started = std::time::Instant::now();
    let bad = core
        .client()
        .browse_storage_endpoint(&wrong, "")
        .await
        .unwrap_err();
    assert!(
        matches!(
            bad,
            Error::Api { .. } | Error::Http { .. } | Error::AccessDenied { .. }
        ),
        "wrong private key must be an actual native rejection"
    );
    let wrong_key_refusal_ms = started.elapsed().as_millis();
    let probe = core
        .client()
        .probe_storage_endpoint(&good)
        .await
        .unwrap_err();
    let Error::MutationOutcomeUnknown { source: cause, .. } = probe else {
        return Err("expected native probe outcome boundary".into());
    };
    let response = match *cause {
        Error::Api { response, .. } | Error::Http { response } => response,
        _ => return Err("expected actual native probe error, not request timeout".into()),
    };
    let native: serde_json::Value = serde_json::from_slice(response.body_bytes())?;
    assert_eq!(response.status(), 500);
    assert!(native["error"]
        .as_str()
        .is_some_and(|s| s.contains("no key found")));
    let listing = core.client().browse_storage_endpoint(&good, "").await?;
    assert!(listing
        .entries
        .iter()
        .any(|entry| entry.path == "sentinel.bin"));
    let job = core
        .client()
        .create_local_sync_job(
            &CreateLocalSyncJob::new(
                "explicit inline key",
                StorageEndpoint::local(TargetPath::local(&source))?,
                good,
                LocalSyncMode::MirrorAToB,
            )?
            .ignore_permissions(true),
        )
        .await?;
    let run = execute(&core, &job.job_id).await?;
    assert_eq!(run.summary.failed, 0);
    assert_eq!(std::fs::read(peer.share.join("key-auth.bin"))?, bytes);
    assert_eq!(std::fs::read(source.join("key-auth.bin"))?, bytes);
    assert_eq!(
        std::fs::read(peer.share.join("sentinel.bin"))?,
        b"retained destination bytes"
    );
    core.client().delete_local_sync_job(&job.job_id).await?;
    assert_eq!(std::fs::read(peer.share.join("key-auth.bin"))?, bytes);
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(15)).await?;
    assert_eq!(exit.code, Some(0));
    assert!(!exit.forced && exit.tree_stopped && exit.state_released);
    peer.stop()?;
    println!("native inline SFTP key wrong_key_actual_rejection_ms={wrong_key_refusal_ms} no_password_fallback=true key_authenticated_browse=true exact_preview_run=true all_file_bytes=true registration_removal_keeps_files=true identity_retained=true native_probe500_key_parser_boundary=true verified_host_identity_not_claimed=true normal_tree_exit=true");
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// The explicit native runner serializes tests. This changes only this disposable
// test process before starting owned cores, and restores every previous entry.
struct PrivateTlsNoProxy(Vec<(&'static str, Option<std::ffi::OsString>)>);
impl PrivateTlsNoProxy {
    fn select() -> Self {
        let names = if cfg!(windows) {
            vec!["NO_PROXY"]
        } else {
            vec!["NO_PROXY", "no_proxy"]
        };
        let previous = names
            .into_iter()
            .map(|name| (name, std::env::var_os(name)))
            .collect::<Vec<_>>();
        for (name, old) in &previous {
            let mut selected = old.clone().unwrap_or_default();
            selected.push(",ldap.localhost.direct");
            std::env::set_var(name, selected);
        }
        Self(previous)
    }
}
impl Drop for PrivateTlsNoProxy {
    fn drop(&mut self) {
        for (name, previous) in &self.0 {
            match previous {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

#[tokio::test]
async fn public_https_webdav_trusted_chain_hostname_credentials_and_data_are_verified() -> TestResult
{
    use verysync_sidecar::Error;
    let manifest = std::path::PathBuf::from(
        std::env::var_os("VERYSYNC_TEST_LDAP_TLS_MANIFEST")
            .ok_or("explicit prepared private public-CA loopback TLS fixture required")?,
    );
    if !manifest.is_absolute() || manifest.file_name().is_none_or(|p| p != "manifest.json") {
        return Err("absolute private TLS manifest required".into());
    }
    let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(&manifest)?)?;
    assert_eq!(fixture["hostname"], "ldap.localhost.direct");
    let bypass = PrivateTlsNoProxy::select();
    let root = tempfile::Builder::new()
        .prefix("vs-dav-trusted-")
        .tempdir()?
        .keep();
    let source = root.join("source");
    std::fs::create_dir(&source)?;
    let payload = vec![0x6d; 262144];
    std::fs::write(source.join("trusted TLS %.bin"), &payload)?;
    let mut peer = storage_service::Service::start_public_https(&root, &manifest)?;
    std::fs::write(peer.share.join("sentinel.bin"), b"trusted TLS target-only")?;
    let checked = peer.endpoint.clone().insecure_tls(false)?;
    assert!(checked.uri().starts_with("https://ldap.localhost.direct:"));
    let wrong_host = StorageEndpoint::remote(
        StorageProtocol::WebDav,
        &checked
            .uri()
            .replacen("ldap.localhost.direct", "127.0.0.1", 1),
    )?
    .credentials(
        checked.extra()["user"]
            .as_str()
            .ok_or("private user absent")?,
        checked.extra()["password"]
            .as_str()
            .ok_or("private password absent")?,
    )?
    .insecure_tls(false)?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    core.client().probe_storage_endpoint(&checked).await?;
    let refused = core
        .client()
        .probe_storage_endpoint(&wrong_host)
        .await
        .expect_err("trusted chain must not bypass hostname validation");
    let cause = match &refused {
        Error::MutationOutcomeUnknown { source, .. } => source.as_ref(),
        error => error,
    };
    let response = match cause {
        Error::Api { response, .. } | Error::Http { response } => response,
        error => {
            return Err(
                format!("expected completed native hostname refusal, observed {error:?}").into(),
            )
        }
    };
    let text = String::from_utf8_lossy(response.body_bytes()).to_ascii_lowercase();
    assert!(
        text.contains("certificate")
            && (text.contains("127.0.0.1") || text.contains("ip san") || text.contains("hostname"))
    );
    let denied = core
        .client()
        .probe_storage_endpoint(&peer.bad_endpoint.clone().insecure_tls(false)?)
        .await
        .expect_err("strict TLS must retain credential validation");
    let denied = match &denied {
        Error::MutationOutcomeUnknown { source, .. } => source.as_ref(),
        error => error,
    };
    assert!(
        matches!(
            denied,
            Error::Api { .. } | Error::Http { .. } | Error::AccessDenied { .. }
        ),
        "actual credential refusal required, observed {denied:?}"
    );
    assert!(!peer.share.join("trusted TLS %.bin").exists());
    let job = core
        .client()
        .create_local_sync_job(
            &CreateLocalSyncJob::new(
                "strict trusted HTTPS",
                StorageEndpoint::local(TargetPath::local(&source))?,
                checked,
                LocalSyncMode::MirrorAToB,
            )?
            .ignore_permissions(true),
        )
        .await?;
    assert_disabled_insecure_tls_readback(&job.side_b);
    let first = execute(&core, &job.job_id).await?;
    assert_eq!(first.summary.failed, 0);
    assert_eq!(
        std::fs::read(peer.share.join("trusted TLS %.bin"))?,
        payload
    );
    core.restart(Duration::from_secs(30)).await?;
    let retained = core.client().local_sync_job(&job.job_id).await?;
    assert_disabled_insecure_tls_readback(&retained.side_b);
    core.client()
        .probe_storage_endpoint(&retained.side_b)
        .await?;
    let next_payload = vec![0x93; 131072];
    std::fs::write(source.join("after-restart.bin"), &next_payload)?;
    let next = execute(&core, &job.job_id).await?;
    assert_ne!(first.id, next.id);
    assert_eq!(next.summary.failed, 0);
    for path in [&source, &peer.share] {
        assert_eq!(std::fs::read(path.join("trusted TLS %.bin"))?, payload);
        assert_eq!(std::fs::read(path.join("after-restart.bin"))?, next_payload);
    }
    assert_eq!(
        std::fs::read(peer.share.join("sentinel.bin"))?,
        b"trusted TLS target-only"
    );
    core.client().delete_local_sync_job(&job.job_id).await?;
    assert_eq!(
        std::fs::read(peer.share.join("after-restart.bin"))?,
        next_payload
    );
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    peer.stop()?;
    std::fs::remove_dir_all(&root)?;
    assert!(!root.exists());
    drop(bypass);
    println!(
        "public trusted HTTPS WebDAV identity evidence: {}",
        serde_json::json!({
        "actual_strict_chain_and_hostname_success":true,"actual_wrong_hostname_refused":true,
        "actual_wrong_credentials_refused":true,"actual_no_transfer_before_explicit_run":true,
        "actual_exact_payloads_before_and_after_restart":true,"actual_strict_policy_persisted":true,
        "actual_same_identity_source_sentinel_and_registration_removal_retention":true,
        "actual_normal_tree_and_state_release":true,"actual_owned_peer_and_private_files_removed":true,
        "leaf_sha256":fixture["leaf_sha256"],"system_trust_mutations":0,"insecure_tls":false})
    );
    Ok(())
}

// The native endpoint serializer omits its false default. Preserve that raw
// omission while rejecting null, true and malformed values. This configuration
// check alone never attests SFTP server identity.
fn assert_disabled_insecure_tls_readback(endpoint: &StorageEndpoint) {
    assert!(matches!(
        endpoint.extra().get("insecureTls"),
        None | Some(serde_json::Value::Bool(false))
    ));
}

#[tokio::test]
async fn public_strict_storage_tls_flag_survives_create_update_and_restart() -> TestResult {
    use verysync_sidecar::{Error, LocalSyncJobPatch};
    for protocol in [StorageProtocol::Sftp, StorageProtocol::WebDav] {
        let root = tempfile::Builder::new()
            .prefix("vs-strict-flag-")
            .tempdir()?
            .keep();
        let source = root.join("source");
        std::fs::create_dir(&source)?;
        std::fs::write(
            source.join("source.bin"),
            b"no implicit TLS configuration transfer",
        )?;
        let mut peer = if protocol == StorageProtocol::WebDav {
            storage_service::Service::start_https(&root)?
        } else {
            storage_service::Service::start(protocol, &root, Duration::ZERO)?
        };
        std::fs::write(
            peer.share.join("sentinel.bin"),
            b"destination-only TLS configuration sentinel",
        )?;
        let selected = peer.endpoint.clone().insecure_tls(false)?;
        let mut other_fields = selected.extra().clone();
        other_fields.remove("insecureTls");
        let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
        let identity = core.client().instance().device_id.clone();
        let job = core
            .client()
            .create_local_sync_job(
                &CreateLocalSyncJob::new(
                    "explicit strict TLS flag",
                    StorageEndpoint::local(TargetPath::local(&source))?,
                    selected.clone(),
                    LocalSyncMode::MirrorAToB,
                )?
                .enabled(false)
                .ignore_permissions(true),
            )
            .await?;
        assert!(!job.enabled);
        assert_disabled_insecure_tls_readback(&job.side_b);
        let bypass = core
            .client()
            .update_local_sync_job(
                &job.job_id,
                &LocalSyncJobPatch::default().side_b(peer.endpoint.clone().insecure_tls(true)?),
            )
            .await?;
        assert!(bypass.requested_fields_match);
        assert_eq!(
            bypass.configuration.side_b.extra().get("insecureTls"),
            Some(&serde_json::Value::Bool(true))
        );
        let strict = core
            .client()
            .update_local_sync_job(
                &job.job_id,
                &LocalSyncJobPatch::default().side_b(selected.clone()),
            )
            .await?;
        assert!(strict.requested_fields_match);
        assert_disabled_insecure_tls_readback(&strict.configuration.side_b);
        core.restart(Duration::from_secs(30)).await?;
        let retained = core.client().local_sync_job(&job.job_id).await?;
        assert!(!retained.enabled);
        assert_eq!(retained.side_b.uri(), selected.uri());
        assert_disabled_insecure_tls_readback(&retained.side_b);
        for (name, value) in &other_fields {
            assert!(
                retained.side_b.extra().get(name) == Some(value),
                "unselected endpoint field differs"
            );
        }
        if protocol == StorageProtocol::WebDav {
            let refusal = core
                .client()
                .probe_storage_endpoint(&retained.side_b)
                .await
                .expect_err("omitted false default must not bypass untrusted certificates");
            let cause = match &refusal {
                Error::MutationOutcomeUnknown { source, .. } => source.as_ref(),
                error => error,
            };
            let response = match cause {
                Error::Api { response, .. } | Error::Http { response } => response,
                error => {
                    return Err(format!("native certificate refusal required: {error:?}").into())
                }
            };
            assert!(String::from_utf8_lossy(response.body_bytes())
                .to_ascii_lowercase()
                .contains("certificate"));
        }
        assert_eq!(
            std::fs::read(source.join("source.bin"))?,
            b"no implicit TLS configuration transfer"
        );
        assert!(!peer.share.join("source.bin").exists());
        assert_eq!(
            std::fs::read(peer.share.join("sentinel.bin"))?,
            b"destination-only TLS configuration sentinel"
        );
        core.client().delete_local_sync_job(&job.job_id).await?;
        assert!(core.client().local_sync_jobs().await?.is_empty());
        assert_eq!(core.client().system_status().await?.device_id, identity);
        let exit = core.shutdown(Duration::from_secs(15)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
        peer.stop()?;
        std::fs::remove_dir_all(root)?;
        println!(
            "native strict storage flag evidence: {}",
            serde_json::json!({
            "protocol":format!("{protocol:?}"),"actual_create_and_readback":true,
            "actual_true_to_false_update_and_native_omission_preserved":true,
            "actual_same_identity_restart_and_other_endpoint_fields_preserved":true,
            "actual_no_implicit_transfer_or_unrelated_file_changes":true,
            "actual_webdav_untrusted_certificate_refused_after_restart":protocol == StorageProtocol::WebDav,
            "sftp_host_identity_attested":false,"actual_registration_removal_and_normal_owned_cleanup":true})
        );
    }
    Ok(())
}
