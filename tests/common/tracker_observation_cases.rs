//! Explicit official tracker registration and controlled disconnect observations.
use super::*;
use verysync_sidecar::{TransportPatch, TransportUpdate};

async fn observe_tracker_write(
    core: &ManagedInstance,
    identity: &DeviceId,
    requested: bool,
    expected: &serde_json::Value,
) -> verysync_sidecar::Result<TransportUpdate> {
    let update = core
        .client()
        .update_transport_configuration(&TransportPatch::default().tracker(requested))
        .await;
    match &update {
        Ok(result) => eprintln!(
            "tracker write observation: {}",
            json!({"enable":requested, "typed_acknowledgement":true, "fields_match":result.requested_fields_match})
        ),
        Err(error) => {
            let underlying = match error {
                Error::MutationOutcomeUnknown { source, .. } => match source.as_ref() {
                    Error::Timeout { .. } => "timeout",
                    Error::Transport { .. } => "transport",
                    Error::InvalidResponse { .. } => "invalid response",
                    Error::Http { .. } => "HTTP error",
                    _ => "other unknown result",
                },
                _ => "different API error",
            };
            let readback = tokio::time::timeout(Duration::from_secs(4), async {
                let identity_matches = core
                    .client()
                    .system_status()
                    .await
                    .is_ok_and(|status| status.device_id == *identity);
                (identity_matches, core.client().configuration().await.ok())
            })
            .await;
            let (identity_matches, document) = readback
                .map(|(matches, document)| (Some(matches), document))
                .unwrap_or((None, None));
            let observed = document.as_ref().and_then(|config| {
                config
                    .native_document()
                    .pointer("/options/trackerEnabled")
                    .and_then(serde_json::Value::as_bool)
            });
            let exact = document
                .as_ref()
                .is_some_and(|config| config.native_document() == expected);
            eprintln!(
                "tracker write observation: {}",
                json!({"enable":requested, "typed_acknowledgement":false, "error_kind":underlying,
                       "identity_matches":identity_matches, "independent_readback":observed,
                       "entire_configuration_matches":exact, "write_retried":false})
            );
        }
    }
    update
}

#[tokio::test]
async fn native_tracker_registers_and_exposes_controlled_disconnect() -> TestResult {
    if std::env::var("VERYSYNC_TEST_TRACKER").as_deref() != Ok("explicit-official-network-test") {
        return Err("official tracker test requires explicit network opt-in".into());
    }
    let control = std::path::PathBuf::from(
        std::env::var_os("VERYSYNC_TEST_TRACKER_CUT_FILE")
            .ok_or("owned tracker cut file required")?,
    );
    let token = std::env::var("VERYSYNC_TEST_TRACKER_CUT_TOKEN")?;
    if !control.is_absolute() || control.exists() || token.len() != 64 {
        return Err("fresh owned tracker control and nonce required".into());
    }
    let root = tempfile::Builder::new()
        .prefix("vs-tracker-")
        .tempdir()?
        .keep();
    let sentinel = root.join("sentinel.bin");
    let bytes = b"independent caller sample survives tracker configuration";
    std::fs::write(&sentinel, bytes)?;
    let mut core = ManagedInstance::start(options(&root.join("state"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let original = core.client().transport_configuration().await?;
    assert!(
        !original.tracker_enabled
            && !original.nat_enabled
            && !original.udp_enabled
            && !original.relays_enabled
            && !original.tcp_punch_enabled
    );
    let network = core.client().network_configuration().await?;
    assert!(!network.global_announce_enabled && !network.local_announce_enabled);
    let disabled = core.client().transport_status().await?;
    assert_eq!(disabled.tracker.connection_state, "disabled");
    assert!(core.client().folders().await?.is_empty());
    let before = core.client().configuration().await?;
    let state = core.state_directory().to_path_buf();
    let credentials = [
        std::fs::read(state.join("key.pem"))?,
        std::fs::read(state.join("cert.pem"))?,
    ];
    let mut enabled_document = before.native_document().clone();
    enabled_document["options"]["trackerEnabled"] = serde_json::json!(true);
    let changed = observe_tracker_write(&core, &identity, true, &enabled_document).await?;
    assert!(changed.requested_fields_match && changed.configuration.tracker_enabled);
    assert!(
        changed.configuration.extra == original.extra,
        "unrelated transport fields changed"
    );
    assert!(
        core.client().configuration().await?.native_document() == &enabled_document,
        "unrelated enabled configuration changed"
    );
    core.restart(Duration::from_secs(30)).await?;
    assert!(
        core.client().instance().device_id == identity,
        "owned identity changed"
    );
    assert!(
        core.client().configuration().await?.native_document() == &enabled_document,
        "unrelated enabled configuration changed"
    );
    let start = tokio::time::Instant::now();
    let deadline = start + Duration::from_secs(30);
    let mut registration_ms = None;
    let mut failure_ms = None;
    while tokio::time::Instant::now() < deadline {
        let status = core.client().transport_status().await?;
        let native_state = status
            .tracker
            .extra
            .get("state")
            .and_then(serde_json::Value::as_str);
        let error = status
            .tracker
            .extra
            .get("connectError")
            .and_then(serde_json::Value::as_str);
        if registration_ms.is_none()
            && status.tracker.connection_state == "connected"
            && native_state == Some("state:synchronized")
            && error == Some("")
            && status
                .tracker
                .extra
                .get("host")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|s| !s.is_empty())
        {
            registration_ms = Some(start.elapsed().as_millis());
            std::fs::write(&control, token.as_bytes())?;
        } else if registration_ms.is_some()
            && status.tracker.connection_state != "connected"
            && error.is_some_and(|s| !s.is_empty())
        {
            failure_ms = Some(start.elapsed().as_millis());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        registration_ms.is_some(),
        "actual native registration was not observed"
    );
    assert!(
        failure_ms.is_some(),
        "actual native error after controlled cut was not observed"
    );
    let changed = observe_tracker_write(&core, &identity, false, before.native_document()).await?;
    assert!(changed.requested_fields_match);
    core.restart(Duration::from_secs(30)).await?;
    assert!(
        core.client().instance().device_id == identity,
        "owned identity changed"
    );
    assert_eq!(
        core.client()
            .transport_status()
            .await?
            .tracker
            .connection_state,
        "disabled"
    );
    let after = core.client().configuration().await?;
    assert!(
        before.native_document() == after.native_document(),
        "original full configuration was not restored"
    );
    for (name, expected) in ["key.pem", "cert.pem"].into_iter().zip(credentials) {
        assert!(
            std::fs::read(state.join(name))? == expected,
            "owned credential bytes changed"
        );
    }
    assert_eq!(std::fs::read(&sentinel)?, bytes);
    assert!(core.client().folders().await?.is_empty());
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.code == Some(0) && !exit.forced && exit.tree_stopped && exit.state_released);
    std::fs::remove_dir_all(root)?;
    println!(
        "native tracker registration and controlled disconnect: {}",
        serde_json::json!({
            "explicit_official_network_opt_in":true,"empty_independent_identity":true,
            "registration_ms":registration_ms,"controlled_failure_ms":failure_ms,"observation_bound_seconds":30,
            "actual_connected_and_native_synchronized":true,"actual_nonempty_error_after_cut":true,
            "raw_host_error_or_identity_logged":false,"all_other_network_features_disabled":true,
            "original_full_configuration_keys_certificate_identity_and_sentinel_preserved":true,
            "disabled_restored":true,"normal_code0_nonforced_tree_and_state_exit":true,
            "uncontrolled_provider_outage_claimed":false
        })
    );
    Ok(())
}
