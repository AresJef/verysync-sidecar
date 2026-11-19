//! Native additional peer defaults and independent existing-peer configuration.
use super::*;

#[tokio::test]
async fn native_advanced_device_defaults_and_existing_peer_edits_retain_identity_and_data(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-device-options-")
        .tempdir()?
        .keep();
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let mut first = ManagedInstance::start(options(&root.join("first"))?).await?;
    let mut second = ManagedInstance::start(options(&root.join("second"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let old = first.client().instance().device_id.clone();
    let new = second.client().instance().device_id.clone();
    let sentinel = root.join("sentinel.bin");
    std::fs::write(&sentinel, b"retained native device options")?;
    let existing = core
        .client()
        .create_device(
            &CreateDeviceOptions::new(old.clone()).settings(
                DevicePatch::default()
                    .paused(true)
                    .advanced_configuration(DeviceAdvancedPatch::default().introducer(true))?,
            ),
        )
        .await?
        .configuration;
    let before = core.client().configuration().await?;
    for selected in [true, false] {
        let response = core
            .client()
            .update_device(
                &old,
                &DevicePatch::default().advanced_configuration(
                    DeviceAdvancedPatch::default().self_classification(selected),
                )?,
            )
            .await?;
        assert!(response.requested_fields_match);
        assert_eq!(
            response
                .configuration
                .advanced_configuration()?
                .self_classification,
            Some(selected)
        );
    }
    let default_source = core
        .client()
        .update_device_defaults(&DevicePatch::default().advanced_configuration(
            DeviceAdvancedPatch::default().introduced_by(Some(old.clone())),
        )?)
        .await?;
    assert!(!default_source.requested_fields_match);
    assert!(matches!(
        default_source
            .configuration
            .advanced_configuration()?
            .introduced_by,
        Some(IntroductionSource::None)
    ));
    let ignored = IgnoredFolder {
        id: FolderId::parse("synthetic-ignored-default")?,
        label: "synthetic retained offer".into(),
        time: "2026-11-15T00:00:00Z".into(),
        extra: std::collections::BTreeMap::new(),
    };
    let advanced = DeviceAdvancedPatch::default()
        .self_classification(true)
        .certificate_name("synthetic-native-name")
        .introducer(true)
        .skip_introduction_removals(true)
        .allowed_networks(vec!["127.0.0.0/8".into(), "::1/128".into()])
        .auto_accept_folders(true)
        .max_request_kib(4096)
        .untrusted(false)
        .num_connections(3)
        .overwrite_remote_device_names_on_connect(false)
        .ignored_folders(vec![ignored]);
    let patch = DevicePatch::default()
        .paused(true)
        .advanced_configuration(advanced)?;
    let requested = serde_json::to_value(&patch)?;
    let defaults = core.client().update_device_defaults(&patch).await?;
    if !defaults.requested_fields_match {
        let actual = serde_json::to_value(&defaults.configuration)?;
        for (key, value) in requested.as_object().ok_or("device patch absent")? {
            if key == "introducedBy" {
                println!(
                    "native_template_introduction_source_empty={}",
                    actual.get(key).and_then(serde_json::Value::as_str) == Some("")
                );
            }
            println!(
                "native_device_template_field_match key={key} matched={}",
                actual.get(key) == Some(value)
            );
        }
    }
    assert!(defaults.requested_fields_match);
    assert_eq!(
        defaults
            .configuration
            .advanced_configuration()?
            .num_connections,
        Some(3)
    );
    assert!(
        core.client().device(&old).await?.extra == existing.extra,
        "existing peer inherited future defaults"
    );
    let inherited = core
        .client()
        .create_device(&CreateDeviceOptions::new(new.clone()))
        .await?;
    assert!(inherited.requested_fields_match && inherited.configuration.paused);
    for (key, value) in requested.as_object().ok_or("device patch absent")? {
        if key != "paused" {
            assert!(
                inherited.configuration.extra.get(key) == Some(value),
                "device did not inherit selected field: {key}"
            );
        }
    }
    assert_eq!(core.client().ignored_folders(&new).await?.len(), 1);
    let introduction = core
        .client()
        .update_device(
            &new,
            &DevicePatch::default().advanced_configuration(
                DeviceAdvancedPatch::default().introduced_by(Some(old.clone())),
            )?,
        )
        .await?;
    println!(
        "native_configured_introduction_source_matched={} source_empty={}",
        introduction.requested_fields_match,
        matches!(
            introduction
                .configuration
                .advanced_configuration()?
                .introduced_by,
            Some(IntroductionSource::None)
        )
    );
    assert!(introduction.requested_fields_match);
    assert!(
        matches!(introduction.configuration.advanced_configuration()?.introduced_by,
        Some(IntroductionSource::Device(ref id)) if id==&old)
    );
    core.restart(Duration::from_secs(30)).await?;
    assert!(
        matches!(core.client().device(&new).await?.advanced_configuration()?.introduced_by,
        Some(IntroductionSource::Device(ref id)) if id==&old)
    );
    let changed = core
        .client()
        .update_device(
            &old,
            &DevicePatch::default().advanced_configuration(
                DeviceAdvancedPatch::default()
                    .num_connections(2)
                    .introduced_by(None)
                    .auto_accept_folders(false)
                    .introducer(false)
                    .untrusted(true),
            )?,
        )
        .await?;
    assert!(changed.requested_fields_match);
    assert_eq!(
        changed.configuration.advanced_configuration()?.untrusted,
        Some(true)
    );
    assert!(matches!(
        changed
            .configuration
            .advanced_configuration()?
            .introduced_by,
        Some(IntroductionSource::None)
    ));
    assert_eq!(
        core.client()
            .device(&new)
            .await?
            .advanced_configuration()?
            .untrusted,
        Some(false)
    );
    let after = core.client().configuration().await?;
    for section in ["folders", "gui", "ldap", "relayServer", "options"] {
        assert!(
            before.native_document()[section] == after.native_document()[section],
            "unrelated device-option section changed"
        );
    }
    let mut snapshot = after;
    snapshot.set_device_defaults(
        &DevicePatch::default()
            .advanced_configuration(DeviceAdvancedPatch::default().num_connections(4))?,
    )?;
    assert!(
        core.client()
            .replace_configuration(&snapshot)
            .await?
            .requested_fields_match
    );
    let stopped = core.shutdown(Duration::from_secs(10)).await?;
    assert!(
        stopped.tree_stopped
            && stopped.state_released
            && !stopped.forced
            && stopped.code == Some(0)
    );
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(core.client().instance().device_id, identity);
    assert_eq!(
        core.client()
            .device_defaults()
            .await?
            .advanced_configuration()?
            .num_connections,
        Some(4)
    );
    assert_eq!(
        core.client()
            .device(&new)
            .await?
            .advanced_configuration()?
            .num_connections,
        Some(3)
    );
    assert_eq!(
        core.client()
            .device(&old)
            .await?
            .advanced_configuration()?
            .num_connections,
        Some(2)
    );
    for id in [&old, &new] {
        assert!(core.client().remove_device(id).await?.configuration_absent);
    }
    assert_eq!(std::fs::read(&sentinel)?, b"retained native device options");
    for owned in [&mut core, &mut first, &mut second] {
        let stopped = owned.shutdown(Duration::from_secs(10)).await?;
        assert!(
            stopped.tree_stopped
                && stopped.state_released
                && !stopped.forced
                && stopped.code == Some(0)
        );
    }
    println!("native_advanced_device_effects=15 selected_template_fields={} introduction_auto_accept_encryption_runtime_not_claimed=true",requested.as_object().ok_or("device patch absent")?.len());
    Ok(())
}
