//! Actual default inheritance, independent runtime state and persisted configuration.
#[path = "common/device_options_cases.rs"]
mod device_options_cases;
#[path = "common/folder_options_cases.rs"]
mod folder_options_cases;
#[path = "common/folder_policy_cases.rs"]
mod folder_policy_cases;
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
#[path = "common/process_priority.rs"]
mod process_priority;
use managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::*;

#[tokio::test]
async fn native_system_preferences_write_real_event_audit_and_preserve_target_selections(
) -> TestResult {
    use std::io::Read;
    let root = tempfile::Builder::new()
        .prefix("vs-system-preferences-")
        .tempdir()?
        .keep();
    let audit = root.join("native event audit.log");
    let cache = root.join("native thumbnail cache");
    let sentinel = root.join("sentinel.bin");
    std::fs::write(&sentinel, b"unrelated native preference sentinel")?;
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    assert_ne!(address.port(), 18886);
    let proxy = format!("http://{address}");
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let before = core.client().configuration().await?;
    let update = core
        .client()
        .update_system_preferences(
            &SystemPreferencesPatch::default()
                .event_audit_enabled(true)
                .event_audit_file(NativePathSelection::Path(TargetPath::local(audit.clone())))
                .thumbnail_enabled(true)
                .thumbnail_cache_directory(NativePathSelection::Path(TargetPath::local(
                    cache.clone(),
                )))
                .proxy_enabled(true)
                .proxy_address(proxy.clone()),
        )
        .await?;
    assert!(update.requested_fields_match);
    assert!(
        matches!(&update.configuration.event_audit_file,NativePathSelection::Path(path) if path.local_path().is_none()&&path.to_protocol().ok()==audit.to_str())
    );
    let after = core.client().configuration().await?;
    for section in [
        "folders",
        "devices",
        "gui",
        "ldap",
        "defaults",
        "relayServer",
    ] {
        assert!(
            before.native_document()[section] == after.native_document()[section],
            "unrelated section changed"
        );
    }
    core.restart(Duration::from_secs(30)).await?;
    let persisted = core.client().system_preferences().await?;
    assert!(
        persisted.event_audit_enabled && persisted.thumbnail_enabled && persisted.proxy_enabled
    );
    assert!(persisted.proxy_address() == proxy);
    assert!(
        matches!(&persisted.thumbnail_cache_directory,NativePathSelection::Path(path) if path.to_protocol().ok()==cache.to_str())
    );
    let content = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match std::fs::File::open(&audit) {
                Ok(file) => {
                    let mut bytes = Vec::new();
                    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
                    assert!(
                        bytes.len() <= 1024 * 1024,
                        "private event audit observation exceeded bound"
                    );
                    if let Some(end) = bytes.iter().rposition(|b| *b == b'\n') {
                        let text = std::str::from_utf8(&bytes[..=end])?;
                        let events: Vec<serde_json::Value> = text
                            .lines()
                            .map(serde_json::from_str)
                            .collect::<std::result::Result<_, _>>()?;
                        if events.iter().any(|e| {
                            e["type"] == "StartupComplete"
                                && e["data"].is_object()
                                && e["time"].is_string()
                        }) {
                            return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                                bytes[..=end].to_vec(),
                            );
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    let disabled = core
        .client()
        .update_system_preferences(
            &SystemPreferencesPatch::default()
                .event_audit_enabled(false)
                .event_audit_file(NativePathSelection::Default)
                .thumbnail_enabled(false)
                .thumbnail_cache_directory(NativePathSelection::Default)
                .proxy_enabled(false)
                .proxy_address(""),
        )
        .await?;
    assert!(disabled.requested_fields_match);
    assert!(matches!(
        disabled.configuration.event_audit_file,
        NativePathSelection::Default
    ));
    assert!(matches!(
        disabled.configuration.thumbnail_cache_directory,
        NativePathSelection::Default
    ));
    core.restart(Duration::from_secs(30)).await?;
    assert!(
        !core
            .client()
            .system_preferences()
            .await?
            .event_audit_enabled
    );
    assert!(std::fs::read(&audit)?.starts_with(&content));
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"unrelated native preference sentinel"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    drop(listener);
    println!("native_system_preferences_effects=12 proxy_transfer_and_thumbnail_artifact_not_claimed=true");
    Ok(())
}

#[tokio::test]
async fn native_crash_preferences_preserve_fixed_usage_fields_and_survive_restart() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-crash-preferences-")
        .tempdir()?
        .keep();
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    assert_ne!(address.port(), 18886);
    let url = format!("http://{address}/synthetic-crash-collector");
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let original = core.client().configuration().await?;
    let before = original.diagnostics_options()?;
    // Independently classify legacy requested values through the already-public
    // raw API. A matching fixed readback is not consent or transmission evidence.
    let legacy_ack=core.client().raw_request(&RawRequest::new(RawMethod::Patch,["rest","config","options"],RequestEffect::MayModify)?
        .json_body(&serde_json::json!({"urAccepted":-1,"urSeen":0,"urPostInsecurely":false,"urURL":url,"urInitialDelayS":1}))?).await?;
    assert_eq!(legacy_ack.status(), 200);
    assert!(legacy_ack.body_bytes().is_empty());
    let legacy = core.client().diagnostics_options().await?;
    assert_eq!(legacy.usage_accepted_version, before.usage_accepted_version);
    assert_eq!(legacy.usage_seen_version, before.usage_seen_version);
    assert_eq!(legacy.usage_post_insecurely, before.usage_post_insecurely);
    assert_eq!(
        legacy.usage_initial_delay_seconds,
        before.usage_initial_delay_seconds
    );
    assert!(legacy.usage_report_url() == before.usage_report_url());
    for enabled in [false, true, false] {
        let changed = core
            .client()
            .update_crash_reporting(
                &CrashReportingPatch::default()
                    .enabled(enabled)
                    .url(url.clone()),
            )
            .await?;
        assert!(changed.requested_fields_match);
        assert_eq!(changed.configuration.crash_reporting_enabled, enabled);
        assert!(changed.configuration.crash_report_url() == url);
        assert_eq!(
            changed.configuration.usage_accepted_version,
            before.usage_accepted_version
        );
        assert_eq!(
            changed.configuration.usage_seen_version,
            before.usage_seen_version
        );
        assert!(changed.configuration.usage_report_url() == before.usage_report_url());
        assert!(changed.configuration.usage_identifier() == before.usage_identifier());
        assert_eq!(
            changed.configuration.usage_initial_delay_seconds,
            before.usage_initial_delay_seconds
        );
        assert_eq!(
            changed.configuration.usage_post_insecurely,
            before.usage_post_insecurely
        );
    }
    core.restart(Duration::from_secs(30)).await?;
    let persisted = core.client().diagnostics_options().await?;
    assert!(!persisted.crash_reporting_enabled && persisted.crash_report_url() == url);
    assert!(persisted.usage_identifier() == before.usage_identifier());
    let full = core.client().configuration().await?;
    assert!(!full.diagnostics_options()?.crash_reporting_enabled);
    assert!(
        full.native_document()["options"]["TOSAccepted"]
            == original.native_document()["options"]["TOSAccepted"]
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    drop(listener);
    println!("native_crash_preferences_effects=10 no_report_upload_requested=true");
    Ok(())
}

#[tokio::test]
async fn native_general_preferences_preserve_sections_disable_progress_and_change_priority_after_restart(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-general-options-")
        .tempdir()?
        .keep();
    let inherited_priority = process_priority::observe(std::process::id()).await?;
    assert_eq!(inherited_priority.len(), 1);
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let before = core.client().configuration().await?;
    let priority_before = process_priority::observe(core.process_id()).await?;
    for unit in [
        DiskSpaceUnit::Percent,
        DiskSpaceUnit::Kilobytes,
        DiskSpaceUnit::Megabytes,
        DiskSpaceUnit::Gigabytes,
        DiskSpaceUnit::Terabytes,
    ] {
        let threshold = DiskFreeRequirement::new(0.0, unit)?;
        let update = core
            .client()
            .update_general_options(
                &GeneralOptionsPatch::default().min_home_disk_free(threshold.clone()),
            )
            .await?;
        assert!(update.requested_fields_match);
        assert_eq!(
            update.configuration.min_home_disk_free.as_ref(),
            Some(&threshold)
        );
    }
    let threshold = DiskFreeRequirement::new(0.25, DiskSpaceUnit::Megabytes)?;
    let update = core
        .client()
        .update_general_options(
            &GeneralOptionsPatch::default()
                .min_home_disk_free(threshold.clone())
                .progress_update_interval_seconds(-1)
                .temp_index_min_blocks(7)
                .overwrite_remote_device_names_on_connect(false)
                .send_full_index_on_upgrade(true)
                .traffic_class(16)
                .set_low_priority(false)
                .max_folder_concurrency(2)
                .max_dial_concurrent(3)
                .max_concurrent_incoming_request_kib(4096)
                .disable_system_sleep_on_sync(false),
        )
        .await?;
    assert!(update.requested_fields_match);
    assert_eq!(update.configuration.progress_update_interval_seconds, -1);
    assert_eq!(update.configuration.traffic_class, Some(16));
    assert_eq!(
        update.configuration.min_home_disk_free.as_ref(),
        Some(&threshold)
    );
    let changed = core.client().configuration().await?;
    for section in [
        "folders",
        "devices",
        "gui",
        "ldap",
        "relayServer",
        "defaults",
    ] {
        assert!(
            before.native_document()[section] == changed.native_document()[section],
            "unrelated native section changed"
        );
    }
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let persisted = core.client().general_options().await?;
    assert_eq!(persisted.progress_update_interval_seconds, -1);
    assert!(!persisted.set_low_priority);
    assert_eq!(persisted.temp_index_min_blocks, Some(7));
    assert_eq!(
        persisted.overwrite_remote_device_names_on_connect,
        Some(false)
    );
    assert_eq!(persisted.send_full_index_on_upgrade, Some(true));
    assert_eq!(persisted.min_home_disk_free.as_ref(), Some(&threshold));
    assert_eq!(
        (
            persisted.max_folder_concurrency,
            persisted.max_dial_concurrent,
            persisted.max_concurrent_incoming_request_kib
        ),
        (2, 3, 4096)
    );
    let priority_after = process_priority::observe(core.process_id()).await?;
    println!("native owned priorities: inherited={inherited_priority:?} before={priority_before:?} after={priority_after:?}");
    #[cfg(unix)]
    {
        let inherited = inherited_priority[0].parse::<i32>()?;
        assert!(priority_before
            .iter()
            .any(|p| p.parse::<i32>().is_ok_and(|v| v > inherited)));
        assert!(priority_after
            .iter()
            .all(|p| p.parse::<i32>().ok() == Some(inherited)));
    }
    #[cfg(windows)]
    {
        assert!(priority_before
            .iter()
            .any(|p| p == "BelowNormal" || p == "Idle"));
        // CreateProcess inherits Idle/BelowNormal from the creating process
        // when no explicit class is requested. Other parent classes default
        // to Normal. Do not rewrite caller process priority to force a test.
        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
        let expected = match inherited_priority[0].as_str() {
            "Idle" => "Idle",
            "BelowNormal" => "BelowNormal",
            _ => "Normal",
        };
        assert!(priority_after.iter().all(|p| p == expected));
    }
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    println!("native_general_preferences_effects=18");
    Ok(())
}

#[tokio::test]
async fn full_configuration_save_preserves_sections_and_rejects_stale_snapshots() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-config-save-")
        .tempdir()?
        .keep();
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let id = FolderId::parse("synthetic-save")?;
    let data = root.join("synthetic data");
    std::fs::create_dir(&data)?;
    std::fs::write(data.join("sentinel"), b"configuration save retains files")?;
    core.client()
        .create_folder(
            &CreateFolderOptions::new(id.clone(), TargetPath::local(data.clone())).paused(true),
        )
        .await?;
    let before = core.client().configuration().await?;
    let hours = before.general_options()?.keep_temporaries_hours;
    let mut desired = before.clone();
    desired.set_general_options(
        &GeneralOptionsPatch::default()
            .keep_temporaries_hours(hours + 1)
            .progress_update_interval_seconds(2),
    )?;
    desired.set_folder_defaults(&FolderDefaultsPatch::default().rescan_interval_seconds(317))?;
    let saved = core.client().replace_configuration(&desired).await?;
    assert!(saved.requested_fields_match);
    assert_eq!(
        saved
            .configuration
            .general_options()?
            .keep_temporaries_hours,
        hours + 1
    );
    for section in [
        "folders",
        "devices",
        "gui",
        "ldap",
        "relayServer",
        "remoteIgnoredDevices",
        "version",
    ] {
        assert!(
            saved.configuration.native_document()[section] == before.native_document()[section],
            "unrelated configuration section changed"
        );
    }
    assert_eq!(saved.configuration.folders()?[0].path.local_path(), None);
    assert_eq!(
        saved.configuration.folders()?[0].path.to_protocol()?,
        TargetPath::local(data.clone()).to_protocol()?
    );
    assert_eq!(
        saved.configuration.devices()?.len(),
        before.devices()?.len()
    );
    let update = core
        .client()
        .update_general_options(&GeneralOptionsPatch::default().keep_temporaries_hours(hours + 2))
        .await?;
    assert!(update.requested_fields_match);
    assert!(matches!(
        core.client().replace_configuration(&desired).await,
        Err(Error::ConfigurationChanged)
    ));
    assert_eq!(
        core.client()
            .general_options()
            .await?
            .keep_temporaries_hours,
        hours + 2
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(core.client().instance().device_id, identity);
    let persisted = core.client().configuration().await?;
    assert_eq!(
        persisted.general_options()?.keep_temporaries_hours,
        hours + 2
    );
    assert_eq!(
        persisted
            .general_options()?
            .progress_update_interval_seconds,
        2
    );
    assert_eq!(persisted.folder_defaults()?.rescan_interval_seconds, 317);
    for section in ["folders", "devices", "gui", "ldap", "relayServer"] {
        assert!(
            persisted.native_document()[section] == before.native_document()[section],
            "persisted unrelated configuration section changed"
        );
    }
    assert!(
        core.client()
            .configuration_sync_state()
            .await?
            .config_in_sync
    );
    assert_eq!(
        std::fs::read(data.join("sentinel"))?,
        b"configuration save retains files"
    );
    assert!(
        core.client()
            .remove_folder_keep_files(&id)
            .await?
            .configuration_absent
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    println!("full_configuration_save_effects=14");
    Ok(())
}

#[tokio::test]
async fn defaults_are_inherited_only_by_new_objects_and_survive_normal_restart() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-config-")
        .tempdir()?
        .keep();
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let mut peer = ManagedInstance::start(options(&root.join("peer"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let id = FolderId::parse("synthetic-defaults")?;
    let folder_path = root.join("data");
    std::fs::create_dir(&folder_path)?;
    std::fs::write(folder_path.join("sentinel.txt"), b"retained synthetic data")?;
    let original_folder = core.client().folder_defaults().await?;
    let original_device = core.client().device_defaults().await?;
    assert!(matches!(
        core.client()
            .update_folder_defaults(&FolderDefaultsPatch::default())
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        core.client()
            .update_device_defaults(&DevicePatch::default())
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    let changed = core
        .client()
        .update_folder_defaults(
            &FolderDefaultsPatch::default()
                .label("synthetic inherited label")
                .paused(true)
                .rescan_interval_seconds(313)
                .watcher_enabled(false),
        )
        .await?;
    assert!(changed.requested_fields_match);
    assert_eq!(changed.configuration.label, "synthetic inherited label");
    assert_eq!(changed.configuration.rescan_interval_seconds, 313);
    for (key, value) in &original_folder.extra {
        assert!(
            changed.configuration.extra.get(key) == Some(value),
            "unrelated folder default changed"
        );
    }
    let changed = core
        .client()
        .update_device_defaults(
            &DevicePatch::default()
                .name("synthetic inherited peer")
                .paused(true)
                .compression(DeviceCompression::Never),
        )
        .await?;
    assert!(changed.requested_fields_match);
    assert!(
        changed.configuration.extra == original_device.extra,
        "unrelated device default changed"
    );
    let folder = core
        .client()
        .create_folder(&CreateFolderOptions::new(
            id.clone(),
            TargetPath::local(folder_path.clone()),
        ))
        .await?;
    assert!(folder.paused);
    assert_eq!(folder.label, "synthetic inherited label");
    assert_eq!(folder.extra["rescanIntervalS"], 313);
    assert_eq!(folder.extra["fsWatcherEnabled"], false);
    let remote_id = peer.client().instance().device_id.clone();
    let device = core
        .client()
        .create_device(&CreateDeviceOptions::new(remote_id.clone()))
        .await?;
    assert!(device.requested_fields_match);
    assert!(device.configuration.paused);
    assert_eq!(device.configuration.name, "synthetic inherited peer");
    assert_eq!(device.configuration.compression, DeviceCompression::Never);
    core.client()
        .update_folder_defaults(&FolderDefaultsPatch::default().label("future folders only"))
        .await?;
    core.client()
        .update_device_defaults(&DevicePatch::default().name("future peers only"))
        .await?;
    assert_eq!(
        core.client().folder(&id).await?.label,
        "synthetic inherited label"
    );
    assert_eq!(
        core.client().device(&remote_id).await?.name,
        "synthetic inherited peer"
    );
    let before_restart = core.client().configuration_sync_state().await?;
    println!(
        "native_configuration_in_sync_before_restart={}",
        before_restart.config_in_sync
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(core.client().instance().device_id, identity);
    assert_eq!(
        core.client().folder_defaults().await?.label,
        "future folders only"
    );
    assert_eq!(
        core.client().device_defaults().await?.name,
        "future peers only"
    );
    assert_eq!(
        core.client().folder(&id).await?.extra["rescanIntervalS"],
        313
    );
    assert_eq!(
        core.client().device(&remote_id).await?.compression,
        DeviceCompression::Never
    );
    assert!(
        core.client()
            .configuration_sync_state()
            .await?
            .config_in_sync
    );
    assert_eq!(
        std::fs::read(folder_path.join("sentinel.txt"))?,
        b"retained synthetic data"
    );
    assert!(
        core.client()
            .remove_folder_keep_files(&id)
            .await?
            .configuration_absent
    );
    assert!(
        core.client()
            .remove_device(&remote_id)
            .await?
            .configuration_absent
    );
    for owned in [&mut core, &mut peer] {
        let exit = owned.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    println!("configuration_defaults_effects=18");
    Ok(())
}
