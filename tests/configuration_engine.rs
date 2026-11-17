//! Actual default inheritance, independent runtime state and persisted configuration.
#[path = "common/default_ignore_cases.rs"]
mod default_ignore_cases;
#[path = "common/default_versioning_cases.rs"]
mod default_versioning_cases;
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
async fn native_whole_section_gui_migration_changes_credentials_and_adopts_explicit_endpoint(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-full-gui-migration-")
        .tempdir()?
        .keep();
    std::fs::write(root.join("caller-sentinel"), b"GUI migration caller data")?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let before = core.client().configuration().await?;
    let old_key = core.client().gui_authentication().await?.api_key()?;
    let key = ApiKey::generate()?;
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    assert_ne!(address.port(), 18886);
    drop(listener);
    let endpoint = ManagementEndpoint::http(&format!("http://{address}/"))?;
    let credentials = GuiCredentials::new("whole-gui-new-user", "whole-gui-new-password")?;
    let mut desired = before.clone();
    desired.set_gui_listener(
        &GuiListenerPatch::default().address(GuiListenAddress::tcp(&address.to_string())?),
    )?;
    desired.set_gui_credentials(&credentials)?;
    desired.set_gui_auth_mode(&GuiAuthMode::Static)?;
    desired.set_gui_api_key(&key)?;
    let acknowledged = match core.client().replace_gui_configuration(&desired).await {
        Ok(value) => {
            assert_eq!(value.acknowledgement.status(), 200);
            true
        }
        Err(Error::MutationOutcomeUnknown { .. }) => false,
        Err(error) => return Err(error.into()),
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let selected = ConnectOptions::new(endpoint.clone(), key.clone())
                .expected_device_id(identity.clone())
                .request_timeout(Duration::from_secs(1))?;
            match core.reconnect_management(selected).await {
                Ok(()) => return Ok(()),
                Err(
                    Error::Transport { .. } | Error::Timeout { .. } | Error::Authentication { .. },
                ) => tokio::time::sleep(Duration::from_millis(50)).await,
                Err(error) => return Err(error),
            }
        }
    })
    .await??;
    let adopted = core.client().configuration().await?;
    let stored_key_matches =
        adopted.native_document()["gui"]["apiKey"] == desired.native_document()["gui"]["apiKey"];
    assert!(
        stored_key_matches,
        "complete GUI PUT did not retain the selected API key"
    );
    let denied = Client::connect(
        ConnectOptions::new(endpoint.clone(), old_key)
            .expected_device_id(identity.clone())
            .request_timeout(Duration::from_secs(2))?,
    )
    .await;
    let previous_key_outcome = match &denied {
        Ok(_) => "accepted",
        Err(Error::Authentication { .. }) => "authentication_rejected",
        Err(Error::AccessDenied { .. }) => "access_denied_403",
        Err(Error::Transport { .. }) => "transport",
        Err(Error::Timeout { .. }) => "timeout",
        Err(_) => "other_error",
    };
    eprintln!("native full GUI migration boundary: stored_key_matches={stored_key_matches} previous_key_outcome={previous_key_outcome} gui_user_matches={} password_present={} application_in_sync={}",
        adopted.native_document()["gui"]["user"]=="whole-gui-new-user",
        core.client().gui_authentication().await?.password_is_set(),
        core.client().configuration_sync_state().await?.config_in_sync);
    assert!(
        matches!(
            denied,
            Err(Error::Authentication { .. } | Error::AccessDenied { .. })
        ),
        "old management key was not rejected at the new endpoint"
    );
    let session = GuiSession::login(
        GuiLoginOptions::new(endpoint.clone(), credentials).expected_device_id(identity.clone()),
    )
    .await?;
    assert_eq!(session.system_status().await?.device_id, identity);
    session.logout().await?;
    let actual = core.client().configuration().await?;
    assert!(actual.native_document()["gui"]["password"]
        .as_str()
        .is_some_and(|p| !p.is_empty() && p != "whole-gui-new-password"));
    for section in [
        "options",
        "devices",
        "folders",
        "defaults",
        "ldap",
        "relayServer",
        "remoteIgnoredDevices",
        "version",
    ] {
        assert!(
            actual.native_document()[section] == before.native_document()[section],
            "GUI replacement changed an unrelated section"
        );
    }
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let persisted = core.client().gui_listener().await?;
    assert_eq!(
        persisted.address.tcp_authority(),
        Some(address.to_string().as_str())
    );
    assert_eq!(
        std::fs::read(root.join("caller-sentinel"))?,
        b"GUI migration caller data"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    println!("native_full_gui_migration=true write_acknowledged={acknowledged} explicit_endpoint_and_key_adoption=true old_key_rejected_at_new_endpoint=true real_new_password_login=true stored_password_not_plaintext=true unrelated_sections_retained=true normal_restart_same_identity_and_endpoint=true caller_bytes_retained=true normal_owned_tree_exit=true");
    Ok(())
}

#[tokio::test]
async fn native_whole_section_replacements_preserve_credentials_other_sections_and_files(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-whole-sections-")
        .tempdir()?
        .keep();
    let data = root.join("caller data");
    std::fs::create_dir(&data)?;
    std::fs::write(data.join("sentinel"), b"whole section caller bytes")?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    core.client()
        .create_folder(
            &CreateFolderOptions::new(
                FolderId::parse("whole-section-folder")?,
                TargetPath::local(data.clone()),
            )
            .paused(true),
        )
        .await?;
    core.client()
        .set_local_gui_credentials(
            &GuiCredentials::new("synthetic-section-user", "synthetic-section-password")?,
            Duration::from_secs(10),
        )
        .await?;
    let identity = core.client().instance().device_id.clone();
    let before = core.client().configuration().await?;
    assert!(before.native_document()["gui"]["password"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
    let mut expected = before.native_document().clone();
    let hours = before
        .general_options()?
        .keep_temporaries_hours
        .checked_add(1)
        .ok_or("synthetic temporary retention overflow")?;
    for section in ["options", "gui"] {
        let mut desired = core.client().configuration().await?;
        if section == "options" {
            expected[section]["keepTemporariesH"] = hours.into();
            expected[section]["reconnectionIntervalS"] = 67.into();
            expected[section]["natLeaseMinutes"] = 7.into();
            desired.set_general_options(
                &GeneralOptionsPatch::default().keep_temporaries_hours(hours),
            )?;
            desired.set_network_configuration(
                &NetworkPatch::default().reconnection_interval_seconds(67),
            )?;
            desired.set_transport_configuration(&TransportPatch::default().nat_lease_minutes(7))?;
            let readback = core
                .client()
                .replace_options_configuration(&desired)
                .await?;
            assert!(readback.requested_fields_match);
            assert_eq!(readback.configuration.keep_temporaries_hours, hours);
        } else {
            expected[section]["theme"] = "dark".into();
            desired.set_gui_preferences(&GuiPreferencesPatch::default().theme("dark"))?;
            let receipt = core.client().replace_gui_configuration(&desired).await?;
            assert_eq!(receipt.acknowledgement.status(), 200);
            assert!(receipt.previous_configuration.password_is_set());
        }
        let observed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match core.client().configuration().await {
                    Ok(value) => return Ok(value),
                    Err(Error::Transport { .. } | Error::Timeout { .. }) => {
                        tokio::time::sleep(Duration::from_millis(50)).await
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await??;
        assert!(
            observed.native_document() == &expected,
            "whole-section PUT changed unexpected native values"
        );
        assert_eq!(core.client().system_status().await?.device_id, identity);
    }
    core.restart(Duration::from_secs(30)).await?;
    assert!(
        core.client().configuration().await?.native_document() == &expected,
        "whole-section values were not retained across normal restart"
    );
    assert_eq!(
        std::fs::read(data.join("sentinel"))?,
        b"whole section caller bytes"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    println!("native_whole_section_put=2 existing_gui_credentials_and_unknown_values_preserved=true other_sections_and_files_preserved=true normal_restart_persistence=true same_identity=true normal_owned_tree_exit=true");
    Ok(())
}

#[tokio::test]
async fn native_narrow_configuration_reads_preserve_identity_folders_and_state() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-narrow-configuration-")
        .tempdir()?
        .keep();
    let data = root.join("synthetic data");
    std::fs::create_dir(&data)?;
    std::fs::write(
        data.join("sentinel"),
        b"narrow queries preserve caller files",
    )?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    assert!(core.client().folder_configurations().await?.is_empty());
    let id = FolderId::parse("synthetic-narrow-read")?;
    core.client()
        .create_folder(
            &CreateFolderOptions::new(id.clone(), TargetPath::local(data.clone())).paused(true),
        )
        .await?;
    let before = core.client().configuration().await?;
    let ping = core.client().ping().await?;
    assert!(ping.is_pong());
    assert_eq!(ping.reply, "pong");
    let folders = core.client().folder_configurations().await?;
    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0].id, id);
    assert!(folders[0].paused);
    assert_eq!(
        folders[0].path.to_protocol()?,
        data.to_str().ok_or("synthetic UTF-8 path absent")?
    );
    assert!(
        folders[0].extra == before.folders()?[0].extra,
        "narrow folder read changed native extension values"
    );
    let legacy = core
        .client()
        .raw_request(&RawRequest::new(
            RawMethod::Get,
            ["rest", "system", "config"],
            RequestEffect::ReadOnly,
        )?)
        .await?;
    assert_eq!(legacy.status(), 200);
    assert!(
        serde_json::from_slice::<serde_json::Value>(legacy.body_bytes())?
            == *before.native_document(),
        "legacy configuration read differs from canonical snapshot"
    );
    let defaults = core.client().folder_defaults().await?;
    assert!(
        serde_json::to_value(defaults)? == before.native_document()["defaults"]["folder"],
        "dedicated defaults differ from the complete snapshot"
    );
    core.client().configuration_sync_state().await?;
    assert_eq!(core.client().system_status().await?.device_id, identity);
    assert!(
        core.client().configuration().await?.native_document() == before.native_document(),
        "read queries changed native configuration"
    );
    assert_eq!(
        std::fs::read(data.join("sentinel"))?,
        b"narrow queries preserve caller files"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    println!("native_narrow_configuration_reads=3 empty_and_populated_folder_collection=true full_config_alias_equal=true ping_pong=true identity_configuration_files_preserved=true normal_owned_exit=true");
    Ok(())
}

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
    let proxy = address.to_string();
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

#[path = "common/socks5_peer.rs"]
mod socks5_peer;

#[tokio::test]
async fn native_socks5_proxy_authentication_transfer_and_explicit_disable_preserve_data(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vpx-").tempdir()?.keep();
    let env_names = [
        "ALL_PROXY",
        "ALL_PROXY_NO_FALLBACK",
        "HTTP_PROXY",
        "HTTPS_PROXY",
    ];
    let inherited: Vec<_> = env_names.iter().map(std::env::var_os).collect();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let aid = a.client().instance().device_id.clone();
    let bid = b.client().instance().device_id.clone();
    let upstream = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for status in b.client().listener_status().await?.into_values() {
                for address in status.lan_addresses {
                    if let Some(target) = address
                        .strip_prefix("tcp://")
                        .and_then(|v| v.parse::<std::net::SocketAddr>().ok())
                        .filter(|v| {
                            v.ip() == std::net::Ipv4Addr::LOCALHOST
                                && !matches!(v.port(), 0 | 18886)
                        })
                    {
                        return Ok::<_, Error>(target);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let peer = socks5_peer::Socks5Peer::start(upstream).await?;
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    let source = root.join("source");
    let received = root.join("receiver");
    std::fs::create_dir(&source)?;
    let sample: Vec<u8> = (0..32768).map(|i| (i % 251) as u8).collect();
    let name = "private 二 %.bin";
    std::fs::write(source.join(name), &sample)?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&source)).paused(true))
        .await?;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(&received)).paused(true))
        .await?;
    for (client, folder, id, addresses) in [
        (
            a.client(),
            &af.configuration.id,
            &bid,
            vec!["tcp://198.51.100.17:22000".into()],
        ),
        (
            b.client(),
            &bf.configuration.id,
            &aid,
            vec!["dynamic".into()],
        ),
    ] {
        client
            .update_network_configuration(&NetworkPatch::default().reconnection_interval_seconds(5))
            .await?;
        client
            .create_device(
                &CreateDeviceOptions::new(id.clone()).settings(
                    DevicePatch::default()
                        .addresses(addresses)
                        .allowed_transports(vec![DeviceTransport::Tcp])
                        .advanced_configuration(
                            DeviceAdvancedPatch::default().num_connections(1),
                        )?,
                ),
            )
            .await?;
        client.share_folder_with(folder, id).await?;
        client.resume_folder(folder).await?;
    }
    let wrong = SystemPreferencesPatch::default()
        .proxy_enabled(true)
        .proxy_address(peer.authority("wrong-private-password"));
    assert!(!format!("{wrong:?}").contains("wrong-private-password"));
    assert!(
        a.client()
            .update_system_preferences(&wrong)
            .await?
            .requested_fields_match
    );
    a.restart(Duration::from_secs(30)).await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        while peer.counts().0 == 0 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await?;
    assert_eq!(peer.counts().1, 0);
    assert_eq!(peer.counts().2, 0);
    assert!(!a
        .client()
        .connections()
        .await?
        .connections
        .get(&bid)
        .is_some_and(|v| v.connected));
    assert!(!received.join(name).try_exists()?);
    let selected = peer.authority("private%40token");
    let patch = SystemPreferencesPatch::default()
        .proxy_enabled(true)
        .proxy_address(selected.clone());
    assert!(!format!("{patch:?}").contains("private%40token"));
    let change = a.client().update_system_preferences(&patch).await?;
    assert!(change.requested_fields_match);
    assert!(!format!("{change:?}").contains("private%40token"));
    a.restart(Duration::from_secs(30)).await?;
    assert_eq!(
        a.client().system_preferences().await?.proxy_address(),
        selected
    );
    a.client().request_scan(&af.configuration.id).await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if std::fs::read(received.join(name)).ok().as_deref() == Some(sample.as_slice()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    assert!(peer.counts().1 > 0 && peer.counts().2 > 0);
    assert!(a
        .client()
        .connections()
        .await?
        .connections
        .get(&bid)
        .is_some_and(|v| v.connected));
    assert!(b
        .client()
        .connections()
        .await?
        .connections
        .get(&aid)
        .is_some_and(|v| v.connected));
    assert_eq!(a.client().instance().device_id, aid);
    assert_eq!(b.client().instance().device_id, bid);
    let before_disable = peer.counts();
    assert!(
        a.client()
            .update_system_preferences(
                &SystemPreferencesPatch::default()
                    .proxy_enabled(false)
                    .proxy_address("")
            )
            .await?
            .requested_fields_match
    );
    a.restart(Duration::from_secs(30)).await?;
    // Include startup and the explicit five-second reconnect interval.
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(peer.counts(), before_disable);
    assert!(!a
        .client()
        .connections()
        .await?
        .connections
        .get(&bid)
        .is_some_and(|v| v.connected));
    let cleared = a.client().system_preferences().await?;
    assert!(!cleared.proxy_enabled && cleared.proxy_address().is_empty());
    for core in [&mut a, &mut b] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    peer.close().await?;
    assert_eq!(std::fs::read(source.join(name))?, sample);
    assert_eq!(std::fs::read(received.join(name))?, sample);
    assert_eq!(
        env_names.iter().map(std::env::var_os).collect::<Vec<_>>(),
        inherited
    );
    std::fs::remove_dir_all(root)?;
    println!(
        "native SOCKS5 proxy evidence: {}",
        serde_json::json!({"actual_wrong_credentials_refused":true,"actual_refusal_did_not_connect_or_transfer":true,"actual_percent_encoded_credentials_accepted":true,"actual_native_socks5_connect_to_fixed_synthetic_destination":true,"actual_only_owned_loopback_upstream_forwarded":true,"actual_bidirectional_native_device_connection":true,"actual_file_bytes_transferred_through_selected_proxy":true,"actual_selected_authority_retained_on_restart":true,"actual_disable_and_clear_stop_using_selected_peer":true,"actual_source_and_receiver_bytes_retained":true,"actual_identities_retained":true,"actual_parent_proxy_environment_unchanged":true,"actual_both_normal_owned_tree_and_state_exits":true})
    );
    Ok(())
}

async fn name_policy_connection_pair(
    a: &ManagedInstance,
    b: &ManagedInstance,
    wanted: bool,
) -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let aa = a.client().connections().await?;
            let bb = b.client().connections().await?;
            if aa
                .connections
                .get(&b.client().instance().device_id)
                .is_some_and(|v| v.connected == wanted)
                && bb
                    .connections
                    .get(&a.client().instance().device_id)
                    .is_some_and(|v| v.connected == wanted)
            {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn native_remote_device_name_policy_uses_global_selection_and_preserves_real_data(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vname-").tempdir()?.keep();
    let sentinel = root.join("unrelated sentinel.bin");
    std::fs::write(
        &sentinel,
        b"unrelated caller bytes retained across name-policy changes",
    )?;
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let aid = a.client().instance().device_id.clone();
    let bid = b.client().instance().device_id.clone();
    let own_name = b.client().device(&bid).await?.name;
    let selected_name = "synthetic caller-selected remote name";
    assert!(!own_name.is_empty() && own_name != selected_name);
    let address = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for status in b.client().listener_status().await?.into_values() {
                for text in status.lan_addresses {
                    if let Some(address) = text
                        .strip_prefix("tcp://")
                        .and_then(|v| v.parse::<std::net::SocketAddr>().ok())
                        .filter(|v| {
                            v.ip() == std::net::Ipv4Addr::LOCALHOST
                                && !matches!(v.port(), 0 | 18886)
                        })
                    {
                        return Ok::<_, Error>(address);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    for client in [a.client(), b.client()] {
        assert!(
            client
                .update_general_options(
                    &GeneralOptionsPatch::default().overwrite_remote_device_names_on_connect(false)
                )
                .await?
                .requested_fields_match
        );
        assert!(
            client
                .update_network_configuration(
                    &NetworkPatch::default().reconnection_interval_seconds(5)
                )
                .await?
                .requested_fields_match
        );
    }
    a.client()
        .create_device(
            &CreateDeviceOptions::new(bid.clone()).settings(
                DevicePatch::default()
                    .name(selected_name)
                    .paused(true)
                    .addresses(vec![format!("tcp://{address}")])
                    .allowed_transports(vec![DeviceTransport::Tcp])
                    .advanced_configuration(
                        DeviceAdvancedPatch::default()
                            .overwrite_remote_device_names_on_connect(false),
                    )?,
            ),
        )
        .await?;
    b.client()
        .create_device(
            &CreateDeviceOptions::new(aid.clone()).settings(
                DevicePatch::default()
                    .name("synthetic source configuration")
                    .addresses(vec!["dynamic".into()])
                    .allowed_transports(vec![DeviceTransport::Tcp]),
            ),
        )
        .await?;
    let source = root.join("source");
    let received = root.join("received");
    std::fs::create_dir(&source)?;
    let file = "name policy 二 %.bin";
    std::fs::write(source.join(file), vec![0x21; 32768])?;
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&source)).paused(true))
        .await?;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(&received)).paused(true))
        .await?;
    a.client()
        .share_folder_with(&af.configuration.id, &bid)
        .await?;
    b.client()
        .share_folder_with(&bf.configuration.id, &aid)
        .await?;
    a.client().resume_folder(&af.configuration.id).await?;
    b.client().resume_folder(&bf.configuration.id).await?;
    for (index, (global, peer)) in [(false, false), (true, false), (false, true), (true, true)]
        .into_iter()
        .enumerate()
    {
        if index > 0 {
            assert!(a.client().pause_device(&bid).await?.requested_fields_match);
            name_policy_connection_pair(&a, &b, false).await?;
        }
        assert!(
            a.client()
                .update_device(
                    &bid,
                    &DevicePatch::default()
                        .name(selected_name)
                        .advanced_configuration(
                            DeviceAdvancedPatch::default()
                                .overwrite_remote_device_names_on_connect(peer)
                        )?
                )
                .await?
                .requested_fields_match
        );
        assert!(
            a.client()
                .update_general_options(
                    &GeneralOptionsPatch::default()
                        .overwrite_remote_device_names_on_connect(global)
                )
                .await?
                .requested_fields_match
        );
        a.restart(Duration::from_secs(30)).await?;
        assert_eq!(a.client().instance().device_id, aid);
        assert!(a.client().resume_device(&bid).await?.requested_fields_match);
        name_policy_connection_pair(&a, &b, true).await?;
        let bytes = vec![0x30 + index as u8; 32768];
        std::fs::write(source.join(file), &bytes)?;
        a.client().request_scan(&af.configuration.id).await?;
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if std::fs::read(received.join(file)).is_ok_and(|v| v == bytes) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await?;
        let observed = a.client().device(&bid).await?;
        assert!(
            observed.name
                == if global {
                    own_name.as_str()
                } else {
                    selected_name
                },
            "native remote name must match the reviewed global adoption policy"
        );
        println!(
            "native remote-name policy evidence: {}",
            serde_json::json!({"global":global,"peer":peer,
            "actual_custom_name_retained":observed.name==selected_name,"actual_sender_name_adopted":observed.name==own_name,
            "actual_new_payload_after_reconnect":true,"actual_global_policy_matches_adoption":true,"peer_flag_independent_adoption_not_claimed":true})
        );
        assert_eq!(std::fs::read(source.join(file))?, bytes);
        assert_eq!(
            std::fs::read(&sentinel)?,
            b"unrelated caller bytes retained across name-policy changes"
        );
    }
    assert_eq!(b.client().instance().device_id, bid);
    for core in [&mut a, &mut b] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!(
        "native remote-name policy cleanup evidence: {}",
        serde_json::json!({"four_global_and_peer_combinations":true,"actual_new_bytes_after_each_fresh_connection":true,"actual_source_and_receiver_bytes_retained":true,"actual_unrelated_sentinel_retained":true,"actual_both_device_identities_retained":true,"actual_both_normal_tree_and_state_exits":true})
    );
    Ok(())
}

async fn home_policy_index_ready(client: &Client, folder: &FolderId, files: u64) -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let status = client.folder_status(folder).await?;
            if status.state == Some(FolderState::Idle) && status.local_files == Some(files) {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn native_home_free_threshold_blocks_index_updates_and_explicit_reset_recovers() -> TestResult
{
    let root = tempfile::Builder::new()
        .prefix("vhomefree-")
        .tempdir()?
        .keep();
    let data = root.join("synthetic data");
    std::fs::create_dir(&data)?;
    let original = b"independent low-threshold fixture";
    let later = b"synthetic new bytes under selected high threshold";
    std::fs::write(data.join("retained.txt"), original)?;
    std::fs::write(root.join("sentinel"), b"unrelated disk-policy bytes")?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let id = core.client().instance().device_id.clone();
    let low = DiskFreeRequirement::new(0.0, DiskSpaceUnit::Percent)?;
    let high = DiskFreeRequirement::new(100.0, DiskSpaceUnit::Percent)?;
    assert!(
        core.client()
            .update_general_options(&GeneralOptionsPatch::default().min_home_disk_free(low.clone()))
            .await?
            .requested_fields_match
    );
    let folder = FolderId::parse("native-home-free-space")?;
    core.client()
        .create_folder(&CreateFolderOptions::new(
            folder.clone(),
            TargetPath::local(&data),
        ))
        .await?;
    core.client().request_scan(&folder).await?;
    home_policy_index_ready(core.client(), &folder, 1).await?;
    let before = core.client().configuration().await?;
    assert!(
        core.client()
            .update_general_options(
                &GeneralOptionsPatch::default().min_home_disk_free(high.clone())
            )
            .await?
            .requested_fields_match
    );
    assert!(
        core.client()
            .general_options()
            .await?
            .min_home_disk_free
            .as_ref()
            == Some(&high)
    );
    std::fs::write(data.join("later.txt"), later)?;
    let failure = core
        .client()
        .request_scan(&folder)
        .await
        .expect_err("a selected 100percent minimum must refuse the database's occupied volume");
    assert!(
        matches!(&failure,Error::MutationOutcomeUnknown{source,..}
        if matches!(&**source,Error::Http{response} if response.status()==500
            && String::from_utf8_lossy(response.body_bytes()).contains("insufficient space on disk for database"))),
        "preserve the specific native database-space refusal as an unknown scan outcome"
    );
    let blocked = core.client().folder_status(&folder).await?;
    assert!(blocked.state == Some(FolderState::Error) && blocked.local_files == Some(1));
    assert!(blocked
        .extra
        .get("error")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|v| v.contains("insufficient space on disk for database")
            && v.contains("required 100 %")));
    assert!(
        matches!(core.client().index_file_info(&folder,&TargetPath::local("later.txt")).await,
        Err(Error::Http{response}) if response.status()==404)
    );
    assert_eq!(std::fs::read(data.join("retained.txt"))?, original);
    assert_eq!(std::fs::read(data.join("later.txt"))?, later);
    assert_eq!(
        std::fs::read(root.join("sentinel"))?,
        b"unrelated disk-policy bytes"
    );
    assert!(
        core.client()
            .update_general_options(&GeneralOptionsPatch::default().min_home_disk_free(low.clone()))
            .await?
            .requested_fields_match
    );
    core.client().request_scan(&folder).await?;
    home_policy_index_ready(core.client(), &folder, 2).await?;
    assert!(
        core.client()
            .index_file_info(&folder, &TargetPath::local("later.txt"))
            .await?
            .local
            .name
            == "later.txt"
    );
    core.restart(Duration::from_secs(30)).await?;
    home_policy_index_ready(core.client(), &folder, 2).await?;
    assert!(
        core.client()
            .general_options()
            .await?
            .min_home_disk_free
            .as_ref()
            == Some(&low)
    );
    let after = core.client().configuration().await?;
    for key in ["gui", "devices", "folders", "ldap"] {
        assert!(
            before.native_document().get(key) == after.native_document().get(key),
            "home-free policy must preserve unrelated configuration sections"
        );
    }
    assert_eq!(core.client().system_status().await?.device_id, id);
    assert_eq!(std::fs::read(data.join("retained.txt"))?, original);
    assert_eq!(std::fs::read(data.join("later.txt"))?, later);
    assert_eq!(
        std::fs::read(root.join("sentinel"))?,
        b"unrelated disk-policy bytes"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "native home-free policy evidence: {}",
        serde_json::json!({
            "actual_low_threshold_indexed_existing_file":true,
            "actual_high_threshold_refused_database_scan_with_native_http500":true,
            "actual_unknown_scan_outcome_preserved":true,
            "actual_error_state_and_unchanged_index_count":true,
            "actual_new_file_absent_from_index_while_physically_retained":true,
            "actual_explicit_low_threshold_reset_and_new_file_indexing":true,
            "actual_normal_restart_retains_low_policy_identity_and_both_indexed_files":true,
            "actual_unrelated_sections_and_caller_bytes_retained":true,
            "actual_normal_owned_tree_and_state_exit":true,
            "physical_disk_exhaustion_induced":false
        })
    );
    Ok(())
}

#[tokio::test]
async fn native_temporary_retention_scans_expire_only_aged_native_inputs_and_survive_restart(
) -> TestResult {
    use std::fs::{File, FileTimes};
    use std::time::SystemTime;
    let root = tempfile::Builder::new()
        .prefix("vtempage-")
        .tempdir()?
        .keep();
    let data = root.join("synthetic data");
    std::fs::create_dir(&data)?;
    let sentinel = root.join("caller-sentinel");
    let ordinary = data.join("ordinary.tmp");
    let retained = data.join("retained-二.txt");
    let outside = root.join(".vs.outside.tmp");
    let old = data.join(".vs.aged-native.tmp");
    let fresh = data.join(".vs.fresh-native.tmp");
    let bytes = b"isolated native retention fixture bytes";
    let aged = SystemTime::now()
        .checked_sub(Duration::from_secs(2 * 60 * 60))
        .ok_or("synthetic file age underflow")?;
    for path in [&sentinel, &ordinary, &retained, &outside, &old, &fresh] {
        std::fs::write(path, bytes)?;
    }
    for path in [&ordinary, &outside, &old] {
        File::options()
            .write(true)
            .open(path)?
            .set_times(FileTimes::new().set_modified(aged))?;
    }
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    assert!(
        core.client()
            .update_general_options(&GeneralOptionsPatch::default().keep_temporaries_hours(4))
            .await?
            .requested_fields_match
    );
    let folder = FolderId::parse("native-temporary-retention")?;
    core.client()
        .create_folder(
            &CreateFolderOptions::new(folder.clone(), TargetPath::local(&data)).paused(true),
        )
        .await?;
    core.client().resume_folder(&folder).await?;
    core.client().request_scan(&folder).await?;
    if let Err(error) = home_policy_index_ready(core.client(), &folder, 1).await {
        let status = core.client().folder_status(&folder).await?;
        eprintln!(
            "native temporary retention initial state={:?} files={:?} native_error={:?}",
            status.state,
            status.local_files,
            status.extra.get("error")
        );
        return Err(error);
    }
    assert_eq!(
        core.client()
            .index_file_info(&folder, &TargetPath::local("retained-二.txt"))
            .await?
            .local
            .name,
        "retained-二.txt"
    );
    assert!(
        matches!(core.client().index_file_info(&folder,&TargetPath::local("ordinary.tmp")).await,
        Err(Error::Http{response}) if response.status()==404)
    );
    assert_eq!(std::fs::read(&old)?, bytes);
    assert_eq!(std::fs::read(&fresh)?, bytes);
    assert!(
        matches!(core.client().index_file_info(&folder,&TargetPath::local(".vs.aged-native.tmp")).await,
        Err(Error::Http{response}) if response.status()==404)
    );
    let before = core.client().configuration().await?;
    assert!(
        core.client()
            .update_general_options(&GeneralOptionsPatch::default().keep_temporaries_hours(1))
            .await?
            .requested_fields_match
    );
    core.client().request_scan(&folder).await?;
    home_policy_index_ready(core.client(), &folder, 1).await?;
    assert!(
        !old.try_exists()?,
        "selected one-hour retention did not expire the two-hour native input"
    );
    assert_eq!(std::fs::read(&fresh)?, bytes);
    for path in [&sentinel, &ordinary, &retained, &outside] {
        assert_eq!(std::fs::read(path)?, bytes);
    }
    let after = core.client().configuration().await?;
    for section in ["gui", "devices", "folders", "defaults", "ldap"] {
        assert!(before.native_document()[section] == after.native_document()[section]);
    }
    // A second aged input must be removed by a new scan after normal restart,
    // while the fresh native input and ordinary aged file remain intact.
    let restart_old = data.join(".vs.restart-aged.tmp");
    std::fs::write(&restart_old, bytes)?;
    File::options()
        .write(true)
        .open(&restart_old)?
        .set_times(FileTimes::new().set_modified(aged))?;
    core.restart(Duration::from_secs(30)).await?;
    core.client().request_scan(&folder).await?;
    home_policy_index_ready(core.client(), &folder, 1).await?;
    assert!(!restart_old.try_exists()?);
    assert_eq!(
        core.client()
            .general_options()
            .await?
            .keep_temporaries_hours,
        1
    );
    assert_eq!(core.client().system_status().await?.device_id, identity);
    assert_eq!(std::fs::read(&fresh)?, bytes);
    for path in [&sentinel, &ordinary, &retained, &outside] {
        assert_eq!(std::fs::read(path)?, bytes);
    }
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "native temporary retention evidence: {}",
        serde_json::json!({
            "actual_four_hour_policy_preserved_two_hour_native_input":true,
            "actual_one_hour_policy_expired_aged_native_input_on_scan":true,
            "actual_fresh_native_input_retained":true,
            "actual_native_temporary_input_excluded_from_index":true,
            "actual_ordinary_aged_tmp_and_outside_native_named_file_retained":true,
            "actual_normal_restart_and_persisted_policy_expired_new_aged_input":true,
            "actual_unrelated_sections_identity_and_caller_bytes_retained":true,
            "actual_normal_owned_tree_and_state_exit":true,
            "host_clock_changed":false,"manual_temporary_cleanup_invoked":false
        })
    );
    Ok(())
}

#[cfg(target_os = "macos")]
#[path = "common/sleep_prevention_cases.rs"]
mod sleep_prevention_cases;

async fn configuration_policy_listener(core: &ManagedInstance) -> TestResult<std::net::SocketAddr> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for status in core.client().listener_status().await?.into_values() {
                for text in status.lan_addresses {
                    if let Some(address) = text
                        .strip_prefix("tcp://")
                        .and_then(|v| v.parse::<std::net::SocketAddr>().ok())
                        .filter(|v| {
                            v.ip() == std::net::Ipv4Addr::LOCALHOST
                                && !matches!(v.port(), 0 | 18886)
                        })
                    {
                        return Ok::<_, Error>(address);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await?
    .map_err(Into::into)
}

#[path = "common/folder_concurrency_cases.rs"]
mod folder_concurrency_cases;

#[path = "common/dial_concurrency_cases.rs"]
mod dial_concurrency_cases;

#[path = "common/incoming_request_budget_cases.rs"]
mod incoming_request_budget_cases;
