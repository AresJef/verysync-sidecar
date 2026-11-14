//! Actual template inheritance and scoped advanced selections on owned data.
use super::*;

#[tokio::test]
async fn native_advanced_template_and_folder_edits_preserve_data_and_remain_independent(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-folder-options-")
        .tempdir()?
        .keep();
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let old = FolderId::parse("existing-options")?;
    let new = FolderId::parse("inherited-options")?;
    let old_path = root.join("existing");
    let new_path = root.join("inherited");
    for path in [&old_path, &new_path] {
        std::fs::create_dir(path)?;
        std::fs::write(
            path.join("sentinel.bin"),
            b"retained advanced synthetic data",
        )?;
    }
    let existing = core
        .client()
        .create_folder(
            &CreateFolderOptions::new(old.clone(), TargetPath::local(old_path.clone()))
                .paused(true),
        )
        .await?;
    let before = core.client().configuration().await?;
    // Acknowledged legacy edits do not establish a programmable budget.
    for full_save in [false, true] {
        let body = if full_save {
            let mut document = core
                .client()
                .configuration()
                .await?
                .native_document()
                .clone();
            document["defaults"]["folder"]["pullerMaxPendingKiB"] = 8192.into();
            document
        } else {
            serde_json::json!({"pullerMaxPendingKiB":512})
        };
        let request = if full_save {
            RawRequest::new(RawMethod::Put, ["rest", "config"], RequestEffect::MayModify)?
        } else {
            RawRequest::new(
                RawMethod::Patch,
                ["rest", "config", "defaults", "folder"],
                RequestEffect::MayModify,
            )?
        }
        .json_body(&body)?;
        assert_eq!(core.client().raw_request(&request).await?.status(), 200);
        assert_eq!(
            core.client()
                .folder_defaults()
                .await?
                .advanced_configuration()?
                .puller_max_pending_kib,
            Some(0)
        );
    }
    let advanced = FolderAdvancedPatch::default()
        .ignore_permissions(true)
        .auto_normalize(false)
        .minimum_disk_free(DiskFreeRequirement::new(0.25, DiskSpaceUnit::Megabytes)?)
        .copiers(3)
        .hashers(2)
        .ignore_delete(true)
        .puller_pause_seconds(17)
        .puller_delay_seconds(2)
        .max_conflicts(-1)
        .disable_sparse_files(true)
        .copy_ownership_from_parent(true)
        .modification_time_window_seconds(2)
        .max_concurrent_writes(4)
        .disable_fsync(false)
        .case_sensitive_filesystem(true)
        .junctions_as_directories(true)
        .sync_ownership(true)
        .send_ownership(true)
        .sync_extended_attributes(true)
        .send_extended_attributes(true)
        .block_indexing(true)
        .backup_only(true)
        .auto_repair_marker(false)
        .puller_session_enabled(false)
        .ants_puller_enabled(false)
        .ignore_live_photos(true)
        .tags(vec!["synthetic advanced template".into()]);
    let patch = FolderDefaultsPatch::default()
        .paused(true)
        .scan_configuration(
            FolderScanPatch::default()
                .rescan_interval_seconds(0)
                .watcher(false)
                .watcher_delay_seconds(0.5)
                .watcher_timeout_seconds(7)
                .progress_interval_seconds(-1)
                .disable_initial_scan(true),
        )?
        .advanced_configuration(advanced.clone())?
        .pull_order(FolderPullOrder::Alphabetic)?
        .selective_enabled(false);
    let requested = serde_json::to_value(&patch)?;
    let updated = core.client().update_folder_defaults(&patch).await?;
    if !updated.requested_fields_match {
        let actual = serde_json::to_value(&updated.configuration)?;
        for (key, value) in requested.as_object().ok_or("template patch absent")? {
            if key == "pullerMaxPendingKiB" {
                println!(
                    "native_pending_kib requested={} observed={}",
                    value,
                    actual.get(key).unwrap_or(&serde_json::Value::Null)
                );
            }
            println!(
                "native_template_selected_field_match key={key} matched={}",
                actual.get(key) == Some(value)
            );
        }
    }
    assert!(updated.requested_fields_match);
    assert_eq!(
        updated
            .configuration
            .scan_configuration()?
            .watcher_delay_seconds,
        0.5
    );
    assert_eq!(
        updated.configuration.scheduling_configuration()?.pull_order,
        FolderPullOrder::Alphabetic
    );
    assert!(!updated.configuration.selective_configuration()?.enabled);
    assert_eq!(
        updated.configuration.advanced_configuration()?.hashers,
        Some(2)
    );
    let full = core.client().configuration().await?;
    for section in ["gui", "devices", "ldap", "relayServer", "options"] {
        assert!(
            before.native_document()[section] == full.native_document()[section],
            "unrelated section changed"
        );
    }
    assert!(
        existing.extra == core.client().folder(&old).await?.extra,
        "existing advanced settings inherited template unexpectedly"
    );
    let inherited = core
        .client()
        .create_folder(&CreateFolderOptions::new(
            new.clone(),
            TargetPath::local(new_path.clone()),
        ))
        .await?;
    assert!(inherited.paused);
    for (key, value) in requested.as_object().ok_or("template patch absent")? {
        if key != "paused" {
            assert!(
                inherited.extra.get(key) == Some(value),
                "new folder did not inherit selected field: {key}"
            );
        }
    }
    assert_eq!(
        core.client()
            .folder_scan_configuration(&new)
            .await?
            .watcher_timeout_seconds,
        7
    );
    let changed = core
        .client()
        .update_folder_advanced_configuration(
            &old,
            &FolderAdvancedPatch::default()
                .hashers(4)
                .copiers(5)
                .max_conflicts(3),
        )
        .await?;
    assert!(changed.requested_fields_match);
    assert_eq!(changed.configuration.hashers, Some(4));
    assert_eq!(
        core.client()
            .folder_advanced_configuration(&new)
            .await?
            .hashers,
        Some(2)
    );
    assert_eq!(
        core.client()
            .folder_defaults()
            .await?
            .advanced_configuration()?
            .hashers,
        Some(2)
    );
    let mut snapshot = core.client().configuration().await?;
    snapshot.set_folder_defaults(
        &FolderDefaultsPatch::default()
            .advanced_configuration(FolderAdvancedPatch::default().hashers(6))?,
    )?;
    assert!(
        core.client()
            .replace_configuration(&snapshot)
            .await?
            .requested_fields_match
    );
    assert_eq!(
        core.client()
            .folder_advanced_configuration(&new)
            .await?
            .hashers,
        Some(2)
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
            .folder_defaults()
            .await?
            .advanced_configuration()?
            .hashers,
        Some(6)
    );
    assert_eq!(
        core.client()
            .folder_advanced_configuration(&new)
            .await?
            .hashers,
        Some(2)
    );
    assert_eq!(
        core.client()
            .folder_advanced_configuration(&old)
            .await?
            .hashers,
        Some(4)
    );
    for id in [&old, &new] {
        assert!(
            core.client()
                .remove_folder_keep_files(id)
                .await?
                .configuration_absent
        );
    }
    for path in [&old_path, &new_path] {
        assert_eq!(
            std::fs::read(path.join("sentinel.bin"))?,
            b"retained advanced synthetic data"
        );
    }
    let stopped = core.shutdown(Duration::from_secs(10)).await?;
    assert!(
        stopped.tree_stopped
            && stopped.state_released
            && !stopped.forced
            && stopped.code == Some(0)
    );
    println!("native_advanced_folder_effects=17 selected_template_fields={} platform_metadata_effects_pending=true",requested.as_object().ok_or("template patch absent")?.len());
    Ok(())
}
