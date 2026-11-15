//! Native helper results are checked independently from raw research calls.
use super::managed_fixture::{options, TestResult};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use verysync_sidecar::{Error, ManagedInstance};

#[tokio::test]
async fn actual_native_index_browse_keeps_depth_filters_and_index_only_observations() -> TestResult
{
    use verysync_sidecar::{
        CreateFolderOptions, FolderId, FolderScanPatch, FolderState, IndexBrowseOptions,
        IndexTreeEntry, SyncFileKind, TargetPath,
    };
    fn node<'a>(entries: &'a [IndexTreeEntry], name: &str) -> TestResult<&'a IndexTreeEntry> {
        entries
            .iter()
            .find(|entry| entry.name == name)
            .ok_or_else(|| "expected indexed entry absent".into())
    }
    let root = tempfile::Builder::new()
        .prefix("vs-index-tree-")
        .tempdir()?
        .keep();
    let data = root.join("synthetic data");
    let branch = std::path::Path::new("branch \u{4e8c} % +");
    let deep = branch.join("deep");
    std::fs::create_dir_all(data.join(&deep))?;
    let payload = b"synthetic indexed browse bytes";
    let files = [
        std::path::PathBuf::from("root.txt"),
        branch.join("child.txt"),
        deep.join("leaf.txt"),
    ];
    for file in &files {
        std::fs::write(data.join(file), payload)?;
    }
    let mut owner = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = owner.client().instance().device_id.clone();
    let folder = FolderId::parse("typed-native-index-browse")?;
    owner
        .client()
        .create_folder(
            &CreateFolderOptions::new(folder.clone(), TargetPath::local(&data)).paused(true),
        )
        .await?;
    owner
        .client()
        .update_folder_scan_configuration(
            &folder,
            &FolderScanPatch::default()
                .watcher(false)
                .rescan_interval_seconds(0)
                .disable_initial_scan(false),
        )
        .await?;
    owner.client().resume_folder(&folder).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status = owner.client().folder_status(&folder).await?;
            if status.state == Some(FolderState::Idle) && status.local_files == Some(3) {
                return Ok::<_, verysync_sidecar::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await??;
    let configuration = std::fs::read(root.join("core").join("setting.dat"))?;
    // A newly created but unscanned file proves that this reads native index
    // knowledge rather than performing a controller or target filesystem listing.
    std::fs::write(data.join("not-indexed.txt"), b"unindexed retained bytes")?;
    let flat = owner
        .client()
        .browse_index(&folder, &IndexBrowseOptions::default())
        .await?;
    assert_eq!(flat.entries.len(), 2);
    assert!(flat.entries.iter().all(|entry| entry.children.is_none()));
    let branch_name = branch.to_str().ok_or("synthetic prefix must be UTF8")?;
    assert_eq!(
        node(&flat.entries, branch_name)?.kind,
        SyncFileKind::Directory
    );
    assert_eq!(node(&flat.entries, "root.txt")?.size, payload.len() as u64);
    assert!(!format!("{flat:?} {:?}", node(&flat.entries, branch_name)?).contains(branch_name));
    let one = owner
        .client()
        .browse_index(&folder, &IndexBrowseOptions::default().levels(Some(1)))
        .await?;
    let first = node(&one.entries, branch_name)?
        .children
        .as_ref()
        .ok_or("first descendant level absent")?;
    assert_eq!(first.len(), 2);
    assert!(node(first, "deep")?.children.is_none());
    let complete = owner
        .client()
        .browse_index(&folder, &IndexBrowseOptions::default().levels(None))
        .await?;
    let first = node(&complete.entries, branch_name)?
        .children
        .as_ref()
        .ok_or("native descendants absent")?;
    let second = node(first, "deep")?
        .children
        .as_ref()
        .ok_or("second descendant level absent")?;
    assert_eq!(node(second, "leaf.txt")?.kind, SyncFileKind::File);
    assert!(!node(second, "leaf.txt")?.modified.is_empty());
    let directories = owner
        .client()
        .browse_index(
            &folder,
            &IndexBrowseOptions::default()
                .levels(None)
                .directories_only(true),
        )
        .await?;
    assert_eq!(directories.entries.len(), 1);
    assert_eq!(directories.entries[0].kind, SyncFileKind::Directory);
    let nested = directories.entries[0]
        .children
        .as_ref()
        .ok_or("nested directory absent")?;
    assert_eq!(nested.len(), 1);
    assert_eq!(nested[0].name, "deep");
    assert_eq!(nested[0].kind, SyncFileKind::Directory);
    assert!(nested[0].children.is_none());
    let all_again = owner
        .client()
        .browse_index(
            &folder,
            &IndexBrowseOptions::default()
                .levels(None)
                .directories_only(false),
        )
        .await?;
    assert_eq!(all_again.entries.len(), 2);
    assert_eq!(
        node(&all_again.entries, "root.txt")?.kind,
        SyncFileKind::File
    );
    let scoped = owner
        .client()
        .browse_index(
            &folder,
            &IndexBrowseOptions::default().prefix(TargetPath::local(branch)),
        )
        .await?;
    assert_eq!(scoped.entries.len(), 2);
    assert_eq!(
        node(&scoped.entries, "child.txt")?.size,
        payload.len() as u64
    );
    assert!(node(&scoped.entries, "deep")?.children.is_none());
    let nested = owner
        .client()
        .browse_index(
            &folder,
            &IndexBrowseOptions::default().prefix(TargetPath::local(&deep)),
        )
        .await?;
    assert_eq!(nested.entries.len(), 1);
    assert_eq!(nested.entries[0].name, "leaf.txt");
    for prefix in [
        std::path::Path::new("absent"),
        std::path::Path::new("root.txt"),
    ] {
        assert!(owner
            .client()
            .browse_index(
                &folder,
                &IndexBrowseOptions::default().prefix(TargetPath::local(prefix))
            )
            .await?
            .entries
            .is_empty());
    }
    assert!(matches!(
        owner
            .client()
            .browse_index(
                &FolderId::parse("not-configured")?,
                &IndexBrowseOptions::default()
            )
            .await,
        Err(Error::FolderNotFound { .. })
    ));
    assert_eq!(
        owner.client().folder_status(&folder).await?.local_files,
        Some(3)
    );
    assert_eq!(owner.client().system_status().await?.device_id, identity);
    assert_eq!(
        std::fs::read(root.join("core").join("setting.dat"))?,
        configuration
    );
    for file in &files {
        assert_eq!(std::fs::read(data.join(file))?, payload);
    }
    assert_eq!(
        std::fs::read(data.join("not-indexed.txt"))?,
        b"unindexed retained bytes"
    );
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_index_browse_snapshots=9 flat_zero_and_native_unlimited_depth=true actual_directory_filter_and_false_omission=true native_relative_unicode_prefix=true empty_missing_or_file_prefix=true index_not_filesystem_observation=true unknown_folder_refused=true identity_configuration_and_four_files_retained=true normal_owned_tree_exit=true");
    Ok(())
}

#[tokio::test]
async fn actual_native_core_log_text_retains_messages_filters_and_owned_state() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vslogtext-")
        .tempdir()?
        .keep();
    let state = root.join("core");
    let sentinel = root.join("retained.txt");
    std::fs::write(&sentinel, b"text log reads retain synthetic bytes")?;
    let mut owner = ManagedInstance::start(options(&state)?).await?;
    let identity = owner.client().instance().device_id.clone();
    let configuration = std::fs::read(state.join("setting.dat"))?;
    let nonce = "synthetic-private-text-log-message 二 %";
    owner.client().record_core_error(nonce).await?;
    let all = owner.client().core_log_text(None).await?;
    assert!(all.text.contains(nonce));
    assert!(!format!("{all:?}").contains(nonce));
    assert!(owner
        .client()
        .core_log_text(Some("1970-01-01T00:00:00Z"))
        .await?
        .text
        .contains(nonce));
    assert!(owner
        .client()
        .core_log_text(Some("2100-01-01T00:00:00Z"))
        .await?
        .text
        .is_empty());
    assert!(owner
        .client()
        .core_log_text(None)
        .await?
        .text
        .contains(nonce));
    assert_eq!(owner.client().system_status().await?.device_id, identity);
    assert_eq!(std::fs::read(state.join("setting.dat"))?, configuration);
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"text log reads retain synthetic bytes"
    );
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_core_log_text_snapshots=4 actual_explicit_synthetic_message=true native_past_filter=true empty_future_filter=true repeated_read_retains_message=true private_debug=true identity_configuration_sentinel_retained=true normal_owned_tree_exit=true no_controller_logger=true");
    Ok(())
}

#[tokio::test]
async fn actual_native_random_strings_preserve_requested_lengths_and_owned_state() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vsrandom-")
        .tempdir()?
        .keep();
    let state = root.join("core");
    let sentinel = root.join("retained.txt");
    std::fs::write(&sentinel, b"native generation retains synthetic data")?;
    let mut owner = ManagedInstance::start(options(&state)?).await?;
    let identity = owner.client().instance().device_id.clone();
    let configuration = std::fs::read(state.join("setting.dat"))?;
    for (length, expected) in [
        (None, 32),
        (Some(0), 32),
        (Some(1), 1),
        (Some(16), 16),
        (Some(u16::MAX), 65535),
    ] {
        let result = owner.client().native_random_string(length).await?;
        assert_eq!(result.value.len(), expected);
        assert!(result.value.bytes().all(|b| b.is_ascii_alphanumeric()));
        if expected >= 16 {
            assert!(!format!("{result:?}").contains(&result.value));
        }
    }
    assert_eq!(owner.client().system_status().await?.device_id, identity);
    assert!(owner.client().folders().await?.is_empty());
    assert_eq!(std::fs::read(state.join("setting.dat"))?, configuration);
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"native generation retains synthetic data"
    );
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_random_string_effects=5 default_and_zero_length_32=true exact_positive_lengths_1_16_65535=true ascii_alphanumeric=true identity_configuration_and_sentinel_retained=true private_debug=true normal_owned_tree_exit=true no_uniqueness_or_cryptographic_claim=true");
    Ok(())
}

#[tokio::test]
async fn actual_native_helpers_normalize_ids_collect_reports_and_preserve_explicit_boundaries(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vshelpers-")
        .tempdir()?
        .keep();
    let mut owner = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = owner.client().instance().device_id.clone();
    for value in [
        identity.to_string(),
        identity.as_str().to_lowercase(),
        identity.as_str().replace('-', ""),
    ] {
        assert_eq!(owner.client().normalize_device_id(&value).await?, identity);
    }
    assert!(matches!(
        owner.client().normalize_device_id("invalid").await,
        Err(Error::Api { .. })
    ));
    let mut checksum = identity.as_str().as_bytes().to_vec();
    let last = checksum.last_mut().ok_or("identity absent")?;
    *last = if *last == b'A' { b'B' } else { b'A' };
    let checksum = String::from_utf8(checksum)?;
    assert!(verysync_sidecar::DeviceId::parse(&checksum).is_ok());
    assert!(matches!(
        owner.client().normalize_device_id(&checksum).await,
        Err(Error::Api { .. })
    ));
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let lookup = owner.client().lookup_target_ip(ip).await?;
        assert_eq!(lookup.ip, ip);
        assert!(
            lookup.province.is_empty() && lookup.city.is_empty() && lookup.description.is_empty()
        );
    }
    let before = owner.client().diagnostics_options().await?;
    let health = owner.client().native_health().await?;
    assert!(matches!(
        health.status,
        verysync_sidecar::NativeHealthStatus::Ok
    ));
    let native_health = owner
        .client()
        .raw_request(&verysync_sidecar::RawRequest::new(
            verysync_sidecar::RawMethod::Get,
            ["rest", "noauth", "health"],
            verysync_sidecar::RequestEffect::ReadOnly,
        )?)
        .await?;
    assert_eq!(native_health.status(), 200);
    let raw_health: serde_json::Value = serde_json::from_slice(native_health.body_bytes())?;
    assert_eq!(raw_health["status"], health.status.native_value());
    let migration = owner.client().native_migration_progress().await?;
    assert!(migration.finished && migration.error_message.is_empty());
    let native_migration = owner
        .client()
        .raw_request(&verysync_sidecar::RawRequest::new(
            verysync_sidecar::RawMethod::Get,
            ["rest", "migrate", "progress"],
            verysync_sidecar::RequestEffect::ReadOnly,
        )?)
        .await?;
    assert_eq!(native_migration.status(), 200);
    let raw_migration: serde_json::Value = serde_json::from_slice(native_migration.body_bytes())?;
    assert!(raw_migration["name"].as_str() == Some(migration.name.as_str()));
    assert_eq!(raw_migration["total"].as_i64(), Some(migration.total));
    assert_eq!(
        raw_migration["completed"].as_i64(),
        Some(migration.completed)
    );
    assert_eq!(raw_migration["percent"].as_f64(), Some(migration.percent));
    assert_eq!(
        raw_migration["finished"].as_bool(),
        Some(migration.finished)
    );
    assert!(raw_migration["error"].as_str() == Some(migration.error_message.as_str()));
    #[cfg(unix)]
    {
        let control = reqwest::Client::builder()
            .unix_socket(root.join("core").join("gui.sock"))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()?;
        let reply = control
            .get("http://localhost/rest/noauth/health")
            .send()
            .await?;
        assert_eq!(reply.status(), reqwest::StatusCode::OK);
        assert!(reply.content_length().is_some_and(|length| length <= 4096));
        let value: serde_json::Value = reply.json().await?;
        assert_eq!(value["status"], "OK");
        println!("native_health_unauthenticated_control=true private_unix_socket_only=true");
    }
    let report = owner.client().collect_native_usage_report().await?;
    assert_eq!(report.version, verysync_sidecar::BASELINE_ENGINE_VERSION);
    let version = &owner.client().instance().version;
    assert_eq!(report.platform, format!("{}-{}", version.os, version.arch));
    assert_eq!(report.device_count, 1);
    assert!(!report.unique_id.as_deref().unwrap_or("").is_empty());
    let after = owner.client().diagnostics_options().await?;
    assert_eq!(before.usage_accepted_version, after.usage_accepted_version);
    assert_eq!(before.usage_seen_version, after.usage_seen_version);
    assert_eq!(before.usage_identifier(), after.usage_identifier());
    assert_eq!(before.usage_report_url(), after.usage_report_url());
    assert_eq!(
        before.crash_reporting_enabled,
        after.crash_reporting_enabled
    );
    for _ in 0..3 {
        let _native_number = owner.client().native_random_number().await?;
    }
    let pending = owner.client().pending_native_link().await?;
    assert!(pending.link().is_none());
    assert!(owner.client().folders().await?.is_empty());
    assert_eq!(owner.client().system_status().await?.device_id, identity);
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_helper_observations native_health_ok=true health_matches_independent_native_response=true migration_completed_baseline_matches_independent_native_response=true migration_not_started=true migration_active_effect_not_observed=true native_id_normalization_and_checksum_rejection=true explicit_loopback_lookup=true report_collection_without_consent_change=true random_quality_not_asserted=true empty_link_only_native_effect=true");
    Ok(())
}
