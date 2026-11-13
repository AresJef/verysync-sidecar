//! Actual version retention and restoration through public Rust APIs.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::{path::Path, time::Duration};
use verysync_sidecar::{
    CreateDeviceOptions, DevicePatch, DeviceTransport, FileVersionRestore, FolderVersioningPolicy,
    JoinFolderOptions, ManagedInstance, TargetPath,
};
async fn past_archive_generation(core: &ManagedInstance, stamp: &str) -> TestResult {
    let selected = chrono::DateTime::parse_from_rfc3339(stamp)?.timestamp();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let status = core.client().system_status().await?;
            let now = chrono::DateTime::parse_from_rfc3339(
                status
                    .now_time
                    .as_deref()
                    .ok_or("native current clock absent")?,
            )?
            .timestamp();
            if now > selected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn public_same_second_restore_refusal_preserves_selected_old_archive_and_current_bytes(
) -> TestResult {
    use sha2::{Digest, Sha256};
    use verysync_sidecar::{DirectoryVersionOrder, Error, VersionedDirectory};
    let root = tempfile::Builder::new().prefix("vguard-").tempdir()?.keep();
    let data_dir = root.join("data");
    std::fs::create_dir(&data_dir)?;
    let old = b"selected old archive bytes";
    let new = b"current synthetic contents of another size";
    for name in ["same.txt", "older.txt"] {
        std::fs::write(data_dir.join(name), new)?;
    }
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let share = core.client().generate_share().await?;
    let key = core
        .client()
        .validate_share_key(&share.read_write_key)
        .await?;
    let folder = core
        .client()
        .join_folder(&JoinFolderOptions::new(key, TargetPath::local(&data_dir)))
        .await?
        .configuration;
    core.client()
        .set_folder_versioning(
            &folder.id,
            FolderVersioningPolicy::Simple {
                keep: 3,
                cleanout_days: 0,
                cleanup_interval_seconds: 3600,
            },
        )
        .await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let state = core.client().folder_status(&folder.id).await?;
            if state.local_files == Some(2)
                && state.state == Some(verysync_sidecar::FolderState::Idle)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, verysync_sidecar::Error>(())
    })
    .await??;
    let first = core
        .client()
        .system_status()
        .await?
        .now_time
        .ok_or("native clock absent")?;
    let stamp = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let next = core
                .client()
                .system_status()
                .await?
                .now_time
                .ok_or("native clock absent")?;
            if next != first {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(next);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    assert!(stamp.is_ascii() && stamp.len() >= 19);
    let tag = format!(
        "{}{}{}-{}{}{}",
        &stamp[0..4],
        &stamp[5..7],
        &stamp[8..10],
        &stamp[11..13],
        &stamp[14..16],
        &stamp[17..19]
    );
    let archive = data_dir.join(".verysync").join("Archive");
    std::fs::create_dir_all(&archive)?;
    let same_archive = archive.join(format!("same~{tag}.txt"));
    std::fs::write(&same_archive, old)?;
    std::fs::write(archive.join("older~20000101-000000.txt"), old)?;
    let listed = core.client().folder_versions(&folder.id, None).await?;
    let same_stamp = listed.0["same.txt"][0].version_time.clone();
    let same = FileVersionRestore::new(TargetPath::local(Path::new("same.txt")), same_stamp)?;
    assert!(matches!(
        core.client()
            .restore_file_versions(&folder.id, &[same])
            .await,
        Err(Error::ArchiveRestorePrecondition { .. })
    ));
    assert!(matches!(
        core.client()
            .restore_directory_versions(
                &folder.id,
                &VersionedDirectory::FolderRoot,
                DirectoryVersionOrder::Oldest
            )
            .await,
        Err(Error::ArchiveRestorePrecondition { .. })
    ));
    let now = core
        .client()
        .system_status()
        .await?
        .now_time
        .ok_or("native clock absent")?;
    assert_eq!(
        &stamp[..19],
        &now[..19],
        "same-second fixture crossed a target clock boundary"
    );
    assert_eq!(std::fs::read(&same_archive)?, old);
    assert_eq!(std::fs::read(data_dir.join("same.txt"))?, new);
    assert_eq!(
        Sha256::digest(std::fs::read(&same_archive)?),
        Sha256::digest(old)
    );
    assert_eq!(
        Sha256::digest(std::fs::read(data_dir.join("same.txt"))?),
        Sha256::digest(new)
    );
    let older = FileVersionRestore::new(
        TargetPath::local(Path::new("older.txt")),
        listed.0["older.txt"][0].version_time.clone(),
    )?;
    assert_eq!(
        core.client()
            .restore_file_versions(&folder.id, &[older])
            .await?
            .error_count(),
        0
    );
    data(&data_dir.join("older.txt"), old).await?;
    assert_eq!(std::fs::read(&same_archive)?, old);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    eprintln!(
        "public archive collision guard evidence: {}",
        serde_json::json!({"actual_same_native_second":true,"actual_file_restore_refused":true,"actual_directory_restore_refused":true,"actual_old_archive_bytes_and_sha_preserved":true,"actual_current_bytes_and_sha_preserved":true,"actual_explicit_older_restore_works":true,"actual_unselected_archive_preserved":true,"actual_normal_owned_tree_exit":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
async fn listener(core: &ManagedInstance) -> TestResult<String> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for status in core.client().listener_status().await?.into_values() {
                for address in status.lan_addresses {
                    if address
                        .strip_prefix("tcp://")
                        .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
                        .is_some_and(|a| a.ip().is_loopback() && a.port() != 0 && a.port() != 18886)
                    {
                        return Ok::<_, verysync_sidecar::Error>(address);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??)
}
async fn data(path: &Path, expected: &[u8]) -> TestResult {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if std::fs::read(path).ok().as_deref() == Some(expected) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    Ok(())
}
async fn register(
    a: &ManagedInstance,
    b: &ManagedInstance,
    source: &Path,
    receive: &Path,
) -> TestResult<(
    verysync_sidecar::FolderConfig,
    verysync_sidecar::FolderConfig,
)> {
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_write_key).await?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(source)).paused(true))
        .await?
        .configuration;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(receive)).paused(true))
        .await?
        .configuration;
    let aid = a.client().instance().device_id.clone();
    let bid = b.client().instance().device_id.clone();
    let aa = listener(a).await?;
    let ba = listener(b).await?;
    for (core, folder, peer, address) in [(a, &af.id, &bid, ba), (b, &bf.id, &aid, aa)] {
        core.client()
            .create_device(
                &CreateDeviceOptions::new(peer.clone()).settings(
                    DevicePatch::default()
                        .addresses(vec![address])
                        .allowed_transports(vec![DeviceTransport::Tcp]),
                ),
            )
            .await?;
        core.client().share_folder_with(folder, peer).await?;
    }
    Ok((af, bf))
}
#[tokio::test]
async fn public_version_policy_archives_remote_changes_and_restores_old_bytes() -> TestResult {
    let root = tempfile::Builder::new().prefix("vfh-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let source = root.join("source");
    let receive = root.join("receive");
    std::fs::create_dir(&source)?;
    let initial_bytes = b"first synthetic version payload";
    let old = b"second retained archived payload with unique size";
    let middle = b"third retained archived version bytes";
    let new = b"second distinct synthetic replacement version bytes";
    std::fs::write(source.join("version-sample.bin"), initial_bytes)?;
    let (af, bf) = register(&a, &b, &source, &receive).await?;
    let initial = b.client().folder_versioning(&bf.id).await?;
    assert_eq!(initial.kind, "");
    let configured = b
        .client()
        .set_folder_versioning(
            &bf.id,
            FolderVersioningPolicy::Simple {
                keep: 2,
                cleanout_days: 0,
                cleanup_interval_seconds: 3600,
            },
        )
        .await?;
    assert!(configured.requested_fields_match);
    assert_eq!(
        configured.configuration.filesystem_path,
        initial.filesystem_path
    );
    assert_eq!(
        configured.configuration.filesystem_type,
        initial.filesystem_type
    );
    a.client().resume_folder(&af.id).await?;
    b.client().resume_folder(&bf.id).await?;
    a.client().request_scan(&af.id).await?;
    eprintln!("private version stage: initial-transfer");
    data(&receive.join("version-sample.bin"), initial_bytes).await?;
    assert!(b.client().folder_versions(&bf.id, None).await?.0.is_empty());
    for bytes in [old.as_slice(), middle.as_slice(), new.as_slice()] {
        // Archive names use one-second timestamps; create distinct revisions.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        std::fs::write(source.join("version-sample.bin"), bytes)?;
        a.client().request_scan(&af.id).await?;
        eprintln!("private version stage: remote-update");
        data(&receive.join("version-sample.bin"), bytes).await?;
    }
    let history = b.client().folder_versions(&bf.id, None).await?;
    let versions = history
        .0
        .get("version-sample.bin")
        .ok_or("actual old version missing")?;
    assert_eq!(versions.len(), 2);
    let sizes: std::collections::BTreeSet<_> = versions.iter().map(|v| v.size).collect();
    assert_eq!(
        sizes,
        std::collections::BTreeSet::from([old.len() as u64, middle.len() as u64])
    );
    let stamp = versions
        .iter()
        .find(|v| v.size == old.len() as u64)
        .ok_or("retained archive missing")?
        .version_time
        .clone();
    let prefixed = b
        .client()
        .folder_versions(
            &bf.id,
            Some(&TargetPath::local(Path::new("version-sample.bin"))),
        )
        .await?;
    assert!(prefixed.0.is_empty());
    assert_eq!(std::fs::read(source.join("version-sample.bin"))?, new);
    let exit = a.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    let report = b
        .client()
        .restore_file_versions(
            &bf.id,
            &[FileVersionRestore::new(
                TargetPath::local(Path::new("version-sample.bin")),
                stamp,
            )?],
        )
        .await?;
    assert_eq!(report.error_count(), 0);
    eprintln!("private version stage: restore");
    data(&receive.join("version-sample.bin"), old).await?;
    assert_eq!(std::fs::read(source.join("version-sample.bin"))?, new);
    use sha2::{Digest, Sha256};
    assert_eq!(
        Sha256::digest(std::fs::read(receive.join("version-sample.bin"))?),
        Sha256::digest(old)
    );
    let disabled = b
        .client()
        .set_folder_versioning(&bf.id, FolderVersioningPolicy::Disabled)
        .await?;
    assert!(disabled.requested_fields_match && disabled.configuration.kind.is_empty());
    let reenabled = b
        .client()
        .set_folder_versioning(
            &bf.id,
            FolderVersioningPolicy::Simple {
                keep: 2,
                cleanout_days: 0,
                cleanup_interval_seconds: 3600,
            },
        )
        .await?;
    assert!(reenabled.requested_fields_match);
    assert!(!b.client().folder_versions(&bf.id, None).await?.0.is_empty());
    let exit = b.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public version history evidence: {}",
        serde_json::json!({"actual_default_disabled":true,"actual_simple_configuration":true,"actual_archive_location_preserved":true,"actual_remote_old_to_new_update":true,"actual_keep_two_after_three_remote_updates":true,"actual_file_prefix_observes_empty_descendants":true,"actual_nonempty_versions_and_original_size":true,"actual_source_stopped_before_restore":true,"actual_exact_old_bytes_restored":true,"actual_restored_sha256":true,"actual_stopped_source_new_bytes_preserved":true,"actual_disable_preserves_archives":true,"actual_normal_both_owned_tree_exits":true})
    );
    Ok(())
}

#[tokio::test]
async fn public_trashcan_restores_the_last_remotely_deleted_file() -> TestResult {
    let root = tempfile::Builder::new().prefix("vfht-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let source = root.join("source");
    let receive = root.join("receive");
    std::fs::create_dir(&source)?;
    let relative = Path::new("recycle 二 %.txt");
    let old = b"old before actual remote replacement";
    let new = b"last synthetic bytes before deletion";
    std::fs::write(source.join(relative), old)?;
    let (af, bf) = register(&a, &b, &source, &receive).await?;
    let update = b
        .client()
        .set_folder_versioning(
            &bf.id,
            FolderVersioningPolicy::Trashcan {
                cleanout_days: 0,
                cleanup_interval_seconds: 3600,
            },
        )
        .await?;
    assert!(update.requested_fields_match && update.configuration.kind == "trashcan");
    a.client().resume_folder(&af.id).await?;
    b.client().resume_folder(&bf.id).await?;
    a.client().request_scan(&af.id).await?;
    data(&receive.join(relative), old).await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    std::fs::write(source.join(relative), new)?;
    a.client().request_scan(&af.id).await?;
    data(&receive.join(relative), new).await?;
    let history = b.client().folder_versions(&bf.id, None).await?;
    let key = relative.to_str().ok_or("synthetic name encoding")?;
    assert_eq!(history.0[key].len(), 1);
    assert_eq!(history.0[key][0].size, old.len() as u64);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    std::fs::remove_file(source.join(relative))?;
    a.client().request_scan(&af.id).await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        while receive.join(relative).exists() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    let history = b.client().folder_versions(&bf.id, None).await?;
    assert_eq!(history.0[key].len(), 1);
    assert_eq!(history.0[key][0].size, new.len() as u64);
    let exit = a.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    past_archive_generation(&b, &history.0[key][0].version_time).await?;
    let report = b
        .client()
        .restore_file_versions(
            &bf.id,
            &[FileVersionRestore::new(
                TargetPath::local(relative),
                history.0[key][0].version_time.clone(),
            )?],
        )
        .await?;
    assert_eq!(report.error_count(), 0);
    data(&receive.join(relative), new).await?;
    use sha2::{Digest, Sha256};
    assert_eq!(
        Sha256::digest(std::fs::read(receive.join(relative))?),
        Sha256::digest(new)
    );
    assert!(!source.join(relative).exists());
    let exit = b.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public trashcan version evidence: {}",
        serde_json::json!({
        "actual_trashcan_policy":true,"actual_remote_overwrite_archive":true,"actual_remote_file_delete":true,
        "actual_latest_deleted_bytes_retained":true,"actual_single_recycle_version":true,
        "actual_deleted_file_restored":true,"actual_restored_sha256":true,"actual_stopped_source_stays_deleted":true,
        "actual_unicode_literal_percent_path":true,"actual_both_normal_owned_tree_exits":true})
    );
    Ok(())
}

#[tokio::test]
async fn public_free_audit_settings_report_unretained_enable_and_empty_pages() -> TestResult {
    use verysync_sidecar::AuditHistorySettings;
    let root = tempfile::Builder::new().prefix("vfha-").tempdir()?.keep();
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let initial = core.client().audit_history_settings().await?;
    assert!(!initial.enabled);
    let update = core
        .client()
        .set_audit_history_settings(AuditHistorySettings {
            enabled: true,
            maximum_records: initial.maximum_records,
        })
        .await?;
    assert!(!update.requested_fields_match && !update.configuration.enabled);
    for page in [1, 2] {
        let result = core.client().audit_history(page, 10).await?;
        assert_eq!(result.total, 0);
        assert!(result.records.is_none() && result.error.is_none());
    }
    core.client().reset_audit_history().await?;
    assert_eq!(core.client().audit_history(1, 10).await?.total, 0);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public free audit history evidence: {}",
        serde_json::json!({"actual_default_recording_disabled":true,"actual_enable_not_retained_in_readback":true,"actual_two_explicit_empty_pages":true,"actual_empty_reset_acknowledgement":true,"actual_empty_total_after_reset":true,"actual_normal_owned_tree_exit":true,"scope":"free-instance settings/readback/empty response only; no licensed recording or nonempty history removal claim"})
    );
    Ok(())
}

#[tokio::test]
async fn public_directory_restore_selects_nested_and_explicit_root_versions() -> TestResult {
    use verysync_sidecar::{DirectoryVersionOrder, VersionedDirectory};
    let root = tempfile::Builder::new().prefix("vfhd-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let source = root.join("source");
    let receive = root.join("receive");
    let relative = [
        std::path::PathBuf::from("a.txt"),
        Path::new("nested").join("b 二 %.txt"),
        Path::new("nested").join("deeper").join("c.txt"),
    ];
    let old = b"original archived directory bytes";
    let new = b"distinct newer directory content with another size";
    for p in &relative {
        std::fs::create_dir_all(source.join(p).parent().ok_or("synthetic file parent")?)?;
        std::fs::write(source.join(p), old)?;
    }
    let (af, bf) = register(&a, &b, &source, &receive).await?;
    assert!(
        b.client()
            .set_folder_versioning(
                &bf.id,
                FolderVersioningPolicy::Simple {
                    keep: 3,
                    cleanout_days: 0,
                    cleanup_interval_seconds: 3600
                }
            )
            .await?
            .requested_fields_match
    );
    a.client().resume_folder(&af.id).await?;
    b.client().resume_folder(&bf.id).await?;
    a.client().request_scan(&af.id).await?;
    for p in &relative {
        data(&receive.join(p), old).await?;
    }
    tokio::time::sleep(Duration::from_millis(1100)).await;
    for p in &relative {
        std::fs::write(source.join(p), new)?;
    }
    a.client().request_scan(&af.id).await?;
    for p in &relative {
        data(&receive.join(p), new).await?;
    }
    let root_catalog = b.client().folder_versions(&bf.id, None).await?;
    let nested_catalog = b
        .client()
        .folder_versions(&bf.id, Some(&TargetPath::local(Path::new("nested"))))
        .await?;
    assert!(root_catalog.0.values().any(|versions| !versions.is_empty()));
    assert!(nested_catalog
        .0
        .values()
        .any(|versions| !versions.is_empty()));
    let exit = a.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    // Native archive names have one-second precision. Restoring a selected
    // archive while archiving the current file in that same second can replace
    // the selected archive before it is restored. Establish distinct archive
    // generations explicitly; keep every 30-second content deadline unchanged.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let scope = VersionedDirectory::Path(TargetPath::local(Path::new("nested")));
    let result = b
        .client()
        .restore_directory_versions(&bf.id, &scope, DirectoryVersionOrder::Oldest)
        .await?;
    assert_eq!(result.error_count(), 0);
    for (index, p) in relative[1..].iter().enumerate() {
        let effect = data(&receive.join(p), old).await;
        if effect.is_err() {
            eprintln!(
                "private directory oldest scope diagnostic: {}",
                serde_json::json!({"failed_relative_index":index+1,"old_bytes":relative.iter().map(|p|std::fs::read(receive.join(p)).is_ok_and(|v|v==old)).collect::<Vec<_>>(),"new_bytes":relative.iter().map(|p|std::fs::read(receive.join(p)).is_ok_and(|v|v==new)).collect::<Vec<_>>()})
            );
        }
        effect?;
    }
    assert_eq!(std::fs::read(receive.join(&relative[0]))?, new);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let result = b
        .client()
        .restore_directory_versions(&bf.id, &scope, DirectoryVersionOrder::Newest)
        .await?;
    assert_eq!(result.error_count(), 0);
    for p in &relative {
        data(&receive.join(p), new).await?;
    }
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let result = b
        .client()
        .restore_directory_versions(
            &bf.id,
            &VersionedDirectory::FolderRoot,
            DirectoryVersionOrder::Oldest,
        )
        .await?;
    assert_eq!(result.error_count(), 0);
    use sha2::{Digest, Sha256};
    for p in &relative {
        data(&receive.join(p), old).await?;
        assert_eq!(
            Sha256::digest(std::fs::read(receive.join(p))?),
            Sha256::digest(old)
        );
        assert_eq!(std::fs::read(source.join(p))?, new);
    }
    let exit = b.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public directory version restore evidence: {}",
        serde_json::json!({"actual_three_remote_archived_paths":true,"actual_nested_oldest_restore":true,"actual_deeper_descendant_restored":true,"actual_unselected_root_file_unchanged":true,"actual_nested_newest_restore":true,"actual_explicit_dot_root_oldest_restore":true,"actual_all_restored_sha256":true,"actual_stopped_source_new_bytes_unchanged":true,"actual_unicode_percent_nested_path":true,"actual_both_owned_normal_tree_exits":true})
    );
    Ok(())
}

#[tokio::test]
async fn public_staggered_external_and_archive_locations_preserve_actual_versions() -> TestResult {
    use verysync_sidecar::{ExternalVersioningCommand, VersionArchiveLocation};
    let root = tempfile::Builder::new().prefix("vhu-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let source = root.join("source");
    let receive = root.join("receive");
    let archive = root.join("explicit archive");
    std::fs::create_dir(&source)?;
    std::fs::create_dir(&archive)?;
    let name = "sample 二 %.txt";
    let old = b"old staggered sample";
    let new = b"new version with distinct length";
    let last = b"final external version data";
    std::fs::write(source.join(name), old)?;
    let (af, bf) = register(&a, &b, &source, &receive).await?;
    let location = VersionArchiveLocation::BasicDirectory(TargetPath::local(&archive));
    let changed = b
        .client()
        .set_version_archive_location(&bf.id, &location)
        .await?;
    assert!(changed.requested_fields_match && changed.configuration.filesystem_type == "basic");
    assert_eq!(
        changed.configuration.filesystem_path,
        archive.to_str().ok_or("test path UTF8")?
    );
    let changed = b
        .client()
        .set_folder_versioning(
            &bf.id,
            FolderVersioningPolicy::Staggered {
                max_age_seconds: 0,
                cleanup_interval_seconds: 1,
            },
        )
        .await?;
    assert!(changed.requested_fields_match && changed.configuration.kind == "staggered");
    assert_eq!(
        changed
            .configuration
            .params
            .get("maxAge")
            .map(String::as_str),
        Some("0")
    );
    assert!(!format!("{location:?}").contains(archive.to_str().ok_or("test path UTF8")?));
    a.client().resume_folder(&af.id).await?;
    b.client().resume_folder(&bf.id).await?;
    a.client().request_scan(&af.id).await?;
    data(&receive.join(name), old).await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    std::fs::write(source.join(name), new)?;
    a.client().request_scan(&af.id).await?;
    data(&receive.join(name), new).await?;
    let history = b.client().folder_versions(&bf.id, None).await?;
    assert!(history.0.get(name).is_some_and(|v| v.len() == 1));
    let files = std::fs::read_dir(&archive)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(files
        .iter()
        .any(|p| std::fs::read(p).ok().as_deref() == Some(old.as_slice())));
    let default_archive = receive.join(".verysync").join("Archive");
    assert!(!default_archive.exists() || std::fs::read_dir(default_archive)?.next().is_none());
    let helper = root.join("external-helper.py");
    let external = root.join("external archive");
    std::fs::create_dir(&external)?;
    std::fs::write(
        &helper,
        r#"import sys,json,shutil
from pathlib import Path
folder=Path(sys.argv[1]).resolve();rel=Path(sys.argv[2]);destination=Path(sys.argv[3]).resolve()
assert not rel.is_absolute() and '..' not in rel.parts
source=(folder/rel).resolve();assert source.is_relative_to(folder)
mode='fail' if len(sys.argv)>4 and sys.argv[4]=='fail' else 'archive'
(destination/('failed-invocation.json' if mode=='fail' else 'invocation.json')).write_text(json.dumps({'folder':str(folder),'file':str(rel)}))
if mode=='fail':sys.exit(7)
shutil.move(str(source),str(destination/'kept.bin'))
"#,
    )?;
    let python = std::env::var("VERYSYNC_TEST_PYTHON")?;
    let command = format!(
        "\"{}\" \"{}\" \"%FOLDER_PATH%\" \"%FILE_PATH%\" \"{}\"",
        python,
        helper.display(),
        external.display()
    );
    let command = ExternalVersioningCommand::new(command)?;
    assert!(!format!("{command:?}").contains(helper.to_str().ok_or("test helper UTF8")?));
    let changed = b
        .client()
        .set_folder_versioning(&bf.id, FolderVersioningPolicy::External { command })
        .await?;
    assert!(changed.requested_fields_match && changed.configuration.kind == "external");
    assert_eq!(
        changed.configuration.filesystem_path,
        archive.to_str().ok_or("test path UTF8")?
    );
    std::fs::write(source.join(name), last)?;
    a.client().request_scan(&af.id).await?;
    data(&receive.join(name), last).await?;
    assert_eq!(std::fs::read(external.join("kept.bin"))?, new);
    let called: serde_json::Value =
        serde_json::from_slice(&std::fs::read(external.join("invocation.json"))?)?;
    assert_eq!(called["file"], name);
    assert_eq!(
        Path::new(called["folder"].as_str().ok_or("native folder arg")?),
        std::fs::canonicalize(&receive)?
    );
    let reset_location = b
        .client()
        .set_version_archive_location(&bf.id, &VersionArchiveLocation::FolderDefault)
        .await?;
    assert!(
        reset_location.requested_fields_match
            && reset_location.configuration.filesystem_path.is_empty()
    );
    let changed = b
        .client()
        .set_folder_versioning(
            &bf.id,
            FolderVersioningPolicy::Staggered {
                max_age_seconds: 0,
                cleanup_interval_seconds: 1,
            },
        )
        .await?;
    assert!(changed.requested_fields_match);
    let final_bytes = b"final default archive generation with unique bytes";
    std::fs::write(source.join(name), final_bytes)?;
    a.client().request_scan(&af.id).await?;
    data(&receive.join(name), final_bytes).await?;
    let default_archive = receive.join(".verysync").join("Archive");
    let default_files = std::fs::read_dir(&default_archive)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(default_files
        .iter()
        .any(|p| std::fs::read(p).ok().as_deref() == Some(last.as_slice())));
    let expiring = b
        .client()
        .set_folder_versioning(
            &bf.id,
            FolderVersioningPolicy::Staggered {
                max_age_seconds: 1,
                cleanup_interval_seconds: 1,
            },
        )
        .await?;
    assert!(expiring.requested_fields_match);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if std::fs::read_dir(&default_archive)?.next().is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok::<_, std::io::Error>(())
    })
    .await??;
    assert!(files
        .iter()
        .any(|p| std::fs::read(p).ok().as_deref() == Some(old.as_slice())));
    assert_eq!(std::fs::read(external.join("kept.bin"))?, new);
    assert_eq!(std::fs::read(receive.join(name))?, final_bytes);
    let failure = ExternalVersioningCommand::new(format!(
        "\"{}\" \"{}\" \"%FOLDER_PATH%\" \"%FILE_PATH%\" \"{}\" fail",
        python,
        helper.display(),
        external.display()
    ))?;
    assert!(
        b.client()
            .set_folder_versioning(
                &bf.id,
                FolderVersioningPolicy::External { command: failure }
            )
            .await?
            .requested_fields_match
    );
    let refused = b"new source bytes deliberately refused by the external archiver";
    std::fs::write(source.join(name), refused)?;
    a.client().request_scan(&af.id).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let status = b.client().folder_status(&bf.id).await?;
            if status.pull_errors.is_some_and(|n| n > 0)
                && external.join("failed-invocation.json").is_file()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok::<_, verysync_sidecar::Error>(())
    })
    .await??;
    assert_eq!(std::fs::read(receive.join(name))?, final_bytes);
    assert_eq!(std::fs::read(source.join(name))?, refused);
    assert_eq!(std::fs::read(external.join("kept.bin"))?, new);
    assert!(files
        .iter()
        .any(|p| std::fs::read(p).ok().as_deref() == Some(old.as_slice())));
    for core in [&mut b, &mut a] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    assert_eq!(std::fs::read(source.join(name))?, refused);
    eprintln!(
        "public extended versioner evidence: {}",
        serde_json::json!({"actual_staggered_native_policy_and_zero_age":true,"actual_explicit_basic_archive_location":true,"actual_old_bytes_in_selected_archive":true,"actual_default_archive_initially_empty":true,"actual_native_browse_from_selected_location":true,"actual_external_command_native_readback":true,"actual_external_callback_folder_and_file_arguments":true,"actual_external_callback_archives_old_bytes":true,"actual_explicit_default_location_restored":true,"actual_default_location_archives_next_remote_change":true,"actual_positive_native_age_cleanup_removes_observed_archive":true,"actual_previous_location_archive_not_migrated_or_cleaned":true,"actual_external_archived_bytes_retained":true,"actual_current_source_and_receiver_bytes_retained":true,"actual_private_command_and_location_debug":true,"actual_both_normal_owned_tree_exits":true,"actual_failed_external_callback_invoked":true,"actual_native_pull_error_after_callback_exit_seven":true,"actual_failed_callback_preserves_existing_receiver_bytes":true,"actual_failed_callback_preserves_new_source_bytes":true,"actual_failed_callback_preserves_both_previous_archives":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
