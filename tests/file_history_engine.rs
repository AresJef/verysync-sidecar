//! Actual version retention and restoration through public Rust APIs.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::{path::Path, time::Duration};
use verysync_sidecar::{
    CreateDeviceOptions, DevicePatch, DeviceTransport, FileVersionRestore, FolderVersioningPolicy,
    JoinFolderOptions, ManagedInstance, TargetPath,
};
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
