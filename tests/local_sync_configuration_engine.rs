//! Actual full scoped storage configuration and explicit destructive mirror effects.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
#[path = "common/storage_service.rs"]
mod storage_service;
use managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::*;
async fn execute(
    core: &ManagedInstance,
    id: &LocalSyncJobId,
    peer: &storage_service::Service,
    root: &std::path::Path,
) -> TestResult {
    let op = core.client().start_local_sync_preview(id).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let s = core.client().local_sync_status(id).await?;
            assert_eq!(s.operation_id.as_ref(), Some(&op.id));
            if let Some(message) = s.last_error.as_deref().filter(|e| !e.is_empty()) {
                let mut message =
                    message.replace(root.to_string_lossy().as_ref(), "[OWNED_SYNTHETIC_ROOT]");
                for key in ["user", "password"] {
                    if let Some(value) = peer
                        .endpoint
                        .extra()
                        .get(key)
                        .and_then(serde_json::Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        message = message.replace(value, "[SYNTHETIC_CREDENTIAL]");
                    }
                }
                eprintln!(
                    "synthetic configuration analysis failure: {}",
                    message
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(512)
                        .collect::<String>()
                );
                return Err("native configuration analysis failed".into());
            }
            if s.state == "idle" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    let p = core.client().local_sync_preview(id).await?;
    assert_eq!(p.operation_id, op.id);
    assert_eq!(p.scan_issue_count, 0);
    let run = core.client().run_local_sync_preview_all(id, &p.id).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let r = core.client().local_sync_run(id).await?;
            assert_eq!(r.id, run.id);
            if !r.finished.starts_with("0001-") {
                assert_eq!(r.summary.failed, 0);
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
async fn public_scoped_endpoints_direction_ignore_and_explicit_deletion_match_real_data(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vsp-config-")
        .tempdir()?
        .keep();
    let source = root.join("source");
    let old_target = root.join("old-target");
    let reverse_target = root.join("reverse-target");
    for p in [&source, &old_target, &reverse_target] {
        std::fs::create_dir(p)?;
    }
    std::fs::write(source.join("included.txt"), b"included bytes")?;
    std::fs::write(source.join("ignored.txt"), b"ignored remains at source")?;
    std::fs::write(old_target.join("old-only.txt"), b"old endpoint must remain")?;
    std::fs::write(reverse_target.join("keep.txt"), b"reverse sentinel")?;
    let mut peer = storage_service::Service::start(StorageProtocol::Sftp, &root, Duration::ZERO)?;
    std::fs::write(
        peer.share.join("remove-only.txt"),
        b"explicit deletion target",
    )?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let job = core
        .client()
        .create_local_sync_job(
            &CreateLocalSyncJob::new(
                "scoped complete settings",
                StorageEndpoint::local(TargetPath::local(&source))?,
                StorageEndpoint::local(TargetPath::local(&old_target))?,
                LocalSyncMode::MirrorAToB,
            )?
            .enabled(false)
            .group("retained group")?
            .ignore_permissions(true)
            .parallel_file_operations(2)?
            .ignore_lines(vec!["ignored.txt".to_owned()])?,
        )
        .await?;
    assert!(!job.enabled);
    assert_eq!(
        job.extra
            .get("parallelFileOps")
            .and_then(serde_json::Value::as_u64),
        Some(2)
    );
    let remote = peer
        .endpoint
        .clone()
        .parallel_transfers(3)?
        .sftp_channels(2)?
        .sftp_compression(true)?;
    let changed = core
        .client()
        .update_local_sync_job(
            &job.job_id,
            &LocalSyncJobPatch::default()
                .side_b(remote)
                .enabled(true)
                .mode(LocalSyncMode::MirrorAToB)
                .delete_extraneous(true)
                .parallel_file_operations(2)?
                .ignore_lines(vec!["ignored.txt".to_owned()])?,
        )
        .await?;
    assert!(changed.requested_fields_match);
    assert!(changed.configuration.delete_extraneous);
    assert_eq!(changed.configuration.side_b.transfers(), 3);
    assert_eq!(
        changed
            .configuration
            .side_b
            .extra()
            .get("sftpChannels")
            .and_then(serde_json::Value::as_u64),
        Some(2)
    );
    assert_eq!(
        changed
            .configuration
            .side_b
            .extra()
            .get("enableCompression")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        changed.configuration.group.as_deref(),
        Some("retained group")
    );
    assert_eq!(changed.configuration.label, "scoped complete settings");
    assert!(!peer.share.join("included.txt").exists());
    let unsupported_op = core.client().start_local_sync_preview(&job.job_id).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status = core.client().local_sync_status(&job.job_id).await?;
            assert_eq!(status.operation_id.as_ref(), Some(&unsupported_op.id));
            if let Some(error) = status.last_error.as_deref().filter(|s| !s.is_empty()) {
                assert!(error.contains("SSH compression: endpoint operation unsupported"));
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    assert!(!peer.share.join("included.txt").exists());
    assert_eq!(
        std::fs::read(peer.share.join("remove-only.txt"))?,
        b"explicit deletion target"
    );
    let compression_off = changed
        .configuration
        .side_b
        .clone()
        .sftp_compression(false)?;
    let off = core
        .client()
        .update_local_sync_job(
            &job.job_id,
            &LocalSyncJobPatch::default().side_b(compression_off),
        )
        .await?;
    println!(
        "synthetic compression-disable readback: present={} value={:?}",
        off.configuration
            .side_b
            .extra()
            .contains_key("enableCompression"),
        off.configuration
            .side_b
            .extra()
            .get("enableCompression")
            .and_then(serde_json::Value::as_bool)
    );
    assert!(off.requested_fields_match);
    execute(&core, &job.job_id, &peer, &root).await?;
    assert_eq!(
        std::fs::read(peer.share.join("included.txt"))?,
        b"included bytes"
    );
    assert!(!peer.share.join("remove-only.txt").exists());
    assert!(!peer.share.join("ignored.txt").exists());
    assert_eq!(
        std::fs::read(source.join("ignored.txt"))?,
        b"ignored remains at source"
    );
    assert_eq!(
        std::fs::read(source.join("included.txt"))?,
        b"included bytes"
    );
    assert_eq!(
        std::fs::read(old_target.join("old-only.txt"))?,
        b"old endpoint must remain"
    );
    std::fs::write(
        peer.share.join("ignored.txt"),
        b"new remote file after clear",
    )?;
    let before = core.client().local_sync_job(&job.job_id).await?;
    assert!(matches!(
        core.client()
            .update_local_sync_job(
                &job.job_id,
                &LocalSyncJobPatch::default().mode(LocalSyncMode::Bidirectional)
            )
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        core.client()
            .update_local_sync_job(
                &job.job_id,
                &LocalSyncJobPatch::default().conflict_policy(LocalSyncConflictPolicy::Manual)
            )
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert_eq!(
        serde_json::to_value(core.client().local_sync_job(&job.job_id).await?)?,
        serde_json::to_value(&before)?
    );
    let reverse = core
        .client()
        .update_local_sync_job(
            &job.job_id,
            &LocalSyncJobPatch::default()
                .side_a(StorageEndpoint::local(TargetPath::local(&reverse_target))?)
                .mode(LocalSyncMode::MirrorBToA)
                .delete_extraneous(false)
                .parallel_file_operations(1)?
                .ignore_lines(Vec::new())?,
        )
        .await?;
    println!("synthetic reverse configuration readback: mode={} delete={} ignore_present={} ignore_array_len={:?} ignore_null={} parallel={:?} source_uri_matches={} transfers={}",reverse.configuration.mode,reverse.configuration.delete_extraneous,reverse.configuration.extra.contains_key("ignoreLines"),reverse.configuration.extra.get("ignoreLines").and_then(serde_json::Value::as_array).map(Vec::len),reverse.configuration.extra.get("ignoreLines").is_some_and(serde_json::Value::is_null),reverse.configuration.extra.get("parallelFileOps").and_then(serde_json::Value::as_u64),reverse.configuration.side_a.uri()==reverse_target.to_str().ok_or("synthetic path not UTF8")?,reverse.configuration.side_a.transfers());
    assert!(reverse.requested_fields_match);
    assert_eq!(
        serde_json::to_value(&reverse.configuration.side_b)?,
        serde_json::to_value(&before.side_b)?
    );
    assert_eq!(
        reverse.configuration.group.as_deref(),
        Some("retained group")
    );
    execute(&core, &job.job_id, &peer, &root).await?;
    assert_eq!(
        std::fs::read(reverse_target.join("ignored.txt"))?,
        b"new remote file after clear"
    );
    assert_eq!(
        std::fs::read(reverse_target.join("included.txt"))?,
        b"included bytes"
    );
    assert_eq!(
        std::fs::read(reverse_target.join("keep.txt"))?,
        b"reverse sentinel"
    );
    assert_eq!(
        std::fs::read(source.join("included.txt"))?,
        b"included bytes"
    );
    assert_eq!(
        std::fs::read(source.join("ignored.txt"))?,
        b"ignored remains at source"
    );
    assert_eq!(
        std::fs::read(old_target.join("old-only.txt"))?,
        b"old endpoint must remain"
    );
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    peer.stop()?;
    println!(
        "public complete Local Sync configuration evidence: {}",
        serde_json::json!({"actual_initial_disabled_configuration":true,"actual_endpoint_replacement_readback":true,"actual_native_transfer_channel_compression_preferences":true,"actual_direction_and_parallel_file_options":true,"actual_unselected_label_group_preserved":true,"actual_native_ignore_prevents_remote_copy":true,"actual_explicit_mirror_deletes_only_synthetic_destination_data":true,"actual_old_endpoint_and_all_sources_retained":true,"incompatible_direction_and_conflict_refused_before_write":true,"actual_reverse_endpoint_change_and_data":true,"actual_unselected_remote_credentials_and_options_preserved":true,"actual_reverse_target_sentinel_retained":true,"actual_same_identity_normal_core_and_peer_exit":true,"actual_compression_unsupported_before_data_change":true,"actual_explicit_compression_disable":true,"actual_native_ignore_clear_allows_previous_pattern":true,"negotiated_compression_or_concurrency_measured":false})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
