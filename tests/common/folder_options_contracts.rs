//! Scoped advanced settings and creation-template boundaries.
use super::*;
use verysync_sidecar::{
    DiskFreeRequirement, DiskSpaceUnit, FolderAdvancedPatch, FolderDefaultsPatch, FolderId,
    FolderPullOrder, FolderScanPatch,
};

fn template() -> serde_json::Value {
    serde_json::json!({"label":"","paused":false,"rescanIntervalS":3600,
        "fsWatcherEnabled":true,"fsWatcherDelayS":10,"fsWatcherTimeoutS":0,
        "scanProgressIntervalS":-1,"disableInitialScan":false,"secretKey":KEY,
        "futurePrivate":KEY,"order":"random","selectiveEnabled":false})
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}

#[tokio::test]
async fn folder_template_settings_share_scan_validation_and_keep_absence_and_private_data(
) -> TestResult {
    let mut actual = template();
    for (key, value) in [
        ("copiers", serde_json::json!(3)),
        ("ignoreDelete", true.into()),
        ("fsWatcherDelayS", serde_json::json!(0.5)),
        ("order", "alphabetic".into()),
        ("minDiskFree", serde_json::json!({"value":1,"unit":"MB"})),
    ] {
        actual[key] = value;
    }
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        Reply::json(template()),
        identity(),
        Reply::json(serde_json::json!({})),
        Reply::json(actual.clone()),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let before = client.folder_defaults().await?;
    assert_eq!(before.advanced_configuration()?.copiers, None);
    assert!(!format!("{:?}", before.advanced_configuration()?).contains(KEY));
    let patch = FolderDefaultsPatch::default()
        .scan_configuration(FolderScanPatch::default().watcher_delay_seconds(0.5))?
        .pull_order(FolderPullOrder::Alphabetic)?
        .advanced_configuration(
            FolderAdvancedPatch::default()
                .copiers(3)
                .ignore_delete(true)
                .minimum_disk_free(DiskFreeRequirement::new(1.0, DiskSpaceUnit::Megabytes)?),
        )?;
    let update = client.update_folder_defaults(&patch).await?;
    assert!(update.requested_fields_match);
    assert_eq!(
        update
            .configuration
            .scan_configuration()?
            .watcher_delay_seconds,
        0.5
    );
    assert_eq!(
        update.configuration.scheduling_configuration()?.pull_order,
        FolderPullOrder::Alphabetic
    );
    assert_eq!(
        update.configuration.advanced_configuration()?.copiers,
        Some(3)
    );
    assert_eq!(update.configuration.extra["secretKey"], KEY);
    assert!(!format!("{patch:?} {update:?}").contains(KEY));
    let requests = server.finish().await?;
    let writes: Vec<_> = requests
        .iter()
        .filter(|r| r.starts_with("PATCH "))
        .collect();
    assert_eq!(writes.len(), 1);
    assert!(writes[0].starts_with("PATCH /prefix/rest/config/defaults/folder "));
    let body: serde_json::Value =
        serde_json::from_str(writes[0].split_once("\r\n\r\n").ok_or("body absent")?.1)?;
    assert_eq!(
        body,
        serde_json::json!({"copiers":3,"ignoreDelete":true,"fsWatcherDelayS":0.5,
        "order":"alphabetic","minDiskFree":{"value":1,"unit":"MB"}})
    );
    Ok(())
}

#[tokio::test]
async fn advanced_folder_write_requires_fresh_identity_and_never_retries_unknown_readback(
) -> TestResult {
    let folder = serde_json::json!({"id":"synthetic","label":"","path":"/synthetic","paused":true,
        "hashers":1,"futurePrivate":KEY});
    for invalid in [false, true] {
        let server = ScriptedServer::start(vec![
            version(),
            identity(),
            identity(),
            Reply::json(serde_json::json!({"folders":[folder.clone()]})),
            Reply::json(serde_json::json!({})),
            Reply::json(
                serde_json::json!({"folders":[if invalid {serde_json::json!({"private":KEY})}
                else {let mut f=folder.clone();f["hashers"]=2.into();f}]}),
            ),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let result = client
            .update_folder_advanced_configuration(
                &FolderId::parse("synthetic")?,
                &FolderAdvancedPatch::default().hashers(2),
            )
            .await;
        if invalid {
            assert!(matches!(result, Err(Error::MutationOutcomeUnknown { .. })));
        } else {
            let receipt = result?;
            assert!(receipt.requested_fields_match);
            assert_eq!(receipt.configuration.hashers, Some(2));
        }
        let requests = server.finish().await?;
        assert_eq!(
            requests.iter().filter(|r| r.starts_with("PATCH ")).count(),
            1
        );
        assert!(requests
            .iter()
            .any(|r| r.starts_with("PATCH /prefix/rest/config/folders/synthetic ")));
    }
    Ok(())
}

#[tokio::test]
async fn invalid_advanced_or_template_selection_is_rejected_without_requests() -> TestResult {
    let server = ScriptedServer::start(vec![version(), identity()]).await?;
    let client = Client::connect(server.options()?).await?;
    for patch in [
        FolderAdvancedPatch::default(),
        FolderAdvancedPatch::default().copiers(u32::MAX),
        FolderAdvancedPatch::default().max_conflicts(-2),
        FolderAdvancedPatch::default().tags(vec!["invalid\nprivate".into()]),
    ] {
        assert!(matches!(
            client
                .update_folder_advanced_configuration(&FolderId::parse("synthetic")?, &patch)
                .await,
            Err(Error::InvalidConfiguration { .. })
        ));
        assert!(FolderDefaultsPatch::default()
            .advanced_configuration(patch)
            .is_err());
    }
    assert!(FolderDefaultsPatch::default()
        .scan_configuration(FolderScanPatch::default().watcher_delay_seconds(f64::NAN))
        .is_err());
    assert!(FolderDefaultsPatch::default()
        .pull_order(FolderPullOrder::Unknown(KEY.into()))
        .is_err());
    assert!(matches!(
        client
            .update_folder_defaults(
                &FolderDefaultsPatch::default().rescan_interval_seconds(u32::MAX)
            )
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn advanced_folder_identity_change_prevents_any_write() -> TestResult {
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        Reply::json(serde_json::json!({"myID":ID.replacen('A',"B",1)})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let result = client
        .update_folder_advanced_configuration(
            &FolderId::parse("synthetic")?,
            &FolderAdvancedPatch::default().hashers(2),
        )
        .await;
    assert!(matches!(result, Err(Error::IdentityMismatch { .. })));
    assert_eq!(server.finish().await?.len(), 3);
    Ok(())
}

#[tokio::test]
async fn advanced_partial_readback_mismatch_is_reported_without_replay() -> TestResult {
    let folder = serde_json::json!({"id":"synthetic","label":"","path":"/synthetic","paused":true,
        "hashers":1,"copiers":1});
    let mut observed = folder.clone();
    observed["hashers"] = 2.into();
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!({"folders":[folder]})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"folders":[observed]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let receipt = client
        .update_folder_advanced_configuration(
            &FolderId::parse("synthetic")?,
            &FolderAdvancedPatch::default().hashers(2).copiers(4),
        )
        .await?;
    assert!(!receipt.requested_fields_match);
    assert_eq!(receipt.configuration.hashers, Some(2));
    assert_eq!(receipt.configuration.copiers, Some(1));
    assert_eq!(
        server
            .finish()
            .await?
            .iter()
            .filter(|r| r.starts_with("PATCH "))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn invalid_template_snapshot_edit_preserves_the_original_document() -> TestResult {
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(complete_configuration_fixture()),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let mut snapshot = client.configuration().await?;
    let before = snapshot.native_document().clone();
    assert!(snapshot
        .set_folder_defaults(&FolderDefaultsPatch::default().rescan_interval_seconds(u32::MAX))
        .is_err());
    assert_eq!(snapshot.native_document(), &before);
    snapshot.set_folder_defaults(
        &FolderDefaultsPatch::default()
            .advanced_configuration(FolderAdvancedPatch::default().hashers(2))?,
    )?;
    assert_eq!(
        snapshot
            .folder_defaults()?
            .advanced_configuration()?
            .hashers,
        Some(2)
    );
    assert_eq!(snapshot.native_document()["gui"], before["gui"]);
    assert_eq!(server.finish().await?.len(), 4);
    Ok(())
}
