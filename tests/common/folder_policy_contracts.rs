//! Native policy selectors, encrypted initial registration and transition protection.
use super::*;
use verysync_sidecar::{
    BlockPullOrder, CopyRangeMethod, CreateFolderOptions, ExtendedAttributeFilter,
    ExtendedAttributeRule, FolderAdvancedPatch, FolderId, FolderType, TargetPath,
};
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}

#[tokio::test]
async fn encrypted_initial_create_overrides_only_selected_defaults_without_a_template_write(
) -> TestResult {
    let defaults =
        serde_json::json!({"label":"","paused":false,"type":"sendreceive","privateFuture":KEY});
    let observed = serde_json::json!({"id":"encrypted-initial","label":"","path":"/synthetic","paused":true,
        "type":"receiveencrypted","privateFuture":KEY});
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!({"folders":[]})),
        Reply::json(defaults),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"folders":[observed]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let created = client
        .create_folder(
            &CreateFolderOptions::new(
                FolderId::parse("encrypted-initial")?,
                TargetPath::remote(verysync_sidecar::PathStyle::Unix, "/synthetic")?,
            )
            .paused(true)
            .advanced_configuration(
                FolderAdvancedPatch::default().folder_type(FolderType::ReceiveEncrypted),
            )?,
        )
        .await?;
    assert_eq!(
        created.advanced_configuration()?.folder_type,
        Some(FolderType::ReceiveEncrypted)
    );
    let requests = server.finish().await?;
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("POST ")).count(),
        1
    );
    assert!(!requests.iter().any(|r| r.starts_with("PATCH ")));
    let post = requests
        .iter()
        .find(|r| r.starts_with("POST "))
        .ok_or("create absent")?;
    let body: serde_json::Value =
        serde_json::from_str(post.split_once("\r\n\r\n").ok_or("body absent")?.1)?;
    assert_eq!(body["type"], "receiveencrypted");
    assert_eq!(body["privateFuture"], KEY);
    Ok(())
}

#[tokio::test]
async fn encrypted_existing_transition_is_refused_before_patch_in_both_directions() -> TestResult {
    for (current, desired) in [
        ("sendreceive", FolderType::ReceiveEncrypted),
        ("receiveencrypted", FolderType::SendReceive),
    ] {
        let server=ScriptedServer::start(vec![version(),identity(),identity(),
            Reply::json(serde_json::json!({"folders":[{"id":"synthetic","label":"","path":"/synthetic","paused":true,"type":current}]}))]).await?;
        let client = Client::connect(server.options()?).await?;
        assert!(matches!(
            client
                .update_folder_advanced_configuration(
                    &FolderId::parse("synthetic")?,
                    &FolderAdvancedPatch::default().folder_type(desired)
                )
                .await,
            Err(Error::InvalidConfiguration { .. })
        ));
        assert_eq!(server.finish().await?.len(), 4);
    }
    Ok(())
}

#[tokio::test]
async fn policy_unknown_values_and_invalid_filters_cannot_be_submitted() -> TestResult {
    let server = ScriptedServer::start(vec![version(), identity()]).await?;
    let client = Client::connect(server.options()?).await?;
    for patch in [
        FolderAdvancedPatch::default().folder_type(FolderType::Unknown(KEY.into())),
        FolderAdvancedPatch::default().block_pull_order(BlockPullOrder::Unknown(KEY.into())),
        FolderAdvancedPatch::default().copy_range_method(CopyRangeMethod::Unknown(KEY.into())),
    ] {
        assert!(matches!(
            client
                .update_folder_advanced_configuration(&FolderId::parse("synthetic")?, &patch)
                .await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    assert!(ExtendedAttributeRule::new("invalid\npattern", true).is_err());
    assert!(ExtendedAttributeFilter::new(vec![], u32::MAX, 4096).is_err());
    assert!(!format!("{:?}", ExtendedAttributeRule::new(KEY, true)?).contains(KEY));
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn malformed_filter_readback_after_write_remains_unknown_without_replay() -> TestResult {
    let folder = serde_json::json!({"id":"synthetic","label":"","path":"/synthetic","paused":true});
    let mut actual = folder.clone();
    actual["xattrFilter"] = serde_json::json!({"entries":[{"match":KEY,"permit":"invalid"}],"maxSingleEntrySize":2048,"maxTotalSize":4096});
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!({"folders":[folder]})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"folders":[actual]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let result = client
        .update_folder_advanced_configuration(
            &FolderId::parse("synthetic")?,
            &FolderAdvancedPatch::default().extended_attribute_filter(
                ExtendedAttributeFilter::new(
                    vec![ExtendedAttributeRule::new("*", true)?],
                    2048,
                    4096,
                )?,
            ),
        )
        .await;
    let error = result.unwrap_err();
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    assert!(!format!("{error:?} {error}").contains(KEY));
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
