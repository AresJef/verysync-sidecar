//! Guarded native Local-API configuration proxy contracts, not licensed effects.
use super::*;
use verysync_sidecar::*;
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}
fn folder(label: &str) -> serde_json::Value {
    serde_json::json!({"id":"new-folder","label":label,"path":"/private/new","paused":false,"privateNativeField":KEY})
}
fn projection(present: bool) -> Reply {
    Reply::json(if present {
        serde_json::json!([{"id":"new-folder","path":"/private/new","paused":false}])
    } else {
        serde_json::json!([])
    })
}
fn options(server: &ScriptedServer) -> verysync_sidecar::Result<LocalApiConnectOptions> {
    LocalApiConnectOptions::new(ManagementEndpoint::http(&server.base)?)
}
fn defaults() -> TestResult<FolderDefaults> {
    Ok(serde_json::from_value(
        serde_json::json!({"label":"template","paused":false,"rescanIntervalS":600,"fsWatcherEnabled":false,"privateNativeField":KEY}),
    )?)
}
async fn read_configuration(value: serde_json::Value) -> TestResult<FolderConfig> {
    let server =
        ScriptedServer::start(vec![version(), identity(), identity(), Reply::json(value)]).await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    let configuration = client
        .folder_configuration(&FolderId::parse("new-folder")?)
        .await?;
    assert_eq!(server.finish().await?.len(), 4);
    Ok(configuration)
}

#[tokio::test]
async fn local_api_create_serializes_clones_through_readback_and_preserves_explicit_template(
) -> TestResult {
    use std::{
        future::{poll_fn, Future},
        task::Poll,
    };
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (competitor_tx, competitor_rx) = tokio::sync::oneshot::channel();
    let server = ScriptedServer::with_controls(
        vec![
            version(),
            identity(),
            identity(),
            projection(false),
            identity(),
            Reply::json(serde_json::Value::Null),
            identity(),
            Reply::json(folder("selected")),
            identity(),
            projection(true),
        ],
        None,
        Some((6, ready_tx, competitor_rx)),
    )
    .await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    let selected = CreateFolderOptions::new(
        FolderId::parse("new-folder")?,
        TargetPath::remote(PathStyle::Unix, "/private/new")?,
    )
    .label("selected");
    let template = defaults()?;
    let first_client = client.clone();
    let first_options = selected.clone();
    let first_template = template.clone();
    let first = tokio::spawn(async move {
        first_client
            .create_folder(&first_template, &first_options)
            .await
    });
    ready_rx.await?;
    let mut second = std::pin::pin!(client.create_folder(&template, &selected));
    let pending =
        poll_fn(|cx| Poll::Ready(matches!(second.as_mut().poll(cx), Poll::Pending))).await;
    assert!(pending);
    competitor_tx.send(()).map_err(|_| "missing body gate")?;
    assert_eq!(first.await??.label, "selected");
    assert!(matches!(
        second.await,
        Err(Error::FolderAlreadyExists { .. })
    ));
    let requests = server.finish().await?;
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("POST ")).count(),
        1
    );
    let post = &requests[5];
    assert!(post.starts_with("POST /prefix/rest/localapi/config/folders HTTP/1.1\r\n"));
    let body: serde_json::Value =
        serde_json::from_str(post.split_once("\r\n\r\n").ok_or("body missing")?.1)?;
    assert_eq!(body["label"], "selected");
    assert_eq!(body["path"], "/private/new");
    assert_eq!(body["id"], "new-folder");
    assert_eq!(body["privateNativeField"], KEY);
    assert_eq!(body["rescanIntervalS"], 600);
    assert!(requests
        .iter()
        .all(|r| !r.to_ascii_lowercase().contains("x-api-key:")));
    Ok(())
}

#[tokio::test]
async fn local_api_patch_is_scoped_and_failed_readback_stays_unknown_without_retry() -> TestResult {
    for valid in [true, false] {
        let readback = if valid {
            folder("changed")
        } else {
            serde_json::json!({"id":"new-folder"})
        };
        let server = ScriptedServer::start(vec![
            version(),
            identity(),
            identity(),
            Reply::json(folder("before")),
            identity(),
            Reply::json(serde_json::Value::Null),
            identity(),
            Reply::json(readback),
        ])
        .await?;
        let client = LocalApiClient::connect(options(&server)?).await?;
        let result = client
            .update_folder(
                &FolderId::parse("new-folder")?,
                &FolderPatch::default().label("changed"),
            )
            .await;
        if valid {
            assert!(result?.requested_fields_match);
        } else {
            assert!(matches!(result, Err(Error::MutationOutcomeUnknown { .. })));
        }
        let requests = server.finish().await?;
        let patch = &requests[5];
        assert!(
            patch.starts_with("PATCH /prefix/rest/localapi/config/folders/new-folder HTTP/1.1\r\n")
        );
        let body: serde_json::Value =
            serde_json::from_str(patch.split_once("\r\n\r\n").ok_or("body missing")?.1)?;
        assert_eq!(body, serde_json::json!({"label":"changed"}));
        assert_eq!(
            requests.iter().filter(|r| r.starts_with("PATCH ")).count(),
            1
        );
    }
    Ok(())
}

#[tokio::test]
async fn local_api_full_replacement_retains_private_fields_and_reports_native_mismatch(
) -> TestResult {
    let desired = read_configuration(folder("desired")).await?;
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(folder("before")),
        identity(),
        Reply::json(serde_json::Value::Null),
        identity(),
        Reply::json(folder("native-unchanged")),
    ])
    .await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    let result = client.replace_folder_configuration(&desired).await?;
    assert!(!result.requested_fields_match);
    assert_eq!(result.configuration.label, "native-unchanged");
    let requests = server.finish().await?;
    assert!(
        requests[5].starts_with("PUT /prefix/rest/localapi/config/folders/new-folder HTTP/1.1\r\n")
    );
    let body: serde_json::Value =
        serde_json::from_str(requests[5].split_once("\r\n\r\n").ok_or("body missing")?.1)?;
    assert_eq!(body, folder("desired"));
    assert!(!format!("{result:?}").contains(KEY));
    Ok(())
}

#[tokio::test]
async fn local_api_collection_replacement_is_explicit_and_duplicate_ids_fail_before_write(
) -> TestResult {
    let config = read_configuration(folder("selected")).await?;
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        projection(true),
        identity(),
        Reply::json(serde_json::Value::Null),
        identity(),
        projection(false),
    ])
    .await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    assert!(matches!(
        client
            .replace_folder_configurations(&[config.clone(), config])
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    let result = client.replace_folder_configurations(&[]).await?;
    assert!(
        result.configuration_ids_match
            && result.requested_fields_match
            && result.configurations.is_empty()
    );
    let requests = server.finish().await?;
    assert!(requests[5].starts_with("PUT /prefix/rest/localapi/config/folders HTTP/1.1\r\n"));
    assert_eq!(
        requests[5].split_once("\r\n\r\n").ok_or("body missing")?.1,
        "[]"
    );
    assert_eq!(requests.iter().filter(|r| r.starts_with("PUT ")).count(), 1);
    Ok(())
}

#[tokio::test]
async fn local_api_delete_has_no_file_flags_and_distinguishes_pending_configuration() -> TestResult
{
    for remains in [true, false] {
        let server = ScriptedServer::start(vec![
            version(),
            identity(),
            identity(),
            Reply::json(folder("before")),
            identity(),
            Reply::json(serde_json::Value::Null),
            identity(),
            projection(remains),
        ])
        .await?;
        let client = LocalApiClient::connect(options(&server)?).await?;
        let removal = client
            .remove_folder_keep_files(&FolderId::parse("new-folder")?)
            .await?;
        assert_eq!(removal.configuration_absent, !remains);
        assert_eq!(
            removal.previous_configuration.extra["privateNativeField"],
            KEY
        );
        let requests = server.finish().await?;
        assert!(requests[5]
            .starts_with("DELETE /prefix/rest/localapi/config/folders/new-folder HTTP/1.1\r\n"));
        assert!(requests[5].ends_with("\r\n\r\n"));
        assert_eq!(
            requests.iter().filter(|r| r.starts_with("DELETE ")).count(),
            1
        );
    }
    Ok(())
}

#[tokio::test]
async fn local_api_configuration_license_rejection_is_certain_and_never_writes() -> TestResult {
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!({"code":3001,"error":KEY})),
    ])
    .await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    let error = client
        .remove_folder_keep_files(&FolderId::parse("new-folder")?)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::LicenseRequired { code: 3001, .. }));
    assert!(!format!("{error:?}").contains(KEY));
    assert!(server.finish().await?.iter().all(|r| r.starts_with("GET ")));
    Ok(())
}

#[tokio::test]
async fn local_api_full_collection_sends_caller_order_and_preserves_observed_readback_order(
) -> TestResult {
    let first = read_configuration(folder("first")).await?;
    let mut second = read_configuration(folder("second")).await?;
    second.id = FolderId::parse("z-folder")?;
    second.path = TargetPath::remote(PathStyle::Unix, "/private/other")?;
    let second_body = serde_json::json!({"id":"z-folder","label":"second","path":"/private/other","paused":false,"privateNativeField":KEY});
    let observed = serde_json::json!([{"id":"new-folder","path":"/private/new","paused":false},{"id":"z-folder","path":"/private/other","paused":false}]);
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        projection(false),
        identity(),
        Reply::json(serde_json::Value::Null),
        identity(),
        Reply::json(observed),
        identity(),
        Reply::json(folder("first")),
        identity(),
        Reply::json(second_body),
    ])
    .await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    let result = client
        .replace_folder_configurations(&[second, first])
        .await?;
    assert!(result.configuration_ids_match && result.requested_fields_match);
    assert_eq!(
        result
            .configurations
            .iter()
            .map(|c| c.id.as_str())
            .collect::<Vec<_>>(),
        ["new-folder", "z-folder"]
    );
    let requests = server.finish().await?;
    let body: serde_json::Value =
        serde_json::from_str(requests[5].split_once("\r\n\r\n").ok_or("body missing")?.1)?;
    assert_eq!(body[0]["id"], "z-folder");
    assert_eq!(body[1]["id"], "new-folder");
    assert_eq!(body[0]["privateNativeField"], KEY);
    assert_eq!(requests.len(), 12);
    Ok(())
}
