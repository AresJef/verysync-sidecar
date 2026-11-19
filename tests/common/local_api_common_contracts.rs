//! Native Local-API shared handlers, with gated positive/negative contracts.
use super::*;
use verysync_sidecar::*;

fn options(server: &ScriptedServer) -> verysync_sidecar::Result<LocalApiConnectOptions> {
    LocalApiConnectOptions::new(ManagementEndpoint::http(&server.base)?)
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn initial() -> Vec<Reply> {
    vec![version(), identity(), identity()]
}

#[tokio::test]
async fn local_history_preserves_signed_native_timestamps_missing_fields_and_private_records(
) -> TestResult {
    let mut replies = initial();
    replies.push(Reply::json(serde_json::json!({"error":null,"total":9,"data":[{"idx":3,"modified":-1,"event_time":0,"action":"future-action","name":KEY,"device_name":KEY,"future":KEY}]})));
    let server = ScriptedServer::start(replies).await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    let filter = LocalApiHistoryFilter {
        name: Some("a &b".into()),
        folder: Some(FolderId::parse("selected")?),
        start: Some("2026-11-15T20:00:00+08:00".into()),
        end: Some("2026-11-16T20:00:00+08:00".into()),
        ..Default::default()
    };
    let page = client
        .folder_history(ListPage::new(2, 20)?, &filter)
        .await?;
    assert_eq!(page.total, 9);
    let record = &page.records.as_ref().ok_or("missing records")?[0];
    assert_eq!(record.modified, Some(-1));
    assert_eq!(record.event_time, Some(0));
    assert!(record.label.is_none());
    assert_eq!(record.action.as_deref(), Some("future-action"));
    assert_eq!(record.extra["future"], KEY);
    assert!(!format!("{filter:?} {page:?} {record:?}").contains(KEY));
    let requests = server.finish().await?;
    let target = requests[3]
        .lines()
        .next()
        .ok_or("missing request")?
        .split_whitespace()
        .nth(1)
        .ok_or("missing target")?;
    let url = url::Url::parse(&format!("http://synthetic{target}"))?;
    let query: std::collections::BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    let encoded: serde_json::Value = serde_json::from_str(&query["filters"])?;
    assert_eq!(query["page"], "2");
    assert_eq!(query["perpage"], "20");
    assert_eq!(encoded["name"], "a &b");
    assert_eq!(encoded["folder"], "selected");
    assert_eq!(encoded["start"], "2026-11-15T20:00:00+08:00");
    assert_eq!(url.path(), "/prefix/rest/localapi/folders/history");
    Ok(())
}

#[tokio::test]
async fn local_history_backend_errors_and_malformed_pages_are_not_empty_successes() -> TestResult {
    for (body, api) in [
        (serde_json::json!({"error":KEY,"total":0,"data":null}), true),
        (serde_json::json!({"error":{},"total":0,"data":null}), false),
        (serde_json::json!({"error":null,"data":null}), false),
        (serde_json::json!({"error":null,"total":0}), false),
    ] {
        let mut replies = initial();
        replies.push(Reply::json(body));
        let server = ScriptedServer::start(replies).await?;
        let client = LocalApiClient::connect(options(&server)?).await?;
        let error = client
            .folder_history(ListPage::new(1, 100)?, &LocalApiHistoryFilter::default())
            .await
            .unwrap_err();
        if api {
            assert!(matches!(error, Error::Api { .. }));
        } else {
            assert!(matches!(error, Error::InvalidResponse { .. }));
        }
        assert!(!format!("{error:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 4);
    }
    let mut replies = initial();
    replies.push(Reply::json(
        serde_json::json!({"error":null,"total":0,"data":null}),
    ));
    let server = ScriptedServer::start(replies).await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    assert!(client
        .folder_history(ListPage::new(1, 10)?, &LocalApiHistoryFilter::default())
        .await?
        .records
        .is_none());
    assert_eq!(server.finish().await?.len(), 4);
    Ok(())
}

#[tokio::test]
async fn local_history_invalid_filters_stop_before_any_query() -> TestResult {
    let server = ScriptedServer::start(vec![version(), identity()]).await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    for filter in [
        LocalApiHistoryFilter {
            start: Some("not-a-time".into()),
            ..Default::default()
        },
        LocalApiHistoryFilter {
            start: Some("2026-11-16T00:00:00Z".into()),
            end: Some("2026-11-15T00:00:00Z".into()),
            ..Default::default()
        },
        LocalApiHistoryFilter {
            name: Some("invalid\nfilter".into()),
            ..Default::default()
        },
    ] {
        assert!(matches!(
            client.folder_history(ListPage::new(1, 10)?, &filter).await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn local_secret_validation_reuses_typed_keys_preserves_native_error_objects_and_random_ids(
) -> TestResult {
    let key = ShareKey::new(KEY)?;
    let mut replies = initial();
    replies.push(Reply::json(serde_json::json!({"id":"123","validate":true,"error":"","perm":"ro","readWriteSecret":"","readOnlySecret":KEY})));
    replies.push(identity());
    replies.push(Reply::json(
        serde_json::json!({"validate":false,"error":{}}),
    ));
    let server = ScriptedServer::start(replies).await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    let share = client.validate_share_key(&key).await?;
    assert_eq!(share.permission(), &SharePermission::ReadOnly);
    assert_eq!(share.registration_id().as_str(), "123");
    assert!(share.read_write_key().is_none());
    let error = client.validate_share_key(&key).await.unwrap_err();
    match error {
        Error::ShareKeyRejected { response } => assert_eq!(
            serde_json::from_slice::<serde_json::Value>(response.body_bytes())?["error"],
            serde_json::json!({})
        ),
        _ => panic!("native invalid key classification changed"),
    }
    assert!(!format!("{share:?}").contains(KEY));
    let requests = server.finish().await?;
    assert!(requests[3].starts_with(
        "GET /prefix/rest/localapi/secret/check?key=synthetic-transport-key HTTP/1.1\r\n"
    ));
    Ok(())
}

#[tokio::test]
async fn local_generation_and_shared_licensed_reads_preserve_code3001_without_activation(
) -> TestResult {
    for mode in 0..5 {
        let mut replies = initial();
        replies.push(Reply::json(serde_json::json!({"code":3001,"error":KEY})));
        let server = ScriptedServer::start(replies).await?;
        let client = LocalApiClient::connect(options(&server)?).await?;
        let error = match mode {
            0 => client.generate_share().await.unwrap_err(),
            1 => client
                .validate_share_key(&ShareKey::new(KEY)?)
                .await
                .unwrap_err(),
            2 => client.folder_summaries().await.unwrap_err(),
            3 => client.connections().await.unwrap_err(),
            _ => client.folder_statistics().await.unwrap_err(),
        };
        assert!(matches!(error, Error::LicenseRequired { code: 3001, .. }));
        assert!(!format!("{error:?}").contains(KEY));
        let requests = server.finish().await?;
        assert_eq!(requests.len(), 4);
        assert!(requests
            .iter()
            .all(|r| !r.to_ascii_lowercase().contains("x-api-key:")));
    }
    Ok(())
}

#[tokio::test]
async fn local_hardware_nested_errors_are_private_failures_not_zero_inventories() -> TestResult {
    for body in [
        serde_json::json!({"cpu":{"error":KEY},"memory":{},"network":{}}),
        serde_json::json!({"cpu":1,"memory":{},"network":{}}),
    ] {
        let mut replies = initial();
        replies.push(Reply::json(body));
        let server = ScriptedServer::start(replies).await?;
        let client = LocalApiClient::connect(options(&server)?).await?;
        let error = client.hardware().await.unwrap_err();
        assert!(matches!(
            error,
            Error::Api { .. } | Error::InvalidResponse { .. }
        ));
        assert!(!format!("{error:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 4);
    }
    Ok(())
}

#[tokio::test]
async fn local_hardware_success_keeps_native_negative_unknown_values_and_private_extras(
) -> TestResult {
    let mut replies = initial();
    replies.push(Reply::json(serde_json::json!({"cpu":{"total_cores":1,"total_threads":2,"private":KEY},"memory":{"total_physical_bytes":-1,"total_usable_bytes":4096},"network":{"nics":null}})));
    let server = ScriptedServer::start(replies).await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    let snapshot = client.hardware().await?;
    assert_eq!(snapshot.cpu.total_threads, 2);
    assert_eq!(snapshot.memory.total_physical_bytes, -1);
    assert!(snapshot.network.nics.is_none());
    assert_eq!(snapshot.cpu.extra["private"], KEY);
    assert!(!format!("{snapshot:?}").contains(KEY));
    assert_eq!(server.finish().await?.len(), 4);
    Ok(())
}
