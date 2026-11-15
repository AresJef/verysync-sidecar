//! Independent native per-file transfer progress snapshots.
use super::*;
use verysync_sidecar::FolderId;
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}
fn folders() -> Reply {
    Reply::json(
        serde_json::json!({"folders":[{"id":"download ?%","label":"fixture","path":"/synthetic","paused":false}]}),
    )
}
fn record() -> serde_json::Value {
    serde_json::json!({"total":32,"reused":0,"copiedFromOrigin":1,"copiedFromOriginShifted":2,"copiedFromElsewhere":3,"pulled":4,"pulling":22,"bytesDone":-1,"bytesTotal":i64::MAX,"future":KEY})
}
#[tokio::test]
async fn native_download_progress_preserves_private_records_signed_counters_and_empty_map(
) -> TestResult {
    let filename = format!("branch/{KEY}/\u{4e8c} + %2F");
    let mut body = serde_json::Map::new();
    body.insert(filename.clone(), record());
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        folders(),
        Reply::json(serde_json::Value::Object(body)),
        identity(),
        folders(),
        Reply::json(serde_json::json!({})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let folder = FolderId::parse("download ?%")?;
    let progress: verysync_sidecar::FolderDownloadProgress =
        client.folder_download_progress(&folder).await?;
    let file = &progress.files[&filename];
    assert_eq!(file.total_blocks, 32);
    assert_eq!(file.reused_blocks, 0);
    assert_eq!(file.copied_from_origin_blocks, 1);
    assert_eq!(file.copied_from_origin_shifted_blocks, 2);
    assert_eq!(file.copied_from_elsewhere_blocks, 3);
    assert_eq!(file.pulled_blocks, 4);
    assert_eq!(file.pulling_blocks, 22);
    assert_eq!(file.bytes_done, -1);
    assert_eq!(file.bytes_total, i64::MAX);
    assert_eq!(file.extra["future"], KEY);
    assert!(!format!("{progress:?} {file:?}").contains(KEY));
    assert!(client
        .folder_download_progress(&folder)
        .await?
        .files
        .is_empty());
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 8);
    for i in [4, 7] {
        assert!(requests[i].starts_with("GET "));
        let uri = url::Url::parse(&format!(
            "http://fixture.invalid{}",
            requests[i].split_whitespace().nth(1).unwrap()
        ))?;
        assert_eq!(uri.path(), "/prefix/rest/folder/downloadprogress");
        assert_eq!(
            uri.query_pairs().collect::<Vec<_>>(),
            vec![("folder".into(), "download ?%".into())]
        );
    }
    Ok(())
}
#[tokio::test]
async fn native_download_progress_rejects_incomplete_records_and_keeps_native_errors_without_retry(
) -> TestResult {
    let mut missing = record();
    missing.as_object_mut().unwrap().remove("pulled");
    let mut wrong = record();
    wrong["bytesDone"] = serde_json::json!(KEY);
    let mut overflow = record();
    overflow["total"] = serde_json::json!(u64::MAX);
    for (kind, reply) in [
        (0, Reply::json(serde_json::Value::Null)),
        (0, Reply::json(serde_json::json!([]))),
        (0, Reply::json(serde_json::json!({"file":null}))),
        (0, Reply::json(serde_json::json!({"file":missing}))),
        (0, Reply::json(serde_json::json!({"file":wrong}))),
        (0, Reply::json(serde_json::json!({"file":overflow}))),
        (
            1,
            Reply {
                status: 500,
                ..Reply::json(serde_json::json!({"private":KEY}))
            },
        ),
        (2, Reply::json(serde_json::json!({"error":KEY}))),
        (
            3,
            Reply {
                body: vec![0; 1024],
                ..Reply::json(serde_json::Value::Null)
            },
        ),
    ] {
        let server =
            ScriptedServer::start(vec![version(), identity(), identity(), folders(), reply])
                .await?;
        let client = Client::connect(server.options()?.response_limit(512)?).await?;
        let error = client
            .folder_download_progress(&FolderId::parse("download ?%")?)
            .await
            .expect_err("bad snapshot is never an empty map");
        assert!(!format!("{error:?}").contains(KEY));
        assert!(matches!(
            (kind, &error),
            (0, Error::InvalidResponse { .. })
                | (1, Error::Http { .. })
                | (2, Error::Api { .. })
                | (3, Error::ResponseTooLarge { limit: 512 })
        ));
        assert_eq!(server.finish().await?.len(), 5);
    }
    Ok(())
}
#[tokio::test]
async fn native_download_progress_requires_configured_folder_before_endpoint_read() -> TestResult {
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!({"folders":[]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client
            .folder_download_progress(&FolderId::parse("download ?%")?)
            .await,
        Err(Error::FolderNotFound { .. })
    ));
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 4);
    assert!(!requests.iter().any(|r| r.contains("/downloadprogress")));
    Ok(())
}
