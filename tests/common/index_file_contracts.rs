//! Native full index metadata; absent local records are not fabricated files.
use super::*;
use verysync_sidecar::{FolderId, PathStyle, SyncFileKind, TargetPath};
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}
fn folders() -> Reply {
    Reply::json(
        serde_json::json!({"folders":[{"id":"indexed ?%","label":"synthetic","path":"/synthetic","paused":false}]}),
    )
}
fn metadata() -> serde_json::Value {
    serde_json::json!({"name":KEY,"type":"FILE_INFO_TYPE_FILE","size":30,"modified":KEY,"modifiedBy":KEY,"deleted":false,"ignored":false,"invalid":false,"noPermissions":false,"permissions":KEY,"localFlags":0,"mustRescan":false,"numBlocks":1,"blocksHash":KEY,"previousBlocksHash":null,"sequence":7,"version":[KEY],"signature":{"Version":3,"Sign":KEY,"future":KEY},"platform":{"Unix":null,"future":KEY},"future":KEY})
}
fn info() -> serde_json::Value {
    serde_json::json!({"global":metadata(),"local":metadata(),"availability":null,"future":KEY})
}
#[tokio::test]
async fn indexed_file_keeps_global_local_native_zero_records_and_private_availability() -> TestResult
{
    let first = info();
    let mut second = info();
    second["local"]["name"] = serde_json::json!("");
    second["local"]["size"] = serde_json::json!(0);
    second["local"]["version"] = serde_json::json!([]);
    second["local"]["signature"] = serde_json::json!({"Version":0,"Sign":null});
    second["global"]["type"] = serde_json::json!(KEY);
    second["availability"] = serde_json::json!([{"id":ID,"fromTemporary":true,"future":KEY}]);
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        folders(),
        Reply::json(first),
        identity(),
        folders(),
        Reply::json(second),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let folder = FolderId::parse("indexed ?%")?;
    let path = TargetPath::remote(PathStyle::Unix, "branch/\u{4e8c} + %2F ?")?;
    let first: verysync_sidecar::IndexFileInfo = client.index_file_info(&folder, &path).await?;
    assert!(first.availability.is_none());
    assert_eq!(first.global.name, KEY);
    assert_eq!(first.global.kind, SyncFileKind::File);
    assert_eq!(first.global.modified, KEY);
    assert_eq!(first.global.modified_by, KEY);
    assert_eq!(first.global.permissions, KEY);
    assert_eq!(first.global.blocks_hash.as_deref(), Some(KEY));
    assert!(first.global.previous_blocks_hash.is_none());
    assert_eq!(first.global.sequence, 7);
    assert_eq!(first.global.version, vec![KEY]);
    assert_eq!(first.global.signature.version, 3);
    assert_eq!(
        first.global.signature.encoded_signature.as_deref(),
        Some(KEY)
    );
    assert_eq!(first.global.signature.extra["future"], KEY);
    assert_eq!(first.global.platform["future"], KEY);
    assert_eq!(first.global.extra["future"], KEY);
    assert_eq!(first.extra["future"], KEY);
    let second = client.index_file_info(&folder, &path).await?;
    assert!(second.local.name.is_empty());
    assert_eq!(second.local.size, 0);
    assert!(second.local.version.is_empty());
    assert_eq!(second.local.signature.version, 0);
    assert!(second.local.signature.encoded_signature.is_none());
    assert!(matches!(&second.global.kind,SyncFileKind::Unknown(value) if value==KEY));
    let available = second
        .availability
        .as_ref()
        .ok_or("native availability list missing")?;
    assert_eq!(available.len(), 1);
    assert_eq!(available[0].device_id.as_str(), ID);
    assert!(available[0].from_temporary);
    assert_eq!(available[0].extra["future"], KEY);
    let debug = format!(
        "{first:?} {second:?} {:?} {:?} {:?} {available:?}",
        first.global, first.local, first.global.signature
    );
    assert!(!debug.contains(KEY));
    assert!(!debug.contains(ID));
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 8);
    for i in [4, 7] {
        let uri = url::Url::parse(&format!(
            "http://synthetic.invalid{}",
            requests[i].split_whitespace().nth(1).unwrap()
        ))?;
        assert_eq!(uri.path(), "/prefix/rest/db/file");
        assert_eq!(
            uri.query_pairs().find(|(k, _)| k == "folder").unwrap().1,
            folder.as_str()
        );
        assert_eq!(
            uri.query_pairs().find(|(k, _)| k == "file").unwrap().1,
            path.to_protocol()?
        );
        assert!(!uri.as_str().contains("%25252F"));
    }
    Ok(())
}
#[tokio::test]
async fn indexed_file_refuses_wrong_target_paths_and_missing_folder_before_lookup() -> TestResult {
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!({"folders":[]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let folder = FolderId::parse("indexed ?%")?;
    for path in [
        TargetPath::remote(PathStyle::Unix, "../escape")?,
        TargetPath::remote(PathStyle::Unix, "/absolute")?,
        TargetPath::remote(PathStyle::Unix, ".")?,
        TargetPath::remote(PathStyle::Windows, "relative")?,
    ] {
        assert!(matches!(
            client.index_file_info(&folder, &path).await,
            Err(Error::InvalidPath { .. })
        ));
    }
    assert!(matches!(
        client
            .index_file_info(&folder, &TargetPath::remote(PathStyle::Unix, "file.bin")?)
            .await,
        Err(Error::FolderNotFound { .. })
    ));
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 4);
    assert!(!requests.iter().any(|v| v.contains("/rest/db/file")));
    Ok(())
}
#[tokio::test]
async fn indexed_file_rejects_incomplete_native_schema_and_keeps_not_found_without_retry(
) -> TestResult {
    let mut negative = info();
    negative["global"]["size"] = serde_json::json!(-1);
    let mut signature = info();
    signature["global"]["signature"]["Version"] = serde_json::json!(KEY);
    let mut identity_bad = info();
    identity_bad["availability"] = serde_json::json!([{"id":KEY,"fromTemporary":false}]);
    let mut platform = info();
    platform["local"]["platform"] = serde_json::json!([]);
    for (reply, kind) in [
        serde_json::Value::Null,
        serde_json::json!({}),
        negative,
        signature,
        identity_bad,
        platform,
    ]
    .into_iter()
    .map(|v| (Reply::json(v), 0))
    .chain([
        (Reply::json(serde_json::json!({"error":KEY})), 1),
        (
            Reply {
                status: 404,
                ..Reply::json(serde_json::json!({"private":KEY}))
            },
            2,
        ),
    ]) {
        let server =
            ScriptedServer::start(vec![version(), identity(), identity(), folders(), reply])
                .await?;
        let client = Client::connect(server.options()?).await?;
        let folder = FolderId::parse("indexed ?%")?;
        let error = client
            .index_file_info(&folder, &TargetPath::remote(PathStyle::Unix, "file.bin")?)
            .await
            .expect_err("missing metadata is not a successful empty file");
        assert!(
            matches!(
                (&error, kind),
                (Error::InvalidResponse { .. }, 0) | (Error::Api { .. }, 1)
            ) || matches!((&error,kind),(Error::Http { response },2) if response.status()==404)
        );
        assert!(!format!("{error:?} {error}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 5);
    }
    Ok(())
}

#[tokio::test]
async fn native_index_file_diagnostics_keeps_exact_metadata_and_two_native_zero_records(
) -> TestResult {
    let mut empty = info();
    for field in ["global", "local"] {
        empty[field]["name"] = serde_json::json!("");
        empty[field]["size"] = serde_json::json!(0);
        empty[field]["version"] = serde_json::json!([]);
        empty[field]["numBlocks"] = serde_json::json!(0);
        empty[field]["blocksHash"] = serde_json::Value::Null;
        empty[field]["signature"] = serde_json::json!({"Version":0,"Sign":null});
    }
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        folders(),
        Reply::json(info()),
        identity(),
        folders(),
        Reply::json(empty),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let folder = FolderId::parse("indexed ?%")?;
    let path = TargetPath::remote(PathStyle::Unix, "branch/\u{4e8c} + %2F ?")?;
    let actual: verysync_sidecar::IndexFileInfo =
        client.index_file_diagnostics(&folder, &path).await?;
    assert_eq!(actual.global.name, KEY);
    assert_eq!(actual.global.version, vec![KEY]);
    assert_eq!(
        actual.global.signature.encoded_signature.as_deref(),
        Some(KEY)
    );
    assert_eq!(actual.global.platform["future"], KEY);
    assert_eq!(actual.global.extra["future"], KEY);
    assert_eq!(actual.extra["future"], KEY);
    assert!(actual.availability.is_none());
    assert!(!format!("{actual:?} {:?}", actual.global).contains(KEY));
    let absent = client.index_file_diagnostics(&folder, &path).await?;
    for record in [&absent.global, &absent.local] {
        assert!(record.name.is_empty() && record.version.is_empty());
        assert_eq!(record.size, 0);
        assert_eq!(record.num_blocks, 0);
        assert_eq!(record.signature.version, 0);
        assert!(record.signature.encoded_signature.is_none());
    }
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 8);
    for index in [4, 7] {
        let uri = url::Url::parse(&format!(
            "http://synthetic.invalid{}",
            requests[index].split_whitespace().nth(1).unwrap()
        ))?;
        assert_eq!(uri.path(), "/prefix/rest/debug/file");
        let query = uri
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(query.len(), 2);
        assert_eq!(query.get("folder").unwrap(), folder.as_str());
        assert_eq!(query.get("file").unwrap(), path.to_protocol()?);
        assert!(!uri.as_str().contains("%25252F"));
    }
    Ok(())
}

#[tokio::test]
async fn native_index_file_diagnostics_refuses_bad_paths_and_preserves_schema_errors_without_retry(
) -> TestResult {
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!({"folders":[]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let folder = FolderId::parse("indexed ?%")?;
    for path in [
        TargetPath::remote(PathStyle::Unix, "../escape")?,
        TargetPath::remote(PathStyle::Unix, "/absolute")?,
        TargetPath::remote(PathStyle::Windows, "relative")?,
    ] {
        assert!(matches!(
            client.index_file_diagnostics(&folder, &path).await,
            Err(Error::InvalidPath { .. })
        ));
    }
    assert!(matches!(
        client
            .index_file_diagnostics(&folder, &TargetPath::remote(PathStyle::Unix, "missing")?)
            .await,
        Err(Error::FolderNotFound { .. })
    ));
    assert_eq!(server.finish().await?.len(), 4);
    for (reply, kind) in [
        (Reply::json(serde_json::Value::Null), 0),
        (Reply::json(serde_json::json!({})), 0),
        (Reply::json(serde_json::json!({"error":KEY})), 1),
        (
            Reply {
                status: 500,
                ..Reply::json(serde_json::json!({"private":KEY}))
            },
            2,
        ),
    ] {
        let server =
            ScriptedServer::start(vec![version(), identity(), identity(), folders(), reply])
                .await?;
        let client = Client::connect(server.options()?).await?;
        let error = client
            .index_file_diagnostics(&folder, &TargetPath::remote(PathStyle::Unix, "file.bin")?)
            .await
            .expect_err("missing records are not native zero records");
        assert!(
            matches!(
                (&error, kind),
                (Error::InvalidResponse { .. }, 0) | (Error::Api { .. }, 1)
            ) || matches!((&error,kind),(Error::Http{response},2)if response.status()==500)
        );
        assert!(!format!("{error:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 5);
    }
    Ok(())
}
