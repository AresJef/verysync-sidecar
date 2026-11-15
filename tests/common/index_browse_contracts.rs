//! Native indexed browsing, separate from selective metadata and resource files.
use super::*;
use verysync_sidecar::{FolderId, IndexBrowseOptions, PathStyle, SyncFileKind, TargetPath};
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
#[tokio::test]
async fn indexed_browse_preserves_recursive_native_metadata_unknowns_and_exact_queries(
) -> TestResult {
    let body = serde_json::json!([
      {"name":KEY,"modTime":KEY,"size":0,"type":"FILE_INFO_TYPE_DIRECTORY","future":KEY,"children":[{"name":KEY,"modTime":KEY,"size":30,"type":"FILE_INFO_TYPE_FILE"}]},
      {"name":KEY,"modTime":KEY,"size":7,"type":KEY}]);
    let mut replies = vec![version(), identity()];
    for response in [body, serde_json::json!([]), serde_json::json!([])] {
        replies.extend([identity(), folders(), Reply::json(response)]);
    }
    let server = ScriptedServer::start(replies).await?;
    let client = Client::connect(server.options()?).await?;
    let folder = FolderId::parse("indexed ?%")?;
    let tree: verysync_sidecar::IndexTree = client
        .browse_index(&folder, &IndexBrowseOptions::default())
        .await?;
    assert_eq!(tree.entries.len(), 2);
    let node = &tree.entries[0];
    assert_eq!(node.name, KEY);
    assert_eq!(node.modified, KEY);
    assert_eq!(node.size, 0);
    assert_eq!(node.kind, SyncFileKind::Directory);
    assert_eq!(node.extra["future"], KEY);
    let children = node.children.as_ref().ok_or("native children missing")?;
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].kind, SyncFileKind::File);
    assert_eq!(children[0].size, 30);
    assert!(children[0].children.is_none());
    assert!(matches!(&tree.entries[1].kind,SyncFileKind::Unknown(value) if value==KEY));
    assert!(!format!("{tree:?} {node:?} {children:?} {:?}", tree.entries[1].kind).contains(KEY));
    let prefix = TargetPath::remote(PathStyle::Unix, "branch/\u{4e8c} + %2F ?")?;
    let options = IndexBrowseOptions::default()
        .prefix(prefix.clone())
        .levels(None)
        .directories_only(true);
    assert!(client
        .browse_index(&folder, &options)
        .await?
        .entries
        .is_empty());
    assert!(client
        .browse_index(
            &folder,
            &IndexBrowseOptions::default()
                .levels(Some(u16::MAX))
                .directories_only(false)
        )
        .await?
        .entries
        .is_empty());
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 11);
    let urls: Vec<_> = [4usize, 7, 10]
        .into_iter()
        .map(|i| {
            url::Url::parse(&format!(
                "http://synthetic.invalid{}",
                requests[i].split_whitespace().nth(1).unwrap()
            ))
            .unwrap()
        })
        .collect();
    for uri in &urls {
        assert_eq!(uri.path(), "/prefix/rest/db/browse");
        assert_eq!(
            uri.query_pairs().find(|(k, _)| k == "folder").unwrap().1,
            "indexed ?%"
        );
    }
    assert!(urls[0]
        .query_pairs()
        .any(|(k, v)| k == "levels" && v == "0"));
    assert!(!urls[0]
        .query_pairs()
        .any(|(k, _)| k == "dirsonly" || k == "prefix"));
    assert!(urls[1]
        .query_pairs()
        .any(|(k, v)| k == "prefix" && v == prefix.to_protocol().unwrap()));
    assert!(urls[1]
        .query_pairs()
        .any(|(k, v)| k == "dirsonly" && v == "true"));
    assert!(!urls[1].query_pairs().any(|(k, _)| k == "levels"));
    assert!(!urls[1].as_str().contains("%25252F"));
    assert!(urls[2]
        .query_pairs()
        .any(|(k, v)| k == "levels" && v == "65535"));
    assert!(!urls[2].query_pairs().any(|(k, _)| k == "dirsonly"));
    Ok(())
}
#[tokio::test]
async fn indexed_browse_validates_relative_target_paths_and_folder_before_native_browse(
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
        TargetPath::remote(PathStyle::Unix, ".")?,
        TargetPath::remote(PathStyle::Windows, "relative")?,
    ] {
        assert!(matches!(
            client
                .browse_index(&folder, &IndexBrowseOptions::default().prefix(path))
                .await,
            Err(Error::InvalidPath { .. })
        ));
    }
    assert!(matches!(
        client
            .browse_index(&folder, &IndexBrowseOptions::default())
            .await,
        Err(Error::FolderNotFound { .. })
    ));
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 4);
    assert!(!requests.iter().any(|r| r.contains("/rest/db/browse")));
    Ok(())
}
#[tokio::test]
async fn indexed_browse_keeps_native_errors_and_rejects_malformed_trees_without_retry() -> TestResult
{
    let invalid = [
        serde_json::Value::Null,
        serde_json::json!({}),
        serde_json::json!([{"name":KEY,"modTime":KEY,"size":0}]),
        serde_json::json!([{"name":KEY,"modTime":KEY,"size":-1,"type":"FILE_INFO_TYPE_FILE"}]),
        serde_json::json!([{"name":KEY,"modTime":KEY,"size":0,"type":"FILE_INFO_TYPE_DIRECTORY","children":KEY}]),
    ];
    for (body, kind) in invalid.into_iter().map(|v| (Reply::json(v), 0)).chain([
        (Reply::json(serde_json::json!({"error":KEY})), 1),
        (
            Reply {
                status: 503,
                ..Reply::json(serde_json::json!({"private":KEY}))
            },
            2,
        ),
    ]) {
        let server =
            ScriptedServer::start(vec![version(), identity(), identity(), folders(), body]).await?;
        let client = Client::connect(server.options()?).await?;
        let folder = FolderId::parse("indexed ?%")?;
        let error = client
            .browse_index(&folder, &IndexBrowseOptions::default())
            .await
            .expect_err("malformed index is not a successful empty tree");
        assert!(matches!(
            (&error, kind),
            (Error::InvalidResponse { .. }, 0) | (Error::Api { .. }, 1) | (Error::Http { .. }, 2)
        ));
        assert!(!format!("{error:?} {error}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 5);
    }
    Ok(())
}
