//! Synthetic query contracts, independent of native acceptance.
use super::*;

fn handshake() -> Vec<Reply> {
    vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"windows","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
    ]
}

#[tokio::test]
async fn narrow_queries_preserve_native_markers_unknowns_and_target_paths() -> TestResult {
    let mut replies = handshake();
    replies.extend([
        Reply::json(serde_json::json!({"ping":"pong","futureSecret":KEY})),
        Reply::json(serde_json::json!({"ping":KEY})),
        Reply::json(serde_json::json!([{"id":"opaque/β","label":"synthetic label","path":r"C:\Synthetic β","paused":true,"futureSecret":KEY}])),
        Reply::json(serde_json::json!([])),
    ]);
    let server = ScriptedServer::start(replies).await?;
    let client = Client::connect(server.options()?).await?;
    let pong = client.ping().await?;
    assert!(pong.is_pong());
    assert_eq!(pong.extra["futureSecret"], KEY);
    assert!(!format!("{pong:?}").contains(KEY));
    let unknown = client.ping().await?;
    assert!(!unknown.is_pong());
    assert_eq!(unknown.reply, KEY);
    assert!(!format!("{unknown:?}").contains(KEY));
    let folders = client.folder_configurations().await?;
    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0].id.as_str(), "opaque/β");
    assert_eq!(
        folders[0].path.style(),
        verysync_sidecar::PathStyle::Windows
    );
    assert!(folders[0].path.local_path().is_none());
    assert_eq!(folders[0].path.to_protocol()?, r"C:\Synthetic β");
    assert_eq!(folders[0].extra["futureSecret"], KEY);
    assert!(!format!("{:?}", folders[0]).contains(KEY));
    assert!(client.folder_configurations().await?.is_empty());
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 6);
    assert!(requests[2..4]
        .iter()
        .all(|r| r.starts_with("GET /prefix/rest/system/ping ")));
    assert!(requests[4..]
        .iter()
        .all(|r| r.starts_with("GET /prefix/rest/config/folders ")));
    assert!(requests.iter().all(|r| r
        .to_ascii_lowercase()
        .contains(&format!("x-api-key: {KEY}"))));
    Ok(())
}

#[tokio::test]
async fn malformed_narrow_queries_fail_once_without_inventing_empty_success() -> TestResult {
    for (ping, body) in [
        (true, serde_json::json!({})),
        (true, serde_json::json!({"ping":null})),
        (true, serde_json::json!({"ping":0})),
        (false, serde_json::json!({"folders":[]})),
        (false, serde_json::json!([{"id":"missing-fields"}])),
    ] {
        let mut replies = handshake();
        replies.push(Reply::json(body));
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let result = if ping {
            client.ping().await.map(|_| ())
        } else {
            client.folder_configurations().await.map(|_| ())
        };
        assert!(matches!(result, Err(Error::InvalidResponse { .. })));
        assert_eq!(server.finish().await?.len(), 3);
    }
    Ok(())
}
