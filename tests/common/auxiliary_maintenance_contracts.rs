//! Native path semantics and state-changing cleanup receipts.
use super::*;
use verysync_sidecar::FolderId;
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}
fn paths() -> serde_json::Value {
    serde_json::json!({"baseDir-config":"/private/config","baseDir-data":"/private/data",
        "baseDir-userHome":"/private/home","config":"/private/config/setting.dat",
        "database":"/private/data/index-v2","logFile":"-","auditLog":"/private/audit-%{timestamp}.log",
        "future":KEY})
}
fn folders(id: &str) -> Reply {
    Reply::json(
        serde_json::json!({"folders":[{"id":id,"label":"","path":"/synthetic","paused":false}]}),
    )
}

#[tokio::test]
async fn native_paths_keep_target_locations_templates_and_output_markers_private() -> TestResult {
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(paths()),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let value = client.native_system_paths().await?;
    assert_eq!(
        value.configuration_directory.to_protocol()?,
        "/private/config"
    );
    assert_eq!(value.data_directory.to_protocol()?, "/private/data");
    assert_eq!(
        value.configuration_file.to_protocol()?,
        "/private/config/setting.dat"
    );
    assert!(value.configuration_file.local_path().is_none());
    assert_eq!(value.extra["logFile"], "-");
    assert_eq!(value.extra["auditLog"], "/private/audit-%{timestamp}.log");
    assert_eq!(value.extra["future"], KEY);
    assert!(!format!("{value:?}").contains(KEY));
    assert!(!format!("{value:?}").contains("/private"));
    assert!(server.finish().await?[3].starts_with("GET /prefix/rest/system/paths "));
    Ok(())
}

#[tokio::test]
async fn native_paths_refuse_missing_malformed_or_non_path_primary_locations() -> TestResult {
    for bad in [
        serde_json::json!({}),
        serde_json::json!([]),
        {
            let mut v = paths();
            v["baseDir-data"] = serde_json::json!("-");
            v
        },
        {
            let mut v = paths();
            v["config"] = serde_json::json!("/tmp/%{timestamp}");
            v
        },
        {
            let mut v = paths();
            v["future"] = serde_json::json!(false);
            v
        },
    ] {
        let server =
            ScriptedServer::start(vec![version(), identity(), identity(), Reply::json(bad)])
                .await?;
        let client = Client::connect(server.options()?).await?;
        assert!(matches!(
            client.native_system_paths().await,
            Err(Error::InvalidResponse { .. })
        ));
        assert_eq!(server.finish().await?.len(), 4);
    }
    Ok(())
}

#[tokio::test]
async fn temporary_cleanup_is_one_explicit_get_with_native_errors_kept_unknown() -> TestResult {
    let id = FolderId::parse("cleanup%+opaque")?;
    for (body, accepted) in [
        (serde_json::json!({"error":"","future":KEY}), true),
        (serde_json::json!({"error":KEY}), false),
        (serde_json::json!({}), false),
        (serde_json::json!({"error":null}), false),
    ] {
        let server = ScriptedServer::start(vec![
            version(),
            identity(),
            identity(),
            folders(id.as_str()),
            Reply::json(body),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let result = client.request_folder_temporary_cleanup(&id).await;
        if accepted {
            let receipt = result?;
            assert_eq!(receipt.folder, id);
            assert_eq!(receipt.extra["future"], KEY);
            assert!(!format!("{receipt:?}").contains(KEY));
        } else {
            let error = result.unwrap_err();
            assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
            assert!(!format!("{error:?}").contains(KEY));
        }
        let requests = server.finish().await?;
        assert_eq!(requests.len(), 5);
        let target = requests[4]
            .split_whitespace()
            .nth(1)
            .ok_or("target missing")?;
        let url = url::Url::parse(&format!("http://synthetic.invalid{target}"))?;
        assert_eq!(url.path(), "/prefix/rest/svc/folder/cleantempfiles");
        assert_eq!(
            url.query_pairs().collect::<Vec<_>>(),
            vec![("folder".into(), id.as_str().into())]
        );
    }
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!({"folders":[]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client.request_folder_temporary_cleanup(&id).await,
        Err(Error::FolderNotFound { .. })
    ));
    assert_eq!(server.finish().await?.len(), 4);
    Ok(())
}

#[tokio::test]
async fn changed_identity_stops_paths_and_temporary_cleanup_before_their_routes() -> TestResult {
    let other = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    for cleanup in [false, true] {
        let server = ScriptedServer::start(vec![
            version(),
            identity(),
            Reply::json(serde_json::json!({"myID":other})),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        if cleanup {
            assert!(matches!(
                client
                    .request_folder_temporary_cleanup(&FolderId::parse("selected")?)
                    .await,
                Err(Error::IdentityMismatch { .. })
            ));
        } else {
            assert!(matches!(
                client.native_system_paths().await,
                Err(Error::IdentityMismatch { .. })
            ));
        }
        assert_eq!(server.finish().await?.len(), 3);
    }
    Ok(())
}
