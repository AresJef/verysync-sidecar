//! Synthetic directory-picker schema, identity and uncertain-write contracts.
use super::*;
use verysync_sidecar::{PathStyle, TargetPath};

fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}

#[tokio::test]
async fn directory_helpers_preserve_target_encoding_native_spelling_and_private_extra() -> TestResult
{
    let path = TargetPath::remote(PathStyle::Unix, "/synthetic & + ? # %2F/测试")?;
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!([{"path":"/target","title":KEY,"future":KEY}])),
        identity(),
        Reply::json(
            serde_json::json!({"status":"ok","data":[{"name":KEY,"folder":true,"future":KEY}]}),
        ),
        identity(),
        Reply::json(
            serde_json::json!({"error":"","success":KEY,"path":"/canonical-target","future":KEY}),
        ),
        identity(),
        Reply::json(serde_json::json!({"status":"ok","data":[]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let locations = client.target_directory_locations().await?;
    assert_eq!(locations[0].path.to_protocol()?, "/target");
    assert_eq!(locations[0].path.style(), PathStyle::Unix);
    assert!(locations[0].path.local_path().is_none());
    assert_eq!(locations[0].extra["future"], KEY);
    assert!(!format!("{locations:?}").contains(KEY));
    let entries = client.target_directories(&path).await?;
    assert_eq!(entries[0].name, KEY);
    assert_eq!(entries[0].extra["future"], KEY);
    assert!(!format!("{entries:?}").contains(KEY));
    let created = client.create_target_directory(&path).await?;
    assert_eq!(created.path.to_protocol()?, "/canonical-target");
    assert_eq!(created.native_message, KEY);
    assert_eq!(created.extra["future"], KEY);
    assert!(!format!("{created:?}").contains(KEY));
    let requests = server.finish().await?;
    assert!(requests[3].starts_with("GET /prefix/rest/system/storeages "));
    for index in [5, 9] {
        let target = requests[index]
            .split_whitespace()
            .nth(1)
            .ok_or("target absent")?;
        let url = url::Url::parse(&format!("http://synthetic.invalid{target}"))?;
        assert_eq!(url.path(), "/prefix/rest/system/getdir");
        assert_eq!(
            url.query_pairs().collect::<Vec<_>>(),
            vec![
                ("current".into(), path.to_protocol()?.into()),
                ("filter".into(), "d".into())
            ]
        );
    }
    assert!(requests[7].starts_with("POST /prefix/rest/system/adddir "));
    let body: serde_json::Value =
        serde_json::from_str(requests[7].split_once("\r\n\r\n").ok_or("body absent")?.1)?;
    assert_eq!(body, serde_json::json!({"path":path.to_protocol()?}));
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("POST ")).count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn directory_errors_never_become_empty_success_or_retry_after_uncertain_creation(
) -> TestResult {
    let path = TargetPath::remote(PathStyle::Unix, "/synthetic")?;
    for body in [
        serde_json::json!({"status":"error","faultDetails":KEY}),
        serde_json::json!({"status":"ok"}),
        serde_json::json!({"status":"ok","data":null}),
        serde_json::json!({"status":"unknown","data":[]}),
        serde_json::json!({"status":"ok","data":[{"name":KEY}]}),
    ] {
        let native_error = body["status"] == "error";
        let server =
            ScriptedServer::start(vec![version(), identity(), identity(), Reply::json(body)])
                .await?;
        let client = Client::connect(server.options()?).await?;
        let e = client.target_directories(&path).await.unwrap_err();
        assert!(if native_error {
            matches!(e, Error::Api { .. })
        } else {
            matches!(e, Error::InvalidResponse { .. })
        });
        assert!(!format!("{e:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 4);
    }
    for body in [
        serde_json::json!({"error":KEY,"success":"","path":"/synthetic"}),
        serde_json::json!({"error":"","success":"","path":"/synthetic"}),
        serde_json::json!({"error":"","success":"ok","path":""}),
        serde_json::json!({"success":"ok","path":"/synthetic"}),
    ] {
        let server =
            ScriptedServer::start(vec![version(), identity(), identity(), Reply::json(body)])
                .await?;
        let client = Client::connect(server.options()?).await?;
        let e = client.create_target_directory(&path).await.unwrap_err();
        assert!(matches!(e, Error::MutationOutcomeUnknown { .. }));
        assert!(!format!("{e:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 4);
    }
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!({"error":"","success":"ok","path":"/synthetic"})),
        identity(),
        Reply::json(serde_json::json!({"status":"error","faultDetails":KEY})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client.create_target_directory(&path).await,
        Err(Error::MutationOutcomeUnknown { .. })
    ));
    let requests = server.finish().await?;
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("POST ")).count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn directory_helpers_refuse_foreign_path_syntax_and_changed_identity_before_writes(
) -> TestResult {
    let other = ID.replacen('A', "B", 1);
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        Reply::json(serde_json::json!({"myID":other})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let wrong = TargetPath::remote(PathStyle::Windows, r"C:\synthetic")?;
    assert!(matches!(
        client.target_directories(&wrong).await,
        Err(Error::InvalidPath { .. })
    ));
    assert!(matches!(
        client.create_target_directory(&wrong).await,
        Err(Error::InvalidPath { .. })
    ));
    assert!(client
        .create_target_directory(&TargetPath::local(""))
        .await
        .is_err());
    let path = TargetPath::remote(PathStyle::Unix, "/synthetic")?;
    assert!(matches!(
        client.create_target_directory(&path).await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert_eq!(server.finish().await?.len(), 3);
    Ok(())
}

#[tokio::test]
async fn native_path_browse_preserves_target_paths_private_queries_and_empty_native_result(
) -> TestResult {
    use verysync_sidecar::TargetPathBrowseOptions;
    let prefix = TargetPath::remote(PathStyle::Unix, "/synthetic prefix/\u{4e8c} + %2F")?;
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!([format!("/target/{KEY}"), "/other"])),
        identity(),
        Reply::json(serde_json::json!([])),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let options = TargetPathBrowseOptions::default()
        .current(prefix.clone())
        .filesystem("basic");
    let paths = client.browse_target_paths(&options).await?;
    assert_eq!(paths.paths.len(), 2);
    assert_eq!(paths.paths[0].style(), PathStyle::Unix);
    assert!(paths.paths[0].local_path().is_none());
    assert_eq!(paths.paths[0].to_protocol()?, format!("/target/{KEY}"));
    assert!(!format!("{options:?} {paths:?}").contains(KEY));
    assert!(client
        .browse_target_paths(&TargetPathBrowseOptions::default())
        .await?
        .paths
        .is_empty());
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 6);
    let uri = url::Url::parse(&format!(
        "http://synthetic.invalid{}",
        requests[3].split_whitespace().nth(1).unwrap()
    ))?;
    assert_eq!(uri.path(), "/prefix/rest/system/browse");
    assert_eq!(
        uri.query_pairs().find(|(k, _)| k == "current").unwrap().1,
        prefix.to_protocol()?
    );
    assert!(uri
        .query_pairs()
        .any(|(k, v)| k == "filesystem" && v == "basic"));
    assert!(!uri.as_str().contains("%25252F"));
    assert!(requests[5].starts_with("GET /prefix/rest/system/browse HTTP"));
    Ok(())
}
#[tokio::test]
async fn native_path_browse_guards_style_and_backend_before_io_and_rejects_bad_results(
) -> TestResult {
    use verysync_sidecar::TargetPathBrowseOptions;
    let server = ScriptedServer::start(vec![version(), identity()]).await?;
    let client = Client::connect(server.options()?).await?;
    for backend in [String::new(), "bad\nselector".into(), "x".repeat(129)] {
        assert!(matches!(
            client
                .browse_target_paths(&TargetPathBrowseOptions::default().filesystem(backend))
                .await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    assert!(matches!(
        client
            .browse_target_paths(
                &TargetPathBrowseOptions::default()
                    .current(TargetPath::remote(PathStyle::Windows, "C:\\prefix")?)
            )
            .await,
        Err(Error::InvalidPath { .. })
    ));
    assert_eq!(server.finish().await?.len(), 2);
    for response in [
        serde_json::Value::Null,
        serde_json::json!({}),
        serde_json::json!([42]),
        serde_json::json!([""]),
        serde_json::json!([format!("/private/{KEY}\0")]),
    ] {
        let server = ScriptedServer::start(vec![
            version(),
            identity(),
            identity(),
            Reply::json(response),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let error = client
            .browse_target_paths(&TargetPathBrowseOptions::default())
            .await
            .expect_err("invalid native paths are not empty successes");
        assert!(
            matches!(error, Error::InvalidResponse { .. }),
            "native malformed path error: {error:?}"
        );
        assert!(!format!("{error:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 4);
    }
    for status in [200, 503] {
        let server = ScriptedServer::start(vec![
            version(),
            identity(),
            identity(),
            Reply {
                status,
                ..Reply::json(serde_json::json!({"error":KEY}))
            },
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let error = client
            .browse_target_paths(&TargetPathBrowseOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(
            (&error, status),
            (Error::Api { .. }, 200) | (Error::Http { .. }, 503)
        ));
        assert!(!format!("{error:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 4);
    }
    Ok(())
}
