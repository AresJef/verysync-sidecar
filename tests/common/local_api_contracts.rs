//! Synthetic Local-API transport boundaries; native effects have separate tests.
use super::*;
use verysync_sidecar::{
    DeviceId, LocalApiClient, LocalApiConnectOptions, RawMethod, RawRequest, RequestEffect,
};

fn options(server: &ScriptedServer) -> verysync_sidecar::Result<LocalApiConnectOptions> {
    LocalApiConnectOptions::new(ManagementEndpoint::http(&server.base)?)
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID,"alloc":0,"privateExtension":KEY}))
}
fn local_version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn local_folders(paused: bool) -> Reply {
    Reply::json(
        serde_json::json!([{"id":"local-folder","path":"/private/target","paused":paused,"readWriteSecret":KEY,"peers":[]}]),
    )
}
fn no_ambient_auth(requests: &[String]) {
    for request in requests {
        let header = request
            .split_once("\r\n\r\n")
            .unwrap()
            .0
            .to_ascii_lowercase();
        for name in ["x-api-key:", "authorization:", "cookie:"] {
            assert!(!header.contains(name), "unexpected connection credential");
        }
    }
}

#[tokio::test]
async fn local_api_handshake_reads_status_without_gui_credentials_and_preserves_absence(
) -> TestResult {
    let server = ScriptedServer::start(vec![version("v2.33.2"), identity(), identity()]).await?;
    let client =
        LocalApiClient::connect(options(&server)?.expected_device_id(DeviceId::parse(ID)?)).await?;
    let status = client.system_status().await?;
    assert_eq!(status.memory_allocated_bytes, Some(0));
    assert_eq!(status.runtime_memory_bytes, None);
    assert_eq!(status.extra["privateExtension"], KEY);
    assert!(!format!("{client:?} {status:?}").contains(KEY));
    let requests = server.finish().await?;
    assert!(requests[0].starts_with("GET /prefix/rest/localapi/system/version HTTP/1.1\r\n"));
    assert!(requests[1].starts_with("GET /prefix/rest/localapi/system/status HTTP/1.1\r\n"));
    no_ambient_auth(&requests);
    Ok(())
}

#[tokio::test]
async fn local_api_disabled_response_is_not_license_denial_or_activation() -> TestResult {
    let mut disabled = Reply::json(serde_json::Value::Null);
    disabled.status = 404;
    let server = ScriptedServer::start(vec![disabled]).await?;
    let error = LocalApiClient::connect(options(&server)?)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Http { response } if response.status() == 404));
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 1);
    no_ambient_auth(&requests);
    Ok(())
}

#[tokio::test]
async fn local_api_raw_stays_under_prefix_encodes_components_and_preserves_native_status(
) -> TestResult {
    let mut native =
        Reply::json(serde_json::json!({"code":3001,"message":"Require Local-API License"}));
    native.status = 403;
    let server = ScriptedServer::start(vec![version("v2.33.2"), identity(), native]).await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    let response = client
        .raw(
            RawRequest::new(
                RawMethod::Get,
                ["folders", "a/b%20"],
                RequestEffect::ReadOnly,
            )?
            .query("path", "a &b"),
        )
        .await?;
    assert_eq!(response.status(), 403);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(response.body_bytes())?["code"],
        3001
    );
    let requests = server.finish().await?;
    assert!(requests[2]
        .starts_with("GET /prefix/rest/localapi/folders/a%2Fb%2520?path=a+%26b HTTP/1.1\r\n"));
    no_ambient_auth(&requests);
    Ok(())
}

#[tokio::test]
async fn local_api_changed_identity_prevents_raw_mutation() -> TestResult {
    let other = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    let server = ScriptedServer::start(vec![
        version("v2.33.2"),
        identity(),
        Reply::json(serde_json::json!({"myID":other})),
    ])
    .await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    assert!(matches!(
        client
            .raw(RawRequest::new(
                RawMethod::Post,
                ["system", "shutdown"],
                RequestEffect::MayModify
            )?)
            .await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert_eq!(server.finish().await?.len(), 3);
    Ok(())
}

#[tokio::test]
async fn local_api_version_and_expected_identity_policies_are_enforced() -> TestResult {
    let server = ScriptedServer::start(vec![version("v99.0.0")]).await?;
    assert!(matches!(
        LocalApiClient::connect(options(&server)?).await,
        Err(Error::IncompatibleVersion { .. })
    ));
    assert_eq!(server.finish().await?.len(), 1);
    let server = ScriptedServer::start(vec![version("v99.0.0"), identity()]).await?;
    let client =
        LocalApiClient::connect(options(&server)?.version_policy(VersionPolicy::AllowUnverified))
            .await?;
    assert_eq!(
        client.instance().compatibility,
        VersionCompatibility::Unverified
    );
    assert_eq!(server.finish().await?.len(), 2);
    let server = ScriptedServer::start(vec![version("v2.33.2"), identity()]).await?;
    let other = DeviceId::parse("BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB")?;
    assert!(matches!(
        LocalApiClient::connect(options(&server)?.expected_device_id(other)).await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn local_api_response_limit_and_timeout_do_not_retry() -> TestResult {
    let server = ScriptedServer::start(vec![Reply::json(
        serde_json::json!({"oversized":"x".repeat(4096)}),
    )])
    .await?;
    assert!(matches!(
        LocalApiClient::connect(options(&server)?.response_limit(128)?).await,
        Err(Error::ResponseTooLarge { .. })
    ));
    assert_eq!(server.finish().await?.len(), 1);
    let mut slow = version("v2.33.2");
    slow.delay = Duration::from_millis(250);
    let server = ScriptedServer::start(vec![slow]).await?;
    assert!(matches!(
        LocalApiClient::connect(options(&server)?.request_timeout(Duration::from_millis(50))?)
            .await,
        Err(Error::Timeout { .. })
    ));
    assert_eq!(server.finish().await?.len(), 1);
    Ok(())
}

#[test]
fn local_api_options_reject_unbounded_limits_and_unix_transport() -> TestResult {
    let endpoint = ManagementEndpoint::http("http://127.0.0.1:12345/")?;
    assert!(LocalApiConnectOptions::new(endpoint.clone())?
        .request_timeout(Duration::ZERO)
        .is_err());
    assert!(LocalApiConnectOptions::new(endpoint)?
        .response_limit(0)
        .is_err());
    #[cfg(unix)]
    assert!(
        LocalApiConnectOptions::new(ManagementEndpoint::unix_socket(std::path::Path::new(
            "/private/tmp/synthetic-local-api.sock"
        ))?)
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn local_api_typed_folder_projection_does_not_invent_a_gui_label_or_expose_secrets(
) -> TestResult {
    let server = ScriptedServer::start(vec![
        local_version(),
        identity(),
        identity(),
        local_folders(false),
    ])
    .await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    let folders = client.folders().await?;
    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0].path.to_protocol()?, "/private/target");
    assert!(folders[0].path.local_path().is_none());
    assert_eq!(folders[0].extra["readWriteSecret"], KEY);
    assert!(!format!("{:?}", folders[0]).contains(KEY));
    assert!(!folders[0].extra.contains_key("label"));
    no_ambient_auth(&server.finish().await?);
    Ok(())
}

#[tokio::test]
async fn local_api_typed_license_envelopes_are_distinct_from_raw_and_http_denials() -> TestResult {
    use verysync_sidecar::{FolderId, ListPage, SelectiveAction, SelectiveScope};
    for operation in 0..3 {
        let replies = vec![
            local_version(),
            identity(),
            identity(),
            local_folders(false),
            identity(),
            Reply::json(serde_json::json!({"code":3001,"error":KEY})),
        ];
        let server = ScriptedServer::start(replies).await?;
        let client = LocalApiClient::connect(options(&server)?).await?;
        let id = FolderId::parse("local-folder")?;
        let error = match operation {
            0 => client
                .browse_folder(&id, &SelectiveScope::FolderRoot)
                .await
                .unwrap_err(),
            1 => client
                .folder_need(&id, ListPage::new(2, 25)?)
                .await
                .unwrap_err(),
            _ => client
                .request_selection(
                    &id,
                    &SelectiveScope::FolderRoot,
                    SelectiveAction::RemoveFromAll,
                )
                .await
                .unwrap_err(),
        };
        assert!(matches!(error, Error::LicenseRequired { code: 3001, .. }));
        assert!(!format!("{error:?} {error}").contains(KEY));
        let requests = server.finish().await?;
        let last = requests.last().ok_or("missing native request")?;
        match operation {
            0=>assert!(last.starts_with("GET /prefix/rest/localapi/folders/browser/local-folder/ HTTP/1.1\r\n")),
            1=>assert!(last.starts_with("GET /prefix/rest/localapi/folders/need/local-folder?page=2&perpage=25 HTTP/1.1\r\n")),
            _=>assert!(last.starts_with("POST /prefix/rest/localapi/folders/selective/local-folder/?selected=false&removefromall=true HTTP/1.1\r\n")),
        }
        no_ambient_auth(&requests);
    }
    Ok(())
}

#[tokio::test]
async fn local_api_scan_uses_encoded_target_subpath_and_requires_native_scanning_marker(
) -> TestResult {
    use verysync_sidecar::{FolderId, PathStyle, SelectiveScope, TargetPath};
    for valid in [true, false] {
        let acknowledgement = if valid {
            serde_json::json!({"ok":"scanning"})
        } else {
            serde_json::json!({"ok":"unexpected"})
        };
        let server = ScriptedServer::start(vec![
            local_version(),
            identity(),
            identity(),
            local_folders(false),
            identity(),
            Reply::json(acknowledgement),
        ])
        .await?;
        let client = LocalApiClient::connect(options(&server)?).await?;
        let scope = SelectiveScope::Path(TargetPath::remote(PathStyle::Unix, "nested/a b%file")?);
        let result = client
            .request_scan(&FolderId::parse("local-folder")?, &scope)
            .await;
        if valid {
            assert_eq!(result?.response.status(), 200);
        } else {
            assert!(matches!(result, Err(Error::MutationOutcomeUnknown { .. })));
        }
        let requests = server.finish().await?;
        assert!(requests[5].starts_with("POST /prefix/rest/localapi/folders/scan/local-folder/nested%2Fa%20b%25file HTTP/1.1\r\n"));
        assert!(requests[5].ends_with("\r\n\r\n"));
        no_ambient_auth(&requests);
    }
    Ok(())
}

#[tokio::test]
async fn local_api_paused_or_invalid_scope_never_submits_a_scan() -> TestResult {
    use verysync_sidecar::{FolderId, PathStyle, SelectiveScope, TargetPath};
    let server = ScriptedServer::start(vec![
        local_version(),
        identity(),
        identity(),
        local_folders(true),
    ])
    .await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    let id = FolderId::parse("local-folder")?;
    assert!(matches!(
        client.request_scan(&id, &SelectiveScope::FolderRoot).await,
        Err(Error::ScanNotIdle)
    ));
    let invalid = SelectiveScope::Path(TargetPath::remote(PathStyle::Unix, "../outside")?);
    assert!(matches!(
        client.request_scan(&id, &invalid).await,
        Err(Error::InvalidPath { .. })
    ));
    assert_eq!(server.finish().await?.len(), 4);
    Ok(())
}

#[tokio::test]
async fn local_api_native_device_projection_is_typed_and_keeps_names_private() -> TestResult {
    let server = ScriptedServer::start(vec![
        local_version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!([{"deviceID":ID,"name":KEY}])),
    ])
    .await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    let devices = client.devices().await?;
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id.as_str(), ID);
    assert_eq!(devices[0].name, KEY);
    assert!(!format!("{devices:?}").contains(KEY));
    let requests = server.finish().await?;
    assert!(requests[3].starts_with("GET /prefix/rest/localapi/config/devices HTTP/1.1\r\n"));
    no_ambient_auth(&requests);
    Ok(())
}

#[tokio::test]
async fn local_api_plain_http_denial_and_future_envelopes_do_not_invent_entitlement_errors(
) -> TestResult {
    use verysync_sidecar::{FolderId, ListPage};
    for status in [200, 403] {
        let mut response = Reply::json(serde_json::json!({"code":3002,"error":KEY}));
        response.status = status;
        let server = ScriptedServer::start(vec![
            local_version(),
            identity(),
            identity(),
            local_folders(false),
            identity(),
            response,
        ])
        .await?;
        let client = LocalApiClient::connect(options(&server)?).await?;
        let error = client
            .folder_need(&FolderId::parse("local-folder")?, ListPage::new(1, 10)?)
            .await
            .unwrap_err();
        if status == 403 {
            assert!(matches!(error, Error::AccessDenied { .. }));
        } else {
            assert!(matches!(error, Error::Api { .. }));
        }
        assert!(!format!("{error:?} {error}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 6);
    }
    Ok(())
}
