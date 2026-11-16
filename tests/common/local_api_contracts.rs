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
