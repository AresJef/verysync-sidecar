//! Synthetic management trust, proxy and diagnostic privacy contracts.
use super::*;

#[tokio::test]
async fn gui_proxy_version_errors_omit_reflected_proxy_authentication() -> TestResult {
    use verysync_sidecar::{
        DeviceId, GuiCredentials, GuiLoginOptions, GuiSession, ManagementProxy, ManagementTransport,
    };
    let server=ScriptedServer::start(vec![
        Reply {headers:"Set-Cookie: CSRF-Token-AAAAAAA=private-csrf; Path=/prefix/\r\n".into(),..Reply::json(serde_json::json!({}))},
        Reply {status:204,body:vec![],headers:"Set-Cookie: sessionid-AAAAAAA=private-session; Path=/prefix/\r\n".into(),delay:Duration::ZERO},
        Reply::json(serde_json::json!({"version":"reflected-private-proxy-user-private-proxy-password-encoded-proxy-credential","os":"linux","arch":"amd64"})),
    ]).await?;
    let mut proxy = url::Url::parse(&server.base)?;
    proxy.set_path("/");
    let transport = ManagementTransport::default().proxy(
        ManagementProxy::new(proxy.as_str())?
            .basic_auth("private-proxy-user", "private-proxy-password")?,
    );
    let failure = GuiSession::login(
        GuiLoginOptions::new(
            ManagementEndpoint::http(&server.base)?,
            GuiCredentials::new("private-gui-user", "private-gui-password")?,
        )
        .expected_device_id(DeviceId::parse(ID)?)
        .transport(transport),
    )
    .await
    .err()
    .ok_or("GUI version refusal expected")?;
    assert!(matches!(failure, Error::IncompatibleVersion { .. }));
    let text = format!("{failure:?} {failure}");
    for value in [
        "private-proxy-user",
        "private-proxy-password",
        "encoded-proxy-credential",
    ] {
        assert!(!text.contains(value));
    }
    assert_eq!(server.finish().await?.len(), 3);
    Ok(())
}

#[cfg(not(feature = "tls"))]
#[test]
fn no_tls_build_refuses_https_proxies_and_nonempty_trusted_certificate_input() {
    use verysync_sidecar::{ManagementProxy, ManagementTransport};
    assert!(matches!(
        ManagementProxy::new("https://localhost:42391/"),
        Err(Error::UnsupportedTransport { .. })
    ));
    assert!(matches!(
        ManagementTransport::default().trusted_certificates_pem(b"nonempty certificate input"),
        Err(Error::UnsupportedTransport { .. })
    ));
    assert!(matches!(
        ManagementTransport::default().trusted_certificate_der(b"nonempty certificate input"),
        Err(Error::UnsupportedTransport { .. })
    ));
}

#[tokio::test]
async fn credentialed_proxy_reflection_is_omitted_from_version_errors_and_client_debug(
) -> TestResult {
    use verysync_sidecar::{ManagementProxy, ManagementTransport};
    let reflected = "private-proxy-user private-proxy-password encoded-authorization-reflection";
    for allow_unverified in [false, true] {
        let mut replies = vec![Reply::json(
            serde_json::json!({"version":reflected,"os":"linux","arch":"amd64"}),
        )];
        if allow_unverified {
            replies.push(Reply::json(serde_json::json!({"myID":ID})));
        }
        let server = ScriptedServer::start(replies).await?;
        let mut proxy = url::Url::parse(&server.base)?;
        proxy.set_path("/");
        let transport = ManagementTransport::default().proxy(
            ManagementProxy::new(proxy.as_str())?
                .basic_auth("private-proxy-user", "private-proxy-password")?,
        );
        let mut options = server.options()?.transport(transport);
        if allow_unverified {
            options = options.version_policy(VersionPolicy::AllowUnverified);
        }
        let result = Client::connect(options).await;
        let diagnostic = if allow_unverified {
            let client = result?;
            assert_eq!(client.instance().version.version, reflected);
            format!("{client:?}")
        } else {
            let failure = result.err().ok_or("version refusal expected")?;
            assert!(matches!(failure, Error::IncompatibleVersion { .. }));
            format!("{failure:?} {failure}")
        };
        for value in [
            "private-proxy-user",
            "private-proxy-password",
            "encoded-authorization-reflection",
        ] {
            assert!(!diagnostic.contains(value));
        }
        server.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn explicit_management_proxy_is_used_and_retained_by_key_reconnection() -> TestResult {
    use verysync_sidecar::{DeviceId, ManagementProxy, ManagementTransport};
    let version =
        || Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}));
    let identity = || Reply::json(serde_json::json!({"myID":ID}));
    let server = ScriptedServer::start(vec![version(), identity(), version(), identity()]).await?;
    let mut proxy_url = url::Url::parse(&server.base)?;
    proxy_url.set_path("/");
    let proxy =
        ManagementProxy::new(proxy_url.as_str())?.basic_auth("synthetic-proxy-user", KEY)?;
    let transport = ManagementTransport::default().proxy(proxy);
    assert!(!format!("{transport:?}").contains(KEY));
    let client = Client::connect(
        ConnectOptions::new(
            ManagementEndpoint::http("http://explicit-only.example.invalid:37291/prefix/")?,
            ApiKey::new(KEY)?,
        )
        .expected_device_id(DeviceId::parse(ID)?)
        .transport(transport),
    )
    .await?;
    let reconnected = client.reconnect_with_api_key(ApiKey::new(KEY)?).await?;
    assert_eq!(reconnected.instance().device_id.as_str(), ID);
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 4);
    assert!(requests.iter().all(
        |r| r.starts_with("GET http://explicit-only.example.invalid:37291/prefix/rest/system/")
    ));
    assert!(requests.iter().all(|r| r
        .to_ascii_lowercase()
        .contains("proxy-authorization: basic ")));
    Ok(())
}

#[test]
fn management_proxy_inputs_and_debug_do_not_expose_credentials_or_accept_ignored_paths(
) -> TestResult {
    use verysync_sidecar::ManagementProxy;
    for url in [
        "socks5://localhost:1",
        "http://user:secret@localhost:1/",
        "http://localhost:1/a",
        "http://localhost:0/",
        "http://localhost:1/?q=private",
        "http://localhost:1/#private",
    ] {
        let error = ManagementProxy::new(url)
            .err()
            .ok_or("invalid proxy accepted")?;
        assert!(!format!("{error:?}").contains("secret"));
    }
    let proxy = ManagementProxy::new("http://localhost:42391/")?.basic_auth("private-user", KEY)?;
    let debug = format!("{proxy:?}");
    assert!(!debug.contains(KEY) && !debug.contains("private-user") && !debug.contains("42391"));
    assert!(ManagementProxy::new("http://localhost:42391/")?
        .basic_auth("user:invalid", "secret")
        .is_err());
    Ok(())
}

#[tokio::test]
async fn management_proxy_is_rejected_for_unix_transport_before_any_request() -> TestResult {
    use verysync_sidecar::{ManagementProxy, ManagementTransport};
    let options = ConnectOptions::new(
        ManagementEndpoint::unix_socket(std::env::temp_dir().join("unopened-management.sock"))?,
        ApiKey::new(KEY)?,
    )
    .transport(
        ManagementTransport::default().proxy(ManagementProxy::new("http://127.0.0.1:42391/")?),
    );
    assert!(matches!(
        Client::connect(options).await,
        Err(Error::InvalidConfiguration { .. })
    ));
    Ok(())
}

#[test]
fn explicit_management_roots_reject_empty_or_non_certificate_bundles() {
    use verysync_sidecar::ManagementTransport;
    for bytes in [
        b"".as_slice(),
        b"not a PEM certificate",
        b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
    ] {
        assert!(ManagementTransport::default()
            .trusted_certificates_pem(bytes)
            .is_err());
    }
}
