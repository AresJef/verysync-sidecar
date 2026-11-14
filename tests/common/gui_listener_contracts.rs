//! Synthetic listener receipts and failure boundaries; separate from native effects.
use super::*;
fn gui() -> serde_json::Value {
    serde_json::json!({"enabled":true,"authMode":"static","user":"private-user","password":KEY,"apiKey":KEY,"address":"127.0.0.1:42391","useTLS":false,"unixSocketPermissions":"","futurePrivate":KEY})
}
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}
#[tokio::test]
async fn listener_write_preserves_scope_and_acknowledgement_does_not_invent_reconnect() -> TestResult
{
    use verysync_sidecar::{GuiListenAddress, GuiListenerPatch};
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(gui()),
        Reply::json(serde_json::json!({})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let update = client
        .update_gui_listener(
            &GuiListenerPatch::default()
                .address(GuiListenAddress::tcp("[::1]:42392")?)
                .use_tls(true),
        )
        .await?;
    assert_eq!(update.acknowledgement.status(), 200);
    assert!(!update.requested_fields_match(&update.previous_configuration));
    assert_eq!(update.previous_configuration.extra()["futurePrivate"], KEY);
    assert!(!format!("{update:?}").contains(KEY));
    assert!(update
        .previous_configuration
        .extra()
        .get("password")
        .is_none());
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 5);
    let writes: Vec<_> = requests
        .iter()
        .filter(|r| r.starts_with("PATCH "))
        .collect();
    assert_eq!(writes.len(), 1);
    assert!(writes[0].starts_with("PATCH /prefix/rest/config/gui "));
    let body: serde_json::Value =
        serde_json::from_str(writes[0].split("\r\n\r\n").nth(1).ok_or("missing body")?)?;
    assert_eq!(
        body,
        serde_json::json!({"address":"[::1]:42392","useTLS":true})
    );
    Ok(())
}
#[tokio::test]
async fn listener_failed_write_or_changed_identity_never_becomes_an_automatic_retry() -> TestResult
{
    use verysync_sidecar::GuiListenerPatch;
    for changed in [false, true] {
        let mut replies = vec![
            version(),
            identity(),
            Reply::json(
                serde_json::json!({"myID":if changed {ID.replacen('A',"B",1)} else {ID.into()}}),
            ),
        ];
        if !changed {
            replies.extend([
                Reply::json(gui()),
                Reply {
                    status: 200,
                    body: b"{\"error\":\"private rejected\"}".to_vec(),
                    headers: String::new(),
                    delay: Duration::ZERO,
                },
            ]);
        }
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let result = client
            .update_gui_listener(&GuiListenerPatch::default().enabled(false))
            .await;
        if changed {
            assert!(matches!(result, Err(Error::IdentityMismatch { .. })));
        } else {
            assert!(result.is_err());
        }
        assert_eq!(
            server
                .finish()
                .await?
                .iter()
                .filter(|r| r.starts_with("PATCH "))
                .count(),
            usize::from(!changed)
        );
    }
    Ok(())
}
#[tokio::test]
async fn listener_unknown_readbacks_stay_private_and_invalid_patches_do_not_send() -> TestResult {
    use verysync_sidecar::{GuiListenAddress, GuiListenerPatch, GuiSocketPermissions};
    let mut native = gui();
    native["address"] = format!("unknown-{KEY}").into();
    native["unixSocketPermissions"] = KEY.into();
    let server =
        ScriptedServer::start(vec![version(), identity(), identity(), Reply::json(native)]).await?;
    let client = Client::connect(server.options()?).await?;
    let config = client.gui_listener().await?;
    assert!(config.address.unknown_native().is_some());
    assert!(matches!(
        config.unix_socket_permissions,
        GuiSocketPermissions::Unknown(_)
    ));
    assert!(!format!("{config:?}").contains(KEY));
    for patch in [
        GuiListenerPatch::default(),
        GuiListenerPatch::default().address(config.address),
        GuiListenerPatch::default().unix_socket_permissions(GuiSocketPermissions::Mode(u16::MAX)),
    ] {
        assert!(client.update_gui_listener(&patch).await.is_err());
    }
    for invalid in [
        "http://host:123/",
        "user@host:123",
        "host:no-port",
        "host:65536",
        "host:123/path",
        "host\n:123",
    ] {
        assert!(GuiListenAddress::tcp(invalid).is_err());
    }
    assert!(GuiListenAddress::tcp(":0").is_ok());
    assert_eq!(server.finish().await?.len(), 4);
    Ok(())
}

#[tokio::test]
async fn listener_missing_or_malformed_required_fields_are_not_default_settings() -> TestResult {
    for field in ["useTLS", "address", "unixSocketPermissions"] {
        let mut body = gui();
        body.as_object_mut().unwrap().remove(field);
        let server =
            ScriptedServer::start(vec![version(), identity(), identity(), Reply::json(body)])
                .await?;
        let client = Client::connect(server.options()?).await?;
        assert!(matches!(
            client.gui_listener().await,
            Err(Error::InvalidConfiguration { .. })
        ));
        assert_eq!(server.finish().await?.len(), 4);
    }
    Ok(())
}

#[tokio::test]
async fn windows_listener_refuses_unix_socket_changes_without_sending_requests() -> TestResult {
    use verysync_sidecar::{
        GuiListenAddress, GuiListenerPatch, GuiSocketPermissions, PathStyle, TargetPath,
    };
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"windows","arch":"amd64"})),
        identity(),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let socket = GuiListenAddress::unix_socket(TargetPath::remote(
        PathStyle::Unix,
        "/synthetic/unused.sock",
    )?)?;
    for patch in [
        GuiListenerPatch::default().address(socket),
        GuiListenerPatch::default().unix_socket_permissions(GuiSocketPermissions::Mode(0o600)),
    ] {
        assert!(matches!(
            client.update_gui_listener(&patch).await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}
