//! Complete section PUT is distinct from a partial PATCH or a full-root PUT.
use super::*;
use verysync_sidecar::{
    GeneralOptionsPatch, GuiListenAddress, GuiListenerPatch, GuiPreferencesPatch,
};

fn complete() -> serde_json::Value {
    let mut value = complete_configuration_fixture();
    value["gui"] = serde_json::json!({"enabled":true,"authMode":"static","user":"synthetic-user",
        "password":"synthetic-existing-hash","apiKey":KEY,"address":"127.0.0.1:8484","useTLS":false,
        "metricsWithoutAuth":false,"theme":"default","debugging":false,"insecureAdminAccess":false,
        "insecureSkipHostcheck":false,"insecureAllowFrameLoading":false,"sendBasicAuthPrompt":false,
        "sessionCookieDurationS":3600,"sessionCookiePath":"/","futurePrivate":KEY});
    value
}
fn handshake(os: &str) -> Vec<Reply> {
    vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":os,"arch":"amd64"})),
        identity(),
    ]
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}

#[tokio::test]
async fn options_put_preserves_complete_native_values_and_checks_only_its_stale_section(
) -> TestResult {
    for case in ["matching", "stale", "bad-readback"] {
        let original = complete();
        let mut fresh = original.clone();
        fresh["gui"]["theme"] = "independent-writer-theme".into();
        if case == "stale" {
            fresh["options"]["keepTemporariesH"] = 99.into();
        }
        let mut after = fresh.clone();
        after["options"]["keepTemporariesH"] = 25.into();
        let mut replies = handshake("windows");
        replies.extend([
            identity(),
            Reply::json(original.clone()),
            identity(),
            Reply::json(fresh),
        ]);
        if case != "stale" {
            replies.extend([
                Reply::json(serde_json::json!({})),
                identity(),
                Reply::json(if case == "bad-readback" {
                    serde_json::json!({})
                } else {
                    after.clone()
                }),
            ]);
        }
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let mut desired = client.configuration().await?;
        desired.set_general_options(&GeneralOptionsPatch::default().keep_temporaries_hours(25))?;
        let result = client.replace_options_configuration(&desired).await;
        match case {
            "matching" => {
                let receipt = result?;
                assert!(receipt.requested_fields_match);
                assert_eq!(receipt.configuration.keep_temporaries_hours, 25);
                assert_eq!(receipt.configuration.extra["futureSecret"], KEY);
                assert!(!format!("{receipt:?}").contains(KEY));
            }
            "stale" => assert!(matches!(result, Err(Error::ConfigurationChanged))),
            _ => assert!(matches!(result, Err(Error::MutationOutcomeUnknown { .. }))),
        }
        let requests = server.finish().await?;
        let writes: Vec<_> = requests.iter().filter(|r| r.starts_with("PUT ")).collect();
        assert_eq!(writes.len(), usize::from(case != "stale"));
        if let Some(write) = writes.first() {
            assert!(write.starts_with("PUT /prefix/rest/config/options "));
            let body: serde_json::Value =
                serde_json::from_str(write.split_once("\r\n\r\n").ok_or("PUT body absent")?.1)?;
            assert_eq!(body, after["options"]);
        }
    }
    Ok(())
}

#[tokio::test]
async fn complete_gui_put_can_migrate_listener_without_implicit_reconnect_or_root_save(
) -> TestResult {
    for stale in [false, true] {
        let original = complete();
        let mut fresh = original.clone();
        if stale {
            fresh["gui"]["theme"] = "other-writer-theme".into();
        }
        let mut replies = handshake("windows");
        replies.extend([
            identity(),
            Reply::json(original.clone()),
            identity(),
            Reply::json(fresh),
        ]);
        if !stale {
            replies.push(Reply::json(serde_json::json!({})));
        }
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let mut desired = client.configuration().await?;
        desired.set_gui_preferences(&GuiPreferencesPatch::default().theme("dark"))?;
        desired.set_gui_listener(
            &GuiListenerPatch::default().address(GuiListenAddress::tcp("127.0.0.1:9191")?),
        )?;
        let result = client.replace_gui_configuration(&desired).await;
        if stale {
            assert!(matches!(result, Err(Error::ConfigurationChanged)));
        } else {
            let receipt = result?;
            assert_eq!(receipt.acknowledgement.status(), 200);
            assert!(receipt.previous_configuration.password_is_set());
            assert!(!format!("{receipt:?}").contains(KEY));
        }
        let requests = server.finish().await?;
        assert_eq!(requests.len(), if stale { 6 } else { 7 });
        let writes: Vec<_> = requests.iter().filter(|r| r.starts_with("PUT ")).collect();
        assert_eq!(writes.len(), usize::from(!stale));
        if let Some(write) = writes.first() {
            assert!(write.starts_with("PUT /prefix/rest/config/gui "));
            let body: serde_json::Value =
                serde_json::from_str(write.split_once("\r\n\r\n").ok_or("GUI body absent")?.1)?;
            assert_eq!(body, desired.native_document()["gui"]);
            assert_eq!(body["password"], original["gui"]["password"]);
            assert_eq!(body["apiKey"], KEY);
        }
    }
    Ok(())
}

#[tokio::test]
async fn snapshot_target_path_style_is_checked_before_every_complete_save() -> TestResult {
    let mut replies = handshake("windows");
    replies.extend([identity(), Reply::json(complete())]);
    let first = ScriptedServer::start(replies).await?;
    let client = Client::connect(first.options()?).await?;
    let snapshot = client.configuration().await?;
    let second = ScriptedServer::start(handshake("linux")).await?;
    let foreign = Client::connect(second.options()?).await?;
    assert!(matches!(
        foreign.replace_configuration(&snapshot).await,
        Err(Error::InvalidPath { .. })
    ));
    assert!(matches!(
        foreign.replace_options_configuration(&snapshot).await,
        Err(Error::InvalidPath { .. })
    ));
    assert!(matches!(
        foreign.replace_gui_configuration(&snapshot).await,
        Err(Error::InvalidPath { .. })
    ));
    assert_eq!(second.finish().await?.len(), 2);
    first.finish().await?;
    Ok(())
}

#[tokio::test]
async fn complete_gui_put_retains_denial_or_unknown_body_without_replaying_write() -> TestResult {
    for delayed in [false, true] {
        let mut write = Reply::json(serde_json::json!({"private":KEY}));
        if delayed {
            write.delay = Duration::from_millis(150);
        } else {
            write.status = 403;
        }
        let mut replies = handshake("windows");
        replies.extend([
            identity(),
            Reply::json(complete()),
            identity(),
            Reply::json(complete()),
            write,
        ]);
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(
            server
                .options()?
                .request_timeout(Duration::from_millis(30))?,
        )
        .await?;
        let mut desired = client.configuration().await?;
        desired.set_gui_preferences(&GuiPreferencesPatch::default().theme("dark"))?;
        let result = client.replace_gui_configuration(&desired).await;
        if delayed {
            assert!(matches!(result, Err(Error::MutationOutcomeUnknown { .. })));
        } else {
            assert!(matches!(result, Err(Error::AccessDenied { .. })));
        }
        let requests = server.finish().await?;
        assert_eq!(requests.iter().filter(|r| r.starts_with("PUT ")).count(), 1);
        assert_eq!(requests.len(), 7);
    }
    Ok(())
}

#[tokio::test]
async fn complete_snapshot_edits_reject_invalid_secrets_modes_and_paths_without_changing_data(
) -> TestResult {
    use verysync_sidecar::{ApiKey, GuiAuthMode, GuiSocketPermissions, NetworkPatch};
    let mut replies = handshake("windows");
    replies.extend([identity(), Reply::json(complete())]);
    let server = ScriptedServer::start(replies).await?;
    let client = Client::connect(server.options()?).await?;
    let mut snapshot = client.configuration().await?;
    let before = snapshot.native_document().clone();
    assert!(matches!(
        snapshot.set_gui_api_key(&ApiKey::new("short")?),
        Err(Error::InvalidCredential { .. })
    ));
    assert!(matches!(
        snapshot.set_gui_auth_mode(&GuiAuthMode::Unknown(KEY.into())),
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        snapshot
            .set_gui_preferences(&GuiPreferencesPatch::default().session_cookie_path("relative")),
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        snapshot.set_gui_listener(
            &GuiListenerPatch::default().unix_socket_permissions(GuiSocketPermissions::Mode(0o600))
        ),
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        snapshot
            .set_network_configuration(&NetworkPatch::default().reconnection_interval_seconds(0)),
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(snapshot.native_document() == &before);
    assert_eq!(server.finish().await?.len(), 4);
    Ok(())
}

#[tokio::test]
async fn every_complete_replacement_refuses_another_identity_before_requests() -> TestResult {
    let mut replies = handshake("windows");
    replies.extend([identity(), Reply::json(complete())]);
    let first = ScriptedServer::start(replies).await?;
    let client = Client::connect(first.options()?).await?;
    let snapshot = client.configuration().await?;
    let mut second_replies = handshake("windows");
    second_replies[1] = Reply::json(serde_json::json!({"myID":ID.replacen('A',"B",1)}));
    let second = ScriptedServer::start(second_replies).await?;
    let other = Client::connect(second.options()?).await?;
    assert!(matches!(
        other.replace_configuration(&snapshot).await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert!(matches!(
        other.replace_options_configuration(&snapshot).await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert!(matches!(
        other.replace_gui_configuration(&snapshot).await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert_eq!(second.finish().await?.len(), 2);
    first.finish().await?;
    Ok(())
}
