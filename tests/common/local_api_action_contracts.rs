//! Native action acknowledgements remain separate from actual core/FS effects.
use super::*;
use verysync_sidecar::*;
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn status() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}
fn options(server: &ScriptedServer) -> verysync_sidecar::Result<LocalApiConnectOptions> {
    LocalApiConnectOptions::new(ManagementEndpoint::http(&server.base)?)
}

#[tokio::test]
async fn local_lifecycle_checks_exact_markers_without_mime_or_process_exit_inference() -> TestResult
{
    for restart in [false, true] {
        for valid in [false, true] {
            let marker = if restart {
                "restarting"
            } else {
                "shutting down"
            };
            let body = if valid {
                serde_json::json!({"ok":marker,"future":KEY})
            } else {
                serde_json::json!({"ok":"unexpected","future":KEY})
            };
            let server =
                ScriptedServer::start(vec![version(), status(), status(), Reply::json(body)])
                    .await?;
            let client = LocalApiClient::connect(options(&server)?).await?;
            let result = if restart {
                client.request_restart().await
            } else {
                client.request_shutdown().await
            };
            if valid {
                let receipt = result?;
                assert_eq!(
                    receipt.action,
                    if restart {
                        LocalApiExitAction::Restart
                    } else {
                        LocalApiExitAction::Shutdown
                    }
                );
                assert!(!format!("{receipt:?}").contains(KEY));
            } else {
                assert!(matches!(result, Err(Error::MutationOutcomeUnknown { .. })));
            }
            let requests = server.finish().await?;
            assert!(requests[3].starts_with(if restart {
                "POST /prefix/rest/localapi/system/restart HTTP/1.1\r\n"
            } else {
                "POST /prefix/rest/localapi/system/shutdown HTTP/1.1\r\n"
            }));
            assert_eq!(requests.len(), 4);
            assert!(requests[3].ends_with("\r\n\r\n"));
        }
    }
    Ok(())
}

#[tokio::test]
async fn local_upgrade_distinguishes_native_empty_reply_from_restart_and_uncertainty() -> TestResult
{
    for mode in 0..3 {
        let reply = match mode {
            0 => Reply {
                status: 200,
                body: vec![],
                headers: String::new(),
                delay: Duration::ZERO,
            },
            1 => Reply::json(serde_json::json!({"ok":"restarting","future":KEY})),
            _ => Reply::json(serde_json::json!({"ok":"unknown","future":KEY})),
        };
        let server = ScriptedServer::start(vec![version(), status(), status(), reply]).await?;
        let client = LocalApiClient::connect(options(&server)?).await?;
        let result = client.request_server_selected_upgrade().await;
        if mode < 2 {
            let receipt = result?;
            assert_eq!(receipt.restart_acknowledged, mode == 1);
            assert!(!format!("{receipt:?}").contains(KEY));
        } else {
            assert!(matches!(result, Err(Error::MutationOutcomeUnknown { .. })));
        }
        let requests = server.finish().await?;
        assert!(requests[3].starts_with("POST /prefix/rest/localapi/system/upgrade HTTP/1.1\r\n"));
        assert_eq!(requests.len(), 4);
    }
    Ok(())
}

#[tokio::test]
async fn local_cleanup_preserves_native_error_and_never_fabricates_complete_removal() -> TestResult
{
    for valid in [false, true] {
        let body = serde_json::json!({"error":if valid{""}else{KEY},"future":KEY});
        let server = ScriptedServer::start(vec![
            version(),
            status(),
            status(),
            Reply::json(
                serde_json::json!([{"id":"selected","path":"/private/target","paused":false}]),
            ),
            status(),
            Reply::json(body),
        ])
        .await?;
        let client = LocalApiClient::connect(options(&server)?).await?;
        let result = client
            .request_folder_temporary_cleanup(&FolderId::parse("selected")?)
            .await;
        if valid {
            let receipt = result?;
            assert_eq!(receipt.folder.as_str(), "selected");
            assert_eq!(receipt.extra["future"], KEY);
            assert!(!format!("{receipt:?}").contains(KEY));
        } else {
            assert!(matches!(result, Err(Error::MutationOutcomeUnknown { .. })));
        }
        let requests = server.finish().await?;
        assert!(requests[5].starts_with(
            "GET /prefix/rest/localapi/tools/cleantempfiles?folder=selected HTTP/1.1\r\n"
        ));
        assert_eq!(requests.len(), 6);
    }
    Ok(())
}

#[tokio::test]
async fn local_changed_identity_prevents_lifecycle_action_before_post() -> TestResult {
    let other = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    let server = ScriptedServer::start(vec![
        version(),
        status(),
        Reply::json(serde_json::json!({"myID":other})),
    ])
    .await?;
    let client = LocalApiClient::connect(options(&server)?).await?;
    assert!(matches!(
        client.request_shutdown().await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert!(server.finish().await?.iter().all(|r| r.starts_with("GET ")));
    Ok(())
}
