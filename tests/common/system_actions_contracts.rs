//! A native restart acknowledgement never certifies process completion.
use super::*;

fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn identity(value: &str) -> Reply {
    Reply::json(serde_json::json!({"myID":value}))
}

#[tokio::test]
async fn native_restart_validates_its_receipt_without_relaunch_polling_or_retry() -> TestResult {
    for body in [
        serde_json::json!({"ok":"restarting","futurePrivate":KEY}),
        serde_json::json!({"ok":"private-other-result","futurePrivate":KEY}),
        serde_json::json!({"ok":false,"futurePrivate":KEY}),
        serde_json::json!({"futurePrivate":KEY}),
        serde_json::Value::Null,
    ] {
        let success = body.get("ok").and_then(serde_json::Value::as_str) == Some("restarting");
        let server = ScriptedServer::start(vec![
            version(),
            identity(ID),
            identity(ID),
            Reply::json(body),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let result = client.request_restart().await;
        if success {
            result?;
        } else {
            let error = result.unwrap_err();
            assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
            assert!(!format!("{error:?}").contains(KEY));
        }
        let requests = server.finish().await?;
        assert_eq!(requests.len(), 4);
        assert!(requests[3].starts_with("POST /prefix/rest/system/restart "));
        assert_eq!(
            requests.iter().filter(|r| r.starts_with("POST ")).count(),
            1
        );
    }
    Ok(())
}

#[tokio::test]
async fn native_restart_refuses_changed_identity_and_retains_uncertain_http_failure() -> TestResult
{
    for changed in [true, false] {
        let other = ID.replacen('A', "B", 1);
        let mut replies = vec![
            version(),
            identity(ID),
            identity(if changed { &other } else { ID }),
        ];
        if !changed {
            replies.push(Reply {
                status: 500,
                body: KEY.as_bytes().to_vec(),
                headers: String::new(),
                delay: Duration::ZERO,
            });
        }
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let error = client.request_restart().await.unwrap_err();
        assert!(if changed {
            matches!(error, Error::IdentityMismatch { .. })
        } else {
            matches!(error, Error::MutationOutcomeUnknown { .. })
        });
        assert!(!format!("{error:?}").contains(KEY));
        let requests = server.finish().await?;
        assert_eq!(
            requests.iter().filter(|r| r.starts_with("POST ")).count(),
            usize::from(!changed)
        );
    }
    Ok(())
}
