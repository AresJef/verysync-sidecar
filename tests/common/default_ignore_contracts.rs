//! Default templates are independent from existing ignore files and parsing.
use super::*;
use verysync_sidecar::IgnorePatterns;

fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}
fn handshake() -> Vec<Reply> {
    vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        identity(),
    ]
}

#[tokio::test]
async fn default_ignore_replacement_preserves_unknowns_and_reports_actual_complete_readback(
) -> TestResult {
    for case in [
        "match",
        "changed",
        "malformed-before",
        "malformed-after",
        "empty",
    ] {
        let before = serde_json::json!({"lines":["old"],"futurePrivate":KEY});
        let lines = if case == "empty" {
            vec![]
        } else {
            vec!["// synthetic".into(), "*.tmp".into()]
        };
        let patterns = IgnorePatterns::new(lines.clone())?;
        let mut expected = before.clone();
        expected["lines"] = serde_json::json!(lines);
        let mut after = expected.clone();
        if case == "changed" {
            after["futurePrivate"] = "changed by another writer".into();
        }
        if case == "malformed-after" {
            after = serde_json::json!({"lines":true});
        }
        let mut replies = handshake();
        replies.push(identity());
        replies.push(Reply::json(if case == "malformed-before" {
            serde_json::json!({"lines":false})
        } else {
            before
        }));
        if case != "malformed-before" {
            replies.extend([
                Reply::json(serde_json::json!({})),
                identity(),
                Reply::json(after),
            ]);
        }
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let result = client.set_default_ignore_patterns(&patterns).await;
        match case {
            "malformed-before" => assert!(result.is_err()),
            "malformed-after" => {
                assert!(matches!(result, Err(Error::MutationOutcomeUnknown { .. })))
            }
            _ => {
                let receipt = result?;
                assert_eq!(receipt.requested_fields_match, case != "changed");
                assert_eq!(receipt.configuration.lines, lines);
                if case != "changed" {
                    assert_eq!(receipt.configuration.extra["futurePrivate"], KEY);
                }
                assert!(!format!("{receipt:?}").contains(KEY));
                assert!(!format!("{receipt:?}").contains("synthetic"));
            }
        }
        let requests = server.finish().await?;
        let writes: Vec<_> = requests.iter().filter(|r| r.starts_with("PUT ")).collect();
        assert_eq!(writes.len(), usize::from(case != "malformed-before"));
        if let Some(request) = writes.first() {
            assert!(request.starts_with("PUT /prefix/rest/config/defaults/ignores "));
            let body: serde_json::Value =
                serde_json::from_str(request.split_once("\r\n\r\n").ok_or("body absent")?.1)?;
            assert_eq!(body, expected);
        }
        assert!(!requests
            .iter()
            .any(|r| r.starts_with("PATCH ") || r.contains("/rest/db/ignores")));
    }
    Ok(())
}

#[tokio::test]
async fn default_ignore_write_denial_and_uncertain_error_are_not_retried() -> TestResult {
    for status in [403, 500] {
        let mut replies = handshake();
        replies.extend([
            identity(),
            Reply::json(serde_json::json!({"lines":[]})),
            Reply {
                status,
                body: KEY.as_bytes().to_vec(),
                headers: String::new(),
                delay: Duration::ZERO,
            },
        ]);
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let error = client
            .set_default_ignore_patterns(&IgnorePatterns::new(vec!["*.tmp".into()])?)
            .await
            .unwrap_err();
        if status == 403 {
            assert!(matches!(error, Error::AccessDenied { .. }));
        } else {
            assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
        }
        assert!(!format!("{error:?}").contains(KEY));
        assert_eq!(
            server
                .finish()
                .await?
                .iter()
                .filter(|r| r.starts_with("PUT "))
                .count(),
            1
        );
    }
    Ok(())
}

#[tokio::test]
async fn default_ignore_snapshot_edit_preserves_all_other_defaults_and_private_values() -> TestResult
{
    let mut original = complete_configuration_fixture();
    original["defaults"]["ignores"] = serde_json::json!({"lines":["old"],"privateFuture":KEY});
    let mut replies = handshake();
    replies.extend([identity(), Reply::json(original.clone())]);
    let server = ScriptedServer::start(replies).await?;
    let client = Client::connect(server.options()?).await?;
    let mut snapshot = client.configuration().await?;
    assert_eq!(snapshot.default_ignore_patterns()?.lines, vec!["old"]);
    snapshot.set_default_ignore_patterns(&IgnorePatterns::new(vec![])?)?;
    original["defaults"]["ignores"]["lines"] = serde_json::json!([]);
    assert!(snapshot.native_document() == &original);
    assert_eq!(
        snapshot.default_ignore_patterns()?.extra["privateFuture"],
        KEY
    );
    assert!(!format!("{:?}", snapshot.default_ignore_patterns()?).contains(KEY));
    assert_eq!(server.finish().await?.len(), 4);
    Ok(())
}
