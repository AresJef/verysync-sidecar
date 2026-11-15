//! Native helper schemas, redaction and explicit request effects.
use super::*;
use std::net::IpAddr;
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}

#[tokio::test]
async fn native_core_log_text_preserves_exact_utf8_empty_snapshots_and_timestamp_queries(
) -> TestResult {
    let text = format!("native private text 二 %\r\n{KEY}\n");
    let plain = |body: Vec<u8>| Reply {
        body,
        ..Reply::json(serde_json::Value::Null)
    };
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        plain(text.as_bytes().to_vec()),
        identity(),
        plain(text.as_bytes().to_vec()),
        identity(),
        plain(Vec::new()),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let all: verysync_sidecar::CoreLogText = client.core_log_text(None).await?;
    assert_eq!(all.text, text);
    assert!(!format!("{all:?}").contains(KEY));
    let since = "2026-11-11T12:34:56.123456789+08:00";
    assert_eq!(client.core_log_text(Some(since)).await?.text, text);
    assert!(client
        .core_log_text(Some("2100-01-01T00:00:00Z"))
        .await?
        .text
        .is_empty());
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 8);
    assert!(requests[3].starts_with("GET /prefix/rest/system/log.txt HTTP/1.1"));
    assert!(requests[5].contains("since=2026-11-11T12%3A34%3A56.123456789%2B08%3A00"));
    assert!(!requests[5].contains("%252B"));
    Ok(())
}

#[tokio::test]
async fn native_core_log_text_and_json_share_input_guards_before_any_native_request() -> TestResult
{
    let server = ScriptedServer::start(vec![version(), identity()]).await?;
    let client = Client::connect(server.options()?).await?;
    for value in [String::new(), "\nprivate".to_owned(), "x".repeat(129)] {
        assert!(matches!(
            client.core_log_text(Some(&value)).await,
            Err(Error::InvalidConfiguration { .. })
        ));
        assert!(matches!(
            client.core_log(Some(&value)).await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn native_core_log_text_keeps_read_errors_and_invalid_utf8_without_retry() -> TestResult {
    for kind in 0..3 {
        let reply = match kind {
            0 => Reply {
                body: vec![0xff, 0xfe],
                ..Reply::json(serde_json::Value::Null)
            },
            1 => Reply {
                status: 503,
                ..Reply::json(serde_json::json!({"private":KEY}))
            },
            _ => Reply::json(serde_json::json!({"error":KEY})),
        };
        let server = ScriptedServer::start(vec![version(), identity(), identity(), reply]).await?;
        let client = Client::connect(server.options()?).await?;
        let error = client
            .core_log_text(None)
            .await
            .expect_err("failed read is not successful text");
        assert!(matches!(
            (&error, kind),
            (Error::InvalidResponse { .. }, 0) | (Error::Http { .. }, 1) | (Error::Api { .. }, 2)
        ));
        assert!(!format!("{error:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 4);
    }
    Ok(())
}

#[tokio::test]
async fn native_random_strings_keep_lengths_private_values_and_explicit_queries() -> TestResult {
    let cases = [
        (None, 32),
        (Some(0), 32),
        (Some(1), 1),
        (Some(16), 16),
        (Some(u16::MAX), 65535),
    ];
    let mut replies = vec![version(), identity()];
    for (_, length) in cases {
        replies.extend([
            identity(),
            Reply::json(serde_json::json!({"random":"R".repeat(length),"future":KEY})),
        ]);
    }
    let server = ScriptedServer::start(replies).await?;
    let client = Client::connect(server.options()?).await?;
    for (requested, expected) in cases {
        let result: verysync_sidecar::NativeRandomString =
            client.native_random_string(requested).await?;
        assert_eq!(result.value, "R".repeat(expected));
        assert_eq!(result.extra["future"], KEY);
        assert!(!format!("{result:?}").contains(KEY));
        if expected >= 16 {
            assert!(!format!("{result:?}").contains(&result.value));
        }
    }
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 12);
    for (index, (length, _)) in cases.iter().enumerate() {
        let query = length.map(|n| format!("?length={n}")).unwrap_or_default();
        assert!(requests[index * 2 + 3].starts_with(&format!(
            "GET /prefix/rest/svc/random/string{query} HTTP/1.1"
        )));
    }
    Ok(())
}

#[tokio::test]
async fn native_random_strings_reject_malformed_or_mismatched_receipts_without_retry() -> TestResult
{
    for body in [
        serde_json::json!({}),
        serde_json::json!({"random":null}),
        serde_json::json!({"random":16}),
        serde_json::json!({"random":"short"}),
        serde_json::json!({"random":"\n".repeat(16)}),
        serde_json::json!([]),
    ] {
        let server =
            ScriptedServer::start(vec![version(), identity(), identity(), Reply::json(body)])
                .await?;
        let client = Client::connect(server.options()?).await?;
        let error = client
            .native_random_string(Some(16))
            .await
            .expect_err("invalid native receipt must remain uncertain");
        assert!(
            matches!(&error,Error::MutationOutcomeUnknown{source,..} if matches!(source.as_ref(),Error::InvalidResponse{..}))
        );
        assert!(!format!("{error:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 4);
    }
    Ok(())
}

#[tokio::test]
async fn native_random_strings_preserve_native_body_errors_without_accepting_partial_values(
) -> TestResult {
    for body in [
        serde_json::json!({"error":KEY}),
        serde_json::json!({"random":"R".repeat(16),"error":KEY}),
    ] {
        let server =
            ScriptedServer::start(vec![version(), identity(), identity(), Reply::json(body)])
                .await?;
        let client = Client::connect(server.options()?).await?;
        let error = client
            .native_random_string(Some(16))
            .await
            .expect_err("native error is not a successful string");
        assert!(
            matches!(&error,Error::MutationOutcomeUnknown{source,..} if matches!(source.as_ref(),Error::Api{..}))
        );
        assert!(!format!("{error:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 4);
    }
    Ok(())
}

#[tokio::test]
async fn native_migration_progress_preserves_global_snapshots_and_task_errors() -> TestResult {
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!({
            "name":KEY,"total":200,"completed":50,"percent":28.125,
            "finished":false,"error":"","future":KEY
        })),
        identity(),
        Reply::json(serde_json::json!({
            "name":KEY,"total":-1,"completed":-2,"percent":125.5,
            "finished":true,"error":KEY,"future":KEY
        })),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let running: verysync_sidecar::NativeMigrationProgress =
        client.native_migration_progress().await?;
    assert_eq!(running.name, KEY);
    assert_eq!((running.total, running.completed), (200, 50));
    assert_eq!(running.percent, 28.125);
    assert!(!running.finished);
    assert!(running.error_message.is_empty());
    assert_eq!(running.extra["future"], KEY);
    let failed = client.native_migration_progress().await?;
    assert_eq!((failed.total, failed.completed), (-1, -2));
    assert_eq!(failed.percent, 125.5);
    assert!(failed.finished);
    assert_eq!(failed.error_message, KEY);
    assert!(!format!("{running:?} {failed:?}").contains(KEY));
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 6);
    for index in [3, 5] {
        assert!(requests[index].starts_with("GET /prefix/rest/migrate/progress HTTP/1.1"));
        assert!(requests[index]
            .to_ascii_lowercase()
            .contains("x-api-key: synthetic-transport-key"));
    }
    Ok(())
}

#[tokio::test]
async fn native_migration_progress_rejects_incomplete_or_wrongly_typed_snapshots() -> TestResult {
    let complete = serde_json::json!({
        "name":KEY,"total":100,"completed":100,"percent":100,
        "finished":true,"error":"","future":KEY
    });
    let mut invalid = Vec::new();
    for field in ["name", "total", "completed", "percent", "finished", "error"] {
        let mut missing = complete.clone();
        missing
            .as_object_mut()
            .ok_or("object expected")?
            .remove(field);
        invalid.push(missing);
        let mut null = complete.clone();
        null[field] = serde_json::Value::Null;
        invalid.push(null);
    }
    for (field, value) in [
        ("name", serde_json::json!(true)),
        ("total", serde_json::json!(1.5)),
        ("completed", serde_json::json!(u64::MAX)),
        ("percent", serde_json::json!("100")),
        ("finished", serde_json::json!("true")),
        ("error", serde_json::json!({"private":KEY})),
    ] {
        let mut body = complete.clone();
        body[field] = value;
        invalid.push(body);
    }
    invalid.push(serde_json::json!([]));
    for body in invalid {
        let server =
            ScriptedServer::start(vec![version(), identity(), identity(), Reply::json(body)])
                .await?;
        let client = Client::connect(server.options()?).await?;
        let error = client.native_migration_progress().await.unwrap_err();
        assert!(matches!(error, Error::InvalidResponse { .. }));
        assert!(!format!("{error:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 4);
    }
    Ok(())
}

#[tokio::test]
async fn native_migration_progress_keeps_request_failures_and_identity_changes_separate(
) -> TestResult {
    for status in [200, 503] {
        let mut reply = Reply::json(serde_json::json!({"error":KEY}));
        reply.status = status;
        let server = ScriptedServer::start(vec![version(), identity(), identity(), reply]).await?;
        let client = Client::connect(server.options()?).await?;
        let error = client.native_migration_progress().await.unwrap_err();
        assert!(match status {
            200 => matches!(error, Error::Api { .. }),
            _ => matches!(error, Error::Http { .. }),
        });
        assert!(!format!("{error:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 4);
    }
    let other = ID.replacen('A', "B", 1);
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        Reply::json(serde_json::json!({"myID":other})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client.native_migration_progress().await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert_eq!(server.finish().await?.len(), 3);
    Ok(())
}

#[tokio::test]
async fn native_health_preserves_status_and_unknown_fields_without_logging_values() -> TestResult {
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!({"status":"OK","future":KEY})),
        identity(),
        Reply::json(serde_json::json!({"status":KEY,"future":KEY})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let healthy = client.native_health().await?;
    assert!(matches!(
        healthy.status,
        verysync_sidecar::NativeHealthStatus::Ok
    ));
    assert_eq!(healthy.status.native_value(), "OK");
    assert_eq!(healthy.extra["future"], KEY);
    let other = client.native_health().await?;
    assert!(
        matches!(&other.status, verysync_sidecar::NativeHealthStatus::Other(value) if value == KEY)
    );
    assert_eq!(other.status.native_value(), KEY);
    assert!(!format!("{other:?} {:?}", other.status).contains(KEY));
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 6);
    for index in [3, 5] {
        assert!(requests[index].starts_with("GET /prefix/rest/noauth/health HTTP/1.1"));
        assert!(requests[index]
            .to_ascii_lowercase()
            .contains("x-api-key: synthetic-transport-key"));
    }
    Ok(())
}

#[tokio::test]
async fn native_health_rejects_missing_empty_or_invalid_native_status() -> TestResult {
    for body in [
        serde_json::json!({"future":KEY}),
        serde_json::json!({"status":"","future":KEY}),
        serde_json::json!({"status":null}),
        serde_json::json!({"status":true}),
        serde_json::json!({"status":1}),
        serde_json::json!([]),
        serde_json::json!({"status":"OK","error":{ "private":KEY }}),
    ] {
        let server =
            ScriptedServer::start(vec![version(), identity(), identity(), Reply::json(body)])
                .await?;
        let client = Client::connect(server.options()?).await?;
        let error = client.native_health().await.unwrap_err();
        assert!(matches!(error, Error::InvalidResponse { .. }));
        assert!(!format!("{error:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 4);
    }
    Ok(())
}

#[tokio::test]
async fn native_health_keeps_native_body_errors_and_changed_identity_separate() -> TestResult {
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!({"status":"OK","error":KEY})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let error = client.native_health().await.unwrap_err();
    assert!(matches!(error, Error::Api { .. }));
    assert!(!format!("{error:?}").contains(KEY));
    assert_eq!(server.finish().await?.len(), 4);

    let other = ID.replacen('A', "B", 1);
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        Reply::json(serde_json::json!({"myID":other})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client.native_health().await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert_eq!(server.finish().await?.len(), 3);
    Ok(())
}

#[tokio::test]
async fn native_helper_contracts_preserve_values_without_logging_or_automatic_link_actions(
) -> TestResult {
    let server=ScriptedServer::start(vec![version(),identity(),
        identity(),Reply::json(serde_json::json!({"id":ID})),
        identity(),Reply::json(serde_json::json!({"random":"18446744073709551615"})),
        identity(),Reply::json(serde_json::json!({"ip":"::1","pro":KEY,"city":"","addr":"","future":KEY})),
        identity(),Reply::json(serde_json::json!({"version":"v2.33.2","platform":"linux-amd64","numDevices":1,"uniqueID":KEY,"future":KEY})),
        identity(),Reply::json(serde_json::json!({"link":format!("custom-private://{KEY}"),"future":KEY})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let input = "lower + ? % id";
    assert_eq!(client.normalize_device_id(input).await?.as_str(), ID);
    assert_eq!(client.native_random_number().await?, u64::MAX);
    let ip: IpAddr = "::1".parse()?;
    let lookup = client.lookup_target_ip(ip).await?;
    assert_eq!(lookup.ip, ip);
    assert_eq!(lookup.province, KEY);
    assert_eq!(lookup.extra["future"], KEY);
    assert!(!format!("{lookup:?}").contains(KEY));
    let report = client.collect_native_usage_report().await?;
    assert_eq!(report.unique_id.as_deref(), Some(KEY));
    assert_eq!(report.extra["future"], KEY);
    assert!(!format!("{report:?}").contains(KEY));
    let link = client.pending_native_link().await?;
    assert_eq!(
        link.link(),
        Some(format!("custom-private://{KEY}").as_str())
    );
    assert_eq!(link.extra["future"], KEY);
    assert!(!format!("{link:?}").contains(KEY));
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 12);
    let expected = [
        (3, "/prefix/rest/svc/deviceid"),
        (5, "/prefix/rest/svc/random/number"),
        (7, "/prefix/rest/svc/ip/lookup"),
        (9, "/prefix/rest/svc/report"),
        (11, "/prefix/rest/svc/link/await"),
    ];
    for (index, path) in expected {
        let target = requests[index]
            .split_whitespace()
            .nth(1)
            .ok_or("target absent")?;
        let url = url::Url::parse(&format!("http://synthetic.invalid{target}"))?;
        assert_eq!(url.path(), path);
        if index == 3 {
            assert_eq!(
                url.query_pairs().collect::<Vec<_>>(),
                vec![("id".into(), input.into())]
            );
        }
        if index == 7 {
            assert_eq!(
                url.query_pairs().collect::<Vec<_>>(),
                vec![("ip".into(), "::1".into())]
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_random_invalid_receipts_keep_unknown_outcome_and_never_retry() -> TestResult {
    for value in [
        serde_json::json!(""),
        serde_json::json!("-1"),
        serde_json::json!("+1"),
        serde_json::json!(" 1"),
        serde_json::json!("18446744073709551616"),
        serde_json::json!(1),
        serde_json::Value::Null,
    ] {
        let server = ScriptedServer::start(vec![
            version(),
            identity(),
            identity(),
            Reply::json(serde_json::json!({"random":value,"private":KEY})),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let e = client.native_random_number().await.unwrap_err();
        assert!(matches!(e, Error::MutationOutcomeUnknown { .. }));
        assert!(!format!("{e:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 4);
    }
    Ok(())
}

#[tokio::test]
async fn native_helpers_refuse_malformed_mismatched_or_missing_results_and_changed_identity(
) -> TestResult {
    for (kind, body) in [
        ("id", serde_json::json!({"id":KEY})),
        (
            "ip",
            serde_json::json!({"ip":"127.0.0.2","pro":"","city":"","addr":""}),
        ),
        (
            "ip",
            serde_json::json!({"ip":"127.0.0.1","city":"","addr":""}),
        ),
        (
            "report",
            serde_json::json!({"version":"v2.33.2","platform":"linux-amd64","uniqueID":KEY}),
        ),
        (
            "report",
            serde_json::json!({"version":"","platform":"linux-amd64","numDevices":1}),
        ),
        ("link", serde_json::json!({"future":KEY})),
        ("link", serde_json::json!({"link":null})),
    ] {
        let server =
            ScriptedServer::start(vec![version(), identity(), identity(), Reply::json(body)])
                .await?;
        let client = Client::connect(server.options()?).await?;
        let e = match kind {
            "id" => client.normalize_device_id("input").await.unwrap_err(),
            "ip" => client
                .lookup_target_ip("127.0.0.1".parse()?)
                .await
                .unwrap_err(),
            "report" => client.collect_native_usage_report().await.unwrap_err(),
            _ => client.pending_native_link().await.unwrap_err(),
        };
        assert!(if matches!(kind, "report" | "link") {
            matches!(e, Error::MutationOutcomeUnknown { .. })
        } else {
            matches!(e, Error::InvalidResponse { .. })
        });
        assert!(!format!("{e:?}").contains(KEY));
        assert_eq!(server.finish().await?.len(), 4);
    }
    let other = ID.replacen('A', "B", 1);
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        Reply::json(serde_json::json!({"myID":other})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    for input in ["", "a\n", &"x".repeat(1025)] {
        assert!(client.normalize_device_id(input).await.is_err());
    }
    assert!(matches!(
        client.native_random_number().await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert_eq!(server.finish().await?.len(), 3);
    Ok(())
}
