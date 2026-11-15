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
