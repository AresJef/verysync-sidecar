//! Signed native request-budget selections, separate from limiter runtime proof.
use super::{complete_configuration_fixture, Client, Reply, ScriptedServer, TestResult, ID};

#[tokio::test]
async fn incoming_request_budgets_decode_native_negative_zero_and_large_signed_values() -> TestResult
{
    for selected in [-1_i64, i64::MIN, 0, 32768, i64::from(u32::MAX) + 1] {
        let mut options = complete_configuration_fixture()["options"].clone();
        options["maxConcurrentIncomingRequestKiB"] = selected.into();
        let server = ScriptedServer::start(vec![
            Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
            Reply::json(serde_json::json!({"myID":ID})),
            Reply::json(options),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let actual = client.general_options().await?;
        assert_eq!(
            serde_json::to_value(actual)?["maxConcurrentIncomingRequestKiB"],
            selected
        );
        let requests = server.finish().await?;
        assert_eq!(requests.len(), 3);
        assert!(requests[2].starts_with("GET /prefix/rest/config/options "));
    }
    Ok(())
}

#[tokio::test]
async fn incoming_request_budgets_patch_and_snapshot_edits_preserve_signed_values() -> TestResult {
    use verysync_sidecar::GeneralOptionsPatch;
    for selected in [-1_i64, i64::MIN, 0, i64::MAX] {
        let mut options = complete_configuration_fixture()["options"].clone();
        options["maxConcurrentIncomingRequestKiB"] = selected.into();
        let server = ScriptedServer::start(vec![
            Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
            Reply::json(serde_json::json!({"myID":ID})),
            Reply::json(serde_json::json!({"myID":ID})),
            Reply::json(serde_json::json!({})),
            Reply::json(options),
            Reply::json(serde_json::json!({"myID":ID})),
            Reply::json(complete_configuration_fixture()),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let patch = GeneralOptionsPatch::default().max_concurrent_incoming_request_kib(selected);
        let update = client.update_general_options(&patch).await?;
        assert!(update.requested_fields_match);
        assert_eq!(
            update.configuration.max_concurrent_incoming_request_kib,
            selected
        );
        let mut snapshot = client.configuration().await?;
        snapshot.set_general_options(&patch)?;
        assert_eq!(
            snapshot.native_document()["options"]["maxConcurrentIncomingRequestKiB"],
            selected
        );
        let requests = server.finish().await?;
        let writes: Vec<_> = requests
            .iter()
            .filter(|r| r.starts_with("PATCH "))
            .collect();
        assert_eq!(writes.len(), 1);
        assert!(writes[0].starts_with("PATCH /prefix/rest/config/options "));
        let (_, body) = writes[0]
            .split_once("\r\n\r\n")
            .ok_or("missing patch body")?;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body)?,
            serde_json::json!({"maxConcurrentIncomingRequestKiB":selected})
        );
    }
    Ok(())
}
