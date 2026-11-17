//! Signed general-option domains, without interpreting negative runtime policy.
use super::{complete_configuration_fixture, Client, Reply, ScriptedServer, TestResult, ID};

#[tokio::test]
async fn general_integer_domains_decode_native_signed_values_without_unsigned_narrowing(
) -> TestResult {
    let mut rejected = Vec::new();
    for field in [
        "keepTemporariesH",
        "maxFolderConcurrency",
        "maxDialConcurrent",
        "tempIndexMinBlocks",
        "trafficClass",
    ] {
        for selected in [-1_i64, i64::MIN, 0, i64::MAX] {
            let mut options = complete_configuration_fixture()["options"].clone();
            options[field] = selected.into();
            let server = ScriptedServer::start(vec![
                Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
                Reply::json(serde_json::json!({"myID":ID})),
                Reply::json(options),
            ])
            .await?;
            let client = Client::connect(server.options()?).await?;
            match client.general_options().await {
                Ok(actual) => assert_eq!(serde_json::to_value(actual)?[field], selected),
                Err(_) => rejected.push(field),
            }
            let requests = server.finish().await?;
            assert_eq!(requests.len(), 3);
            assert!(requests[2].starts_with("GET /prefix/rest/config/options "));
        }
    }
    assert!(
        rejected.is_empty(),
        "native signed values were rejected in {} cases",
        rejected.len()
    );
    Ok(())
}

#[tokio::test]
async fn general_integer_domains_keep_exact_signed_patch_and_snapshot_fields() -> TestResult {
    use verysync_sidecar::GeneralOptionsPatch;
    for selected in [-1_i64, 0, i64::MAX] {
        let mut options = complete_configuration_fixture()["options"].clone();
        let mut expected = serde_json::Map::new();
        for field in [
            "keepTemporariesH",
            "maxFolderConcurrency",
            "maxDialConcurrent",
            "tempIndexMinBlocks",
            "trafficClass",
        ] {
            options[field] = selected.into();
            expected.insert(field.into(), selected.into());
        }
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
        let patch = GeneralOptionsPatch::default()
            .keep_temporaries_hours(selected)
            .max_folder_concurrency(selected)
            .max_dial_concurrent(selected)
            .temp_index_min_blocks(selected)
            .traffic_class(selected);
        let update = client.update_general_options(&patch).await?;
        assert!(update.requested_fields_match);
        let mut snapshot = client.configuration().await?;
        snapshot.set_general_options(&patch)?;
        for (name, value) in &expected {
            assert_eq!(&snapshot.native_document()["options"][name], value);
        }
        let requests = server.finish().await?;
        let writes: Vec<_> = requests
            .iter()
            .filter(|r| r.starts_with("PATCH "))
            .collect();
        assert_eq!(writes.len(), 1);
        assert!(writes[0].starts_with("PATCH /prefix/rest/config/options "));
        let (_, body) = writes[0]
            .split_once("\r\n\r\n")
            .ok_or("missing general patch")?;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body)?,
            serde_json::Value::Object(expected)
        );
    }
    Ok(())
}
