//! Partial connection limits, uncertainty and portable integer bounds.
use super::*;
use verysync_sidecar::{NetworkConfig, NetworkPatch};

fn configuration(maximum: Option<serde_json::Value>) -> serde_json::Value {
    let mut value = serde_json::json!({"options":{
        "listenAddresses":[],"globalAnnounceServers":[],
        "globalAnnounceEnabled":false,"localAnnounceEnabled":false,
        "localAnnouncePort":21027,"localAnnounceMCAddr":"[ff12::8384]:21027",
        "reconnectionIntervalS":5,"futureSecret":KEY
    }});
    if let Some(maximum) = maximum {
        value["options"]["connectionLimitMax"] = maximum;
    }
    value
}
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}

#[tokio::test]
async fn network_limits_require_every_selected_readback_and_preserve_unknown_outcomes() -> TestResult
{
    for field in ["connectionLimitMax", "connectionLimitEnough"] {
        for shape in [
            "match",
            "unchanged",
            "absent",
            "null",
            "private-type",
            "negative",
        ] {
            let requested = if field == "connectionLimitMax" { 3 } else { 2 };
            let mut config = configuration(Some(3.into()));
            config["options"]["connectionLimitEnough"] = 2.into();
            if shape == "absent" {
                config["options"]
                    .as_object_mut()
                    .ok_or("options absent")?
                    .remove(field);
            } else {
                config["options"][field] = match shape {
                    "match" => requested.into(),
                    "unchanged" => (requested - 1).into(),
                    "null" => serde_json::Value::Null,
                    "private-type" => KEY.into(),
                    _ => (-1).into(),
                };
            }
            let server = ScriptedServer::start(vec![
                version(),
                identity(),
                identity(),
                Reply::json(serde_json::json!({})),
                Reply::json(config),
            ])
            .await?;
            let client = Client::connect(server.options()?).await?;
            let result = client
                .update_network_configuration(
                    &NetworkPatch::default()
                        .connection_limit_max(3)
                        .connection_limit_enough(2),
                )
                .await;
            if matches!(shape, "private-type" | "negative") {
                let error = result.unwrap_err();
                assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
                assert!(!format!("{error:?}").contains(KEY));
            } else {
                let update = result?;
                assert_eq!(
                    update.requested_fields_match,
                    shape == "match",
                    "field={field} shape={shape}"
                );
                assert_eq!(update.configuration.extra["futureSecret"], KEY);
                assert!(!format!("{update:?}").contains(KEY));
            }
            let requests = server.finish().await?;
            let writes: Vec<_> = requests
                .iter()
                .filter(|r| r.starts_with("PATCH "))
                .collect();
            assert_eq!(writes.len(), 1);
            let body: serde_json::Value =
                serde_json::from_str(writes[0].split_once("\r\n\r\n").ok_or("missing body")?.1)?;
            assert_eq!(
                body,
                serde_json::json!({"connectionLimitMax":3,"connectionLimitEnough":2})
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn network_limit_zero_is_selected_and_nonportable_values_send_no_request() -> TestResult {
    for maximum in [true, false] {
        let mut config = configuration(Some(0.into()));
        config["options"]["connectionLimitEnough"] = 0.into();
        let server = ScriptedServer::start(vec![
            version(),
            identity(),
            identity(),
            Reply::json(serde_json::json!({})),
            Reply::json(config),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let patch = |value| {
            if maximum {
                NetworkPatch::default().connection_limit_max(value)
            } else {
                NetworkPatch::default().connection_limit_enough(value)
            }
        };
        for value in [i32::MAX as u32 + 1, u32::MAX] {
            assert!(matches!(
                client.update_network_configuration(&patch(value)).await,
                Err(Error::InvalidConfiguration { .. })
            ));
        }
        let update = client.update_network_configuration(&patch(0)).await?;
        assert!(update.requested_fields_match);
        assert_eq!(update.configuration.connection_limit_max, Some(0));
        assert_eq!(update.configuration.connection_limit_enough, Some(0));
        let requests = server.finish().await?;
        assert_eq!(requests.len(), 5);
        let body: serde_json::Value =
            serde_json::from_str(requests[3].split_once("\r\n\r\n").ok_or("missing body")?.1)?;
        assert_eq!(
            body,
            if maximum {
                serde_json::json!({"connectionLimitMax":0})
            } else {
                serde_json::json!({"connectionLimitEnough":0})
            }
        );
    }
    Ok(())
}

#[test]
fn connection_limit_observations_keep_absence_distinct_from_zero() -> TestResult {
    let absent: NetworkConfig = serde_json::from_value(configuration(None)["options"].clone())?;
    assert_eq!(absent.connection_limit_max, None);
    assert_eq!(absent.connection_limit_enough, None);
    let mut zero = configuration(Some(0.into()));
    zero["options"]["connectionLimitEnough"] = 0.into();
    let zero: NetworkConfig = serde_json::from_value(zero["options"].clone())?;
    assert_eq!(zero.connection_limit_max, Some(0));
    assert_eq!(zero.connection_limit_enough, Some(0));
    assert!(!zero.extra.contains_key("connectionLimitMax"));
    assert!(!zero.extra.contains_key("connectionLimitEnough"));
    Ok(())
}
