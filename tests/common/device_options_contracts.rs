//! Device advanced selectors use the existing guarded mutation paths.
use super::*;
use verysync_sidecar::{DeviceAdvancedPatch, DeviceId, DevicePatch, IntroductionSource};
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}
fn defaults() -> serde_json::Value {
    serde_json::json!({"name":"","addresses":["dynamic"],"compression":"metadata","paused":true,"privateUnknown":KEY})
}

#[tokio::test]
async fn advanced_device_defaults_preserve_absence_and_submit_only_selected_fields() -> TestResult {
    let mut actual = defaults();
    actual["introducer"] = true.into();
    actual["certName"] = KEY.into();
    actual["introducedBy"] = ID.into();
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        Reply::json(defaults()),
        identity(),
        Reply::json(serde_json::json!({})),
        Reply::json(actual),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert_eq!(
        client
            .device_defaults()
            .await?
            .advanced_configuration()?
            .introducer,
        None
    );
    let patch = DevicePatch::default().advanced_configuration(
        DeviceAdvancedPatch::default()
            .introducer(true)
            .certificate_name(KEY)
            .introduced_by(Some(DeviceId::parse(ID)?)),
    )?;
    let receipt = client.update_device_defaults(&patch).await?;
    assert!(receipt.requested_fields_match);
    let observed = receipt.configuration.advanced_configuration()?;
    assert_eq!(observed.introducer, Some(true));
    assert!(
        matches!(observed.introduced_by,Some(IntroductionSource::Device(ref id)) if id.as_str()==ID)
    );
    assert!(!format!("{patch:?} {observed:?} {receipt:?}").contains(KEY));
    let requests = server.finish().await?;
    let writes: Vec<_> = requests
        .iter()
        .filter(|r| r.starts_with("PATCH "))
        .collect();
    assert_eq!(writes.len(), 1);
    let body: serde_json::Value =
        serde_json::from_str(writes[0].split_once("\r\n\r\n").ok_or("body absent")?.1)?;
    assert_eq!(
        body,
        serde_json::json!({"introducer":true,"certName":KEY,"introducedBy":ID})
    );
    Ok(())
}

#[tokio::test]
async fn advanced_device_partial_mismatch_remains_false_and_unknown_source_stays_private(
) -> TestResult {
    let remote = ID.replacen('A', "B", 1);
    let mut before = defaults();
    before["deviceID"] = remote.clone().into();
    let mut actual = before.clone();
    actual["numConnections"] = 2.into();
    actual["autoAcceptFolders"] = false.into();
    actual["introducedBy"] = KEY.into();
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!({"devices":[before]})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"devices":[actual]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let receipt = client
        .update_device(
            &DeviceId::parse(&remote)?,
            &DevicePatch::default().advanced_configuration(
                DeviceAdvancedPatch::default()
                    .num_connections(2)
                    .auto_accept_folders(true),
            )?,
        )
        .await?;
    assert!(!receipt.requested_fields_match);
    let advanced = receipt.configuration.advanced_configuration()?;
    assert!(matches!(advanced.introduced_by,Some(IntroductionSource::Unknown(ref v)) if v==KEY));
    assert!(!format!("{advanced:?}").contains(KEY));
    assert_eq!(
        server
            .finish()
            .await?
            .iter()
            .filter(|r| r.starts_with("PATCH "))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn invalid_advanced_device_inputs_fail_before_requests() -> TestResult {
    let server = ScriptedServer::start(vec![version(), identity()]).await?;
    let client = Client::connect(server.options()?).await?;
    for patch in [
        DeviceAdvancedPatch::default(),
        DeviceAdvancedPatch::default().num_connections(u32::MAX),
        DeviceAdvancedPatch::default().max_request_kib(u32::MAX),
        DeviceAdvancedPatch::default().certificate_name("invalid\nprivate"),
        DeviceAdvancedPatch::default().allowed_networks(vec!["".into()]),
    ] {
        assert!(DevicePatch::default()
            .advanced_configuration(patch)
            .is_err());
    }
    assert!(matches!(
        client.update_device_defaults(&DevicePatch::default()).await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn malformed_selected_device_readback_is_unknown_for_create_update_and_defaults() -> TestResult
{
    use verysync_sidecar::CreateDeviceOptions;
    let peer = DeviceId::parse(&ID.replacen('A', "B", 1))?;
    let mut before = defaults();
    before["deviceID"] = peer.as_str().into();
    let mut invalid = before.clone();
    invalid["numConnections"] = "invalid native numeric type".into();
    for operation in ["create", "update", "defaults"] {
        let mut replies = vec![version(), identity(), identity()];
        match operation {
            "create" => replies.extend([
                Reply::json(serde_json::json!({"devices":[]})),
                Reply::json(defaults()),
            ]),
            "update" => replies.push(Reply::json(serde_json::json!({"devices":[before.clone()]}))),
            _ => {}
        }
        replies.push(Reply::json(serde_json::json!({})));
        replies.push(Reply::json(if operation == "defaults" {
            let mut d = defaults();
            d["numConnections"] = "invalid native numeric type".into();
            d
        } else {
            serde_json::json!({"devices":[invalid.clone()]})
        }));
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let patch = DevicePatch::default()
            .advanced_configuration(DeviceAdvancedPatch::default().num_connections(2))?;
        let error = match operation {
            "create" => client
                .create_device(&CreateDeviceOptions::new(peer.clone()).settings(patch))
                .await
                .map(|_| ())
                .unwrap_err(),
            "update" => client
                .update_device(&peer, &patch)
                .await
                .map(|_| ())
                .unwrap_err(),
            _ => client
                .update_device_defaults(&patch)
                .await
                .map(|_| ())
                .unwrap_err(),
        };
        assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
        let requests = server.finish().await?;
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.starts_with("PATCH ") || r.starts_with("POST "))
                .count(),
            1
        );
    }
    Ok(())
}
