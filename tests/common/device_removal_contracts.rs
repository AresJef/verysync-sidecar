//! Explicit disconnect/removal ordering, not native-engine acceptance.
use super::*;

fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn configured(peer: &str, paused: bool) -> Reply {
    Reply::json(
        serde_json::json!({"devices":[{"deviceID":peer,"name":"owned peer","addresses":[],"compression":"metadata","paused":paused,"unrelatedPrivate":KEY}]}),
    )
}

#[tokio::test]
async fn explicit_removal_requires_present_disconnected_peer_before_single_delete() -> TestResult {
    let peer = verysync_sidecar::DeviceId::parse(&ID.replacen('A', "B", 1))?;
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        configured(peer.as_str(), false),
        Reply::json(serde_json::json!({})),
        configured(peer.as_str(), true),
        identity(),
        Reply::json(serde_json::json!({"connections":{}})),
        identity(),
        Reply::json(serde_json::json!({"connections":{peer.as_str():{"connected":true}}})),
        identity(),
        Reply::json(serde_json::json!({"connections":{peer.as_str():{"connected":false}}})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"devices":[],"folders":[]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let result = client
        .disconnect_and_remove_device(&peer, Duration::from_secs(3))
        .await?;
    assert!(result.configuration_absent && result.remaining_folder_associations.is_empty());
    assert!(!result.previous_configuration.paused);
    assert_eq!(result.previous_configuration.extra["unrelatedPrivate"], KEY);
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 14);
    assert!(requests[12].starts_with("DELETE "));
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("DELETE ")).count(),
        1
    );
    let patches = requests
        .iter()
        .filter(|r| r.starts_with("PATCH "))
        .collect::<Vec<_>>();
    assert_eq!(patches.len(), 1);
    let body: serde_json::Value =
        serde_json::from_str(patches[0].split("\r\n\r\n").nth(1).ok_or("body absent")?)?;
    assert_eq!(body, serde_json::json!({"paused":true}));
    Ok(())
}

#[tokio::test]
async fn explicit_removal_rejects_self_and_deadlines_before_writing() -> TestResult {
    let peer = verysync_sidecar::DeviceId::parse(&ID.replacen('A', "B", 1))?;
    let server = ScriptedServer::start(vec![version(), identity()]).await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client
            .disconnect_and_remove_device(
                &verysync_sidecar::DeviceId::parse(ID)?,
                Duration::from_secs(1)
            )
            .await,
        Err(Error::LocalDeviceProtected)
    ));
    assert!(matches!(
        client
            .disconnect_and_remove_device(&peer, Duration::ZERO)
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        client
            .disconnect_and_remove_device(&peer, Duration::from_nanos(1))
            .await,
        Err(Error::Timeout { .. })
    ));
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn failure_after_pause_preserves_unknown_outcome_and_does_not_delete_or_retry() -> TestResult
{
    let peer = verysync_sidecar::DeviceId::parse(&ID.replacen('A', "B", 1))?;
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        configured(peer.as_str(), false),
        Reply::json(serde_json::json!({})),
        configured(peer.as_str(), true),
        identity(),
        Reply {
            status: 503,
            ..Reply::json(serde_json::json!({"error":KEY}))
        },
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let failure = client
        .disconnect_and_remove_device(&peer, Duration::from_secs(3))
        .await
        .err()
        .ok_or("failure expected")?;
    assert!(matches!(failure, Error::MutationOutcomeUnknown { .. }));
    assert!(!format!("{failure:?} {failure}").contains(KEY));
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 8);
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("PATCH ")).count(),
        1
    );
    assert!(!requests.iter().any(|r| r.starts_with("DELETE ")));
    Ok(())
}
