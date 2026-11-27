//! Explicit peer-removal checkpoints and the separate read-only observation.
use super::*;
use verysync_sidecar::{ControlOperationReceipt, ControlSubmission, DeviceId};

fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}
fn peer() -> verysync_sidecar::Result<DeviceId> {
    DeviceId::parse(&ID.replacen('A', "B", 1))
}
fn record(id: &DeviceId, paused: bool) -> Reply {
    Reply::json(serde_json::json!({
        "devices":[{"deviceID":id.as_str(),"name":"synthetic","addresses":[],
                    "compression":"metadata","paused":paused,"other":KEY}],
        "folders":[{"id":"synthetic-registration","devices":[{"deviceID":id.as_str()}]}]
    }))
}

#[tokio::test]
async fn a_lost_delete_reply_survives_reopen_and_does_not_send_another_delete() -> TestResult {
    let peer = peer()?;
    let mut lost = Reply::json(serde_json::json!({}));
    lost.delay = Duration::from_millis(500);
    let submission = ScriptedServer::start(vec![
        version(),
        identity(),
        version(),
        identity(),
        record(&peer, false),
        version(),
        identity(),
        lost,
    ])
    .await?;
    let client = Client::connect(
        submission
            .options()?
            .request_timeout(Duration::from_millis(250))?,
    )
    .await?;
    let prepared = client.prepare_device_removal(&peer)?;
    let mut written = Vec::new();
    let report = client
        .execute_device_removal_persisted(prepared, |receipt| {
            written.push(receipt);
            std::future::ready(Ok(()))
        })
        .await;
    assert_eq!(
        report.receipt.submission(),
        ControlSubmission::PossiblySubmitted
    );
    assert!(matches!(
        report.result,
        Err(Error::MutationOutcomeUnknown { .. })
    ));
    assert_eq!(written.len(), 2);
    assert_eq!(written[0].submission(), ControlSubmission::Prepared);
    assert_eq!(
        written[1].submission(),
        ControlSubmission::PossiblySubmitted
    );
    let requests = submission.finish().await?;
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("DELETE ")).count(),
        1
    );
    assert!(requests[7].starts_with(&format!(
        "DELETE /prefix/rest/config/devices/{} ",
        peer.as_str()
    )));
    assert!(requests[..7].iter().all(|r| r.starts_with("GET ")));
    drop(client);

    let recovery = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(serde_json::json!({"devices":[],"folders":[]})),
        version(),
        identity(),
    ])
    .await?;
    let reopened = ControlOperationReceipt::decode(&written[1].encode()?)?;
    let observed = reopened.observe_device_removal(recovery.options()?).await?;
    assert!(observed.configuration_absent && observed.remaining_folder_associations.is_empty());
    assert_eq!(observed.identity.device_id().as_str(), ID);
    assert_eq!(reopened.submission(), ControlSubmission::PossiblySubmitted);
    let requests = recovery.finish().await?;
    assert_eq!(requests.len(), 6);
    assert!(requests.iter().all(|r| r.starts_with("GET ")));
    Ok(())
}

#[tokio::test]
async fn absence_of_disconnect_proof_keeps_acknowledged_pause_and_zero_deletes() -> TestResult {
    let peer = peer()?;
    let unavailable = Reply {
        status: 503,
        ..Reply::json(serde_json::json!({"error":KEY}))
    };
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        version(),
        identity(),
        record(&peer, false),
        version(),
        identity(),
        Reply::json(serde_json::json!({})),
        record(&peer, true),
        identity(),
        unavailable,
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let prepared = client.prepare_device_disconnect_and_remove(&peer, Duration::from_secs(2))?;
    let report = client.execute_device_removal(prepared).await;
    assert!(matches!(
        report.result,
        Err(Error::MutationOutcomeUnknown { .. })
    ));
    assert_eq!(report.receipt.submission(), ControlSubmission::NotSubmitted);
    let stages = report
        .receipt
        .device_removal_progress()
        .ok_or("device-stage receipt absent")?;
    assert_eq!(
        stages.pause_request,
        Some(ControlSubmission::Acknowledged { status: 200 })
    );
    assert!(!stages.disconnection_observed);
    assert!(!format!("{report:?}").contains(KEY));
    let requests = server.finish().await?;
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("PATCH ")).count(),
        1
    );
    assert!(!requests.iter().any(|r| r.starts_with("DELETE ")));
    Ok(())
}

#[tokio::test]
async fn explicit_removal_checkpoints_pause_then_connection_then_delete() -> TestResult {
    let peer = peer()?;
    let empty_registration = Reply::json(serde_json::json!({"devices":[],"folders":[]}));
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        version(),
        identity(),
        record(&peer, false),
        version(),
        identity(),
        Reply::json(serde_json::json!({})),
        record(&peer, true),
        identity(),
        Reply::json(serde_json::json!({"connections":{peer.as_str():{"connected":false}}})),
        version(),
        identity(),
        Reply::json(serde_json::json!({})),
        identity(),
        empty_registration,
        version(),
        identity(),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let prepared = client.prepare_device_disconnect_and_remove(&peer, Duration::from_secs(2))?;
    let mut checkpoints = Vec::new();
    let finished = client
        .execute_device_removal_persisted(prepared, |receipt| {
            checkpoints.push(receipt);
            std::future::ready(Ok(()))
        })
        .await;
    assert_eq!(checkpoints.len(), 3);
    assert_eq!(checkpoints[0].submission(), ControlSubmission::Prepared);
    assert_eq!(
        checkpoints[1]
            .device_removal_progress()
            .ok_or("stages absent")?
            .pause_request,
        Some(ControlSubmission::PossiblySubmitted)
    );
    let delete_checkpoint = ControlOperationReceipt::decode(&checkpoints[2].encode()?)?;
    assert_eq!(
        delete_checkpoint.submission(),
        ControlSubmission::PossiblySubmitted
    );
    let stages = delete_checkpoint
        .device_removal_progress()
        .ok_or("stages absent")?;
    assert!(stages.disconnection_observed);
    assert_eq!(
        stages.pause_request,
        Some(ControlSubmission::Acknowledged { status: 200 })
    );
    assert_eq!(
        finished.receipt.submission(),
        ControlSubmission::Acknowledged { status: 200 }
    );
    assert!(finished.result?.configuration_absent);
    let requests = server.finish().await?;
    let mutations: Vec<&str> = requests
        .iter()
        .filter(|line| !line.starts_with("GET "))
        .map(|line| line.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(mutations, ["PATCH", "DELETE"]);
    assert!(requests[10].starts_with("GET /prefix/rest/system/connections "));
    Ok(())
}

#[tokio::test]
async fn acknowledged_delete_and_failed_readback_are_reported_separately() -> TestResult {
    let peer = peer()?;
    let temporary_error = Reply {
        status: 503,
        ..Reply::json(serde_json::json!({"error":KEY}))
    };
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        version(),
        identity(),
        record(&peer, true),
        version(),
        identity(),
        Reply::json(serde_json::json!({})),
        identity(),
        temporary_error,
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let prepared = client.prepare_device_removal(&peer)?;
    let report = client.execute_device_removal(prepared).await;
    assert!(
        matches!(report.result, Err(Error::MutationOutcomeUnknown { source, .. })
        if matches!(*source, Error::Http { .. }))
    );
    assert_eq!(
        report.receipt.submission(),
        ControlSubmission::Acknowledged { status: 200 }
    );
    assert_eq!(report.receipt.response_status(), Some(200));
    let requests = server.finish().await?;
    assert_eq!(
        requests.iter().filter(|r| !r.starts_with("GET ")).count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn rejected_storage_checkpoint_and_target_change_prevent_delete() -> TestResult {
    let peer = peer()?;
    for changed in [false, true] {
        let mut replies = vec![
            version(),
            identity(),
            version(),
            identity(),
            record(&peer, true),
        ];
        if changed {
            replies.extend([
                version(),
                Reply::json(serde_json::json!({"myID":peer.as_str()})),
            ]);
        }
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let prepared = client.prepare_device_removal(&peer)?;
        let report = client
            .execute_device_removal_persisted(prepared, |receipt| {
                std::future::ready(
                    if !changed && receipt.submission() != ControlSubmission::Prepared {
                        Err(std::io::Error::other(
                            "private synthetic storage unavailable",
                        ))
                    } else {
                        Ok(())
                    },
                )
            })
            .await;
        assert_eq!(report.receipt.submission(), ControlSubmission::NotSubmitted);
        match report.result {
            Err(Error::IdentityMismatch { .. }) if changed => {}
            Err(Error::LocalIo { .. }) if !changed => {}
            result => panic!("unexpected replacement or checkpoint outcome {result:?}"),
        }
        assert!(server.finish().await?.iter().all(|r| r.starts_with("GET ")));
    }
    Ok(())
}
