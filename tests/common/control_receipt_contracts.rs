//! Listener receipt durability and original response evidence.
use super::*;
use std::sync::{Arc, Mutex};
use verysync_sidecar::{
    ControlOperationReceipt, ControlSubmission, GuiListenAddress, GuiListenerPatch,
};

fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}

fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}

fn listener() -> Reply {
    Reply::json(serde_json::json!({
        "enabled":true, "authMode":"static", "user":"private-user", "password":KEY, "apiKey":KEY,
        "address":"127.0.0.1:41233", "useTLS":false, "unixSocketPermissions":""
    }))
}

#[tokio::test]
async fn receipt_checkpoint_failure_proves_zero_writes() -> TestResult {
    let server = ScriptedServer::start(vec![version(), identity(), identity(), listener()]).await?;
    let client = Client::connect(server.options()?).await?;
    let patch = GuiListenerPatch::default().address(GuiListenAddress::tcp("127.0.0.1:41234")?);
    let operation = client.prepare_gui_listener_change(&patch)?;
    let saved: Arc<Mutex<Vec<ControlOperationReceipt>>> = Arc::default();
    let report = client
        .execute_gui_listener_change_persisted(operation, {
            let observed = saved.clone();
            move |receipt| {
                let mut checkpoints = observed.lock().unwrap();
                checkpoints.push(receipt);
                let count = checkpoints.len();
                async move {
                    if count == 2 {
                        Err(std::io::Error::other(KEY))
                    } else {
                        Ok(())
                    }
                }
            }
        })
        .await;
    assert!(matches!(report.result, Err(Error::LocalIo { .. })));
    assert_eq!(report.receipt.submission(), ControlSubmission::NotSubmitted);
    assert!(!format!("{report:?}").contains(KEY));
    let checkpoints = saved.lock().unwrap();
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(checkpoints[0].submission(), ControlSubmission::Prepared);
    assert_eq!(
        checkpoints[1].submission(),
        ControlSubmission::PossiblySubmitted
    );
    assert_eq!(checkpoints[0].id(), checkpoints[1].id());
    drop(checkpoints);
    assert!(server.finish().await?.iter().all(|r| r.starts_with("GET ")));
    Ok(())
}

#[tokio::test]
async fn receipt_is_versioned_bounded_and_redacted() -> TestResult {
    let server = ScriptedServer::start(vec![version(), identity()]).await?;
    let client = Client::connect(server.options()?).await?;
    let address = "127.0.0.1:41234";
    let operation = client.prepare_gui_listener_change(
        &GuiListenerPatch::default().address(GuiListenAddress::tcp(address)?),
    )?;
    let receipt = operation.receipt();
    let encoded = receipt.encode()?;
    let text = std::str::from_utf8(&encoded)?;
    assert!(!text.contains(KEY));
    assert!(!format!("{receipt:?}").contains(address));
    assert!(!format!("{receipt:?}").contains(ID));
    let reopened = ControlOperationReceipt::decode(&encoded)?;
    assert_eq!(reopened.id(), receipt.id());
    assert_eq!(reopened.submission(), ControlSubmission::Prepared);
    assert_eq!(reopened.target_device_id().as_str(), ID);
    assert!(ControlOperationReceipt::decode(&encoded[..encoded.len() - 1]).is_err());
    assert!(ControlOperationReceipt::decode(&vec![b' '; 100_000]).is_err());
    let mut wrong_format: serde_json::Value = serde_json::from_slice(&encoded)?;
    wrong_format["schema_version"] = serde_json::json!(999);
    assert!(ControlOperationReceipt::decode(&serde_json::to_vec(&wrong_format)?).is_err());
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn receipt_distinguishes_acknowledgement_and_uncertain_transport() -> TestResult {
    for acknowledged in [true, false] {
        let mut reply = Reply::json(serde_json::json!({}));
        if !acknowledged {
            reply.delay = Duration::from_secs(2);
        }
        let server = ScriptedServer::start(vec![
            version(),
            identity(),
            identity(),
            listener(),
            version(),
            identity(),
            reply,
        ])
        .await?;
        let options = server.options()?.request_timeout(Duration::from_secs(1))?;
        let client = Client::connect(options).await?;
        let patch = GuiListenerPatch::default().address(GuiListenAddress::tcp("127.0.0.1:41234")?);
        let operation = client.prepare_gui_listener_change(&patch)?;
        let report = client.execute_gui_listener_change(operation).await;
        let expected = if acknowledged {
            assert!(report.result.is_ok());
            assert_eq!(report.receipt.response_status(), Some(200));
            ControlSubmission::Acknowledged { status: 200 }
        } else {
            assert!(
                matches!(report.result, Err(Error::MutationOutcomeUnknown { source, .. })
                if matches!(*source, Error::Timeout { .. }))
            );
            assert_eq!(report.receipt.response_status(), None);
            ControlSubmission::PossiblySubmitted
        };
        assert_eq!(report.receipt.submission(), expected);
        let reopened = ControlOperationReceipt::decode(&report.receipt.encode()?)?;
        assert_eq!(reopened.log_event(), report.receipt.log_event());
        let requests = server.finish().await?;
        assert_eq!(requests.len(), 7);
        assert!(requests[..6]
            .iter()
            .all(|request| request.starts_with("GET ")));
        assert!(requests[6].starts_with("PATCH /prefix/rest/config/gui "));
    }
    Ok(())
}

#[tokio::test]
async fn receipt_cancellation_during_initial_save_leaves_zero_writes() -> TestResult {
    use tokio::sync::Notify;

    let server = ScriptedServer::start(vec![version(), identity()]).await?;
    let client = Client::connect(server.options()?).await?;
    let patch = GuiListenerPatch::default().address(GuiListenAddress::tcp("127.0.0.1:41234")?);
    let prepared = client.prepare_gui_listener_change(&patch)?;
    let saving = Arc::new(Notify::new());
    let mut future = Box::pin(client.execute_gui_listener_change_persisted(prepared, {
        let saving = saving.clone();
        move |receipt| {
            assert_eq!(receipt.submission(), ControlSubmission::Prepared);
            saving.notify_one();
            std::future::pending::<std::io::Result<()>>()
        }
    }));
    tokio::select! {
        _ = saving.notified() => {}
        _ = &mut future => panic!("a pending save should suspend dispatch"),
        _ = tokio::time::sleep(Duration::from_secs(2)) => panic!("save callback was not polled"),
    }
    drop(future);
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
    Ok(())
}
