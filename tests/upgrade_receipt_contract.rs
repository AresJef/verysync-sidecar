//! Public upgrade receipt contracts over a caller-owned synthetic HTTP peer.
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, watch},
};
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, Error, ManagementEndpoint, OperationOptions, OperationPhase,
    UpgradeDispatch, UpgradeOutcome,
};

const DEVICE: &str = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";
const DEADLINE: Duration = Duration::from_millis(400);

async fn peer(
    reply: Option<&'static str>,
) -> Result<(Client, mpsc::UnboundedReceiver<String>), Box<dyn std::error::Error>> {
    peer_with_replies(move |_| reply).await
}

async fn peer_with_replies(
    reply: impl Fn(usize) -> Option<&'static str> + Send + Sync + 'static,
) -> Result<(Client, mpsc::UnboundedReceiver<String>), Box<dyn std::error::Error>> {
    peer_with_behavior(reply, |_read| DEVICE, Duration::ZERO).await
}

async fn peer_with_behavior(
    reply: impl Fn(usize) -> Option<&'static str> + Send + Sync + 'static,
    identity: impl Fn(usize) -> &'static str + Send + Sync + 'static,
    delay_response: Duration,
) -> Result<(Client, mpsc::UnboundedReceiver<String>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (records, observed) = mpsc::unbounded_channel();
    let reply = Arc::new(reply);
    let upgrade_requests = Arc::new(AtomicUsize::new(0));
    let identity = Arc::new(identity);
    let status_requests = Arc::new(AtomicUsize::new(0));
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let records = records.clone();
            let reply = Arc::clone(&reply);
            let upgrade_requests = Arc::clone(&upgrade_requests);
            let identity = Arc::clone(&identity);
            let status_requests = Arc::clone(&status_requests);
            tokio::spawn(async move {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
                    match stream.read_u8().await {
                        Ok(b) => request.push(b),
                        Err(_) => return,
                    }
                }
                let Ok(request) = std::str::from_utf8(&request) else {
                    return;
                };
                let line = request.lines().next().unwrap_or_default();
                let mut fields = line.split_whitespace();
                let (Some(method), Some(path)) = (fields.next(), fields.next()) else {
                    return;
                };
                let body = match path {
                    "/rest/system/ping" => r#"{"ping":"pong"}"#.to_owned(),
                    "/rest/system/version" => {
                        r#"{"version":"v2.33.2","os":"darwin","arch":"arm64"}"#.to_owned()
                    }
                    "/rest/system/status" => {
                        let id = identity(status_requests.fetch_add(1, Ordering::SeqCst));
                        format!(r#"{{"myID":"{id}"}}"#)
                    }
                    "/rest/system/upgrade" => {
                        let _ = records.send(method.to_owned());
                        if let Some(reply) = reply(upgrade_requests.fetch_add(1, Ordering::SeqCst))
                        {
                            if !delay_response.is_zero() {
                                tokio::time::sleep(delay_response).await;
                            }
                            let _ = stream.write_all(reply.as_bytes()).await;
                        } else {
                            let _ = stream.read_u8().await;
                        }
                        return;
                    }
                    _ => panic!("unexpected synthetic request {path}"),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    let client = Client::connect(ConnectOptions::new(
        ManagementEndpoint::http(&format!("http://{address}"))?,
        ApiKey::new("synthetic-upgrade-key")?,
    ))
    .await?;
    Ok((client, observed))
}

const RELEASE: &str = concat!(
    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 72\r\n\r\n",
    "{\"running\":\"v2.33.2\",\"latest\":\"v2.33.3\",\"newer\":true,\"majorNewer\":false}"
);
const FORBIDDEN: &str = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const NO_RELEASE: &str = concat!(
    "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 36\r\n\r\n",
    "couldn't find a release to download\n"
);

#[tokio::test]
async fn opted_in_version_query_recovers_one_timeout_and_keeps_its_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let (client, mut observed) =
        peer_with_replies(|attempt| (attempt == 1).then_some(RELEASE)).await?;
    let report = client
        .with_transient_read_retries()
        .query_kernel_upgrade(OperationOptions::new(DEADLINE))
        .await?;
    let first = report
        .first_failed_attempt
        .as_ref()
        .ok_or("missing first attempt")?;
    assert!(matches!(first.source, Error::Timeout { .. }));
    assert_eq!(first.receipt.outcome(), UpgradeOutcome::QueryFailed);
    assert_eq!(
        first.receipt.operation_id(),
        report.final_attempt.receipt.operation_id()
    );
    assert_eq!(report.final_attempt.result?.latest, "v2.33.3");
    assert_eq!(observed.try_recv()?, "GET");
    assert_eq!(observed.try_recv()?, "GET");
    assert!(observed.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn per_operation_opt_out_and_complete_denial_send_only_one_query(
) -> Result<(), Box<dyn std::error::Error>> {
    for (source, disable) in [(None, true), (Some(FORBIDDEN), false)] {
        let (client, mut observed) =
            peer_with_replies(move |attempt| if attempt == 0 { source } else { Some(RELEASE) })
                .await?;
        let options = OperationOptions::new(DEADLINE);
        let options = if disable {
            options.without_read_retry()
        } else {
            options
        };
        let report = client
            .with_transient_read_retries()
            .query_kernel_upgrade(options)
            .await?;
        assert!(report.first_failed_attempt.is_none());
        if disable {
            assert!(matches!(
                report.final_attempt.result,
                Err(Error::Timeout { .. })
            ));
        } else {
            assert!(matches!(
                report.final_attempt.result,
                Err(Error::AccessDenied { .. })
            ));
        }
        assert_eq!(observed.try_recv()?, "GET");
        assert!(observed.try_recv().is_err());
    }
    Ok(())
}

#[tokio::test]
async fn slow_viable_query_and_native_no_release_stop_after_one_request(
) -> Result<(), Box<dyn std::error::Error>> {
    for reply in [RELEASE, NO_RELEASE] {
        let (client, mut observed) =
            peer_with_behavior(move |_| Some(reply), |_| DEVICE, Duration::from_millis(125))
                .await?;
        let report = client
            .with_transient_read_retries()
            .query_kernel_upgrade(OperationOptions::new(DEADLINE))
            .await?;
        assert!(report.first_failed_attempt.is_none());
        if reply == RELEASE {
            assert!(report.final_attempt.result.is_ok());
        } else {
            assert!(matches!(
                report.final_attempt.result,
                Err(Error::UpgradeReleaseUnavailable { .. })
            ));
        }
        assert_eq!(observed.try_recv()?, "GET");
        assert!(observed.try_recv().is_err());
    }
    Ok(())
}

#[tokio::test]
async fn bounded_read_retries_never_query_a_replacement_identity(
) -> Result<(), Box<dyn std::error::Error>> {
    let (client, mut observed) = peer_with_behavior(
        |attempt| (attempt == 1).then_some(RELEASE),
        |status| {
            if status < 2 {
                DEVICE
            } else {
                "BAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA"
            }
        },
        Duration::ZERO,
    )
    .await?;
    let report = client
        .with_transient_read_retries()
        .query_kernel_upgrade(OperationOptions::new(DEADLINE))
        .await?;
    assert!(matches!(
        report
            .first_failed_attempt
            .as_ref()
            .map(|item| &item.source),
        Some(Error::Timeout { .. })
    ));
    assert_eq!(
        report.final_attempt.receipt.dispatch(),
        UpgradeDispatch::Preparing
    );
    assert!(matches!(
        report.final_attempt.result,
        Err(Error::IdentityMismatch { .. })
    ));
    assert_eq!(observed.try_recv()?, "GET");
    assert!(observed.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn permanent_silence_stops_at_one_retry_and_cancellation_stops_during_backoff(
) -> Result<(), Box<dyn std::error::Error>> {
    let (client, mut calls) = peer(None).await?;
    let started = tokio::time::Instant::now();
    let report = client
        .with_transient_read_retries()
        .query_kernel_upgrade(OperationOptions::new(DEADLINE))
        .await?;
    assert!(report.first_failed_attempt.is_some());
    assert!(matches!(
        report.final_attempt.result,
        Err(Error::Timeout { .. })
    ));
    assert_eq!(calls.try_recv()?, "GET");
    assert_eq!(calls.try_recv()?, "GET");
    assert!(calls.try_recv().is_err());
    assert!(started.elapsed() < DEADLINE + Duration::from_millis(200));

    let (client, mut calls) = peer(None).await?;
    let (cancel, signal) = watch::channel(false);
    let (progress, mut phases) = watch::channel(OperationPhase::Pending);
    let client = client.with_transient_read_retries();
    let job = client.query_kernel_upgrade(
        OperationOptions::new(DEADLINE)
            .cancel_wait_on(signal)
            .report_progress_to(progress),
    );
    let (report, ()) = tokio::join!(job, async {
        phases
            .wait_for(|phase| *phase == OperationPhase::WaitingToRetry)
            .await
            .unwrap();
        cancel.send(true).unwrap();
    });
    let report = report?;
    assert!(report.first_failed_attempt.is_some());
    assert!(matches!(
        report.final_attempt.result,
        Err(Error::OperationWaitCancelled { .. })
    ));
    assert_eq!(
        report.final_attempt.receipt.dispatch(),
        UpgradeDispatch::Preparing
    );
    assert_eq!(*phases.borrow(), OperationPhase::Finished);
    assert_eq!(calls.try_recv()?, "GET");
    assert!(calls.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn query_expiry_reports_no_installation() -> Result<(), Box<dyn std::error::Error>> {
    let (client, mut observed) = peer(None).await?;
    let attempt = client.check_kernel_upgrade_with_receipt(DEADLINE).await?;
    assert!(matches!(attempt.result, Err(Error::Timeout { .. })));
    assert_eq!(attempt.receipt.outcome(), UpgradeOutcome::QueryFailed);
    assert_eq!(
        attempt.receipt.dispatch(),
        UpgradeDispatch::Http {
            status: None,
            complete: false
        }
    );
    assert_eq!(observed.try_recv()?, "GET");
    assert!(observed.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn installation_preserves_distinct_application_response_stages(
) -> Result<(), Box<dyn std::error::Error>> {
    for (reply, status, complete, outcome) in [
        ("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", 403, true, UpgradeOutcome::Rejected),
        ("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 20\r\n\r\n", 403, false, UpgradeOutcome::Unknown),
        ("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 19\r\n\r\n{\"ok\":\"restarting\"}", 200, true, UpgradeOutcome::Acknowledged),
        ("HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 36\r\n\r\ncouldn't find a release to download\n", 500, true, UpgradeOutcome::ReleaseUnavailable),
    ] {
        let (client, mut observed) = peer(Some(reply)).await?;
        let attempt = client.request_server_selected_upgrade_with_receipt(DEADLINE).await?;
        assert_eq!(attempt.receipt.dispatch(), UpgradeDispatch::Http { status: Some(status), complete });
        assert_eq!(attempt.receipt.outcome(), outcome);
        match outcome {
            UpgradeOutcome::Rejected => assert!(matches!(attempt.result, Err(Error::AccessDenied { .. }))),
            UpgradeOutcome::Unknown => assert!(matches!(attempt.result, Err(Error::MutationOutcomeUnknown { .. }))),
            UpgradeOutcome::ReleaseUnavailable => assert!(matches!(attempt.result, Err(Error::UpgradeReleaseUnavailable { .. }))),
            UpgradeOutcome::Acknowledged => assert!(attempt.result.is_ok()),
            other => panic!("unexpected expected outcome {other:?}"),
        }
        assert_eq!(observed.try_recv()?, "POST");
        assert!(observed.try_recv().is_err());
    }
    Ok(())
}

#[tokio::test]
async fn fixed_archive_preflight_preserves_legacy_error_and_sends_no_upgrade_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let (client, mut observed) = peer(None).await?;
    let target = verysync_sidecar::official_programs()?
        .into_iter()
        .next()
        .ok_or("fixed catalog is empty")?;
    assert!(matches!(
        client
            .upload_kernel_upgrade("relative-archive.zip", &target)
            .await,
        Err(Error::InvalidPath { .. })
    ));
    let attempt = client
        .upload_kernel_upgrade_with_receipt("relative-archive.zip", &target, DEADLINE)
        .await?;
    assert!(matches!(attempt.result, Err(Error::InvalidPath { .. })));
    assert_eq!(attempt.receipt.outcome(), UpgradeOutcome::NotSubmitted);
    assert_eq!(attempt.receipt.dispatch(), UpgradeDispatch::Preparing);
    assert_eq!(
        attempt.receipt.archive_sha256(),
        Some(target.archive_sha256())
    );
    assert!(observed.try_recv().is_err());
    assert!(!format!("{:?}", attempt.receipt).contains("synthetic-upgrade-key"));
    Ok(())
}
