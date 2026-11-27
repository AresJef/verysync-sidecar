//! Public upgrade receipt contracts over a caller-owned synthetic HTTP peer.
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
};
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, Error, ManagementEndpoint, UpgradeDispatch, UpgradeOutcome,
};

const DEVICE: &str = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";
const DEADLINE: Duration = Duration::from_millis(400);

async fn peer(
    reply: Option<&'static str>,
) -> Result<(Client, mpsc::UnboundedReceiver<String>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (records, observed) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let records = records.clone();
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
                    "/rest/system/status" => format!(r#"{{"myID":"{DEVICE}"}}"#),
                    "/rest/system/upgrade" => {
                        let _ = records.send(method.to_owned());
                        if let Some(reply) = reply {
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
