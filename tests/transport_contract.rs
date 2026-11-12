//! Synthetic transport evidence, separate from real-engine acceptance.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, Error, ManagementEndpoint, VersionCompatibility, VersionPolicy,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const KEY: &str = "synthetic-transport-key";
const ID: &str = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";

#[cfg(not(feature = "tls"))]
#[tokio::test]
async fn https_without_tls_is_rejected_before_network_io() -> TestResult {
    let options = ConnectOptions::new(
        ManagementEndpoint::http("https://synthetic.invalid/")?,
        ApiKey::new(KEY)?,
    );
    assert!(matches!(
        Client::connect(options).await,
        Err(Error::UnsupportedTransport { .. })
    ));
    Ok(())
}

struct Reply {
    status: u16,
    body: Vec<u8>,
    headers: String,
    delay: Duration,
}
impl Reply {
    fn json(value: serde_json::Value) -> Self {
        Self {
            status: 200,
            body: serde_json::to_vec(&value).unwrap(),
            headers: String::new(),
            delay: Duration::ZERO,
        }
    }
}

struct ScriptedServer {
    base: String,
    task: Option<JoinHandle<TestResult<Vec<String>>>>,
}
impl ScriptedServer {
    async fn start(replies: Vec<Reply>) -> TestResult<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let base = format!("http://{}/prefix", listener.local_addr()?);
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for reply in replies {
                let (mut stream, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    let mut buffer = [0; 1024];
                    let count =
                        tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
                            .await??;
                    if count == 0 || bytes.len() + count > 16 * 1024 {
                        return Err("invalid synthetic HTTP request".into());
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                }
                requests.push(String::from_utf8(bytes)?);
                tokio::time::sleep(reply.delay).await;
                let head = format!(
                    "HTTP/1.1 {} Test\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n",
                    reply.status,
                    reply.body.len(),
                    reply.headers
                );
                // A deliberate timeout may close the client before this write.
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&reply.body).await;
            }
            Ok(requests)
        });
        Ok(Self {
            base,
            task: Some(task),
        })
    }
    fn options(&self) -> verysync_sidecar::Result<ConnectOptions> {
        Ok(ConnectOptions::new(
            ManagementEndpoint::http(&self.base)?,
            ApiKey::new(KEY)?,
        ))
    }
    async fn finish(mut self) -> TestResult<Vec<String>> {
        self.task
            .take()
            .ok_or("synthetic server already joined")?
            .await?
    }
}
impl Drop for ScriptedServer {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn version(value: &str) -> Reply {
    Reply::json(
        serde_json::json!({"version":value,"os":"synthetic-os","arch":"synthetic-arch","vendorExtension":{"preserved":true}}),
    )
}

#[tokio::test]
async fn unverified_version_requires_explicit_policy_and_retains_unknown_metadata() -> TestResult {
    let server = ScriptedServer::start(vec![version("v99.0.0")]).await?;
    let error = Client::connect(server.options()?).await.unwrap_err();
    assert!(matches!(error, Error::IncompatibleVersion { actual } if actual == "v99.0.0"));
    assert_eq!(server.finish().await?.len(), 1);

    let server = ScriptedServer::start(vec![
        version("v99.0.0"),
        Reply::json(serde_json::json!({"myID":ID})),
    ])
    .await?;
    let client = Client::connect(
        server
            .options()?
            .version_policy(VersionPolicy::AllowUnverified),
    )
    .await?;
    assert_eq!(
        client.instance().compatibility,
        VersionCompatibility::Unverified
    );
    assert_eq!(
        client.instance().version.extra["vendorExtension"]["preserved"],
        true
    );
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /prefix/rest/system/version HTTP/1.1\r\n"));
    assert!(requests[1].starts_with("GET /prefix/rest/system/status HTTP/1.1\r\n"));
    assert!(requests.iter().all(|request| request
        .to_ascii_lowercase()
        .contains(&format!("x-api-key: {KEY}\r\n"))));
    Ok(())
}

#[tokio::test]
async fn reflected_credentials_are_redacted_in_version_errors_and_client_debug() -> TestResult {
    let reflected = format!("v99.0.0+{KEY}");
    let server = ScriptedServer::start(vec![version(&reflected)]).await?;
    let error = Client::connect(server.options()?).await.unwrap_err();
    assert!(!format!("{error:?} {error}").contains(KEY));
    server.finish().await?;

    let server = ScriptedServer::start(vec![
        version(&reflected),
        Reply::json(serde_json::json!({"myID":ID})),
    ])
    .await?;
    let client = Client::connect(
        server
            .options()?
            .version_policy(VersionPolicy::AllowUnverified),
    )
    .await?;
    assert!(!format!("{client:?}").contains(KEY));
    server.finish().await?;
    Ok(())
}

#[tokio::test]
async fn redirects_are_not_followed_and_response_diagnostics_are_not_logged() -> TestResult {
    let destination = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    destination.set_nonblocking(true)?;
    let redirect = Reply {
        status: 302,
        body: KEY.as_bytes().to_vec(),
        headers: format!(
            "Location: http://{}/owned-redirect-target\r\n",
            destination.local_addr()?
        ),
        delay: Duration::ZERO,
    };
    let server = ScriptedServer::start(vec![redirect]).await?;
    let error = Client::connect(server.options()?).await.unwrap_err();
    assert!(!format!("{error:?} {error}").contains(KEY));
    match error {
        Error::Http { response } => {
            assert_eq!(response.status(), 302);
            assert_eq!(response.body_bytes(), KEY.as_bytes());
        }
        other => return Err(format!("unexpected synthetic redirect result: {other}").into()),
    }
    assert_eq!(
        destination.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(server.finish().await?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn malformed_metadata_or_identity_is_not_a_successful_connection() -> TestResult {
    for body in [
        serde_json::json!({}),
        serde_json::json!({"version":"","os":"linux","arch":"amd64"}),
    ] {
        let server = ScriptedServer::start(vec![Reply::json(body)]).await?;
        assert!(matches!(
            Client::connect(server.options()?).await,
            Err(Error::InvalidResponse {
                operation: "read version",
                ..
            })
        ));
        server.finish().await?;
    }
    let server = ScriptedServer::start(vec![
        version(verysync_sidecar::BASELINE_ENGINE_VERSION),
        Reply::json(serde_json::json!({"myID":"invalid-identity"})),
    ])
    .await?;
    assert!(matches!(
        Client::connect(server.options()?).await,
        Err(Error::InvalidResponse {
            operation: "read identity",
            ..
        })
    ));
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn management_reads_enforce_response_size_and_deadlines() -> TestResult {
    let mut large = version(verysync_sidecar::BASELINE_ENGINE_VERSION);
    large.body = vec![b'x'; 1024];
    let server = ScriptedServer::start(vec![large]).await?;
    assert!(matches!(
        Client::connect(server.options()?.response_limit(64)?).await,
        Err(Error::ResponseTooLarge { limit: 64 })
    ));
    server.finish().await?;

    let mut delayed = version(verysync_sidecar::BASELINE_ENGINE_VERSION);
    delayed.delay = Duration::from_secs(2);
    let server = ScriptedServer::start(vec![delayed]).await?;
    assert!(matches!(
        Client::connect(server.options()?.request_timeout(Duration::from_secs(1))?).await,
        Err(Error::Timeout {
            operation: "read version"
        })
    ));
    server.finish().await?;
    Ok(())
}

#[tokio::test]
async fn status_reads_are_fresh_preserve_unknowns_and_encode_folder_ids() -> TestResult {
    use verysync_sidecar::{FolderId, FolderState};
    let server=ScriptedServer::start(vec![
        version(verysync_sidecar::BASELINE_ENGINE_VERSION),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"synthetic-os","arch":"synthetic-arch","freshVendor":true})),
        Reply::json(serde_json::json!({"myID":ID,"vendorStatus":{"value":"sensitive-vendor-status"}})),
        Reply::json(serde_json::json!({"myID":ID,"uptime":7,"alloc":0,"cpuPercent":0,"goroutines":4})),
        Reply::json(serde_json::json!({"state":"future-hashing","localBytes":5,"vendorFolder":{"retained":true}})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let fresh_version = client.version().await?;
    assert_eq!(fresh_version.extra["freshVendor"], true);
    assert!(!client.instance().version.extra.contains_key("freshVendor"));
    let unknown = client.system_status().await?;
    assert_eq!(unknown.device_id.as_str(), ID);
    assert_eq!(unknown.uptime_seconds, None);
    assert_eq!(unknown.memory_allocated_bytes, None);
    assert_eq!(unknown.cpu_percent, None);
    assert_eq!(
        unknown.extra["vendorStatus"]["value"],
        "sensitive-vendor-status"
    );
    assert!(!format!("{unknown:?}").contains("sensitive-vendor-status"));
    let reported_zero = client.system_status().await?;
    assert_eq!(reported_zero.uptime_seconds, Some(7));
    assert_eq!(reported_zero.memory_allocated_bytes, Some(0));
    assert_eq!(reported_zero.cpu_percent, Some(0.0));
    let id = FolderId::parse("folder /?&中文")?;
    let status = client.folder_status(&id).await?;
    assert_eq!(
        status.state,
        Some(FolderState::Unknown("future-hashing".to_owned()))
    );
    assert_eq!(status.local_bytes, Some(5));
    assert_eq!(status.need_bytes, None);
    assert_eq!(status.extra["vendorFolder"]["retained"], true);
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 6);
    let path = requests[5].lines().next().ok_or("missing request line")?;
    assert!(path.starts_with("GET /prefix/rest/db/status?folder="));
    assert!(path.contains("folder+%2F%3F%26%E4%B8%AD%E6%96%87"));
    Ok(())
}

#[tokio::test]
async fn fresh_status_rejects_invalid_metrics_and_changed_identity() -> TestResult {
    let other = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    let server = ScriptedServer::start(vec![
        version(verysync_sidecar::BASELINE_ENGINE_VERSION),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID,"alloc":-1})),
        Reply::json(serde_json::json!({"myID":other,"uptime":9})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client.system_status().await,
        Err(Error::InvalidResponse { .. })
    ));
    assert!(matches!(
        client.system_status().await,
        Err(Error::IdentityMismatch { .. })
    ));
    server.finish().await?;
    Ok(())
}
