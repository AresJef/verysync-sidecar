//! Test-only response faults between a public Client and its exact owned fixture.

use super::engine_fixture::{EngineFixture, TestResult};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;
use verysync_sidecar::ManagementEndpoint;

#[derive(Clone, Copy)]
pub enum ResponseFault {
    DropAfterApply,
    HoldAfterApply,
}

pub struct ResponseProxy {
    endpoint: ManagementEndpoint,
    task: Option<JoinHandle<TestResult<()>>>,
    stop: watch::Sender<bool>,
    applied: Arc<Notify>,
    release: Arc<Notify>,
    posts: Arc<AtomicUsize>,
}

impl ResponseProxy {
    pub async fn start(instance: &EngineFixture, fault: ResponseFault) -> TestResult<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let endpoint = ManagementEndpoint::http(&format!("http://{}/", listener.local_addr()?))?;
        let builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(10));
        #[cfg(unix)]
        let (builder, base) = (
            builder.unix_socket(instance.state_dir().join("gui.sock")),
            "http://localhost".to_owned(),
        );
        #[cfg(windows)]
        let base = format!("http://{}", instance.management_address());
        let upstream = builder.build()?;
        let mut key = reqwest::header::HeaderValue::from_str(instance.api_key())?;
        key.set_sensitive(true);
        let (stop, mut stopped) = watch::channel(false);
        let applied = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let posts = Arc::new(AtomicUsize::new(0));
        let (notify, resume, count) = (applied.clone(), release.clone(), posts.clone());
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = tokio::select! {
                    changed = stopped.changed() => { let _ = changed; break; },
                    incoming = listener.accept() => incoming?,
                };
                let mut bytes = Vec::new();
                let end = loop {
                    if let Some(offset) = bytes.windows(4).position(|p| p == b"\r\n\r\n") {
                        break offset + 4;
                    }
                    let mut buffer = [0; 1024];
                    let n = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buffer))
                        .await??;
                    if n == 0 || bytes.len() + n > 16 * 1024 {
                        return Err("invalid bounded fault-proxy request".into());
                    }
                    bytes.extend_from_slice(&buffer[..n]);
                };
                let headers = std::str::from_utf8(&bytes[..end])?;
                let authorized =
                    headers
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .any(|(name, value)| {
                            name.eq_ignore_ascii_case("x-api-key")
                                && value.trim().as_bytes() == key.as_bytes()
                        });
                if !authorized {
                    return Err(
                        "fault-proxy request lacks its dedicated management credential".into(),
                    );
                }
                let mut first = headers
                    .lines()
                    .next()
                    .ok_or("missing request line")?
                    .split_whitespace();
                let method = first.next().ok_or("missing method")?.to_owned();
                let route = first.next().ok_or("missing route")?.to_owned();
                if !matches!(
                    route.as_str(),
                    "/rest/system/version"
                        | "/rest/system/status"
                        | "/rest/config"
                        | "/rest/config/defaults/folder"
                        | "/rest/config/folders"
                ) || !matches!(method.as_str(), "GET" | "POST")
                {
                    return Err("fault proxy received an unapproved fixture route".into());
                }
                let length = headers
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map(|(_, v)| v.trim().parse::<usize>())
                    .transpose()?
                    .unwrap_or(0);
                if end + length > 16 * 1024 {
                    return Err("fault-proxy request body exceeds its bound".into());
                }
                while bytes.len() < end + length {
                    let mut buffer = [0; 1024];
                    let n = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buffer))
                        .await??;
                    if n == 0 {
                        return Err("fault-proxy request ended early".into());
                    }
                    bytes.extend_from_slice(&buffer[..n]);
                }
                let mutation = method == "POST" && route == "/rest/config/folders";
                if mutation {
                    count.fetch_add(1, Ordering::SeqCst);
                }
                let mut request = upstream
                    .request(
                        reqwest::Method::from_bytes(method.as_bytes())?,
                        format!("{base}{route}"),
                    )
                    .header("X-API-Key", key.clone());
                if length > 0 {
                    request = request
                        .header("Content-Type", "application/json")
                        .body(bytes[end..end + length].to_vec());
                }
                let mut response = request.send().await?;
                let status = response.status().as_u16();
                let mut body = Vec::new();
                while let Some(chunk) = response.chunk().await? {
                    if body.len() + chunk.len() > 1024 * 1024 {
                        return Err("fault-proxy upstream response exceeds its bound".into());
                    }
                    body.extend_from_slice(&chunk);
                }
                if mutation {
                    if !(200..300).contains(&status) {
                        return Err("fixture mutation was rejected before fault injection".into());
                    }
                    notify.notify_one();
                    match fault {
                        ResponseFault::DropAfterApply => continue,
                        ResponseFault::HoldAfterApply => tokio::select! {
                            _=resume.notified()=>(),
                            changed=stopped.changed()=>{let _=changed;break;},
                        },
                    }
                }
                let head = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                // Timeout/cancellation may have closed this owned client socket.
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&body).await;
            }
            Ok(())
        });
        Ok(Self {
            endpoint,
            task: Some(task),
            stop,
            applied,
            release,
            posts,
        })
    }
    pub fn endpoint(&self) -> ManagementEndpoint {
        self.endpoint.clone()
    }
    pub async fn mutation_applied(&self) {
        self.applied.notified().await;
    }
    pub fn release_response(&self) {
        self.release.notify_one();
    }
    pub fn post_count(&self) -> usize {
        self.posts.load(Ordering::SeqCst)
    }
    pub async fn finish(mut self) -> TestResult<()> {
        let _ = self.stop.send(true);
        let mut task = self.task.take().ok_or("fault proxy already joined")?;
        match tokio::time::timeout(Duration::from_secs(10), &mut task).await {
            Ok(joined) => joined??,
            Err(_) => {
                task.abort();
                let _ = task.await;
                return Err(
                    "fault proxy shutdown deadline exceeded; task aborted and joined".into(),
                );
            }
        }
        Ok(())
    }
}
impl Drop for ResponseProxy {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
