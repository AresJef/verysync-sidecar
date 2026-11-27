//! Loopback-only HTTP witness for the control reliability tests.
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const MAX_REQUEST: usize = 16 * 1024;
const MAX_ROWS: usize = 64;
const IO_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Submission,
    Recovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    Get,
    Patch,
    Post,
    Put,
    Delete,
    Other,
}

impl Method {
    fn parse(value: &str) -> Self {
        match value {
            "GET" => Self::Get,
            "PATCH" => Self::Patch,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    Version,
    Identity,
    Gui,
    RegistrationConfig,
    Peer,
    Unknown,
}

impl Route {
    fn parse(value: &str) -> Self {
        match value {
            "/rest/system/version" => Self::Version,
            "/rest/system/status" => Self::Identity,
            "/rest/config/gui" => Self::Gui,
            "/rest/config" => Self::RegistrationConfig,
            value if value.starts_with("/rest/config/devices/") => Self::Peer,
            _ => Self::Unknown,
        }
    }

    pub fn path(self) -> Option<&'static str> {
        match self {
            Self::Version => Some("/rest/system/version"),
            Self::Identity => Some("/rest/system/status"),
            Self::Gui => Some("/rest/config/gui"),
            Self::RegistrationConfig => Some("/rest/config"),
            Self::Peer | Self::Unknown => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    InFlight,
    RejectedByFixture,
    ResponseSent,
    DownstreamClosed,
    DroppedAfterBackendResponse,
    DroppedWithoutBackendResponse,
    BackendDisconnected,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Event {
    pub phase: Phase,
    pub origin: &'static str,
    pub method: Method,
    pub route: Route,
    pub credential_header: bool,
    pub backend_status: Option<u16>,
    pub delivery: Delivery,
}

struct Book {
    phase: Phase,
    rows: Vec<Event>,
    fault: bool,
}

/// Counts before forwarding so even a rejected or unanswered write is visible.
#[derive(Clone)]
pub struct Witness(Arc<Mutex<Book>>);

impl Witness {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Book {
            phase: Phase::Submission,
            rows: Vec::new(),
            fault: false,
        })))
    }

    pub fn recovery(&self) -> TestResult {
        let mut book = self.0.lock().map_err(|_| "fixture witness lock poisoned")?;
        if book
            .rows
            .iter()
            .any(|row| row.delivery == Delivery::InFlight)
        {
            return Err("fixture phase changes require completed requests".into());
        }
        book.phase = Phase::Recovery;
        Ok(())
    }

    pub fn rows(&self) -> TestResult<Vec<Event>> {
        let book = self.0.lock().map_err(|_| "fixture witness lock poisoned")?;
        if book.fault
            || book
                .rows
                .iter()
                .any(|row| row.delivery == Delivery::InFlight)
        {
            return Err("fixture request evidence is incomplete".into());
        }
        Ok(book.rows.clone())
    }

    fn record(&self, origin: &'static str, request: &Request) -> TestResult<(usize, Phase)> {
        let mut book = self.0.lock().map_err(|_| "fixture witness lock poisoned")?;
        if book.rows.len() >= MAX_ROWS {
            return Err("fixture request evidence exceeded its bound".into());
        }
        let phase = book.phase;
        let position = book.rows.len();
        book.rows.push(Event {
            phase,
            origin,
            method: request.method,
            route: request.route,
            credential_header: request.credential.is_some(),
            backend_status: None,
            delivery: Delivery::InFlight,
        });
        Ok((position, phase))
    }

    fn complete(&self, index: usize, response: &Response) -> TestResult {
        let mut book = self.0.lock().map_err(|_| "fixture witness lock poisoned")?;
        let row = &mut book.rows[index];
        row.delivery = response.delivery;
        row.backend_status = response.backend_status;
        Ok(())
    }
}

pub struct Request {
    pub method: Method,
    pub route: Route,
    pub credential: Option<reqwest::header::HeaderValue>,
    pub body: Vec<u8>,
    pub peer: Option<verysync_sidecar::DeviceId>,
}

pub struct Response {
    status: Option<u16>,
    backend_status: Option<u16>,
    body: Vec<u8>,
    delivery: Delivery,
}

impl Response {
    pub fn json(value: &serde_json::Value) -> TestResult<Self> {
        Ok(Self::forwarded(200, serde_json::to_vec(value)?))
    }

    pub fn rejected() -> Self {
        Self {
            status: Some(405),
            backend_status: None,
            body: Vec::new(),
            delivery: Delivery::RejectedByFixture,
        }
    }

    pub fn forwarded(status: u16, body: Vec<u8>) -> Self {
        Self {
            status: Some(status),
            backend_status: Some(status),
            body,
            delivery: Delivery::ResponseSent,
        }
    }

    pub fn drop_reply(backend_status: Option<u16>) -> Self {
        Self {
            status: None,
            backend_status,
            body: Vec::new(),
            delivery: if backend_status.is_some() {
                Delivery::DroppedAfterBackendResponse
            } else {
                Delivery::DroppedWithoutBackendResponse
            },
        }
    }

    pub fn backend_disconnected() -> Self {
        Self {
            delivery: Delivery::BackendDisconnected,
            ..Self::drop_reply(None)
        }
    }
}

pub struct Origin {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Origin {
    pub async fn start<F, Fut>(name: &'static str, witness: Witness, handle: F) -> TestResult<Self>
    where
        F: Fn(Phase, Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = TestResult<Response>> + Send + 'static,
    {
        Self::start_for_peer(name, witness, None, handle).await
    }

    pub async fn start_for_peer<F, Fut>(
        name: &'static str,
        witness: Witness,
        selected_peer: Option<verysync_sidecar::DeviceId>,
        handle: F,
    ) -> TestResult<Self>
    where
        F: Fn(Phase, Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = TestResult<Response>> + Send + 'static,
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        if addr.port() == 18886 {
            return Err("fixture may not use the default management port".into());
        }
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let result = tokio::time::timeout(IO_TIMEOUT, async {
                    let request = read_request(&mut stream).await?;
                    let (index, phase) = witness.record(name, &request)?;
                    let permitted_read = request.method == Method::Get && match request.route {
                        Route::Version | Route::Identity | Route::Gui => true,
                        Route::RegistrationConfig => selected_peer.is_some(),
                        _ => false,
                    };
                    let permitted_write = phase == Phase::Submission && (
                        request.method == Method::Patch && request.route == Route::Gui
                        || matches!(request.method, Method::Patch | Method::Delete)
                            && selected_peer.as_ref().is_some_and(|peer| request.peer.as_ref() == Some(peer))
                    );
                    let mut response = if permitted_read || permitted_write {
                        handle(phase, request).await?
                    } else {
                        Response::rejected()
                    };
                    if let Some(status) = response.status {
                        let head = format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.body.len());
                        if stream.write_all(head.as_bytes()).await.is_err()
                            || stream.write_all(&response.body).await.is_err()
                        {
                            response.delivery = Delivery::DownstreamClosed;
                        }
                    }
                    // Record the disposition before dropping the client stream.
                    witness.complete(index, &response)?;
                    Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                }).await;
                if !matches!(result, Ok(Ok(()))) {
                    if let Ok(mut book) = witness.0.lock() {
                        book.fault = true;
                    }
                }
            }
        });
        Ok(Self { addr, task })
    }

    pub fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    pub fn address(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_request(stream: &mut TcpStream) -> TestResult<Request> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    let head_end = loop {
        if let Some(start) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break start + 4;
        }
        read_more(stream, &mut bytes, &mut buffer).await?;
    };
    let head =
        std::str::from_utf8(&bytes[..head_end]).map_err(|_| "invalid fixture request encoding")?;
    let mut lines = head.split("\r\n");
    let mut first = lines
        .next()
        .ok_or("fixture request line absent")?
        .split(' ');
    let method = Method::parse(first.next().ok_or("fixture request method absent")?);
    let path = first.next().ok_or("fixture request route absent")?;
    let route = Route::parse(path);
    let peer = path
        .strip_prefix("/rest/config/devices/")
        .map(verysync_sidecar::DeviceId::parse)
        .transpose()?;
    if first.next() != Some("HTTP/1.1") || first.next().is_some() {
        return Err("fixture requires an HTTP/1.1 request line".into());
    }
    let mut length = None;
    let mut credential = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or("invalid fixture request header")?;
        match name.to_ascii_lowercase().as_str() {
            "content-length" if length.is_none() => {
                length = Some(value.trim().parse::<usize>()?);
            }
            "x-api-key" if credential.is_none() => {
                let mut value = reqwest::header::HeaderValue::from_str(value.trim())?;
                value.set_sensitive(true);
                credential = Some(value);
            }
            "content-length" | "transfer-encoding" | "x-api-key" => {
                return Err("unsupported fixture request framing".into());
            }
            _ => {}
        }
    }
    let end = head_end
        .checked_add(length.unwrap_or(0))
        .filter(|size| *size <= MAX_REQUEST)
        .ok_or("fixture request exceeded its bound")?;
    while bytes.len() < end {
        read_more(stream, &mut bytes, &mut buffer).await?;
    }
    if bytes.len() != end {
        return Err("fixture received unexpected pipelined data".into());
    }
    Ok(Request {
        method,
        route,
        credential,
        body: bytes.split_off(head_end),
        peer,
    })
}

async fn read_more(
    stream: &mut TcpStream,
    bytes: &mut Vec<u8>,
    buffer: &mut [u8; 1024],
) -> TestResult {
    let count = stream.read(buffer).await?;
    if count == 0 || bytes.len() + count > MAX_REQUEST {
        return Err("fixture request ended early or exceeded its bound".into());
    }
    bytes.extend_from_slice(&buffer[..count]);
    Ok(())
}

pub fn assert_read_only(rows: &[Event]) -> TestResult {
    if rows.is_empty()
        || rows.iter().any(|row| {
            row.phase != Phase::Recovery
                || row.method != Method::Get
                || row.route.path().is_none()
                || row.delivery != Delivery::ResponseSent
        })
    {
        return Err("recovery used a method or a route outside the read-only contract".into());
    }
    Ok(())
}
