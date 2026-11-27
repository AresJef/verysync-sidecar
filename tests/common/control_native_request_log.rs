//! Independently count what the isolated native REST server actually handled.
use crate::control_fault_origin::{Route, TestResult};
use crate::forward_http;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use verysync_sidecar::{Client, CoreLogLevel};

const CAPTURE_LIMIT: u64 = 65_536;
const MARKER_ROUTE: &str = "/rest/system/ping";
const LOG_FILE: &str = ".verysync-sidecar-core.log";
const MARKER_POLL: Duration = Duration::from_millis(10);
const MARKER_WAIT: Duration = Duration::from_secs(3);

pub async fn enable(client: &Client) -> TestResult {
    let update = client
        .set_core_log_levels(&BTreeMap::from([("api".to_owned(), CoreLogLevel::Debug)]))
        .await?;
    if !update.requested_levels_match
        || update.configuration.levels.get("api") != Some(&CoreLogLevel::Debug)
    {
        return Err("the isolated native API logger did not confirm its DEBUG level".into());
    }
    Ok(())
}

pub struct LogWindow<'a> {
    path: PathBuf,
    address: SocketAddr,
    api_key: &'a str,
    before: String,
    after: String,
}

impl<'a> LogWindow<'a> {
    pub fn new(state: &Path, address: SocketAddr, api_key: &'a str) -> TestResult<Self> {
        if address.ip() != Ipv4Addr::LOCALHOST || matches!(address.port(), 0 | 18886) {
            return Err("native request witness requires the isolated loopback listener".into());
        }
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| "native marker entropy unavailable")?;
        let nonce: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            path: state.join(LOG_FILE),
            address,
            api_key,
            before: format!("{MARKER_ROUTE}?test_control_start={nonce}"),
            after: format!("{MARKER_ROUTE}?test_control_end={nonce}"),
        })
    }

    pub async fn open(&self) -> TestResult {
        self.marker(&self.before).await?;
        let start = Instant::now();
        loop {
            let current = self.snapshot()?;
            if marker_count(&current, &self.before) == 1 {
                return Ok(());
            }
            if start.elapsed() >= MARKER_WAIT {
                return Err("native request witness did not find its first unique marker".into());
            }
            tokio::time::sleep(MARKER_POLL).await;
        }
    }

    pub async fn close(&self) -> TestResult<Value> {
        self.marker(&self.after).await?;
        let start = Instant::now();
        loop {
            let current = self.snapshot()?;
            if marker_count(&current, &self.after) == 1 {
                let routes = read_window(&current, &self.before, &self.after)?;
                return Ok(json!({
                    "source":"owned_native_api_request_log",
                    "ordered_reads":routes,
                    "request_count":routes.len(),
                    "modifications_received":0,
                    "both_native_markers_present":true
                }));
            }
            if start.elapsed() >= MARKER_WAIT {
                return Err("native request witness did not find its second unique marker".into());
            }
            tokio::time::sleep(MARKER_POLL).await;
        }
    }

    async fn marker(&self, path: &str) -> TestResult {
        let response = forward_http()?
            .get(format!("http://{}{path}", self.address))
            .header("x-api-key", self.api_key)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err("native read-only witness marker did not receive success".into());
        }
        let bytes = response.bytes().await?;
        if bytes.len() > 1024 || serde_json::from_slice::<Value>(&bytes)?["ping"] != "pong" {
            return Err("native read-only witness did not receive its expected pong".into());
        }
        Ok(())
    }

    fn snapshot(&self) -> TestResult<String> {
        let mut bytes = Vec::new();
        std::fs::File::open(&self.path)?
            .take(CAPTURE_LIMIT + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > CAPTURE_LIMIT {
            return Err("native request witness exceeded its private size limit".into());
        }
        String::from_utf8(bytes).map_err(|_| "native request witness was not UTF-8".into())
    }
}

#[derive(Clone, Copy)]
struct Entry<'a> {
    method: &'a str,
    path: &'a str,
}

fn request(line: &str) -> TestResult<Option<Entry<'_>>> {
    let Some((_, suffix)) = line.split_once("http: ") else {
        return Ok(None);
    };
    let (method, rest) = suffix
        .split_once(" \"")
        .ok_or("malformed native request record in the observation window")?;
    let (path, result) = rest
        .split_once("\": status ")
        .ok_or("malformed native request path in the observation window")?;
    let (status, _) = result
        .split_once(',')
        .ok_or("native request record has no response status")?;
    if !method.bytes().all(|byte| byte.is_ascii_uppercase()) || status.parse::<u16>().is_err() {
        return Err("native request record has an invalid method or status".into());
    }
    Ok(Some(Entry { method, path }))
}

fn marker_count(source: &str, path: &str) -> usize {
    source
        .lines()
        .filter_map(|line| request(line).ok().flatten())
        .filter(|entry| entry.method == "GET" && entry.path == path)
        .count()
}

fn read_window(source: &str, before: &str, after: &str) -> TestResult<Vec<Route>> {
    if marker_count(source, before) != 1 || marker_count(source, after) != 1 {
        return Err("native request witness requires both unique markers after readback".into());
    }
    let mut open = false;
    let mut routes = Vec::new();
    for line in source.lines() {
        if !open {
            if request(line)
                .ok()
                .flatten()
                .is_some_and(|entry| entry.path == before)
            {
                open = true;
            }
            continue;
        }
        let Some(entry) = request(line)? else {
            continue;
        };
        if entry.path == after && entry.method == "GET" {
            return Ok(routes);
        }
        if entry.method != "GET" {
            return Err("native recovery handled a request whose method was not GET".into());
        }
        routes.push(match entry.path {
            "/rest/system/version" => Route::Version,
            "/rest/system/status" => Route::Identity,
            "/rest/config/gui" => Route::Gui,
            "/rest/config" => Route::RegistrationConfig,
            _ => {
                return Err(
                    "native recovery handled a route outside the read-only allowlist".into(),
                )
            }
        });
    }
    Err("native request markers were out of order".into())
}

#[test]
fn native_log_window_identifies_requests_without_emitting_payloads() -> TestResult {
    let before = "/rest/system/ping?test_control_start=unique";
    let after = "/rest/system/ping?test_control_end=unique";
    let line = |method: &str, path: &str| {
        format!("native-prefix http: {method} \"{path}\": status 200, 1 bytes in 0.02 ms\n")
    };
    let first = line("GET", before);
    let last = line("GET", after);
    let recovered = line("GET", "/rest/system/version") + &line("GET", "/rest/config/gui");
    assert_eq!(
        read_window(&format!("{first}{recovered}{last}"), before, after)?,
        [Route::Version, Route::Gui]
    );
    for changed in [
        format!("{last}{recovered}{first}"),
        format!("{first}{recovered}"),
        format!("{first}{recovered}{last}{last}"),
        format!("{first}{}{last}", line("PATCH", "/rest/config/gui")),
        format!("{first}{}{last}", line("GET", "/rest/svc/folder/secret")),
        format!("{first}native-prefix http: incomplete!\n{last}"),
    ] {
        assert!(read_window(&changed, before, after).is_err());
    }
    Ok(())
}
