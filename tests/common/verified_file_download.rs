//! The fault injector and byte witness run outside the SDK.

use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use super::{mount, options, resource_faults, TestResult};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use verysync_sidecar::{
    Client, ConnectOptions, ManagedInstance, ManagementEndpoint, OperationCompletion,
    OperationOptions, RawMethod, RawRequest, RequestEffect, ResourceArchiveFormat,
    ResourceTransferOptions, VerifiedDownloadOptions,
};

const TOTAL: u64 = 2 * 1024 * 1024 + 17;
const CUT: u64 = 1536 * 1024;
const SOURCE: &str = "resume-synthetic-original.bin";

#[derive(Clone, Copy)]
enum FirstFault {
    Close,
    HoldUntilDeadline,
    Replace,
    AlterPrefix,
    WrongSuffix,
}

#[derive(Debug, Serialize)]
struct DataRequest {
    requested_range: Option<String>,
    native_status: u16,
    native_range: Option<String>,
    forwarded_bytes: u64,
}

struct TransferWitness {
    client: Client,
    records: Arc<Mutex<Vec<DataRequest>>>,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<TestResult>,
}

impl TransferWitness {
    async fn start(
        core: &ManagedInstance,
        source: PathBuf,
        output_root: PathBuf,
        fault: FirstFault,
    ) -> TestResult<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        assert_ne!(listener.local_addr()?.port(), 18886);
        let endpoint = ManagementEndpoint::http(&format!("http://{}/", listener.local_addr()?))?;
        let raw = core
            .client()
            .raw_request(&RawRequest::new(
                RawMethod::Get,
                ["rest", "config", "gui"],
                RequestEffect::ReadOnly,
            )?)
            .await?;
        assert_eq!(raw.status(), 200);
        let native: serde_json::Value = serde_json::from_slice(raw.body_bytes())?;
        let key_text = native["apiKey"]
            .as_str()
            .ok_or("owned fixture key missing")?;
        let key = verysync_sidecar::ApiKey::new(key_text)?;
        let mut authorized = reqwest::header::HeaderValue::from_str(key_text)?;
        authorized.set_sensitive(true);
        let builder = reqwest::Client::builder()
            .no_proxy()
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30));
        #[cfg(unix)]
        let (builder, origin) = (
            builder.unix_socket(
                core.client()
                    .endpoint()
                    .socket_path()
                    .ok_or("private Unix socket required")?,
            ),
            "http://localhost/".parse::<reqwest::Url>()?,
        );
        #[cfg(windows)]
        let origin = core
            .client()
            .endpoint()
            .http_url()
            .ok_or("private loopback endpoint required")?
            .clone();
        let transport = builder.build()?;
        let records = Arc::new(Mutex::new(Vec::new()));
        let observed = records.clone();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut phase = 0;
            loop {
                let (mut socket, _) = tokio::select! {
                    _ = &mut stopped => return Ok(()),
                    incoming = listener.accept() => incoming?,
                };
                let (route, range) = request(&mut socket, &authorized).await?;
                let mut url = origin.clone();
                url.set_path(route.path());
                url.set_query(route.query());
                let is_data = route.path().starts_with("/rest/f/api/raw/");
                if is_data || route.path().starts_with("/rest/f/api/resources/") {
                    assert!(route.path().ends_with(SOURCE), "unexpected fixture file");
                    if is_data {
                        assert_eq!(route.query(), Some("algo=none"));
                    } else {
                        assert_eq!(route.query(), Some("checksum=sha256"));
                        if phase == 1 && matches!(fault, FirstFault::AlterPrefix) {
                            let dir = fs::read_dir(&output_root)?
                                .filter_map(std::result::Result::ok)
                                .find(|e| {
                                    e.file_name()
                                        .to_string_lossy()
                                        .starts_with(".verysync-download-")
                                })
                                .ok_or("private file was not staged")?;
                            let mut file = fs::OpenOptions::new()
                                .write(true)
                                .open(dir.path().join("download.part"))?;
                            file.write_all(b"corrupted prefix")?;
                            file.sync_all()?;
                            phase = 2;
                        }
                    }
                } else if !matches!(route.path(), "/rest/system/status" | "/rest/system/version") {
                    return Err("unexpected route for the owned transfer fixture".into());
                }
                let mut outgoing = transport.get(url).header("X-API-Key", authorized.clone());
                if let Some(range) = &range {
                    outgoing = outgoing.header("Range", range);
                }
                let mut head = outgoing.send().await?;
                let native_status = head.status().as_u16();
                let native_range = head
                    .headers()
                    .get("content-range")
                    .map(|h| h.to_str().map(str::to_owned))
                    .transpose()?;
                let length = head
                    .content_length()
                    .ok_or("native fixture did not report content length")?;
                let mut headers = format!(
                    "HTTP/1.1 {native_status} Fixture\r\nConnection: close\r\nContent-Length: {length}\r\n"
                );
                if let Some(value) = head.headers().get("content-type") {
                    headers.push_str(&format!("Content-Type: {}\r\n", value.to_str()?));
                }
                if let Some(value) = &native_range {
                    if matches!(fault, FirstFault::WrongSuffix) {
                        headers.push_str(&format!(
                            "Content-Range: bytes {CUT}-{}/{}\r\n",
                            TOTAL - 1,
                            TOTAL + 1
                        ));
                    } else {
                        headers.push_str(&format!("Content-Range: {value}\r\n"));
                    }
                }
                headers.push_str("\r\n");
                socket.write_all(headers.as_bytes()).await?;
                let truncate = is_data && phase == 0;
                let limit = if truncate { CUT } else { length };
                let offered =
                    if is_data && matches!(fault, FirstFault::WrongSuffix) && range.is_some() {
                        0
                    } else {
                        forward(&mut socket, &mut head, limit, is_data).await?
                    };
                if truncate {
                    assert_eq!(offered, CUT);
                    phase = 1;
                    if matches!(fault, FirstFault::Replace) {
                        let original_time = fs::metadata(&source)?.modified()?;
                        let mut replacement = fs::OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .open(&source)?;
                        io::copy(&mut io::repeat(249).take(TOTAL), &mut replacement)?;
                        replacement.set_times(fs::FileTimes::new().set_modified(original_time))?;
                        replacement.sync_all()?;
                        assert_eq!(replacement.metadata()?.len(), TOTAL);
                        assert_eq!(replacement.metadata()?.modified()?, original_time);
                    }
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
                if is_data {
                    observed.lock().unwrap().push(DataRequest {
                        requested_range: range,
                        native_status,
                        native_range,
                        forwarded_bytes: offered,
                    });
                }
                if truncate && matches!(fault, FirstFault::HoldUntilDeadline) {
                    // The response remains incomplete until the caller's deadline closes it.
                    let mut byte = [0; 1];
                    assert_eq!(
                        tokio::time::timeout(Duration::from_secs(8), socket.read(&mut byte))
                            .await??,
                        0
                    );
                }
                socket.shutdown().await?;
            }
        });
        let client = Client::connect(
            ConnectOptions::new(endpoint, key)
                .expected_device_id(core.client().instance().device_id.clone()),
        )
        .await?;
        Ok(Self {
            client,
            records,
            stop,
            task,
        })
    }

    async fn finish(self) -> TestResult<Vec<DataRequest>> {
        let _ = self.stop.send(());
        tokio::time::timeout(Duration::from_secs(5), self.task).await???;
        Ok(std::mem::take(&mut *self.records.lock().unwrap()))
    }
}

async fn request(
    socket: &mut TcpStream,
    key: &reqwest::header::HeaderValue,
) -> TestResult<(reqwest::Url, Option<String>)> {
    let mut bytes = Vec::new();
    loop {
        let mut block = [0; 1024];
        let size = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut block)).await??;
        if size == 0 || bytes.len() + size > 16 * 1024 {
            return Err("bounded fixture request ended before the header boundary".into());
        }
        bytes.extend_from_slice(&block[..size]);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let mut lines = std::str::from_utf8(&bytes)?.lines();
    let mut first = lines.next().ok_or("missing request")?.split_whitespace();
    assert_eq!(first.next(), Some("GET"));
    let route = first.next().ok_or("missing request target")?;
    assert!(route.starts_with('/') && !route.starts_with("//"));
    let mut authorized = false;
    let mut range = None;
    for (name, value) in lines.filter_map(|line| line.split_once(':')) {
        if name.eq_ignore_ascii_case("x-api-key") {
            authorized = value.trim().as_bytes() == key.as_bytes();
        }
        if name.eq_ignore_ascii_case("range") {
            range = Some(value.trim().to_owned());
        }
    }
    assert!(authorized, "missing isolated fixture credential");
    Ok((
        reqwest::Url::parse(&format!("http://localhost{route}"))?,
        range,
    ))
}

async fn forward(
    socket: &mut TcpStream,
    source: &mut reqwest::Response,
    bound: u64,
    shaped: bool,
) -> TestResult<u64> {
    let mut count = 0;
    let start = tokio::time::Instant::now();
    while count < bound {
        let chunk = source
            .chunk()
            .await?
            .ok_or("native fixture body ended early")?;
        let size = (bound - count).min(chunk.len() as u64) as usize;
        socket.write_all(&chunk[..size]).await?;
        count += size as u64;
        if shaped {
            // Both policies share the same fixed wire pacing: 125 ns per byte.
            tokio::time::sleep_until(start + Duration::from_nanos(count * 125)).await;
        }
    }
    Ok(count)
}

fn limits(resume: bool) -> VerifiedDownloadOptions {
    let options =
        VerifiedDownloadOptions::new(TOTAL, OperationOptions::new(Duration::from_secs(12)));
    if resume {
        options.resume_once()
    } else {
        options
    }
}

#[tokio::test]
async fn verified_download_native_resumes_only_matching_versions() -> TestResult {
    let root = tempfile::Builder::new().prefix("vsdl-").tempdir()?;
    let mut core = ManagedInstance::start(options(&root.path().join("c"))?).await?;
    let result: TestResult = async {
        let (profile, volume, _) = mount(&core).await?;
        let source = profile.join(SOURCE);
        let resource = volume.child(SOURCE)?;
        for (index, label, fault, enable) in [
            (0, "enabled-before", FirstFault::Close, true),
            (1, "disabled-restart", FirstFault::Close, false),
            (2, "enabled-after", FirstFault::Close, true),
            (
                3,
                "same-size-and-mtime-replacement",
                FirstFault::Replace,
                true,
            ),
            (4, "corrupt-staging", FirstFault::AlterPrefix, true),
            (5, "wrong-suffix-total", FirstFault::WrongSuffix, true),
        ] {
            let (pattern, expected) = resource_faults::write_pattern(&source, TOTAL)?;
            let output_root = root.path().join(format!("case-{index}"));
            fs::create_dir(&output_root)?;
            let destination = output_root.join("new.bin");
            let witness =
                TransferWitness::start(&core, source.clone(), output_root.clone(), fault).await?;
            let start = Instant::now();
            let first = witness
                .client
                .download_file_and_verify(&resource, &destination, limits(enable))
                .await?;
            assert_eq!(first.source_sha256, Some(expected), "{label}: {first:?}");
            let mut restarted = false;
            if matches!(fault, FirstFault::Close) {
                let mut report = first;
                if !enable {
                    assert!(!destination.exists());
                    assert_eq!(report.completion(), OperationCompletion::PartiallyCompleted);
                    assert_eq!(report.data_requests, 1);
                    assert_retained_prefix(&report, &pattern)?;
                    restarted = true;
                    report = witness
                        .client
                        .download_file_and_verify(&resource, &destination, limits(false))
                        .await?;
                    assert_eq!(report.data_requests, 1);
                } else {
                    assert_eq!(report.data_requests, 2, "{report:?}");
                    assert!(report.initial_error.is_some());
                    assert_eq!(
                        report.resumed_range.map(|r| (r.first(), r.last())),
                        Some((CUT, TOTAL - 1))
                    );
                }
                assert_eq!(
                    report.completion(),
                    OperationCompletion::Completed,
                    "{report:?}"
                );
                assert!(report.cleanup_error.is_none() && report.retained_staging_path().is_none());
                assert_eq!(
                    report.completed.as_ref().map(|r| (r.bytes, r.sha256)),
                    Some((TOTAL, expected))
                );
                assert_eq!(
                    resource_faults::verify_pattern(&destination, &pattern, TOTAL)?,
                    (TOTAL, expected)
                );
            } else {
                assert!(!destination.exists());
                assert_eq!(
                    first.completion(),
                    OperationCompletion::PartiallyCompleted,
                    "{first:?}"
                );
                assert_eq!(first.staged_bytes, CUT, "{first:?}");
                assert!(first.initial_error.is_some());
                let text = first.error.as_ref().ok_or("missing refusal")?.to_string();
                let expected_reason = match fault {
                    FirstFault::Replace => "source file changed",
                    FirstFault::AlterPrefix => "staged file SHA-256 changed",
                    FirstFault::WrongSuffix => "exact verified suffix",
                    FirstFault::Close | FirstFault::HoldUntilDeadline => unreachable!(),
                };
                assert!(text.contains(expected_reason), "{label}: {text}");
                if matches!(fault, FirstFault::Replace | FirstFault::WrongSuffix) {
                    assert_retained_prefix(&first, &pattern)?;
                }
            }
            let elapsed = start.elapsed();
            let recorded = witness.finish().await?;
            let suffix = matches!(fault, FirstFault::WrongSuffix)
                || (matches!(fault, FirstFault::Close) && enable);
            assert_eq!(recorded.len(), if suffix || restarted { 2 } else { 1 });
            assert_eq!(recorded[0].forwarded_bytes, CUT);
            assert_eq!(recorded[0].native_status, 200);
            assert!(recorded[0].requested_range.is_none());
            if suffix {
                let observed = &recorded[1];
                assert_eq!(observed.native_status, 206);
                assert_eq!(
                    observed.requested_range,
                    Some(format!("bytes={CUT}-{}", TOTAL - 1))
                );
                assert_eq!(
                    observed.native_range,
                    Some(format!("bytes {CUT}-{}/{TOTAL}", TOTAL - 1))
                );
                let expected_bytes = if matches!(fault, FirstFault::WrongSuffix) {
                    0
                } else {
                    TOTAL - CUT
                };
                assert_eq!(observed.forwarded_bytes, expected_bytes);
            }
            if restarted {
                assert_eq!(recorded[1].native_status, 200);
                assert!(recorded[1].requested_range.is_none());
                assert_eq!(recorded[1].forwarded_bytes, TOTAL);
            }
            println!(
                "Verified single-file witness: case={label} elapsed_us={} requests={}",
                elapsed.as_micros(),
                serde_json::to_string(&recorded)?
            );
        }
        let (pattern, _) = resource_faults::write_pattern(&source, TOTAL)?;
        let deadline_root = root.path().join("deadline");
        fs::create_dir(&deadline_root)?;
        let destination = deadline_root.join("new.bin");
        let witness =
            TransferWitness::start(&core, source, deadline_root, FirstFault::HoldUntilDeadline)
                .await?;
        let report = witness
            .client
            .download_file_and_verify(
                &resource,
                &destination,
                VerifiedDownloadOptions::new(TOTAL, OperationOptions::new(Duration::from_secs(3)))
                    .resume_once(),
            )
            .await?;
        assert_eq!(report.data_requests, 1);
        assert!(matches!(
            report.error,
            Some(verysync_sidecar::Error::Timeout { .. })
        ));
        assert_eq!(report.completion(), OperationCompletion::PartiallyCompleted);
        assert!(!destination.exists());
        assert_retained_prefix(&report, &pattern)?;
        let recorded = witness.finish().await?;
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].forwarded_bytes, CUT);
        println!(
            "Verified single-file witness: case=total-deadline requests={}",
            serde_json::to_string(&recorded)?
        );
        Ok(())
    }
    .await;
    let exit = core.shutdown(Duration::from_secs(15)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    root.close()?;
    println!("Verified single-file owned exit and fixture removal: true");
    result
}

fn assert_retained_prefix(
    report: &verysync_sidecar::VerifiedDownloadReport,
    pattern: &[u8],
) -> TestResult {
    let retained = report
        .retained_staging_path()
        .ok_or("no private prefix retained")?;
    assert_eq!(
        resource_faults::verify_pattern(retained, pattern, TOTAL)?.0,
        CUT
    );
    Ok(())
}

#[tokio::test]
async fn verified_download_native_empty_zip_and_preflight() -> TestResult {
    let root = tempfile::Builder::new().prefix("vsde-").tempdir()?;
    let mut core = ManagedInstance::start(options(&root.path().join("c"))?).await?;
    let result: TestResult = async {
        let (profile, volume, _) = mount(&core).await?;
        fs::create_dir(profile.join("archive-source"))?;
        fs::write(profile.join("archive-source").join("only"), b"synthetic")?;
        let archive = root.path().join("original.zip");
        core.client().download_resource_archive(
            &volume.clone().child("archive-source")?, ResourceArchiveFormat::Zip,
            &archive, &ResourceTransferOptions::default(),
        ).await?;
        let archive = fs::read(archive)?;
        for (name, data) in [("empty", b"".as_slice()), ("valid.zip", archive.as_slice())] {
            fs::write(profile.join(name), data)?;
            let destination = root.path().join(name);
            let report = core.client().download_file_and_verify(
                &volume.clone().child(name)?, &destination, limits(true),
            ).await?;
            assert_eq!(report.completion(), OperationCompletion::Completed, "{name}: {report:?}");
            assert_eq!(report.data_requests, 1);
            assert_eq!(fs::read(destination)?, data);
        }
        let absent = root.path().join("disallowed");
        let directory = core.client().download_file_and_verify(
            &volume.clone().child("archive-source")?, &absent, limits(true),
        ).await?;
        assert_eq!(directory.data_requests, 0);
        assert_eq!(directory.completion(), OperationCompletion::GoalNotMet);
        assert!(!absent.exists());
        let sentinel = root.path().join("already-exists");
        fs::write(&sentinel, b"keep")?;
        let existed = core.client().download_file_and_verify(
            &volume.clone().child("valid.zip")?, &sentinel, limits(true),
        ).await?;
        assert_eq!(existed.data_requests, 0);
        assert_eq!(fs::read(sentinel)?, b"keep");
        let (_cancel, cancelled) = tokio::sync::watch::channel(true);
        let cancellation = VerifiedDownloadOptions::new(TOTAL, OperationOptions::new(Duration::from_secs(12)).cancel_wait_on(cancelled)).resume_once();
        let file = volume.child("valid.zip")?;
        let wrong_digest = core.client().download_file_and_verify(
            &file, &absent, limits(true).expected_sha256([0; 32]),
        ).await?;
        assert_eq!(wrong_digest.data_requests, 0);
        assert_eq!(wrong_digest.completion(), OperationCompletion::GoalNotMet);
        assert!(!absent.exists());
        let cancelled = core.client().download_file_and_verify(
            &file, &absent, cancellation,
        ).await?;
        assert_eq!(cancelled.data_requests, 0);
        assert!(matches!(cancelled.error, Some(verysync_sidecar::Error::OperationWaitCancelled { .. })));
        assert!(!absent.exists());
        println!("Verified single-file readback: empty=true archive_file=true directory_zero_data=true existing_unchanged=true digest_mismatch_zero_data=true cancelled_zero_data=true");
        Ok(())
    }.await;
    let exit = core.shutdown(Duration::from_secs(15)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    root.close()?;
    println!("Verified single-file basic fixture owned exit and removal: true");
    result
}
