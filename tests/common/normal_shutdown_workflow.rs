//! A private TCP witness observes exactly the SDK's single shutdown request.

use std::{
    net::Ipv4Addr,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use verysync_sidecar::{
    ApiKey, ConnectOptions, Error, ManagedInstance, ManagedOptions, ManagementEndpoint,
    OperationOptions,
};

use crate::{managed_fixture, TestResult};

#[tokio::test]
async fn native_shutdown_receipt_preserves_timeout_and_observes_late_exit() -> TestResult {
    exercise_shutdown(true).await
}

#[tokio::test]
async fn native_shutdown_receipt_preserves_unconfirmed_exit_without_retry() -> TestResult {
    exercise_shutdown(false).await
}

async fn fixture_options(root: &Path) -> TestResult<ManagedOptions> {
    let base = managed_fixture::options(&root.join("state"))?;
    let reserve = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let endpoint = ManagementEndpoint::http(&format!("http://{}/", reserve.local_addr()?))?;
    Ok(ManagedOptions::new(
        base.program().clone(),
        base.state_directory(),
        endpoint,
    )?)
}

async fn header(stream: &mut TcpStream) -> TestResult<String> {
    let mut data = Vec::new();
    while !data.ends_with(b"\r\n\r\n") && data.len() < 8192 {
        data.push(stream.read_u8().await?);
    }
    if !data.ends_with(b"\r\n\r\n") {
        return Err("private management header exceeded the bound".into());
    }
    Ok(String::from_utf8(data)?)
}

async fn exercise_shutdown(late: bool) -> TestResult {
    let root = tempfile::Builder::new().prefix("s30-stop-").tempdir()?;
    let options = fixture_options(root.path()).await?;
    let mut core = ManagedInstance::start(options.clone()).await?;
    let direct = core.client().clone();
    let device = direct.instance().device_id.clone();
    let original = core.control_generation();
    let pid = core.process_id();
    let preserved = root.path().join("sample.bin");
    std::fs::write(&preserved, b"preserve this synthetic content")?;
    let config = std::fs::File::open(core.state_directory().join("setting.dat"))?;
    let key = rmpv::decode::read_value(&mut std::io::BufReader::new(config))?;
    let key = ApiKey::new(
        key["4"]["6"]
            .as_str()
            .ok_or("private fixture key missing")?,
    )?;
    let native_port = options
        .management_endpoint()
        .http_url()
        .and_then(|url| url.port())
        .ok_or("private native port missing")?;
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let endpoint = ManagementEndpoint::http(&format!("http://{}/", proxy.local_addr()?))?;
    let requests = Arc::new(AtomicUsize::new(0));
    let forwarded = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&requests);
    let observed_forward = Arc::clone(&forwarded);
    let mut server = tokio::spawn(async move {
        loop {
            let (mut source, _) = proxy.accept().await?;
            let request = header(&mut source).await?;
            let shutdown = request.starts_with("POST /rest/system/shutdown ");
            if shutdown {
                assert_eq!(observed.fetch_add(1, Ordering::SeqCst), 0);
                if !late {
                    let _ = source.read_u8().await;
                    continue;
                }
                // The old first wait ends at 10 seconds. Forward the already
                // received original request after that same old boundary.
                tokio::time::sleep(Duration::from_millis(10200)).await;
            } else {
                assert!(request.starts_with("GET "));
            }
            let mut target = TcpStream::connect((Ipv4Addr::LOCALHOST, native_port)).await?;
            let rewritten = request
                .lines()
                .filter(|line| {
                    !line.is_empty() && !line.to_ascii_lowercase().starts_with("connection:")
                })
                .collect::<Vec<_>>()
                .join("\r\n")
                + "\r\nConnection: close\r\n\r\n";
            target.write_all(rewritten.as_bytes()).await?;
            if shutdown {
                observed_forward.fetch_add(1, Ordering::SeqCst);
                let mut response = Vec::new();
                target.take(65537).read_to_end(&mut response).await?;
                assert!(response.starts_with(b"HTTP/1.1 200 ") && response.len() <= 65536);
                let _ = source.write_all(&response).await;
            } else {
                tokio::io::copy_bidirectional(&mut source, &mut target).await?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    core.reconnect_management(
        ConnectOptions::new(endpoint, key).expected_device_id(device.clone()),
    )
    .await?;
    let overall = if late {
        Duration::from_secs(24)
    } else {
        Duration::from_secs(4)
    };
    let result = core.shutdown_and_verify(OperationOptions::new(overall));
    let report = tokio::select! {
        result = result => result?,
        ended = &mut server => { ended??; return Err("private shutdown witness stopped early".into()); },
    };
    assert_eq!(
        report.initial_limit,
        if late {
            Duration::from_secs(10)
        } else {
            Duration::from_secs(2)
        }
    );
    assert_eq!(report.generation, original);
    assert_eq!(core.control_generation(), original);
    assert_eq!(core.process_id(), pid);
    assert!(matches!(report.original, Err(Error::Timeout { .. })));
    assert!(report.request.dispatched);
    assert_eq!(report.request.status, None);
    assert!(!report.request.response_complete);
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    assert_eq!(forwarded.load(Ordering::SeqCst), usize::from(late));
    if late {
        let exit = report
            .confirmed_exit()
            .ok_or("late native exit was not confirmed")?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    } else {
        assert!(report.confirmed_exit().is_none());
        assert_eq!(direct.system_status().await?.device_id, device);
        // Explicit fixture cleanup through the original direct endpoint,
        // after the call has returned. This is outside the observed operation.
        direct.request_shutdown().await?;
        let exit = tokio::time::timeout(Duration::from_secs(15), core.wait_for_exit()).await??;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    assert_eq!(
        std::fs::read(preserved)?,
        b"preserve this synthetic content"
    );
    server.abort();
    assert!(server.await.is_err_and(|error| error.is_cancelled()));
    drop(core);

    let mut replacement = ManagedInstance::start(options).await?;
    assert_eq!(replacement.client().instance().device_id, device);
    assert_ne!(replacement.control_generation(), original);
    let replaced = replacement
        .observe_control_exit(&original, Duration::from_secs(1))
        .await;
    assert!(matches!(replaced, Err(Error::ManagedFailure { .. })));
    let exit = replacement.shutdown(Duration::from_secs(15)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    drop(replacement);
    root.close()?;
    println!(
        "sdk shutdown workflow {}",
        json!({
            "late_case":late,"first_limit_ms":report.initial_limit.as_millis(),
            "first_timeout":true,"sdk_submissions":1,"forwarded_shutdowns":usize::from(late),
            "same_owner_confirmed_by_later_read":report.confirmed_exit().is_some(),
            "original_request_result":report.original.as_ref().err().map(ToString::to_string),
            "user_result":report.to_string(),"replacement_generation_rejected":true,
            "both_instances_cleaned":true
        })
    );
    Ok(())
}
