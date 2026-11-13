//! Public explicit program preparation contracts.
#![cfg(feature = "download")]

use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use verysync_sidecar::{official_programs, DownloadOptions, Error};

async fn source(status: u16, length: u64, stall: bool) -> (url::Url, JoinHandle<()>) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let url = format!("http://{}/fixed-archive", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 4096];
        let _ = stream.read(&mut request).await;
        let header = format!(
            "HTTP/1.1 {status} Test\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
        );
        if stream.write_all(header.as_bytes()).await.is_err() {
            return;
        }
        let bytes = [0; 64 * 1024];
        let mut remaining = length;
        while remaining > 0 {
            let n = remaining.min(bytes.len() as u64) as usize;
            if stream.write_all(&bytes[..n]).await.is_err() {
                return;
            }
            remaining -= n as u64;
            if stall {
                std::future::pending::<()>().await;
            }
        }
    });
    (url, task)
}

async fn cleaned(path: &std::path::Path) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("native file owner must finish cleanup");
}

#[tokio::test]
async fn http_length_and_checksum_failures_never_enable_a_program() {
    let root = tempfile::tempdir().unwrap();
    let asset = official_programs().unwrap().remove(0);
    for (case, status, length) in [
        ("status", 403, 0),
        ("short", 200, 12),
        ("digest", 200, asset.archive_bytes()),
    ] {
        let destination = root.path().join(case);
        let (url, server) = source(status, length, false).await;
        let result = DownloadOptions::new(asset.clone(), &destination)
            .unwrap()
            .source_url(url)
            .unwrap()
            .prepare()
            .await;
        assert!(result.is_err());
        cleaned(&destination).await;
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn cancellation_and_deadline_clean_actual_partial_files() {
    let root = tempfile::tempdir().unwrap();
    let asset = official_programs().unwrap().remove(0);
    for timed in [false, true] {
        let destination = root.path().join(if timed { "deadline" } else { "cancel" });
        let (url, server) = source(200, asset.archive_bytes(), true).await;
        let options = DownloadOptions::new(asset.clone(), &destination)
            .unwrap()
            .source_url(url)
            .unwrap();
        let options = if timed {
            options.timeout(Duration::from_millis(500)).unwrap()
        } else {
            options
        };
        let transfer = tokio::spawn(options.prepare());
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if std::fs::metadata(destination.join("archive.part")).is_ok_and(|m| m.len() > 0) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("observe real streamed bytes before cancellation");
        if timed {
            assert!(matches!(
                transfer.await.unwrap(),
                Err(Error::Timeout { .. })
            ));
        } else {
            transfer.abort();
            assert!(transfer.await.unwrap_err().is_cancelled());
        }
        cleaned(&destination).await;
        server.abort();
        let _ = server.await;
    }
}

#[test]
fn runtime_shutdown_cleans_partial_files_without_a_running_executor() {
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("runtime-cancelled");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let asset = official_programs().unwrap().remove(0);
        let (url, _server) = source(200, asset.archive_bytes(), true).await;
        let transfer = tokio::spawn(
            DownloadOptions::new(asset, &destination)
                .unwrap()
                .source_url(url)
                .unwrap()
                .prepare(),
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if std::fs::metadata(destination.join("archive.part")).is_ok_and(|m| m.len() > 0) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        // Dropping the handle leaves the task running until runtime shutdown.
        drop(transfer);
    });
    drop(runtime);
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while destination.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!destination.exists());
}

#[test]
fn preparation_is_explicit_and_rejects_ambiguous_inputs_without_io() {
    let asset = official_programs().unwrap().remove(0);
    assert!(DownloadOptions::new(asset.clone(), "relative").is_err());
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("not-created");
    let options = DownloadOptions::new(asset, &destination).unwrap();
    assert!(options.clone().timeout(Duration::ZERO).is_err());
    for source in [
        "http://example.invalid/a",
        "https://user:secret@example.invalid/a",
        "https://example.invalid/a?token=secret",
        "https://example.invalid/a#fragment",
    ] {
        assert!(options.clone().source_url(source.parse().unwrap()).is_err());
    }
    assert!(!destination.exists());
}

#[tokio::test]
async fn an_existing_destination_is_never_modified_or_used_as_an_implicit_cache() {
    let root = tempfile::tempdir().unwrap();
    let sample = root.path().join("sample");
    std::fs::write(&sample, b"retain synthetic sample").unwrap();
    let asset = official_programs().unwrap().remove(0);
    let result = DownloadOptions::new(asset, root.path())
        .unwrap()
        .prepare()
        .await;
    assert!(matches!(result, Err(Error::DownloadRejected { .. })));
    assert_eq!(std::fs::read(sample).unwrap(), b"retain synthetic sample");
}
