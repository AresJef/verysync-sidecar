//! Public cache admission, offline and fixed identity contracts.
#![cfg(feature = "download")]
use verysync_sidecar::{official_programs, CachePolicy, Error, ProgramCache};

#[tokio::test]
async fn an_offline_miss_does_not_create_directories_or_contact_a_source() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("absent-cache");
    let cache = ProgramCache::new(&directory).unwrap();
    let result = cache
        .resolve(official_programs().unwrap().remove(0), CachePolicy::Offline)
        .await;
    assert!(matches!(result, Err(Error::CacheMiss)));
    assert!(!directory.exists());
}

#[tokio::test]
async fn caller_data_is_never_adopted_as_a_cache() {
    let root = tempfile::tempdir().unwrap();
    let sample = root.path().join("retain");
    std::fs::write(&sample, b"synthetic caller data").unwrap();
    let cache = ProgramCache::new(root.path()).unwrap();
    let result = cache
        .resolve(
            official_programs().unwrap().remove(0),
            CachePolicy::DownloadMissing,
        )
        .await;
    assert!(matches!(result, Err(Error::CacheRejected { .. })));
    assert_eq!(std::fs::read(sample).unwrap(), b"synthetic caller data");
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn an_explicit_empty_private_root_can_be_initialized_without_a_timed_marker_race() {
    use std::os::unix::fs::DirBuilderExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("empty-private");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let source = format!("http://{}/fixed", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        let _ = stream.read(&mut request).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });
    let result = ProgramCache::new(&directory)
        .unwrap()
        .source_url(source)
        .unwrap()
        .resolve(
            official_programs().unwrap().remove(0),
            CachePolicy::DownloadMissing,
        )
        .await;
    assert!(matches!(result, Err(Error::DownloadHttp { status: 403 })));
    server.await.unwrap();
    assert!(directory.join(".verysync-sidecar-cache-v1").is_dir());
}
