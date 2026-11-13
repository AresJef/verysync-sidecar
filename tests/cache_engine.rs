//! Fixed archive cache effects, actual running-program preservation and native callers.
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use verysync_sidecar::{
    official_programs, BuildVariant, CachePolicy, CacheStatus, Error, ManagedInstance,
    ManagedOptions, ManagementEndpoint, OfficialProgram, ProgramArchitecture, ProgramCache,
    ProgramOs,
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn fixture() -> TestResult<(OfficialProgram, Arc<Vec<u8>>)> {
    let os = match std::env::consts::OS {
        "macos" => ProgramOs::MacOs,
        "windows" => ProgramOs::Windows,
        "linux" => ProgramOs::Linux,
        _ => return Err("native fixture required".into()),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => ProgramArchitecture::Amd64,
        "aarch64" => ProgramArchitecture::Arm64,
        _ => return Err("native fixture architecture required".into()),
    };
    let asset = official_programs()?
        .into_iter()
        .find(|a| {
            a.target().os() == os
                && a.target().architecture() == arch
                && a.target().variant() == BuildVariant::Standard
        })
        .ok_or("exact native archive required")?;
    let path = PathBuf::from(
        std::env::var_os("VERYSYNC_TEST_ARCHIVE")
            .ok_or("explicit verified private archive required")?,
    );
    assert!(std::fs::metadata(&path)?.len() <= 32 * 1024 * 1024);
    let bytes = std::fs::read(path)?;
    assert_eq!(bytes.len() as u64, asset.archive_bytes());
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&bytes)),
        asset.archive_sha256()
    );
    Ok((asset, Arc::new(bytes)))
}
struct Mirror {
    url: url::Url,
    requests: Arc<AtomicUsize>,
    stall_next: Arc<AtomicBool>,
    task: JoinHandle<()>,
    release: Arc<tokio::sync::Notify>,
}
impl Drop for Mirror {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Mirror {
    async fn new(data: Arc<Vec<u8>>) -> TestResult<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("http://{}/fixed", listener.local_addr()?).parse()?;
        let requests = Arc::new(AtomicUsize::new(0));
        let stall_next = Arc::new(AtomicBool::new(false));
        let release = Arc::new(tokio::sync::Notify::new());
        let release_child = release.clone();
        let count = requests.clone();
        let stall = stall_next.clone();
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    connection = listener.accept() => {
                        let Ok((mut stream, _)) = connection else { break; };
                        let data = data.clone(); let count = count.clone(); let stall = stall.clone(); let release = release_child.clone();
                        children.spawn(async move {
                            let mut request = Vec::new(); let mut buffer = [0; 1024];
                            while request.len() <= 4096 && !request.windows(4).any(|w| w == b"\r\n\r\n") {
                                let Ok(n) = stream.read(&mut buffer).await else { return; };
                                if n == 0 { return; } request.extend_from_slice(&buffer[..n]);
                            }
                            count.fetch_add(1, Ordering::SeqCst);
                            let stall_this = stall.swap(false, Ordering::SeqCst);
                            if stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",data.len()).as_bytes()).await.is_err() { return; }
                            for (index, chunk) in data.chunks(64 * 1024).enumerate() {
                                if stream.write_all(chunk).await.is_err() { return; }
                                if stall_this && index == 0 {
                                    let mut closed = [0; 1];
                                    tokio::select! {
                                        _ = release.notified() => {},
                                        _ = stream.read(&mut closed) => return,
                                    }
                                }
                            }
                        });
                    }
                    _ = children.join_next(), if !children.is_empty() => {},
                }
            }
        });
        Ok(Self {
            url,
            requests,
            stall_next,
            task,
            release,
        })
    }
}

struct OwnedCaller(std::process::Child);
impl Drop for OwnedCaller {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
impl OwnedCaller {
    async fn output(&mut self) -> TestResult<serde_json::Value> {
        use std::io::Read;
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = self.0.try_wait()? {
                break status;
            }
            if std::time::Instant::now() > deadline {
                return Err("private cache example did not finish".into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        let mut output = Vec::new();
        self.0
            .stdout
            .take()
            .ok_or("private example stdout missing")?
            .take(8193)
            .read_to_end(&mut output)?;
        assert!(output.len() <= 8192);
        assert!(status.success(), "cache example exit {status}");
        Ok(serde_json::from_slice(&output)?)
    }
}

#[tokio::test]
async fn independent_compiled_callers_share_the_actual_cross_process_preparation_lock() -> TestResult
{
    let (asset, bytes) = fixture()?;
    let mirror = Mirror::new(bytes).await?;
    mirror.stall_next.store(true, Ordering::SeqCst);
    let root = tempfile::Builder::new()
        .prefix("vsc-callers-")
        .tempdir()?
        .keep();
    let cache_root = root.join("cache");
    let examples = PathBuf::from(
        std::env::var_os("VERYSYNC_TEST_EXAMPLE_DIR")
            .ok_or("explicit compiled example directory required")?,
    );
    let executable = examples.join(if cfg!(windows) {
        "cache_program.exe"
    } else {
        "cache_program"
    });
    let mut callers = Vec::new();
    for _ in 0..2 {
        callers.push(OwnedCaller(
            std::process::Command::new(&executable)
                .arg(asset.target().id())
                .arg(&cache_root)
                .arg(mirror.url.as_str())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?,
        ));
    }
    actual_partial(&cache_root).await;
    mirror.release.notify_one();
    let first = callers[0].output().await?;
    let second = callers[1].output().await?;
    assert_ne!(first["downloaded"], second["downloaded"]);
    assert_eq!(first["program"], second["program"]);
    assert_eq!(mirror.requests.load(Ordering::SeqCst), 1);
    assert_eq!(generation_count(&cache_root), 1);
    println!(
        "public compiled cache example evidence: {}",
        serde_json::json!({"two_native_callers_executed":true,"both_actual_zero_exit":true,"actual_partial_transfer_observed":true,"one_transfer_across_processes":true,"one_download_one_verified_hit":true,"same_immutable_program_path":true,"one_complete_generation":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
fn generation_count(root: &Path) -> usize {
    std::fs::read_dir(root.join(".verysync-sidecar-cache-v1"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("generation-"))
        .count()
}
async fn actual_partial(root: &Path) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(entries) = std::fs::read_dir(root.join(".verysync-sidecar-cache-v1")) {
                if entries.filter_map(Result::ok).any(|e| {
                    std::fs::metadata(e.path().join("archive.part")).is_ok_and(|m| m.len() > 0)
                }) {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("observe actual cache download bytes");
}

#[tokio::test]
async fn shared_preparation_offline_hit_and_corrupt_index_repair_preserve_a_running_program(
) -> TestResult {
    let (asset, bytes) = fixture()?;
    let mirror = Mirror::new(bytes).await?;
    let root = tempfile::Builder::new()
        .prefix("vsc 中文 spaces-")
        .tempdir()?
        .keep();
    let cache_root = root.join("private cache");
    let cache = ProgramCache::new(&cache_root)?.source_url(mirror.url.clone())?;
    let (first, second) = tokio::join!(
        cache.resolve(asset.clone(), CachePolicy::DownloadMissing),
        cache.resolve(asset.clone(), CachePolicy::DownloadMissing)
    );
    let first = first?;
    let second = second?;
    assert_ne!(first.status(), second.status());
    assert_eq!(first.program().path(), second.program().path());
    assert_eq!(mirror.requests.load(Ordering::SeqCst), 1);
    assert_eq!(generation_count(&cache_root), 1);
    let offline = cache.resolve(asset.clone(), CachePolicy::Offline).await?;
    assert_eq!(offline.status(), CacheStatus::VerifiedHit);
    assert_eq!(offline.program().path(), first.program().path());
    assert_eq!(mirror.requests.load(Ordering::SeqCst), 1);
    let state = root.join("private state");
    #[cfg(unix)]
    let endpoint = ManagementEndpoint::unix_socket(state.join("gui.sock"))?;
    #[cfg(windows)]
    let endpoint = {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        ManagementEndpoint::http(&format!("http://{}/", listener.local_addr()?))?
    };
    let mut instance = ManagedInstance::start(
        ManagedOptions::new(first.program().clone(), &state, endpoint)?
            .startup_timeout(Duration::from_secs(25))?,
    )
    .await?;
    let old_digest = instance.program_info().sha256;
    let index_path = std::fs::read_dir(cache_root.join(".verysync-sidecar-cache-v1"))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .ok_or("complete cache index missing")?;
    let mut index: serde_json::Value = serde_json::from_slice(&std::fs::read(&index_path)?)?;
    index["executable_sha256"][0] = serde_json::json!((old_digest[0] ^ 1) as u64);
    std::fs::write(&index_path, serde_json::to_vec(&index)?)?;
    assert!(matches!(
        cache.resolve(asset.clone(), CachePolicy::Offline).await,
        Err(Error::CacheCorrupt { .. })
    ));
    assert_eq!(mirror.requests.load(Ordering::SeqCst), 1);
    let repaired = cache.resolve(asset, CachePolicy::DownloadMissing).await?;
    assert_eq!(repaired.status(), CacheStatus::Downloaded);
    assert_ne!(first.program().path(), repaired.program().path());
    assert_eq!(mirror.requests.load(Ordering::SeqCst), 2);
    assert_eq!(generation_count(&cache_root), 2);
    let old_program = first.program().path().to_owned();
    let runtime_thread = std::thread::current().id();
    let (observed_digest, hashing_thread) =
        tokio::task::spawn_blocking(move || -> TestResult<_> {
            use std::io::Read;
            let mut file = std::fs::File::open(old_program)?;
            let mut digest = Sha256::new();
            let mut buffer = [0; 64 * 1024];
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                digest.update(&buffer[..n]);
            }
            Ok((
                <[u8; 32]>::from(digest.finalize()),
                std::thread::current().id(),
            ))
        })
        .await??;
    assert_ne!(runtime_thread, hashing_thread);
    assert_eq!(observed_digest, old_digest);
    if let Err(error) = instance.client().system_status().await {
        use std::error::Error as _;
        let mut native_errors = Vec::new();
        let mut cause = error.source();
        for _ in 0..8 {
            let Some(current) = cause else {
                break;
            };
            if let Some(io) = current.downcast_ref::<std::io::Error>() {
                native_errors.push(
                    serde_json::json!({"kind":format!("{:?}",io.kind()),"code":io.raw_os_error()}),
                );
            }
            cause = current.source();
        }
        let exited = matches!(
            tokio::time::timeout(Duration::from_millis(50), instance.wait_for_exit()).await,
            Ok(Ok(_))
        );
        eprintln!(
            "cache preservation diagnostic: {}",
            serde_json::json!({"actual_exit_observed":exited,"native_errors":native_errors,"error_classification":error.to_string()})
        );
        return Err(error.into());
    }
    let exit = instance.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    println!(
        "public Rust cache effects evidence: {}",
        serde_json::json!({"one_transfer_for_concurrent_preparations":true,"same_complete_generation_returned":true,"actual_offline_hit":true,"offline_did_not_contact_source":true,"corrupt_index_detected":true,"corrupt_offline_did_not_contact_source":true,"exact_fixed_asset_refetched":true,"new_immutable_path_committed":true,"previous_generation_retained":true,"actual_running_program_sha_unchanged":true,"actual_management_remained_authenticated":true,"actual_normal_tree_exit":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn cancelled_preparation_releases_lock_after_native_cleanup_and_waiter_can_complete(
) -> TestResult {
    let (asset, bytes) = fixture()?;
    let mirror = Mirror::new(bytes).await?;
    mirror.stall_next.store(true, Ordering::SeqCst);
    let root = tempfile::Builder::new()
        .prefix("vsc-cancel-")
        .tempdir()?
        .keep();
    let cache_root = root.join("cache");
    let cache = ProgramCache::new(&cache_root)?.source_url(mirror.url.clone())?;
    let first_cache = cache.clone();
    let first_asset = asset.clone();
    let first = tokio::spawn(async move {
        first_cache
            .resolve(first_asset, CachePolicy::DownloadMissing)
            .await
    });
    actual_partial(&cache_root).await;
    let limited = cache.clone().timeout(Duration::from_millis(150))?;
    assert!(matches!(
        limited
            .resolve(asset.clone(), CachePolicy::DownloadMissing)
            .await,
        Err(Error::Timeout { .. })
    ));
    assert!(!first.is_finished());
    assert_eq!(mirror.requests.load(Ordering::SeqCst), 1);
    let waiter =
        tokio::spawn(async move { cache.resolve(asset, CachePolicy::DownloadMissing).await });
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let ready = tokio::time::timeout(Duration::from_secs(15), waiter).await???;
    assert_eq!(ready.status(), CacheStatus::Downloaded);
    assert_eq!(generation_count(&cache_root), 1);
    assert_eq!(mirror.requests.load(Ordering::SeqCst), 2);
    assert_eq!(
        std::fs::read_dir(ready.program().path().parent().unwrap())?.count(),
        1
    );
    println!(
        "public Rust cache cancellation evidence: {}",
        serde_json::json!({"actual_partial_archive_observed":true,"bounded_lock_wait_timed_out":true,"lock_timeout_did_not_cancel_original_owner":true,"caller_future_cancelled":true,"waiting_preparation_completed":true,"exactly_one_complete_generation":true,"cancelled_partial_generation_removed":true,"only_exact_core_materialized":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn malformed_indices_and_changed_program_bytes_are_never_offline_hits() -> TestResult {
    use std::io::{Seek, SeekFrom, Write};
    let (asset, bytes) = fixture()?;
    let mirror = Mirror::new(bytes).await?;
    let root = tempfile::Builder::new()
        .prefix("vsc-corrupt-")
        .tempdir()?
        .keep();
    let cache_root = root.join("cache");
    let cache = ProgramCache::new(&cache_root)?.source_url(mirror.url.clone())?;
    let ready = cache
        .resolve(asset.clone(), CachePolicy::DownloadMissing)
        .await?;
    let marker = cache_root.join(".verysync-sidecar-cache-v1");
    let index_path = std::fs::read_dir(&marker)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .ok_or("index missing")?;
    let original = std::fs::read(&index_path)?;
    let original_value: serde_json::Value = serde_json::from_slice(&original)?;
    for field in ["generation", "version", "archive_sha256", "malformed"] {
        let mut value = original_value.clone();
        match field {
            "generation" => value["generation"] = serde_json::json!("../outside"),
            "version" => value["version"] = serde_json::json!("v999.0.0"),
            "archive_sha256" => value["archive_sha256"] = serde_json::json!(vec![0; 32]),
            _ => (),
        }
        std::fs::write(
            &index_path,
            if field == "malformed" {
                b"{".to_vec()
            } else {
                serde_json::to_vec(&value)?
            },
        )?;
        assert!(
            matches!(
                cache.resolve(asset.clone(), CachePolicy::Offline).await,
                Err(Error::CacheCorrupt { .. })
            ),
            "corrupt index case {field}"
        );
        assert_eq!(mirror.requests.load(Ordering::SeqCst), 1);
    }
    std::fs::write(&index_path, original)?;
    let mut program = std::fs::OpenOptions::new()
        .write(true)
        .open(ready.program().path())?;
    program.seek(SeekFrom::Start(0))?;
    program.write_all(b"bad!")?;
    program.sync_all()?;
    drop(program);
    assert!(matches!(
        cache.resolve(asset.clone(), CachePolicy::Offline).await,
        Err(Error::CacheCorrupt { .. })
    ));
    assert_eq!(mirror.requests.load(Ordering::SeqCst), 1);
    let recovered = cache.resolve(asset, CachePolicy::DownloadMissing).await?;
    assert_eq!(recovered.status(), CacheStatus::Downloaded);
    assert_ne!(ready.program().path(), recovered.program().path());
    assert_eq!(mirror.requests.load(Ordering::SeqCst), 2);
    assert_eq!(&std::fs::read(ready.program().path())?[..4], b"bad!");
    let offline = cache
        .resolve(recovered.asset().clone(), CachePolicy::Offline)
        .await?;
    assert_eq!(offline.program().path(), recovered.program().path());
    assert_eq!(mirror.requests.load(Ordering::SeqCst), 2);
    println!(
        "public Rust cache integrity evidence: {}",
        serde_json::json!({"index_path_escape_rejected":true,"index_version_mismatch_rejected":true,"index_archive_identity_mismatch_rejected":true,"malformed_index_rejected":true,"actual_changed_executable_detected":true,"corrupt_offline_never_downloaded":true,"exact_asset_repaired_to_new_path":true,"old_corrupt_path_not_overwritten":true,"repaired_bytes_verified_offline":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn runtime_shutdown_cleans_cache_files_and_releases_its_native_lease() -> TestResult {
    let (asset, bytes) = fixture()?;
    let root = tempfile::Builder::new()
        .prefix("vsc-runtime-")
        .tempdir()?
        .keep();
    let cache_root = root.join("cache");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mirror = runtime.block_on(async {
        let mirror = Mirror::new(bytes).await?;
        mirror.stall_next.store(true, Ordering::SeqCst);
        let cache = ProgramCache::new(&cache_root)?.source_url(mirror.url.clone())?;
        let transfer =
            tokio::spawn(async move { cache.resolve(asset, CachePolicy::DownloadMissing).await });
        actual_partial(&cache_root).await;
        drop(transfer);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(mirror)
    })?;
    drop(runtime);
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while generation_count(&cache_root) != 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(generation_count(&cache_root), 0);
    let marker = cache_root.join(".verysync-sidecar-cache-v1");
    let lock = std::fs::read_dir(&marker)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "lock"))
        .ok_or("preparation lock missing")?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock)?;
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => break,
            Err(error)
                if std::time::Instant::now() < deadline
                    && (error.kind() == std::io::ErrorKind::WouldBlock
                        || fs2::lock_contended_error()
                            .raw_os_error()
                            .is_some_and(|code| error.raw_os_error() == Some(code))) =>
            {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(error) => return Err(error.into()),
        }
    }
    fs2::FileExt::unlock(&file)?;
    drop(file);
    println!(
        "public Rust cache runtime cancellation evidence: {}",
        serde_json::json!({"actual_partial_before_shutdown":true,"caller_runtime_dropped":true,"native_cleanup_without_executor":true,"incomplete_generation_removed":true,"actual_preparation_lock_released":true})
    );
    drop(mirror);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
