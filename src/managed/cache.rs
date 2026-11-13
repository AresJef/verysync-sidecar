//! Immutable program generations with a cross-process preparation lock and atomic index.

use super::{download, native};
use crate::{DownloadOptions, Error, LocalProgram, OfficialProgram, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
use url::Url;

const MARKER: &str = ".verysync-sidecar-cache-v1";
const MAX_PROGRAM: u64 = 256 * 1024 * 1024;

/// Whether a cache miss may explicitly fetch the selected fixed official asset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CachePolicy {
    /// Read and verify existing entries only; never download or initialize a cache.
    Offline,
    /// Fetch only the exact selected asset when missing or corrupt.
    DownloadMissing,
}
/// How the exact program was obtained by this resolve call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheStatus {
    /// Existing bytes were rehashed and matched a complete fixed index.
    VerifiedHit,
    /// This call downloaded and committed a new immutable program generation.
    Downloaded,
}
/// A verified program at an immutable cache path. Cache resolution never runs it.
#[derive(Clone, Debug)]
pub struct CachedProgram {
    program: LocalProgram,
    asset: OfficialProgram,
    status: CacheStatus,
}
impl CachedProgram {
    /// Local program with its actual executable digest pinned for managed startup.
    pub fn program(&self) -> &LocalProgram {
        &self.program
    }
    /// Exact fixed official archive identity.
    pub fn asset(&self) -> &OfficialProgram {
        &self.asset
    }
    /// Actual hit/download outcome for this call.
    pub fn status(&self) -> CacheStatus {
        self.status
    }
}

/// Explicit cache root. Construction performs no filesystem, network or engine I/O.
/// Existing nonempty unmarked caller directories are never adopted. Old immutable generations
/// are retained, including programs used by a persistent core after its caller exits.
#[derive(Clone)]
pub struct ProgramCache {
    root: PathBuf,
    source: Option<Url>,
    timeout: Duration,
}
impl std::fmt::Debug for ProgramCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgramCache")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}
impl ProgramCache {
    /// Select a new, empty private, or already library-marked absolute root.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        if !root.is_absolute()
            || root.file_name().is_none()
            || root
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            || root.as_os_str().as_encoded_bytes().contains(&0)
        {
            return Err(rejected(
                "cache root must be an absolute native directory without dot components or NUL",
            ));
        }
        Ok(Self {
            root,
            source: None,
            timeout: Duration::from_secs(300),
        })
    }
    /// Bound lock waiting, validation, optional transfer and index commit together.
    pub fn timeout(mut self, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() || Instant::now().checked_add(timeout).is_none() {
            return Err(rejected("cache deadline must be finite and nonzero"));
        }
        self.timeout = timeout;
        Ok(self)
    }
    /// Explicit mirror for the selected asset, retaining its fixed archive SHA/size.
    /// Uses the same HTTPS/literal-loopback and credential restrictions as preparation.
    pub fn source_url(mut self, source: Url) -> Result<Self> {
        download::validate_source(&source)?;
        self.source = Some(source);
        Ok(self)
    }
    /// Resolve and rehash an exact fixed asset; no latest-version fallback or engine execution.
    /// Cancelling this future requests cleanup; a commit racing cancellation can leave
    /// a complete verified cache entry, which a later offline resolve can reconcile.
    pub async fn resolve(
        &self,
        asset: OfficialProgram,
        policy: CachePolicy,
    ) -> Result<CachedProgram> {
        tokio::runtime::Handle::try_current()
            .map_err(|_| rejected("cache resolution requires Tokio I/O and timers"))?;
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or_else(|| rejected("invalid cache deadline"))?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel = Cancel(cancelled.clone());
        let cache = self.clone();
        tokio::time::timeout(self.timeout, async move {
            let lookup_asset = asset.clone();
            let lookup_cancel = cancelled.clone();
            let lookup =
                owner(move || lookup(&cache.root, &lookup_asset, policy, lookup_cancel, deadline))
                    .await?;
            let lease = match lookup {
                Lookup::Hit(program) => return Ok(*program),
                Lookup::Prepare(lease) => lease,
            };
            check(&cancelled, deadline)?;
            let generation = format!("generation-{}", random_id()?);
            let destination = lease.directory.join(&generation);
            let mut options = DownloadOptions::new(asset.clone(), &destination)?
                .timeout(deadline.saturating_duration_since(Instant::now()))?
                .cache_lease(lease.clone());
            if let Some(source) = &self.source {
                options = options.source_url(source.clone())?;
            }
            let prepared = options.prepare().await?;
            owner(move || commit(lease, generation, prepared, &cancelled, deadline)).await
        })
        .await
        .map_err(|_| Error::Timeout {
            operation: "resolve fixed program cache",
        })?
    }
}

struct Cancel(Arc<AtomicBool>);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

pub(super) struct CacheLease {
    file: File,
    directory: PathBuf,
    index: PathBuf,
    _root_handle: File,
    _directory_handle: File,
}
impl Drop for CacheLease {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}
enum Lookup {
    Hit(Box<CachedProgram>),
    Prepare(Arc<CacheLease>),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    schema: u32,
    version: String,
    target: String,
    archive_sha256: [u8; 32],
    generation: String,
    executable_bytes: u64,
    executable_sha256: [u8; 32],
}
fn lookup(
    root: &Path,
    asset: &OfficialProgram,
    policy: CachePolicy,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
) -> Result<Lookup> {
    check(&cancelled, deadline)?;
    let marker = root.join(MARKER);
    let created = match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(rejected("cache root is not a regular directory"));
            }
            false
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && policy == CachePolicy::Offline => {
            return Err(Error::CacheMiss)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match native::create_directory(root) {
                Ok(()) => true,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
                Err(e) => return Err(io("create private cache root", e)),
            }
        }
        Err(e) => return Err(io("inspect cache root", e)),
    };
    let root_handle = native::retain_private_directory(root)
        .map_err(|_| rejected("cache root must be private and belong to the current user"))?;
    if !marker.exists() {
        if policy == CachePolicy::Offline {
            return Err(Error::CacheMiss);
        }
        if !created
            && fs::read_dir(root)
                .map_err(|e| io("inspect unmarked cache admission", e))?
                .next()
                .is_some()
            && !marker.exists()
        {
            return Err(rejected("nonempty caller directory is not a library cache"));
        }
        // Either concurrent initializer can atomically create the same marker.
        // This avoids guessing how long the other process needs after mkdir.
        match native::create_directory(&marker) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(io("mark private cache root", e)),
        }
    }
    let directory_handle = native::retain_private_directory(&marker)
        .map_err(|_| rejected("cache marker must be a private regular directory"))?;
    let key = hex(&asset.archive_sha256());
    let index = marker.join(format!("{key}.json"));
    let lock = marker.join(format!("{key}.lock"));
    let file = native::open_private(&lock, policy == CachePolicy::Offline).map_err(|e| {
        if policy == CachePolicy::Offline && e.kind() == std::io::ErrorKind::NotFound {
            Error::CacheMiss
        } else {
            io("open cache preparation lock", e)
        }
    })?;
    loop {
        check(&cancelled, deadline)?;
        match file.try_lock_exclusive() {
            Ok(()) => break,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || fs2::lock_contended_error()
                        .raw_os_error()
                        .is_some_and(|code| e.raw_os_error() == Some(code)) =>
            {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(e) => return Err(io("lock cache preparation", e)),
        }
    }
    let lease = Arc::new(CacheLease {
        file,
        directory: marker,
        index,
        _root_handle: root_handle,
        _directory_handle: directory_handle,
    });
    match read_index(&lease, asset, &cancelled, deadline) {
        Ok(program) => Ok(Lookup::Hit(Box::new(program))),
        Err(Error::CacheMiss | Error::CacheCorrupt { .. })
            if policy == CachePolicy::DownloadMissing =>
        {
            Ok(Lookup::Prepare(lease))
        }
        Err(error) => Err(error),
    }
}
fn read_index(
    lease: &CacheLease,
    asset: &OfficialProgram,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<CachedProgram> {
    let file = match native::open_private(&lease.index, true) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::CacheMiss),
        Err(_) => return Err(corrupt("index is not a private regular file")),
    };
    let mut bytes = Vec::new();
    file.take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| corrupt("cannot read index"))?;
    if bytes.len() > 16 * 1024 {
        return Err(corrupt("index exceeds its size bound"));
    }
    let index: Index =
        serde_json::from_slice(&bytes).map_err(|_| corrupt("invalid index schema"))?;
    if index.schema != 1
        || index.version != asset.version().as_str()
        || index.target != asset.target().id()
        || index.archive_sha256 != asset.archive_sha256()
        || !valid_generation(&index.generation)
        || index.executable_bytes == 0
        || index.executable_bytes > MAX_PROGRAM
    {
        return Err(corrupt("index does not match the exact fixed asset"));
    }
    let directory = lease.directory.join(&index.generation);
    let _directory = native::retain_private_directory(&directory)
        .map_err(|_| corrupt("generation directory is not private and regular"))?;
    let path = directory.join(asset.executable_name());
    let mut file = native::open_private(&path, true)
        .map_err(|_| corrupt("cached executable is not private and regular"))?;
    let metadata = file
        .metadata()
        .map_err(|_| corrupt("cannot inspect cached executable"))?;
    if metadata.len() != index.executable_bytes {
        return Err(corrupt("cached executable length changed"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(corrupt("cached executable permission changed"));
        }
    }
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        check(cancelled, deadline)?;
        let n = file
            .read(&mut buffer)
            .map_err(|_| corrupt("cannot read cached executable"))?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    if <[u8; 32]>::from(digest.finalize()) != index.executable_sha256 {
        return Err(corrupt("cached executable SHA-256 changed"));
    }
    Ok(CachedProgram {
        program: LocalProgram::new(path)?.expected_sha256(index.executable_sha256),
        asset: asset.clone(),
        status: CacheStatus::VerifiedHit,
    })
}
fn commit(
    lease: Arc<CacheLease>,
    generation: String,
    mut prepared: crate::PreparedProgram,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<CachedProgram> {
    check(cancelled, deadline)?;
    let asset = prepared.asset().clone();
    let bytes = fs::metadata(prepared.program().path())
        .map_err(|e| io("inspect complete cache program", e))?
        .len();
    let index = Index {
        schema: 1,
        version: asset.version().as_str().to_owned(),
        target: asset.target().id(),
        archive_sha256: asset.archive_sha256(),
        generation,
        executable_bytes: bytes,
        executable_sha256: prepared.executable_sha256(),
    };
    let data =
        serde_json::to_vec(&index).map_err(|_| corrupt("cannot serialize fixed cache index"))?;
    let temporary = lease.directory.join(format!("index-{}.part", random_id()?));
    let result = (|| {
        let mut file =
            native::create_private(&temporary).map_err(|e| io("create partial cache index", e))?;
        file.write_all(&data)
            .map_err(|e| io("write cache index", e))?;
        file.sync_all()
            .map_err(|e| io("sync complete cache index", e))?;
        drop(file);
        check(cancelled, deadline)?;
        fs::rename(&temporary, &lease.index).map_err(|e| io("commit complete cache index", e))?;
        // No await/cancellation boundary between publishing the pointer and retaining
        // its immutable generation. The native owner finishes this transaction.
        prepared.retain_in_cache();
        Ok(CachedProgram {
            program: prepared.program().clone(),
            asset,
            status: CacheStatus::Downloaded,
        })
    })();
    let _ = fs::remove_file(temporary);
    result
}
fn valid_generation(name: &str) -> bool {
    name.strip_prefix("generation-")
        .is_some_and(|suffix| suffix.len() == 32 && suffix.bytes().all(|b| b.is_ascii_hexdigit()))
}
fn random_id() -> Result<String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| rejected("native randomness unavailable"))?;
    Ok(hex(&bytes))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn rejected(reason: &'static str) -> Error {
    Error::CacheRejected { reason }
}
fn corrupt(reason: &'static str) -> Error {
    Error::CacheCorrupt { reason }
}
fn io(operation: &'static str, source: std::io::Error) -> Error {
    Error::LocalIo { operation, source }
}
fn check(cancelled: &AtomicBool, deadline: Instant) -> Result<()> {
    if cancelled.load(Ordering::Acquire) {
        return Err(rejected("cache resolution was cancelled"));
    }
    if Instant::now() >= deadline {
        return Err(Error::Timeout {
            operation: "resolve fixed program cache",
        });
    }
    Ok(())
}
async fn owner<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let (tx, rx) = oneshot::channel();
    std::thread::Builder::new()
        .name("verysync-cache".into())
        .spawn(move || {
            let _ = tx.send(operation());
        })
        .map_err(|e| io("start cache file owner", e))?;
    rx.await
        .map_err(|_| rejected("cache owner ended without a result"))?
}
