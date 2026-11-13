//! Explicit bounded transfers; a short-lived native owner survives future/runtime cancellation.

use super::{archive, native};
use crate::{Error, LocalProgram, OfficialProgram, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Write,
    net::IpAddr,
    path::{Component, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
use url::{Host, Url};

/// An explicit transfer request. Construction never creates files or contacts a server.
/// Enable the optional `download` feature to use this API.
#[derive(Clone)]
pub struct DownloadOptions {
    asset: OfficialProgram,
    destination: PathBuf,
    source: Url,
    timeout: Duration,
}
impl std::fmt::Debug for DownloadOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DownloadOptions")
            .field("target", &self.asset.target())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}
impl DownloadOptions {
    /// Prepare one fixed official asset in a new directory below an existing parent.
    /// Existing destinations are refused; this operation is not an implicit cache lookup.
    pub fn new(asset: OfficialProgram, destination: impl Into<PathBuf>) -> Result<Self> {
        let destination = destination.into();
        if !destination.is_absolute()
            || destination.file_name().is_none()
            || destination
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            || destination.as_os_str().as_encoded_bytes().contains(&0)
        {
            return Err(rejected(
                "destination must be an absolute directory without dot components or NUL",
            ));
        }
        Ok(Self {
            source: asset.download_url().clone(),
            asset,
            destination,
            timeout: Duration::from_secs(300),
        })
    }
    /// Bound the complete transfer, checksum and extraction operation.
    pub fn timeout(mut self, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() || Instant::now().checked_add(timeout).is_none() {
            return Err(rejected("preparation deadline must be finite and nonzero"));
        }
        self.timeout = timeout;
        Ok(self)
    }
    /// Explicit mirror override, retaining the immutable official hash and size.
    /// HTTPS or literal loopback HTTP only; no userinfo, query or fragment.
    /// Ambient proxies are ignored, and redirects cannot change the source host.
    pub fn source_url(mut self, source: Url) -> Result<Self> {
        let loopback = match source.host() {
            Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
            Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
            _ => false,
        };
        if !(source.scheme() == "https" || source.scheme() == "http" && loopback)
            || source.host().is_none()
            || !source.username().is_empty()
            || source.password().is_some()
            || source.query().is_some()
            || source.fragment().is_some()
        {
            return Err(rejected("source must be HTTPS or literal loopback HTTP without credentials, query or fragment"));
        }
        self.source = source;
        Ok(self)
    }
    /// Download, verify the complete archive and extract only its exact regular executable.
    /// Dropping this future cancels its native file owner without depending on Tokio shutdown.
    /// Cancellation racing the final commit can leave a complete verified destination;
    /// an existing destination is always refused on a subsequent call.
    pub async fn prepare(self) -> Result<PreparedProgram> {
        tokio::runtime::Handle::try_current()
            .map_err(|_| rejected("preparation requires a Tokio runtime with I/O and timers"))?;
        let timeout = self.timeout;
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel = Cancel(cancelled.clone());
        let (sender, receiver) = mpsc::sync_channel(2);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (result_tx, result_rx) = oneshot::channel();
        let worker_options = self.clone();
        std::thread::Builder::new()
            .name("verysync-prepare".into())
            .spawn(move || {
                let result = worker(worker_options, receiver, cancelled, ready_tx);
                let _ = result_tx.send(result);
            })
            .map_err(|source| io("start program preparation owner", source))?;
        tokio::time::timeout(timeout, async move {
            ready_rx
                .await
                .map_err(|_| rejected("preparation owner ended before readiness"))??;
            let original = self.source.clone();
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                    let url = attempt.url();
                    if attempt.previous().len() < 4
                        && url.scheme() == original.scheme()
                        && url.host_str() == original.host_str()
                        && url.port_or_known_default() == original.port_or_known_default()
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.query().is_none()
                        && url.fragment().is_none()
                    {
                        attempt.follow()
                    } else {
                        attempt.stop()
                    }
                }))
                .build()
                .map_err(transport)?;
            let mut response = client
                .get(self.source.clone())
                .send()
                .await
                .map_err(transport)?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(Error::DownloadHttp {
                    status: response.status().as_u16(),
                });
            }
            if response
                .content_length()
                .is_some_and(|n| n != self.asset.archive_bytes())
            {
                return Err(rejected(
                    "source content length does not match the fixed archive",
                ));
            }
            let mut received = 0_u64;
            while let Some(chunk) = response.chunk().await.map_err(transport)? {
                received = received
                    .checked_add(chunk.len() as u64)
                    .ok_or_else(|| rejected("archive length overflow"))?;
                if received > self.asset.archive_bytes() {
                    return Err(rejected("source exceeded the fixed archive size"));
                }
                for part in chunk.chunks(64 * 1024) {
                    send(&sender, Message::Chunk(part.to_vec())).await?;
                }
            }
            if received != self.asset.archive_bytes() {
                return Err(rejected("source ended before the fixed archive size"));
            }
            send(&sender, Message::Finish).await?;
            drop(sender);
            result_rx
                .await
                .map_err(|_| rejected("preparation owner ended without a result"))?
        })
        .await
        .map_err(|_| Error::Timeout {
            operation: "prepare fixed program",
        })?
    }
}

/// A program extracted from a complete, matching fixed official archive.
/// This is static artifact evidence; managed startup separately checks its actual version.
#[derive(Clone, Debug)]
pub struct PreparedProgram {
    program: LocalProgram,
    asset: OfficialProgram,
    executable_sha256: [u8; 32],
}
impl PreparedProgram {
    /// Native program path with its actual extracted executable digest pinned.
    pub fn program(&self) -> &LocalProgram {
        &self.program
    }
    /// Fixed archive identity used for this preparation.
    pub fn asset(&self) -> &OfficialProgram {
        &self.asset
    }
    /// Actual extracted executable SHA-256, distinct from the archive digest.
    pub fn executable_sha256(&self) -> [u8; 32] {
        self.executable_sha256
    }
}

enum Message {
    Chunk(Vec<u8>),
    Finish,
}
struct Cancel(Arc<AtomicBool>);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
async fn send(sender: &mpsc::SyncSender<Message>, mut message: Message) -> Result<()> {
    loop {
        match sender.try_send(message) {
            Ok(()) => return Ok(()),
            Err(mpsc::TrySendError::Full(value)) => {
                message = value;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                return Err(rejected(
                    "preparation owner stopped accepting archive bytes",
                ))
            }
        }
    }
}
pub(super) fn rejected(reason: &'static str) -> Error {
    Error::DownloadRejected { reason }
}
pub(super) fn io(operation: &'static str, source: std::io::Error) -> Error {
    Error::LocalIo { operation, source }
}
fn transport(source: reqwest::Error) -> Error {
    Error::Transport {
        operation: "download fixed program",
        source: source.without_url(),
    }
}

struct Staging {
    directory: PathBuf,
    handle: Option<File>,
    #[cfg(unix)]
    identity: fs::Metadata,
    committed: bool,
}
impl Drop for Staging {
    fn drop(&mut self) {
        // Unix permits renaming an open directory. Never clean a substituted path.
        let Ok(metadata) = fs::symlink_metadata(&self.directory) else {
            return;
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                != 0
            {
                return;
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != self.identity.dev() || metadata.ino() != self.identity.ino() {
                return;
            }
        }
        // The retained Windows directory handle denies rename/replacement until cleanup.
        let _ = fs::remove_file(self.directory.join("archive.part"));
        let _ = fs::remove_file(self.directory.join("program.part"));
        drop(self.handle.take());
        if !self.committed {
            let _ = fs::remove_dir(&self.directory);
        }
    }
}
fn worker(
    options: DownloadOptions,
    receiver: mpsc::Receiver<Message>,
    cancelled: Arc<AtomicBool>,
    ready: oneshot::Sender<Result<()>>,
) -> Result<PreparedProgram> {
    let deadline = Instant::now()
        .checked_add(options.timeout)
        .ok_or_else(|| rejected("invalid preparation deadline"))?;
    let parent = options
        .destination
        .parent()
        .ok_or_else(|| rejected("missing destination parent"))?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|e| io("inspect preparation parent", e))?;
    if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
        return Err(rejected(
            "preparation parent must be an existing regular directory",
        ));
    }
    match native::create_directory(&options.destination) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = ready.send(Err(rejected("destination already exists")));
            return Err(rejected("destination already exists"));
        }
        Err(e) => {
            let _ = ready.send(Err(io("create private preparation directory", e)));
            return Err(rejected("private destination creation failed"));
        }
    }
    let handle = native::retain_private_directory(&options.destination)
        .map_err(|e| io("retain private preparation directory", e))?;
    let mut staging = Staging {
        directory: options.destination.clone(),
        #[cfg(unix)]
        identity: handle
            .metadata()
            .map_err(|e| io("record preparation directory identity", e))?,
        handle: Some(handle),
        committed: false,
    };
    let archive_path = staging.directory.join("archive.part");
    let mut archive =
        native::create_private(&archive_path).map_err(|e| io("create partial archive", e))?;
    ready
        .send(Ok(()))
        .map_err(|_| rejected("preparation was cancelled before transfer"))?;
    let mut hash = Sha256::new();
    let mut size = 0_u64;
    loop {
        check(&cancelled, deadline)?;
        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(Message::Chunk(bytes)) => {
                size = size
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| rejected("archive length overflow"))?;
                if size > options.asset.archive_bytes() {
                    return Err(rejected("archive exceeds fixed size"));
                }
                archive
                    .write_all(&bytes)
                    .map_err(|e| io("write partial archive", e))?;
                hash.update(bytes);
            }
            Ok(Message::Finish) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(rejected("archive transfer was interrupted"))
            }
        }
    }
    if size != options.asset.archive_bytes()
        || <[u8; 32]>::from(hash.finalize()) != options.asset.archive_sha256()
    {
        return Err(rejected(
            "archive size or SHA-256 does not match the fixed catalog",
        ));
    }
    archive
        .sync_all()
        .map_err(|e| io("sync verified archive", e))?;
    drop(archive);
    let program_path = staging.directory.join("program.part");
    let mut program =
        native::create_private(&program_path).map_err(|e| io("create partial executable", e))?;
    let executable_sha256 = archive::extract(&archive_path, &options.asset, &mut program, || {
        check(&cancelled, deadline)
    })?;
    program
        .sync_all()
        .map_err(|e| io("sync verified executable", e))?;
    make_executable(&program)?;
    drop(program);
    // Inspect actual native ownership/permissions (including the Windows ACL)
    // before enabling the complete executable, rather than trusting creation alone.
    drop(
        native::open_private(&program_path, true)
            .map_err(|e| io("verify prepared executable privacy", e))?,
    );
    check(&cancelled, deadline)?;
    let final_path = staging.directory.join(options.asset.executable_name());
    // Same-directory hard linking commits a complete file without overwriting a destination.
    fs::hard_link(&program_path, &final_path)
        .map_err(|e| io("commit verified executable without replacement", e))?;
    staging.committed = true;
    Ok(PreparedProgram {
        program: LocalProgram::new(final_path)?.expected_sha256(executable_sha256),
        asset: options.asset,
        executable_sha256,
    })
}
pub(super) fn check(cancelled: &AtomicBool, deadline: Instant) -> Result<()> {
    if cancelled.load(Ordering::Acquire) {
        return Err(rejected("preparation was cancelled"));
    }
    if Instant::now() >= deadline {
        return Err(Error::Timeout {
            operation: "prepare fixed program",
        });
    }
    Ok(())
}
fn make_executable(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(|e| io("set executable permissions", e))?;
    }
    #[cfg(windows)]
    {
        let _ = file;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn cleanup_refuses_a_substituted_directory_even_with_matching_partial_filenames() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("owned");
        let moved = root.path().join("moved");
        let unrelated = root.path().join("unrelated");
        native::create_directory(&directory).unwrap();
        let handle = native::retain_private_directory(&directory).unwrap();
        let guard = Staging {
            directory: directory.clone(),
            identity: handle.metadata().unwrap(),
            handle: Some(handle),
            committed: false,
        };
        std::fs::write(directory.join("archive.part"), b"owned partial bytes").unwrap();
        std::fs::create_dir(&unrelated).unwrap();
        std::fs::write(unrelated.join("archive.part"), b"retain unrelated bytes").unwrap();
        std::fs::rename(&directory, &moved).unwrap();
        symlink(&unrelated, &directory).unwrap();
        drop(guard);
        assert_eq!(
            std::fs::read(unrelated.join("archive.part")).unwrap(),
            b"retain unrelated bytes"
        );
        assert_eq!(
            std::fs::read(moved.join("archive.part")).unwrap(),
            b"owned partial bytes"
        );
        assert!(std::fs::symlink_metadata(directory)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}
