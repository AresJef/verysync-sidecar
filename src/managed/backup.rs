//! Bounded offline state copies; partial destinations are retained, not erased.
use super::{io_error, native, state, ManagedInstance};
use crate::{DeviceId, Error, ProgramInfo, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fmt, fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime},
};

const MANIFEST: &str = "manifest.json";
const INCOMPLETE: &str = ".snapshot-incomplete";
const MAX_MANIFEST: u64 = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;

fn linked(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

/// Explicit new destination and resource limits for an offline state snapshot.
#[derive(Clone)]
pub struct StateBackupOptions {
    destination: PathBuf,
    max_bytes: u64,
    max_entries: usize,
    timeout: Duration,
}
impl StateBackupOptions {
    /// Require a new absolute destination. Defaults: 1 GiB of file data, 65,536
    /// entries and a 120-second cooperative copy deadline. No I/O occurs here.
    pub fn new(destination: impl Into<PathBuf>) -> Result<Self> {
        let destination = destination.into();
        absolute(&destination)?;
        Ok(Self {
            destination,
            max_bytes: 1 << 30,
            max_entries: 65_536,
            timeout: Duration::from_secs(120),
        })
    }
    /// Set the positive total file-content bound; copies use a 64-KiB buffer.
    pub fn max_total_bytes(mut self, bytes: u64) -> Result<Self> {
        if bytes == 0 {
            return Err(rejected("the copy byte bound must be positive"));
        }
        self.max_bytes = bytes;
        Ok(self)
    }
    /// Set a positive entry bound, at most 100,000 files and directories.
    pub fn max_entries(mut self, entries: usize) -> Result<Self> {
        if entries == 0 || entries > MAX_ENTRIES {
            return Err(rejected("the entry bound is invalid"));
        }
        self.max_entries = entries;
        Ok(self)
    }
    /// Set a positive cooperative deadline, checked between native I/O calls.
    pub fn timeout(mut self, timeout: Duration) -> Result<Self> {
        deadline(timeout)?;
        self.timeout = timeout;
        Ok(self)
    }
}
impl fmt::Debug for StateBackupOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateBackupOptions")
            .field("max_bytes", &self.max_bytes)
            .field("max_entries", &self.max_entries)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// Snapshot metadata, distinct from a running/restored engine's readiness.
#[derive(Clone, Debug)]
pub struct StateBackupInfo {
    /// Exact SHA-256 of the complete bounded manifest; retain for later opening.
    pub manifest_sha256: [u8; 32],
    /// Identity of the last cleanly stopped source generation.
    pub device_id: DeviceId,
    /// Actual last ready source executable, not a downgrade-compatibility claim.
    pub source_program: ProgramInfo,
    /// Number of regular files copied.
    pub file_count: u64,
    /// Total actual file-content bytes copied.
    pub total_bytes: u64,
}

/// An explicit private snapshot. Restore rechecks its pinned manifest and every
/// copied file hash; holding this value does not freeze external filesystem edits.
#[derive(Clone)]
pub struct StateBackup {
    directory: PathBuf,
    info: StateBackupInfo,
}
impl fmt::Debug for StateBackup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateBackup")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}
impl StateBackup {
    /// Borrow the canonical private snapshot directory, which contains secrets.
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    /// Inspect recorded counts and manifest identity without I/O.
    pub fn info(&self) -> &StateBackupInfo {
        &self.info
    }
    /// Open an existing snapshot using a separately retained manifest SHA-256.
    /// This validates metadata; restoration verifies file content while copying.
    pub async fn open(
        directory: impl Into<PathBuf>,
        expected: [u8; 32],
        timeout: Duration,
    ) -> Result<Self> {
        let directory = directory.into();
        absolute(&directory)?;
        worker(timeout, move |control| {
            control.check()?;
            let (root, manifest, sha) = read_manifest(&directory, Some(expected))?;
            Ok(Self {
                directory: root,
                info: manifest.info(sha),
            })
        })
        .await
    }
    /// Copy into a new private state directory; never overwrite an existing
    /// destination or start a program. The copy retains identity/credentials.
    /// Coordinate the original identity's lifetime before starting the result.
    /// Partial/cancelled destinations retain an admission-blocking marker.
    pub async fn restore_to(
        &self,
        destination: impl Into<PathBuf>,
        timeout: Duration,
    ) -> Result<PathBuf> {
        let destination = destination.into();
        absolute(&destination)?;
        let source = self.directory.clone();
        let expected = self.info.manifest_sha256;
        worker(timeout, move |control| {
            restore(&source, expected, &destination, control)
        })
        .await
    }
}

impl ManagedInstance {
    /// Snapshot only a known, normally stopped owned generation, holding both
    /// SDK and engine state locks. Synced folder payloads outside state are not
    /// copied. Writes never erase caller paths; partial destinations remain for
    /// diagnosis and cannot be opened as complete snapshots. Cancellation is
    /// cooperative; the private worker retains its locks until I/O has ended.
    pub async fn backup_state(&self, options: StateBackupOptions) -> Result<StateBackup> {
        if !self.state_ready_for_backup
            || !self.exit_snapshot().is_some_and(|e| {
                e.tree_stopped && e.state_released && !e.forced && e.code == Some(0)
            })
        {
            return Err(rejected("a known normally stopped generation is required"));
        }
        let source = self.state_directory().to_owned();
        let device = self.client().instance().device_id.clone();
        let program = self.program_info().clone();
        worker(options.timeout, move |control| {
            capture(&source, device, program, options, control)
        })
        .await
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: PathBuf,
    directory: bool,
    bytes: u64,
    sha256: [u8; 32],
    modified: Option<SystemTime>,
    executable: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    os: String,
    arch: String,
    device: DeviceId,
    program_version: String,
    program_sha256: [u8; 32],
    total_bytes: u64,
    entries: Vec<Entry>,
}
impl Manifest {
    fn info(&self, sha: [u8; 32]) -> StateBackupInfo {
        StateBackupInfo {
            manifest_sha256: sha,
            device_id: self.device.clone(),
            source_program: ProgramInfo {
                version: self.program_version.clone(),
                sha256: self.program_sha256,
            },
            file_count: self.entries.iter().filter(|e| !e.directory).count() as u64,
            total_bytes: self.total_bytes,
        }
    }
}

fn rejected(reason: &'static str) -> Error {
    Error::StateBackupRejected { reason }
}
fn absolute(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().contains(&0)
        || path.components().any(|p| matches!(p, Component::ParentDir))
    {
        return Err(rejected(
            "destination must be an absolute native path without parent components",
        ));
    }
    Ok(())
}
fn deadline(timeout: Duration) -> Result<Instant> {
    if timeout.is_zero() {
        return Err(rejected("copy deadline must be positive"));
    }
    Instant::now()
        .checked_add(timeout)
        .ok_or(rejected("copy deadline is not representable"))
}
struct Control {
    cancel: Arc<AtomicBool>,
    deadline: Instant,
}
impl Control {
    fn check(&self) -> Result<()> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(rejected("state copy was cancelled"));
        }
        if Instant::now() >= self.deadline {
            return Err(Error::Timeout {
                operation: "copy private state",
            });
        }
        Ok(())
    }
}
struct CancelOnDrop(Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
async fn worker<T: Send + 'static>(
    timeout: Duration,
    work: impl FnOnce(&Control) -> Result<T> + Send + 'static,
) -> Result<T> {
    let deadline = deadline(timeout)?;
    let cancel = Arc::new(AtomicBool::new(false));
    let _cancel = CancelOnDrop(cancel.clone());
    let (send, receive) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("verysync-sidecar-state-copy".into())
        .spawn(move || {
            let _ = send.send(work(&Control { cancel, deadline }));
        })
        .map_err(|e| io_error("create private state-copy worker", e))?;
    receive
        .await
        .map_err(|_| rejected("state-copy worker ended without a result"))?
}

fn canonical(path: &Path) -> std::io::Result<PathBuf> {
    #[cfg(windows)]
    {
        dunce::canonicalize(path)
    }
    #[cfg(not(windows))]
    {
        fs::canonicalize(path)
    }
}
fn private_root(path: &Path) -> Result<PathBuf> {
    let meta = fs::symlink_metadata(path).map_err(|e| io_error("inspect snapshot root", e))?;
    if !meta.is_dir() || linked(&meta) {
        return Err(rejected("snapshot root must be a private directory"));
    }
    native::private_directory(path, &meta).map_err(|e| io_error("check snapshot privacy", e))?;
    canonical(path).map_err(|e| io_error("resolve snapshot root", e))
}
fn new_root(path: &Path, source: &Path) -> Result<PathBuf> {
    absolute(path)?;
    let parent = path
        .parent()
        .ok_or(rejected("destination parent is required"))?;
    let parent = canonical(parent).map_err(|e| io_error("resolve copy destination parent", e))?;
    let name = path
        .file_name()
        .ok_or(rejected("destination name is required"))?;
    let path = parent.join(name);
    if path.starts_with(source) {
        return Err(rejected("destination must be outside the source tree"));
    }
    native::create_directory(&path)
        .map_err(|e| io_error("create new private copy destination", e))?;
    Ok(path)
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut output =
        native::create_private(path).map_err(|e| io_error("create snapshot metadata", e))?;
    output
        .write_all(bytes)
        .map_err(|e| io_error("write snapshot metadata", e))?;
    output
        .sync_all()
        .map_err(|e| io_error("persist snapshot metadata", e))
}
fn relative(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(rejected("snapshot entry must have a relative name"));
    }
    let mut normalized = PathBuf::new();
    let mut depth = 0;
    for part in path.components() {
        let Component::Normal(name) = part else {
            return Err(rejected("snapshot entry escapes its root"));
        };
        let text = name
            .to_str()
            .ok_or(rejected("snapshot entry names must be UTF-8"))?;
        #[cfg(windows)]
        {
            let stem = text.split('.').next().unwrap_or("").to_ascii_uppercase();
            let device = ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
                || ["COM", "LPT"].iter().any(|prefix| {
                    stem.strip_prefix(prefix).is_some_and(|s| {
                        ["1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"].contains(&s)
                    })
                });
            if device || text.contains(':') || text.ends_with(['.', ' ']) {
                return Err(rejected("snapshot entry uses a reserved native name"));
            }
        }
        #[cfg(not(windows))]
        let _ = text;
        normalized.push(name);
        depth += 1;
    }
    if depth > 64 || normalized.as_os_str() != path.as_os_str() {
        return Err(rejected("snapshot entry is noncanonical or too deep"));
    }
    Ok(())
}
fn validate(manifest: &Manifest) -> Result<()> {
    if manifest.format != 1
        || manifest.os != std::env::consts::OS
        || manifest.arch != std::env::consts::ARCH
        || manifest.entries.len() > MAX_ENTRIES
    {
        return Err(rejected(
            "snapshot format or native target is not supported",
        ));
    }
    let mut names = BTreeSet::new();
    let mut dirs = BTreeSet::new();
    let mut files = BTreeSet::new();
    let mut total = 0u64;
    for entry in &manifest.entries {
        relative(&entry.path)?;
        if !names.insert(entry.path.clone()) {
            return Err(rejected("snapshot has duplicate entry names"));
        }
        if entry.directory {
            if entry.bytes != 0
                || entry.sha256 != [0; 32]
                || entry.modified.is_some()
                || entry.executable
            {
                return Err(rejected("snapshot directory metadata is invalid"));
            }
            dirs.insert(entry.path.clone());
        } else {
            if entry.modified.is_none() {
                return Err(rejected("snapshot file time is missing"));
            }
            total = total
                .checked_add(entry.bytes)
                .ok_or(rejected("snapshot byte count overflows"))?;
            files.insert(entry.path.clone());
        }
    }
    for entry in &manifest.entries {
        for parent in entry
            .path
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
        {
            if !dirs.contains(parent) {
                return Err(rejected("snapshot parent directory is missing"));
            }
        }
    }
    if total != manifest.total_bytes {
        return Err(rejected("snapshot total byte count differs"));
    }
    for name in [
        state::MARKER,
        ".verysync-sidecar-identity",
        ".verysync-sidecar-configured",
        "key.pem",
        "cert.pem",
        "setting.dat",
    ] {
        if !files.contains(Path::new(name)) {
            return Err(rejected("snapshot lacks required state resources"));
        }
    }
    let marker = manifest
        .entries
        .iter()
        .find(|e| e.path == Path::new(state::MARKER))
        .ok_or_else(|| rejected("snapshot lacks its state admission marker"))?;
    let hash: [u8; 32] = Sha256::digest(state::FORMAT).into();
    if marker.bytes != state::FORMAT.len() as u64 || marker.sha256 != hash {
        return Err(rejected("snapshot state admission marker differs"));
    }
    Ok(())
}
fn read_manifest(
    directory: &Path,
    expected: Option<[u8; 32]>,
) -> Result<(PathBuf, Manifest, [u8; 32])> {
    let root = private_root(directory)?;
    match fs::symlink_metadata(root.join(INCOMPLETE)) {
        Ok(_) => return Err(rejected("snapshot is incomplete")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_error("inspect snapshot completion", e)),
    }
    let mut bytes = Vec::new();
    native::open_private(&root.join(MANIFEST), true)
        .map_err(|e| io_error("open snapshot manifest", e))?
        .take(MAX_MANIFEST + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error("read snapshot manifest", e))?;
    if bytes.len() as u64 > MAX_MANIFEST {
        return Err(rejected("snapshot manifest exceeds its bound"));
    }
    let sha: [u8; 32] = Sha256::digest(&bytes).into();
    if expected.is_some_and(|e| e != sha) {
        return Err(rejected("snapshot manifest SHA-256 differs"));
    }
    let manifest =
        serde_json::from_slice(&bytes).map_err(|_| rejected("snapshot manifest is malformed"))?;
    validate(&manifest)?;
    Ok((root, manifest, sha))
}
fn identity(root: &Path) -> Result<DeviceId> {
    let mut bytes = Vec::new();
    native::open_snapshot_input(&root.join(".verysync-sidecar-identity"))
        .map_err(|e| io_error("open snapshot identity", e))?
        .take(257)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error("read snapshot identity", e))?;
    if bytes.len() > 256 {
        return Err(rejected("snapshot identity exceeds its bound"));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| rejected("snapshot identity is malformed"))?;
    DeviceId::parse(text.trim()).map_err(|_| rejected("snapshot identity is malformed"))
}
fn source_path(root: &Path, path: &Path) -> Result<PathBuf> {
    relative(path)?;
    let mut current = root.to_owned();
    let count = path.components().count();
    for (index, part) in path.components().enumerate() {
        current.push(part);
        let meta =
            fs::symlink_metadata(&current).map_err(|e| io_error("inspect snapshot entry", e))?;
        if linked(&meta) || (index + 1 < count && !meta.is_dir()) {
            return Err(rejected("snapshot contains a linked or invalid ancestor"));
        }
    }
    Ok(current)
}
fn copy_file(
    source: &Path,
    destination: &Path,
    entry: &Entry,
    control: &Control,
    expected: bool,
) -> Result<[u8; 32]> {
    control.check()?;
    let mut input =
        native::open_snapshot_input(source).map_err(|e| io_error("open offline state file", e))?;
    let before = input
        .metadata()
        .map_err(|e| io_error("inspect offline state file", e))?;
    let modified = before
        .modified()
        .map_err(|e| io_error("inspect source modification time", e))?;
    if before.len() != entry.bytes || (!expected && entry.modified != Some(modified)) {
        return Err(rejected("state file size changed"));
    }
    let mut output =
        native::create_private(destination).map_err(|e| io_error("create copied state file", e))?;
    let mut buffer = [0; 64 * 1024];
    let mut count = 0u64;
    let mut sha = Sha256::new();
    loop {
        control.check()?;
        let n = input
            .read(&mut buffer)
            .map_err(|e| io_error("read offline state file", e))?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .ok_or(rejected("state file size overflows"))?;
        if count > entry.bytes {
            return Err(rejected("state file grew while copying"));
        }
        output
            .write_all(&buffer[..n])
            .map_err(|e| io_error("copy offline state file", e))?;
        sha.update(&buffer[..n]);
    }
    let after = input
        .metadata()
        .map_err(|e| io_error("recheck offline state file", e))?;
    if count != entry.bytes
        || before.len() != after.len()
        || modified
            != after
                .modified()
                .map_err(|e| io_error("recheck source modification time", e))?
    {
        return Err(rejected("state file changed while copying"));
    }
    let sha: [u8; 32] = sha.finalize().into();
    if expected && sha != entry.sha256 {
        return Err(rejected("state file SHA-256 differs"));
    }
    if let Some(modified) = entry.modified {
        output
            .set_times(fs::FileTimes::new().set_modified(modified))
            .map_err(|e| io_error("retain state file time", e))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        output
            .set_permissions(fs::Permissions::from_mode(if entry.executable {
                0o700
            } else {
                0o600
            }))
            .map_err(|e| io_error("retain private owner executable bit", e))?;
    }
    output
        .sync_all()
        .map_err(|e| io_error("persist copied state file", e))?;
    Ok(sha)
}

fn capture(
    source: &Path,
    device: DeviceId,
    program: ProgramInfo,
    options: StateBackupOptions,
    control: &Control,
) -> Result<StateBackup> {
    control.check()?;
    let source = state::existing(source)?;
    let _lease = state::StateLease::acquire(&source)?;
    if identity(&source)? != device {
        return Err(rejected("source state identity differs"));
    }
    let root = new_root(&options.destination, &source)?;
    write_private(&root.join(INCOMPLETE), b"incomplete private snapshot\n")?;
    let data = root.join("data");
    native::create_directory(&data)
        .map_err(|e| io_error("create snapshot content directory", e))?;
    let mut manifest = Manifest {
        format: 1,
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        device,
        program_version: program.version,
        program_sha256: program.sha256,
        total_bytes: 0,
        entries: Vec::new(),
    };
    let mut encoded_size = 0usize;
    collect(
        &source,
        &data,
        Path::new(""),
        &options,
        &mut manifest,
        &mut encoded_size,
        control,
    )?;
    validate(&manifest)?;
    control.check()?;
    let bytes = serde_json::to_vec(&manifest)
        .map_err(|_| rejected("snapshot metadata cannot be encoded"))?;
    if bytes.len() as u64 > MAX_MANIFEST {
        return Err(rejected("snapshot manifest exceeds its bound"));
    }
    write_private(&root.join(MANIFEST), &bytes)?;
    fs::remove_file(root.join(INCOMPLETE)).map_err(|e| io_error("complete private snapshot", e))?;
    let sha = Sha256::digest(&bytes).into();
    Ok(StateBackup {
        directory: root,
        info: manifest.info(sha),
    })
}

fn collect(
    source: &Path,
    destination: &Path,
    path: &Path,
    options: &StateBackupOptions,
    manifest: &mut Manifest,
    encoded_size: &mut usize,
    control: &Control,
) -> Result<()> {
    control.check()?;
    let mut children = Vec::new();
    for item in
        fs::read_dir(source.join(path)).map_err(|e| io_error("enumerate offline state", e))?
    {
        control.check()?;
        let item = item.map_err(|e| io_error("read offline state entry", e))?;
        if path.as_os_str().is_empty()
            && [state::LEASE, "verysync.lock", "gui.sock", "tmp"]
                .iter()
                .any(|name| item.file_name() == *name)
        {
            continue;
        }
        if children.len() + manifest.entries.len() >= options.max_entries {
            return Err(rejected("state snapshot entry bound exceeded"));
        }
        children.push(item);
    }
    children.sort_by_key(|item| item.file_name());
    for child in children {
        control.check()?;
        if manifest.entries.len() >= options.max_entries {
            return Err(rejected("state snapshot entry bound exceeded"));
        }
        let path = path.join(child.file_name());
        relative(&path)?;
        let meta = fs::symlink_metadata(source.join(&path))
            .map_err(|e| io_error("inspect offline state entry", e))?;
        if linked(&meta) || (!meta.is_dir() && !meta.is_file()) {
            return Err(rejected("state contains a linked or special entry"));
        }
        let mut entry = Entry {
            path: path.clone(),
            directory: meta.is_dir(),
            bytes: 0,
            sha256: [0; 32],
            modified: None,
            executable: false,
        };
        if meta.is_file() {
            entry.bytes = meta.len();
            entry.modified = Some(
                meta.modified()
                    .map_err(|e| io_error("read state file time", e))?,
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                entry.executable = meta.permissions().mode() & 0o100 != 0;
            }
            manifest.total_bytes = manifest
                .total_bytes
                .checked_add(entry.bytes)
                .filter(|n| *n <= options.max_bytes)
                .ok_or(rejected("state snapshot byte bound exceeded"))?;
        }
        let cost = serde_json::to_vec(&entry)
            .map_err(|_| rejected("snapshot entry cannot be encoded"))?
            .len()
            + 128;
        *encoded_size = encoded_size
            .checked_add(cost)
            .ok_or(rejected("snapshot metadata size overflows"))?;
        if *encoded_size as u64 > MAX_MANIFEST - 1024 * 1024 {
            return Err(rejected("snapshot manifest exceeds its bound"));
        }
        if entry.directory {
            native::create_directory(&destination.join(&path))
                .map_err(|e| io_error("create snapshot subdirectory", e))?;
            manifest.entries.push(entry);
            collect(
                source,
                destination,
                &path,
                options,
                manifest,
                encoded_size,
                control,
            )?;
        } else {
            entry.sha256 = copy_file(
                &source.join(&path),
                &destination.join(&path),
                &entry,
                control,
                false,
            )?;
            manifest.entries.push(entry);
        }
    }
    Ok(())
}

fn restore(
    source: &Path,
    expected: [u8; 32],
    destination: &Path,
    control: &Control,
) -> Result<PathBuf> {
    control.check()?;
    let (source, manifest, _) = read_manifest(source, Some(expected))?;
    let content = private_root(&source.join("data"))?;
    let destination = new_root(destination, &source)?;
    let lease = native::open_private(&destination.join(state::LEASE), false)
        .map_err(|e| io_error("reserve restored state", e))?;
    lease
        .try_lock_exclusive()
        .map_err(|e| io_error("lock restored state", e))?;
    write_private(
        &destination.join(state::RESTORE_INCOMPLETE),
        b"incomplete private restore\n",
    )?;
    let mut entries: Vec<_> = manifest.entries.iter().collect();
    entries.sort_by(|a, b| {
        a.path
            .components()
            .count()
            .cmp(&b.path.components().count())
            .then(a.path.cmp(&b.path))
    });
    for entry in entries.iter().filter(|e| e.directory) {
        control.check()?;
        let path = source_path(&content, &entry.path)?;
        if !fs::symlink_metadata(path)
            .map_err(|e| io_error("inspect snapshot directory", e))?
            .is_dir()
        {
            return Err(rejected("snapshot directory type differs"));
        }
        native::create_directory(&destination.join(&entry.path))
            .map_err(|e| io_error("create restored subdirectory", e))?;
    }
    for entry in entries
        .iter()
        .filter(|e| !e.directory && e.path != Path::new(state::MARKER))
    {
        control.check()?;
        let path = source_path(&content, &entry.path)?;
        copy_file(&path, &destination.join(&entry.path), entry, control, true)?;
    }
    if identity(&destination)? != manifest.device {
        return Err(rejected("restored identity differs from the snapshot"));
    }
    let marker_entry = manifest
        .entries
        .iter()
        .find(|e| e.path == Path::new(state::MARKER))
        .unwrap();
    let marker_path = source_path(&content, &marker_entry.path)?;
    let mut marker = Vec::new();
    native::open_snapshot_input(&marker_path)
        .map_err(|e| io_error("open snapshot admission marker", e))?
        .take(129)
        .read_to_end(&mut marker)
        .map_err(|e| io_error("read snapshot admission marker", e))?;
    if marker != state::FORMAT {
        return Err(rejected("snapshot admission marker content differs"));
    }
    control.check()?;
    write_private(&destination.join(state::MARKER), state::FORMAT)?;
    fs::remove_file(destination.join(state::RESTORE_INCOMPLETE))
        .map_err(|e| io_error("complete restored state admission", e))?;
    drop(lease);
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, PathBuf, Manifest) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("snapshot");
        native::create_directory(&root).unwrap();
        native::create_directory(&root.join("data")).unwrap();
        let device =
            DeviceId::parse("AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA")
                .unwrap();
        let mut entries = Vec::new();
        let mut total = 0;
        for (name, data) in [
            (state::MARKER, state::FORMAT),
            (".verysync-sidecar-identity", device.as_str().as_bytes()),
            (".verysync-sidecar-configured", b"1".as_slice()),
            ("key.pem", b"synthetic key".as_slice()),
            ("cert.pem", b"synthetic certificate".as_slice()),
            ("setting.dat", b"synthetic configuration".as_slice()),
        ] {
            write_private(&root.join("data").join(name), data).unwrap();
            total += data.len() as u64;
            entries.push(Entry {
                path: name.into(),
                directory: false,
                bytes: data.len() as u64,
                sha256: Sha256::digest(data).into(),
                modified: Some(SystemTime::UNIX_EPOCH),
                executable: false,
            });
        }
        (
            temp,
            root,
            Manifest {
                format: 1,
                os: std::env::consts::OS.into(),
                arch: std::env::consts::ARCH.into(),
                device,
                program_version: crate::BASELINE_ENGINE_VERSION.into(),
                program_sha256: [7; 32],
                total_bytes: total,
                entries,
            },
        )
    }
    fn commit(root: &Path, manifest: &Manifest) -> [u8; 32] {
        let bytes = serde_json::to_vec(manifest).unwrap();
        // Only this test-owned manifest is rewritten to synthesize hostile input.
        if root.join(MANIFEST).exists() {
            fs::write(root.join(MANIFEST), &bytes).unwrap();
        } else {
            write_private(&root.join(MANIFEST), &bytes).unwrap();
        }
        Sha256::digest(bytes).into()
    }

    #[tokio::test]
    async fn pinned_hostile_manifest_paths_do_not_escape_or_create_state() {
        let paths = vec![
            "../escape-created",
            "/absolute-outside",
            "inside/../../escape-created",
            ".",
            "inside//child",
        ];
        #[cfg(windows)]
        let paths = {
            let mut p = paths;
            p.extend([
                "C:\\outside",
                "\\\\server\\share",
                "CON",
                "file:stream",
                "trailing.",
            ]);
            p
        };
        for path in paths {
            let (temp, root, mut manifest) = fixture();
            let sha = commit(&root, &manifest);
            StateBackup::open(&root, sha, Duration::from_secs(5))
                .await
                .unwrap();
            fs::write(temp.path().join("outside-sentinel"), b"retain outside data").unwrap();
            manifest.entries.push(Entry {
                path: path.into(),
                directory: false,
                bytes: 0,
                sha256: Sha256::digest([]).into(),
                modified: Some(SystemTime::UNIX_EPOCH),
                executable: false,
            });
            let sha = commit(&root, &manifest);
            assert!(matches!(
                StateBackup::open(&root, sha, Duration::from_secs(5)).await,
                Err(Error::StateBackupRejected { .. })
            ));
            assert_eq!(
                fs::read(temp.path().join("outside-sentinel")).unwrap(),
                b"retain outside data"
            );
            assert!(!temp.path().join("escape-created").exists());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn linked_snapshot_ancestor_is_not_followed_and_partial_state_is_not_admitted() {
        let (temp, root, mut manifest) = fixture();
        let outside = temp.path().join("outside");
        native::create_directory(&outside).unwrap();
        let bytes = b"private synthetic outside bytes";
        write_private(&outside.join("secret"), bytes).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("data").join("linked")).unwrap();
        manifest.entries.push(Entry {
            path: "linked".into(),
            directory: true,
            bytes: 0,
            sha256: [0; 32],
            modified: None,
            executable: false,
        });
        manifest.entries.push(Entry {
            path: Path::new("linked").join("secret"),
            directory: false,
            bytes: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            modified: Some(SystemTime::UNIX_EPOCH),
            executable: false,
        });
        manifest.total_bytes += bytes.len() as u64;
        let sha = commit(&root, &manifest);
        let backup = StateBackup::open(&root, sha, Duration::from_secs(5))
            .await
            .unwrap();
        let output = temp.path().join("restore");
        assert!(backup
            .restore_to(&output, Duration::from_secs(5))
            .await
            .is_err());
        assert!(!output.join("linked").join("secret").exists());
        assert!(!output.join(state::MARKER).exists());
        assert!(output.join(state::RESTORE_INCOMPLETE).is_file());
        assert_eq!(fs::read(outside.join("secret")).unwrap(), bytes);
    }
}
