//! Reported synchronization snapshots, independent of business-batch completion.
use crate::{Error, FolderId, Result};
use serde::{Deserialize, Deserializer};
use std::{collections::BTreeMap, fmt};

/// One explicit bounded page. No method silently follows additional pages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListPage {
    pub(crate) number: u32,
    pub(crate) per_page: u16,
}
impl ListPage {
    /// Select a nonzero page and 1..=1000 items, keeping the item offset within
    /// signed 32-bit range for the baseline's smaller official architectures.
    pub fn new(number: u32, per_page: u16) -> Result<Self> {
        if number == 0
            || per_page == 0
            || per_page > 1000
            || u64::from(number) * u64::from(per_page) > i32::MAX as u64
        {
            return Err(Error::InvalidConfiguration{reason:"page and item count must be nonzero, at most 1000 items, with a signed 32-bit item offset"});
        }
        Ok(Self { number, per_page })
    }
    /// Requested one-based page number.
    pub fn number(self) -> u32 {
        self.number
    }
    /// Requested item limit, independent of actual response length.
    pub fn per_page(self) -> u16 {
        self.per_page
    }
}
fn percent<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<f64, D::Error> {
    let value = f64::deserialize(d)?;
    if value.is_finite() && (0.0..=100.0).contains(&value) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "completion must be a finite percentage in 0..=100",
        ))
    }
}
/// One upstream folder/peer completion snapshot, not a durable completion receipt.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletionSnapshot {
    /// Reported percentage. Even 100 can accompany an unknown remote state.
    #[serde(rename = "completion", deserialize_with = "percent")]
    pub completion_percent: f64,
    /// Reported global bytes, when present.
    pub global_bytes: Option<u64>,
    /// Reported global item count, when present.
    pub global_items: Option<u64>,
    /// Reported outstanding bytes, when present.
    pub need_bytes: Option<u64>,
    /// Reported outstanding deletions, when present.
    pub need_deletes: Option<u64>,
    /// Reported outstanding items, when present.
    pub need_items: Option<u64>,
    /// Actual remote-state label, including unknown/future labels.
    pub remote_state: Option<String>,
    /// Actual reported index sequence, not a globally unique transaction ID.
    pub sequence: Option<u64>,
    /// Other actual fields, omitted from Debug.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for CompletionSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompletionSnapshot")
            .field("completion_percent", &self.completion_percent)
            .field("need_bytes", &self.need_bytes)
            .finish_non_exhaustive()
    }
}
/// Actual file-kind labels in model listings.
#[derive(Clone, Eq, PartialEq, Deserialize)]
pub enum SyncFileKind {
    /// A regular file entry.
    #[serde(rename = "FILE_INFO_TYPE_FILE")]
    File,
    /// A directory entry in the native index tree.
    #[serde(rename = "FILE_INFO_TYPE_DIRECTORY")]
    Directory,
    /// An unfamiliar label, retained without guessing filesystem semantics.
    #[serde(untagged)]
    Unknown(String),
}
impl fmt::Debug for SyncFileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::File => "SyncFileKind::File",
            Self::Directory => "SyncFileKind::Directory",
            Self::Unknown(_) => "SyncFileKind::Unknown([REDACTED])",
        })
    }
}
/// An engine-reported entry, not a trusted local filesystem path.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncFile {
    /// Exact engine-relative name; never implicitly joined to a local path.
    pub name: String,
    /// Actual entry kind, including unknown labels.
    #[serde(rename = "type")]
    pub kind: SyncFileKind,
    /// Reported byte size, when present.
    pub size: Option<u64>,
    /// Actual upstream modification timestamp, without clock conversion.
    pub modified: Option<String>,
    /// Actual deletion flag, when present.
    pub deleted: Option<bool>,
    /// Actual ignored flag, when present.
    pub ignored: Option<bool>,
    /// Actual invalid flag, when present.
    pub invalid: Option<bool>,
    /// Other fields, which can contain private file metadata.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for SyncFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncFile")
            .field("kind", &self.kind)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}
/// One current local-need page, with the engine's three actual queue groups.
#[derive(Clone, Deserialize)]
pub struct NeedPage {
    /// Actual reported page, if present.
    pub page: Option<u32>,
    /// Actual reported limit, if present; not assumed to match the request.
    #[serde(rename = "perpage")]
    pub per_page: Option<u32>,
    /// Actual entries reported in progress.
    pub progress: Vec<SyncFile>,
    /// Actual entries reported queued.
    pub queued: Vec<SyncFile>,
    /// Other actual outstanding entries.
    pub rest: Vec<SyncFile>,
    /// Other actual fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for NeedPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NeedPage")
            .field("page", &self.page)
            .field("in_progress", &self.progress.len())
            .field("queued", &self.queued.len())
            .field("rest", &self.rest.len())
            .finish_non_exhaustive()
    }
}
/// One actual remote-need or local-change listing, without automatic pagination.
#[derive(Clone, Deserialize)]
pub struct SyncFilePage {
    /// Actual file entries. A malformed/missing list is not an empty page.
    pub files: Vec<SyncFile>,
    /// Actual reported page, if present.
    pub page: Option<u32>,
    /// Actual reported page size, if present.
    #[serde(rename = "perpage")]
    pub per_page: Option<u32>,
    /// Other actual fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for SyncFilePage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncFilePage")
            .field("page", &self.page)
            .field("file_count", &self.files.len())
            .finish_non_exhaustive()
    }
}
/// One actual scanning/pulling error. Ordinary Debug hides both strings.
#[derive(Clone, Deserialize)]
pub struct FolderSyncError {
    /// Actual entry-relative path. It is not automatically treated as local.
    pub path: String,
    /// Actual engine error, which can include absolute paths or credentials.
    pub error: String,
    /// Other actual metadata.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for FolderSyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FolderSyncError { .. }")
    }
}
/// One actual folder error response. Null lists remain unknown/absent.
#[derive(Clone, Deserialize)]
pub struct FolderErrorPage {
    /// Folder identified in the response.
    pub folder: FolderId,
    /// Actual error list. `None` preserves null/absent rather than inventing `[]`.
    pub errors: Option<Vec<FolderSyncError>>,
    /// Actual reported page, if present.
    pub page: Option<u32>,
    /// Actual reported page size, if present.
    #[serde(rename = "perpage")]
    pub per_page: Option<u32>,
    /// Other actual fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for FolderErrorPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderErrorPage")
            .field("error_count", &self.errors.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}
/// Actual device statistics. Placeholder epoch timestamps are preserved.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceStatistics {
    /// Reported last-seen timestamp; not independently verified presence.
    pub last_seen: Option<String>,
    /// Reported connection duration in seconds, when present.
    #[serde(rename = "lastConnectionDurationS")]
    pub last_connection_duration_seconds: Option<f64>,
    /// Actual creation timestamp, when reported.
    pub created: Option<String>,
    /// Other actual fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for DeviceStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceStatistics { .. }")
    }
}
/// Reported last-file observation, preserving placeholder strings and flags.
#[derive(Clone, Deserialize)]
pub struct LastFileObservation {
    /// Actual timestamp string.
    pub at: Option<String>,
    /// Actual engine-relative name, including a reported empty placeholder.
    pub filename: Option<String>,
    /// Reported deletion flag.
    pub deleted: Option<bool>,
    /// Other actual fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for LastFileObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LastFileObservation { .. }")
    }
}
/// Actual folder statistics. Counters do not certify a caller's file batch.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderStatistics {
    /// Actual last scan timestamp, when reported.
    pub last_scan: Option<String>,
    /// Actual last-file observation, when reported.
    pub last_file: Option<LastFileObservation>,
    /// Actual upstream incoming counter, without inventing its unit.
    pub total_incoming: Option<u64>,
    /// Actual upstream outgoing counter, without inventing its unit.
    pub total_outgoing: Option<u64>,
    /// Actual upstream sending counter, without inventing its unit.
    pub sending: Option<u64>,
    /// Other actual fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for FolderStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FolderStatistics { .. }")
    }
}

/// One explicit native index-tree request, separate from selective-mode metadata.
/// The default asks for root entries at native level zero without children.
#[derive(Clone, Debug)]
pub struct IndexBrowseOptions {
    pub(crate) prefix: Option<crate::TargetPath>,
    pub(crate) levels: Option<u16>,
    pub(crate) directories_only: bool,
}
impl Default for IndexBrowseOptions {
    fn default() -> Self {
        Self {
            prefix: None,
            levels: Some(0),
            directories_only: false,
        }
    }
}
impl IndexBrowseOptions {
    /// Select a strictly relative prefix using the target's path syntax.
    /// Local callers construct it with native Path/PathBuf operations.
    /// The default root scope sends no prefix and touches no controller files.
    pub fn prefix(mut self, prefix: crate::TargetPath) -> Self {
        self.prefix = Some(prefix);
        self
    }
    /// Native level zero returns immediate entries without children. Positive
    /// levels include that many descendant levels. None explicitly requests
    /// the native unbounded-depth default; response size/deadline/JSON bounds
    /// still apply and the SDK does not follow additional requests.
    pub fn levels(mut self, levels: Option<u16>) -> Self {
        self.levels = levels;
        self
    }
    /// Request only directory entries. False omits the query: this fixed core
    /// treats any nonempty dirsonly value, including the text false, as true.
    pub fn directories_only(mut self, directories_only: bool) -> Self {
        self.directories_only = directories_only;
        self
    }
}
/// One native index node. This reports index knowledge, not current file access,
/// local existence, selection, peer connectivity or transfer completion.
#[derive(Clone, Deserialize)]
pub struct IndexTreeEntry {
    /// Exact untrusted entry name. Never implicitly joined to a filesystem path.
    pub name: String,
    /// Exact native modification timestamp, preserving offset and precision.
    #[serde(rename = "modTime")]
    pub modified: String,
    /// Native byte size, including the reported zero for directories.
    pub size: u64,
    /// Actual native kind; unfamiliar labels remain explicitly inspectable.
    #[serde(rename = "type")]
    pub kind: SyncFileKind,
    /// Actual children within the requested depth. Missing/null is retained as
    /// None, separate from an explicitly empty child list.
    pub children: Option<Vec<IndexTreeEntry>>,
    /// Unmodeled native metadata, potentially private.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for IndexTreeEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IndexTreeEntry")
            .field("kind", &self.kind)
            .field("size", &self.size)
            .field("child_count", &self.children.as_ref().map(Vec::len))
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}
/// One ordered native index snapshot, without fabricated selection/existence
/// fields. An empty list is valid; malformed or null root responses are errors.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct IndexTree {
    /// Exact native order and nodes. No automatic recursive fetch or local I/O.
    pub entries: Vec<IndexTreeEntry>,
}
impl fmt::Debug for IndexTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IndexTree")
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Native encoded signature metadata. The SDK preserves it without checking a
/// signature, interpreting its version tag or treating it as a trust decision.
#[derive(Clone, Deserialize)]
pub struct IndexFileSignature {
    /// Native signature format tag, independent from crate/core version numbers.
    #[serde(rename = "Version")]
    pub version: u32,
    /// Exact native encoded Sign value; None retains a native null/absence.
    #[serde(rename = "Sign")]
    pub encoded_signature: Option<String>,
    /// Unmodeled values, potentially private.
    /// Additional native metadata, potentially private.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for IndexFileSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IndexFileSignature")
            .field("version", &self.version)
            .field("has_encoded_signature", &self.encoded_signature.is_some())
            .finish_non_exhaustive()
    }
}
/// One exact full native FileInfo index record. A zero local record with an
/// empty name/version vector is preserved; it does not establish a local file.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexFileMetadata {
    /// Exact untrusted index name, not a controller filesystem path.
    pub name: String,
    /// Actual native type, including preserved unfamiliar labels.
    #[serde(rename = "type")]
    pub kind: SyncFileKind,
    /// Reported size; a zero local record retains zero.
    pub size: u64,
    /// Exact native timestamp including offset/precision or placeholder value.
    pub modified: String,
    /// Exact native short modifier identifier; it is not a full DeviceId.
    pub modified_by: String,
    /// Native tombstone flag, without filesystem deletion by the SDK.
    pub deleted: bool,
    /// Native ignored-state observation.
    pub ignored: bool,
    /// Native invalid-state observation.
    pub invalid: bool,
    /// Native permission-presence flag, without a controller access test.
    pub no_permissions: bool,
    /// Exact native permission string, without host-mode conversion.
    pub permissions: String,
    /// Uninterpreted native local bit flags.
    pub local_flags: u32,
    /// Native rescan-required flag; reading it does not start a scan.
    pub must_rescan: bool,
    /// Native declared block count; block data is not fetched.
    pub num_blocks: u64,
    /// Exact native encoded block-list hash; not an SDK-verified content digest.
    pub blocks_hash: Option<String>,
    /// Exact native previous block-list hash or retained null/absence.
    pub previous_blocks_hash: Option<String>,
    /// Native index sequence, without a cross-request transaction guarantee.
    pub sequence: u64,
    /// Native version-vector strings in their reported order. No clock merge,
    /// sorting, global identifier or freshness inference is performed.
    pub version: Vec<String>,
    /// Exact native signature metadata, without SDK signature verification.
    pub signature: IndexFileSignature,
    /// Native per-platform extension payloads, retained without interpreting
    /// unverified ownership, extended-attribute, ACL or platform schemas.
    pub platform: BTreeMap<String, serde_json::Value>,
    /// Additional native metadata, potentially private.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for IndexFileMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IndexFileMetadata")
            .field("kind", &self.kind)
            .field("size", &self.size)
            .field("deleted", &self.deleted)
            .field("ignored", &self.ignored)
            .field("invalid", &self.invalid)
            .finish_non_exhaustive()
    }
}
/// One native advertised source. This does not prove reachability or a completed
/// download, and the SDK does not contact the listed device.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexFileAvailability {
    #[serde(rename = "id")]
    /// Full native advertised-source device identifier.
    pub device_id: crate::DeviceId,
    /// Native flag that this source advertises temporary file data.
    pub from_temporary: bool,
    /// Additional native metadata, potentially private.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for IndexFileAvailability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IndexFileAvailability")
            .field("from_temporary", &self.from_temporary)
            .finish_non_exhaustive()
    }
}
/// One full native index observation, separate from resource-file metadata,
/// filesystem existence and completed synchronization. Global/local records
/// and advertised availability are not made into one durable transaction.
#[derive(Clone, Deserialize)]
pub struct IndexFileInfo {
    /// Native global index record; not a completed-transfer receipt.
    pub global: IndexFileMetadata,
    /// Native local index record, including an empty zero record when absent.
    pub local: IndexFileMetadata,
    /// None preserves native null/absence; Some empty remains explicitly empty.
    pub availability: Option<Vec<IndexFileAvailability>>,
    /// Additional native metadata, potentially private.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for IndexFileInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IndexFileInfo")
            .field(
                "availability_count",
                &self.availability.as_ref().map(Vec::len),
            )
            .finish_non_exhaustive()
    }
}

/// Native per-file block counters and byte estimates at one instant.
/// Fields retain signed native values without normalization. Byte estimates
/// need not equal the file size, and no completion percentage is inferred.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileDownloadProgress {
    /// Native total block count.
    #[serde(rename = "total")]
    pub total_blocks: i64,
    /// Native reused block count.
    #[serde(rename = "reused")]
    pub reused_blocks: i64,
    /// Native blocks copied from their original offsets.
    #[serde(rename = "copiedFromOrigin")]
    pub copied_from_origin_blocks: i64,
    /// Native blocks copied from shifted original offsets.
    #[serde(rename = "copiedFromOriginShifted")]
    pub copied_from_origin_shifted_blocks: i64,
    /// Native blocks copied from other locations.
    #[serde(rename = "copiedFromElsewhere")]
    pub copied_from_elsewhere_blocks: i64,
    /// Native pulled block count.
    #[serde(rename = "pulled")]
    pub pulled_blocks: i64,
    /// Native pulling block count.
    #[serde(rename = "pulling")]
    pub pulling_blocks: i64,
    /// Native completed-byte estimate, retained without recomputation.
    pub bytes_done: i64,
    /// Native total-byte estimate; not a file-size or transfer-size guarantee.
    pub bytes_total: i64,
    /// Additional private native fields, preserved without interpretation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for FileDownloadProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileDownloadProgress")
            .finish_non_exhaustive()
    }
}

/// One native folder download-progress snapshot, separate from folder state,
/// index need, advertised availability and peer completion. Empty data does not
/// prove a completed transfer; native missing progress state can also be an error.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct FolderDownloadProgress {
    /// Untrusted native file-name keys and their reported progress. Never joined
    /// to a controller path or interpreted as verified local file existence.
    pub files: BTreeMap<String, FileDownloadProgress>,
}
impl fmt::Debug for FolderDownloadProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderDownloadProgress")
            .field("reported_files", &self.files.len())
            .finish_non_exhaustive()
    }
}
