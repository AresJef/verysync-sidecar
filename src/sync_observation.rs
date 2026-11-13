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
    /// An unfamiliar label, retained without guessing filesystem semantics.
    #[serde(untagged)]
    Unknown(String),
}
impl fmt::Debug for SyncFileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if matches!(self, Self::File) {
            "SyncFileKind::File"
        } else {
            "SyncFileKind::Unknown([REDACTED])"
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
