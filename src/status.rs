//! Typed read snapshots; missing metrics remain unknown.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{DeviceId, Error, Result};

/// An opaque upstream folder identifier, preserved without normalization.
///
/// Protocol requests encode this identifier as one query value or path segment.
/// The engine remains
/// responsible for determining whether that identifier names a configured folder.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FolderId(String);

impl FolderId {
    /// Accept a nonempty identifier without Unicode control characters.
    pub fn parse(value: &str) -> Result<Self> {
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(Error::InvalidFolderId {
                reason: "folder identifier must be nonempty without control characters",
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// Borrow the exact upstream identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for FolderId {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}
impl<'de> Deserialize<'de> for FolderId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// A fresh authenticated engine-wide snapshot.
///
/// Absent or null metrics are `None`; a reported zero is `Some(0)`. These
/// metrics describe the engine and do not establish completion of a caller's
/// file batch. Unknown fields, including unmodeled account/license data, remain
/// available explicitly in `extra` and are omitted from ordinary debug output.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemStatus {
    /// Identity in this response, checked against the connection handshake.
    #[serde(rename = "myID")]
    pub device_id: DeviceId,
    /// Reported elapsed engine uptime in seconds, when available.
    #[serde(rename = "uptime")]
    pub uptime_seconds: Option<u64>,
    /// Upstream start-time string, preserved without timezone conversion.
    pub start_time: Option<String>,
    /// Upstream current-time string, preserved without interpreting its clock.
    pub now_time: Option<String>,
    /// Runtime-allocated bytes reported as `alloc`.
    #[serde(rename = "alloc")]
    pub memory_allocated_bytes: Option<u64>,
    /// Runtime memory bytes reported as `sys`, not process RSS.
    #[serde(rename = "sys")]
    pub runtime_memory_bytes: Option<u64>,
    /// Reported machine memory size in bytes, if supplied by this build.
    #[serde(rename = "memorySize")]
    pub machine_memory_bytes: Option<u64>,
    /// Upstream CPU percentage; no per-core normalization is invented.
    pub cpu_percent: Option<f64>,
    /// Reported Go goroutine count, if supplied.
    pub goroutines: Option<u64>,
    /// Processor count reported by the engine.
    #[serde(rename = "numCPU")]
    pub processor_count: Option<u64>,
    /// Go scheduler parallelism reported by the engine.
    pub go_max_procs: Option<u64>,
    /// Target engine path separator; not a local filesystem conversion rule.
    pub path_separator: Option<String>,
    /// Unmodeled upstream fields, retained for explicit caller inspection.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl fmt::Debug for SystemStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemStatus")
            .field("device_id", &self.device_id)
            .field("uptime_seconds", &self.uptime_seconds)
            .field("memory_allocated_bytes", &self.memory_allocated_bytes)
            .field("goroutines", &self.goroutines)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// An upstream folder activity state, including values unknown to this crate.
///
/// `Idle` describes the engine's current activity; it is not a guarantee that
/// arbitrary peers, files, or a business transaction have finished syncing.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FolderState {
    /// No current folder activity reported by the engine.
    Idle,
    /// Scanning local changes.
    Scanning,
    /// Waiting to scan.
    ScanWaiting,
    /// Applying synchronization changes.
    Syncing,
    /// Waiting to synchronize.
    SyncWaiting,
    /// Performing folder cleanup.
    Cleaning,
    /// Waiting for cleanup.
    CleanWaiting,
    /// The engine reports a paused folder.
    Paused,
    /// The engine reports a folder error.
    Error,
    /// An unrecognized state string, preserved exactly.
    Unknown(String),
}
impl FolderState {
    /// Borrow the exact protocol state string.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Idle => "idle",
            Self::Scanning => "scanning",
            Self::ScanWaiting => "scan-waiting",
            Self::Syncing => "syncing",
            Self::SyncWaiting => "sync-waiting",
            Self::Cleaning => "cleaning",
            Self::CleanWaiting => "clean-waiting",
            Self::Paused => "paused",
            Self::Error => "error",
            Self::Unknown(value) => value,
        }
    }
}
impl Serialize for FolderState {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}
impl<'de> Deserialize<'de> for FolderState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "idle" => Self::Idle,
            "scanning" => Self::Scanning,
            "scan-waiting" => Self::ScanWaiting,
            "syncing" => Self::Syncing,
            "sync-waiting" => Self::SyncWaiting,
            "cleaning" => Self::Cleaning,
            "clean-waiting" => Self::CleanWaiting,
            "paused" => Self::Paused,
            "error" => Self::Error,
            _ => Self::Unknown(value),
        })
    }
}

/// A fresh folder synchronization snapshot, not a batch-completion receipt.
///
/// Missing state or counters remain unknown. Unknown state strings and other
/// upstream fields are preserved rather than silently converted to idle/zero.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderStatus {
    /// Reported activity state, if present.
    pub state: Option<FolderState>,
    /// Upstream state-change timestamp, without clock interpretation.
    pub state_changed: Option<String>,
    /// Bytes in the engine's global model, when reported.
    pub global_bytes: Option<u64>,
    /// Files in the engine's global model, when reported.
    pub global_files: Option<u64>,
    /// Directories in the global model, when reported.
    pub global_directories: Option<u64>,
    /// Deleted entries in the global model, when reported.
    pub global_deleted: Option<u64>,
    /// Bytes in the local indexed model, when reported.
    pub local_bytes: Option<u64>,
    /// Files in the local indexed model, when reported.
    pub local_files: Option<u64>,
    /// Directories in the local model, when reported.
    pub local_directories: Option<u64>,
    /// Deleted entries in the local model, when reported.
    pub local_deleted: Option<u64>,
    /// Bytes the engine reports as still needed, when supplied.
    pub need_bytes: Option<u64>,
    /// Files the engine reports as still needed, when supplied.
    pub need_files: Option<u64>,
    /// Directories still needed, when supplied.
    pub need_directories: Option<u64>,
    /// Deletions still needed, when supplied.
    pub need_deletes: Option<u64>,
    /// Reported pull-error count, when supplied.
    pub pull_errors: Option<u64>,
    /// Other upstream fields, omitted from ordinary debug output.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for FolderStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FolderStatus")
            .field("state", &self.state)
            .field("local_files", &self.local_files)
            .field("local_bytes", &self.local_bytes)
            .field("need_files", &self.need_files)
            .field("need_bytes", &self.need_bytes)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}
