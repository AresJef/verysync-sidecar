//! Native file versioning settings, archive observations and explicit restores.
use crate::{Error, Result, TargetPath};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// An explicit built-in versioning policy. A zero cleanout age keeps versions
/// without age-based expiry. Keeping versions applies to future remote changes,
/// not controller edits or a general filesystem snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FolderVersioningPolicy {
    /// Stop creating versions; this does not delete existing archives.
    Disabled,
    /// Keep the most recently archived file, with optional age-based expiry.
    Trashcan {
        /// Whole days before expiry; zero disables age-based expiry.
        cleanout_days: u32,
        /// Positive cleanup interval in whole seconds.
        cleanup_interval_seconds: u32,
    },
    /// Keep an explicit nonzero number of archived versions per path.
    Simple {
        /// Maximum retained versions per file, at least one.
        keep: u32,
        /// Whole days before expiry; zero disables age-based expiry.
        cleanout_days: u32,
        /// Positive cleanup interval in whole seconds.
        cleanup_interval_seconds: u32,
    },
}
impl FolderVersioningPolicy {
    pub(crate) fn apply(self, config: &mut FolderVersioningConfiguration) -> Result<()> {
        let (kind, keep, days, interval) = match self {
            Self::Disabled => ("", None, None, None),
            Self::Trashcan {
                cleanout_days,
                cleanup_interval_seconds,
            } => (
                "trashcan",
                None,
                Some(cleanout_days),
                Some(cleanup_interval_seconds),
            ),
            Self::Simple {
                keep,
                cleanout_days,
                cleanup_interval_seconds,
            } => {
                if keep == 0 || keep > i32::MAX as u32 {
                    return Err(invalid(
                        "version retention count must be between one and i32::MAX",
                    ));
                }
                (
                    "simple",
                    Some(keep),
                    Some(cleanout_days),
                    Some(cleanup_interval_seconds),
                )
            }
        };
        if interval.is_some_and(|s| s == 0 || s > i32::MAX as u32)
            || days.is_some_and(|s| s > i32::MAX as u32)
        {
            return Err(invalid(
                "version cleanout/cleanup values exceed their explicit integer bounds",
            ));
        }
        config.kind = kind.to_owned();
        // Native configuration PATCH merges maps. Preserve inactive parameters
        // as well as unknown ones; an empty object does not delete old keys.
        if let Some(keep) = keep {
            config.params.insert("keep".into(), keep.to_string());
        }
        if let Some(days) = days {
            config
                .params
                .insert("cleanoutDays".into(), days.to_string());
        }
        if let Some(interval) = interval {
            config.cleanup_interval_seconds = interval;
        }
        Ok(())
    }
    pub(crate) fn validate(self) -> Result<()> {
        let mut empty = FolderVersioningConfiguration {
            kind: String::new(),
            params: BTreeMap::new(),
            cleanup_interval_seconds: 0,
            filesystem_path: String::new(),
            filesystem_type: String::new(),
            extra: BTreeMap::new(),
        };
        self.apply(&mut empty)
    }
}

/// The actual native versioner configuration. Unknown modes, parameters and
/// fields are retained. Paths describe the target and are never opened locally.
#[derive(Clone, Deserialize, Serialize, PartialEq)]
pub struct FolderVersioningConfiguration {
    /// Native kind: empty, simple, trashcan, or another observed value.
    #[serde(rename = "type")]
    pub kind: String,
    /// Native string-valued policy parameters, including unknown ones.
    pub params: BTreeMap<String, String>,
    /// Actual configured cleanup interval in whole seconds.
    #[serde(rename = "cleanupIntervalS")]
    pub cleanup_interval_seconds: u32,
    /// Native archive location; an empty value selects the kernel default.
    #[serde(rename = "fsPath")]
    pub filesystem_path: String,
    /// Actual archive filesystem/backend kind.
    #[serde(rename = "fsType")]
    pub filesystem_type: String,
    /// Unknown native fields, potentially private.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for FolderVersioningConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderVersioningConfiguration")
            .field("cleanup_interval_seconds", &self.cleanup_interval_seconds)
            .finish_non_exhaustive()
    }
}
/// Fresh configuration readback after one explicit versioning policy change.
#[derive(Clone, Debug)]
pub struct FolderVersioningUpdate {
    /// Actual native configuration, including preserved archive location.
    pub configuration: FolderVersioningConfiguration,
    /// Exact submitted configuration equals the observed configuration.
    pub requested_fields_match: bool,
}

/// One archived version. The native timestamp is an opaque selection token;
/// do not reinterpret it in the controller's local timezone.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivedFileVersion {
    /// Exact timestamp used to request this version.
    pub version_time: String,
    /// Native original modification timestamp.
    pub mod_time: String,
    /// Archived file size in bytes.
    pub size: u64,
    /// Additional native fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for ArchivedFileVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchivedFileVersion")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}
/// A bounded archive listing keyed by untrusted native relative names. Returned
/// paths are data; the SDK does not traverse them or open controller files.
#[derive(Clone)]
pub struct FolderVersionHistory(pub BTreeMap<String, Vec<ArchivedFileVersion>>);
impl<'de> Deserialize<'de> for FolderVersionHistory {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let entries =
            Option::<BTreeMap<String, Vec<ArchivedFileVersion>>>::deserialize(deserializer)?;
        Ok(Self(entries.unwrap_or_default()))
    }
}
impl fmt::Debug for FolderVersionHistory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderVersionHistory")
            .field("paths", &self.0.len())
            .finish_non_exhaustive()
    }
}
/// One exact file and archived timestamp to restore. This can overwrite current
/// data. It does not restore a directory tree or coordinate other peers.
#[derive(Clone)]
pub struct FileVersionRestore {
    pub(crate) path: TargetPath,
    pub(crate) version_time: String,
}
impl FileVersionRestore {
    /// Retain a relative target path and native timestamp. The path is validated
    /// against the connected target before any request is sent. A timestamp
    /// should come directly from an archive listing; the kernel parses it.
    pub fn new(path: TargetPath, version_time: impl Into<String>) -> Result<Self> {
        let version_time = version_time.into();
        if version_time.is_empty()
            || version_time.len() > 128
            || version_time.chars().any(char::is_control)
        {
            return Err(invalid(
                "archive timestamp must be nonempty, bounded and free of controls",
            ));
        }
        Ok(Self { path, version_time })
    }
}
impl fmt::Debug for FileVersionRestore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileVersionRestore([REDACTED])")
    }
}
/// The native per-path restore report. An empty map is an acknowledgement,
/// not proof that any file changed or that peers accepted the restored data.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct FileVersionRestoreReport(pub BTreeMap<String, Option<String>>);

/// An explicit configured-folder root or one relative directory whose archived
/// file versions should be selected by the native directory restore planner.
#[derive(Clone)]
pub enum VersionedDirectory {
    /// The configured folder's root, deliberately encoded as native dot-root.
    /// This is separate from accepting an arbitrary dot-segment input path.
    FolderRoot,
    /// A relative target directory. Absolute and parent paths are refused.
    Path(TargetPath),
}
impl fmt::Debug for VersionedDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FolderRoot => "VersionedDirectory::FolderRoot",
            Self::Path(_) => "VersionedDirectory::Path([REDACTED])",
        })
    }
}
/// Which native archived version to request for files in a directory scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryVersionOrder {
    /// Request the native planner's newest archived version for each path.
    Newest,
    /// Request the native planner's oldest archived version for each path.
    Oldest,
}
impl FileVersionRestoreReport {
    /// Number of non-null native errors. Error strings can contain target paths.
    pub fn error_count(&self) -> usize {
        self.0.values().filter(|v| v.is_some()).count()
    }
}
impl fmt::Debug for FileVersionRestoreReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileVersionRestoreReport")
            .field("errors", &self.error_count())
            .finish_non_exhaustive()
    }
}
fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfiguration { reason }
}

/// The native global file audit-log settings, distinct from folder versioning.
/// The fixed GUI requires Pro entitlement to enable recording.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub struct AuditHistorySettings {
    /// Whether recording is actually enabled in the observed configuration.
    #[serde(rename = "folderHistoryEnabled")]
    pub enabled: bool,
    /// Retention ceiling; zero requests the native unlimited setting.
    #[serde(rename = "folderHistoryMaxRecords")]
    pub maximum_records: u32,
}
/// Readback after one attempted global audit-log configuration change.
#[derive(Clone, Debug)]
pub struct AuditHistoryUpdate {
    /// Actual settings. An unentitled instance can retain enabled=false.
    pub configuration: AuditHistorySettings,
    /// Submitted enabled/retention values equal actual readback.
    pub requested_fields_match: bool,
}
/// One bounded global audit-log page. Native null and an empty array remain
/// distinguishable. Row schemas require separate licensed validation.
#[derive(Clone, Deserialize)]
pub struct AuditHistoryPage {
    /// Opaque native records; null is not evidence that recording is supported.
    #[serde(rename = "data")]
    pub records: Option<Vec<serde_json::Value>>,
    /// Native reported total before client-side interpretation.
    pub total: u64,
    /// Native page error, if present; errors can contain private data.
    pub error: Option<String>,
    /// Additional native page fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for AuditHistoryPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditHistoryPage")
            .field("total", &self.total)
            .field("records", &self.records.as_ref().map(Vec::len))
            .field("has_error", &self.error.is_some())
            .finish_non_exhaustive()
    }
}
