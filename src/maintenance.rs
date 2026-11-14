//! Observed official-core logs and maintenance settings, not controller logging.
use crate::{FolderId, TargetPath};
use serde::{Deserialize, Deserializer};
use std::{collections::BTreeMap, fmt};

/// Explicit native synchronization-index reset scope. All folders is a distinct
/// choice, never inferred from a missing folder or an empty identifier.
#[derive(Clone, Eq, PartialEq)]
pub enum IndexResetScope {
    /// Reset the selected configured folder's native index.
    Folder(FolderId),
    /// Reset native synchronization indexes for all configured folders.
    AllFolders,
}
impl fmt::Debug for IndexResetScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Folder(_) => "IndexResetScope::Folder([REDACTED])",
            Self::AllFolders => "IndexResetScope::AllFolders",
        })
    }
}
/// Verified native acknowledgement, separate from observed index removal,
/// program exit, future readiness or filesystem-data preservation.
#[derive(Clone)]
pub struct IndexResetAcknowledgement {
    /// The exact explicit scope submitted by the caller.
    pub scope: IndexResetScope,
    /// The native action expects program restart. No implicit SDK restart or
    /// successful readiness is implied by this observation.
    pub restart_expected: bool,
    pub(crate) native_message: String,
    /// Additional native fields, which can contain private target data.
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl IndexResetAcknowledgement {
    /// Inspect the exact private native acknowledgement text explicitly.
    pub fn native_message(&self) -> &str {
        &self.native_message
    }
}
impl fmt::Debug for IndexResetAcknowledgement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IndexResetAcknowledgement")
            .field("scope", &self.scope)
            .field("restart_expected", &self.restart_expected)
            .finish_non_exhaustive()
    }
}

/// One native log/error entry. Message text can contain private target data.
#[derive(Clone, Deserialize)]
pub struct CoreLogEntry {
    /// Native timestamp, retained without controller-timezone conversion.
    pub when: String,
    /// Native entry severity, distinct from configuration level spellings.
    pub level: String,
    /// Exact observed message; omitted from Debug.
    pub message: String,
    /// Additional native fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for CoreLogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CoreLogEntry([REDACTED])")
    }
}
fn nullable_entries<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Vec<CoreLogEntry>>, D::Error> {
    Option::<Vec<CoreLogEntry>>::deserialize(d)
}
/// The native error log. Null is a known empty log; a missing errors field is
/// invalid rather than an invented successful empty response.
#[derive(Clone, Deserialize)]
pub struct CoreErrorLog {
    /// Actual native error entries, preserving null versus an empty array.
    #[serde(deserialize_with = "nullable_entries")]
    pub errors: Option<Vec<CoreLogEntry>>,
    /// Additional native fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl CoreErrorLog {
    /// Whether the observed native error log is empty.
    pub fn is_empty(&self) -> bool {
        self.errors.as_ref().is_none_or(Vec::is_empty)
    }
}
impl fmt::Debug for CoreErrorLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreErrorLog")
            .field("entries", &self.errors.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}
/// One bounded log snapshot. The SDK does not automatically poll or paginate it.
#[derive(Clone, Deserialize)]
pub struct CoreLogSnapshot {
    /// Native log entries, preserving a nullable response.
    #[serde(deserialize_with = "nullable_entries")]
    pub messages: Option<Vec<CoreLogEntry>>,
    /// Additional native fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for CoreLogSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreLogSnapshot")
            .field("entries", &self.messages.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}
/// A verified native runtime logging configuration level. Unknown response
/// values are retained but cannot be submitted as a verified setting.
#[derive(Clone, Eq, PartialEq)]
pub enum CoreLogLevel {
    /// Native DEBUG configuration.
    Debug,
    /// Native INFO configuration.
    Info,
    /// Native WARN configuration.
    Warn,
    /// Native ERROR configuration (log entries can use another spelling).
    Error,
    /// Unmodeled native response value, omitted from Debug.
    Other(String),
}
impl CoreLogLevel {
    pub(crate) fn wire(&self) -> Option<&'static str> {
        match self {
            Self::Debug => Some("DEBUG"),
            Self::Info => Some("INFO"),
            Self::Warn => Some("WARN"),
            Self::Error => Some("ERROR"),
            Self::Other(_) => None,
        }
    }
}
impl<'de> Deserialize<'de> for CoreLogLevel {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Ok(match String::deserialize(d)?.as_str() {
            "DEBUG" => Self::Debug,
            "INFO" => Self::Info,
            "WARN" => Self::Warn,
            "ERROR" => Self::Error,
            value => Self::Other(value.to_owned()),
        })
    }
}
impl fmt::Debug for CoreLogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire().unwrap_or("CoreLogLevel::Other([REDACTED])"))
    }
}
/// Actual active per-package levels and the native package descriptions.
#[derive(Clone, Deserialize)]
pub struct CoreLogLevels {
    /// Current active levels keyed by exact native package identifiers.
    pub levels: BTreeMap<String, CoreLogLevel>,
    /// Native descriptions. Returned strings are untrusted target data.
    pub packages: BTreeMap<String, String>,
    /// Additional native fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for CoreLogLevels {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreLogLevels")
            .field("packages", &self.levels.len())
            .finish_non_exhaustive()
    }
}
/// Fresh runtime level readback after a partial native update.
#[derive(Clone, Debug)]
pub struct CoreLogLevelUpdate {
    /// Actual runtime configuration after the request.
    pub configuration: CoreLogLevels,
    /// Every requested package has the submitted observed level.
    pub requested_levels_match: bool,
}
/// Native diagnostic metadata. Target locations are never opened on the
/// controller and are not interpreted using the controller's path syntax.
#[derive(Clone)]
pub struct CoreDiagnostics {
    /// Exact native databaseSize value; no undocumented unit conversion occurs.
    pub database_size: u64,
    /// Explicit target-syntax locations such as confdir and datadir.
    pub locations: BTreeMap<String, TargetPath>,
    /// Additional native fields.
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for CoreDiagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreDiagnostics")
            .field("database_size", &self.database_size)
            .field("locations", &self.locations.len())
            .finish_non_exhaustive()
    }
}

/// Explicit native profiling activity. Both variants can change core runtime
/// state; a heap profile triggers native garbage collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreProfileRequest {
    /// Collect the native heap profile, including the core's explicit GC.
    Heap,
    /// Collect native CPU activity for 1..=30 whole seconds. The connection's
    /// request deadline still applies and is not silently increased.
    Cpu {
        /// Explicit whole-second sampling duration.
        duration_seconds: u8,
    },
}

/// Bounded, unchanged compressed native pprof data. Private profile bytes are
/// never included in Debug and are not automatically written to a local file.
#[derive(Clone)]
pub struct CoreProfile {
    /// The explicitly requested native profiling activity.
    pub request: CoreProfileRequest,
    pub(crate) bytes: Vec<u8>,
}
impl CoreProfile {
    /// Borrow the exact native gzip-compressed pprof response. The SDK checks
    /// its gzip signature/minimum length, not its CRC, protobuf contents or
    /// symbol/debug information. Decode/validate before using it in tooling.
    pub fn body_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Take the unchanged compressed native bytes for explicit caller storage.
    pub fn into_body_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
impl fmt::Debug for CoreProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreProfile")
            .field("request", &self.request)
            .field("compressed_bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// One bounded UTF-8 Prometheus exposition snapshot from the authenticated
/// management endpoint. Missing metrics, units, rates and timestamps are not
/// invented. Parsing/aggregation follows the caller's chosen metrics tooling.
#[derive(Clone)]
pub struct CoreMetricsSnapshot {
    pub(crate) text: String,
}
impl CoreMetricsSnapshot {
    /// Borrow the exact native exposition text, including unknown metric
    /// families, labels and comments. These strings can contain private data.
    pub fn native_text(&self) -> &str {
        &self.text
    }
    /// Take the unchanged text for the caller's explicit metrics integration.
    pub fn into_native_text(self) -> String {
        self.text
    }
}
impl fmt::Debug for CoreMetricsSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreMetricsSnapshot")
            .field("text_bytes", &self.text.len())
            .finish_non_exhaustive()
    }
}
