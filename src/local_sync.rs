//! Native Local Sync jobs and observations, distinct from P2P registrations.
use crate::{Error, PathStyle, Result, TargetPath};
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::BTreeMap, fmt};

type Extra = BTreeMap<String, serde_json::Value>;

macro_rules! identifier {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Eq, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);
        impl $name {
            /// Preserve one opaque, bounded native identifier; Debug omits it.
            pub fn parse(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if value.is_empty()
                    || value.len() > 1024
                    || matches!(value.as_str(), "." | "..")
                    || value.chars().any(char::is_control)
                {
                    return Err(invalid("Local Sync identifier must be bounded and non-dot"));
                }
                Ok(Self(value))
            }
            /// Explicit access to the exact potentially private native value.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                Self::parse(String::deserialize(d)?)
                    .map_err(|_| serde::de::Error::custom("invalid Local Sync identifier"))
            }
        }
    };
}
identifier!(
    LocalSyncJobId,
    "Opaque native Local Sync job identifier, distinct from a P2P folder."
);
identifier!(
    LocalSyncOperationId,
    "Native operation identity used to distinguish successive job actions."
);
identifier!(
    LocalSyncPreviewId,
    "One exact native preview; starting it does not execute its actions."
);
identifier!(
    LocalSyncRunId,
    "One exact native execution, separate from its operation and preview IDs."
);

/// A native storage endpoint. Basic paths use the target's filesystem syntax.
/// Credentials and unknown fields returned by the target remain private data.
/// Debug never prints the URI or backend options.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageEndpoint {
    fs_type: String,
    uri: String,
    transfers: u16,
    #[serde(flatten)]
    extra: Extra,
    #[serde(skip)]
    input_style: Option<PathStyle>,
}
impl StorageEndpoint {
    /// Select one explicit basic filesystem path on the target. This performs
    /// no controller filesystem access or path expansion. The client verifies
    /// the supplied syntax against the selected core before writing.
    pub fn local(path: TargetPath) -> Result<Self> {
        let uri = path.to_protocol()?;
        if uri.len() > 32768 {
            return Err(invalid("storage path exceeds the protocol bound"));
        }
        Ok(Self {
            fs_type: "basic".to_owned(),
            uri: uri.to_owned(),
            transfers: 2,
            extra: Extra::new(),
            input_style: Some(path.style()),
        })
    }
    /// Exact upstream backend category, including an unknown future value.
    pub fn filesystem_type(&self) -> &str {
        &self.fs_type
    }
    /// Explicit access to a private native target path or backend locator.
    pub fn uri(&self) -> &str {
        &self.uri
    }
    /// Native parallel-transfer setting, without an SDK performance promise.
    pub fn transfers(&self) -> u16 {
        self.transfers
    }
    /// Explicit access to private backend options, including possible credentials.
    pub fn extra(&self) -> &Extra {
        &self.extra
    }
    pub(crate) fn validate_target(&self, style: PathStyle) -> Result<()> {
        if self.input_style.is_some_and(|supplied| supplied != style) {
            return Err(invalid(
                "basic storage path syntax differs from the selected core",
            ));
        }
        if self.uri.is_empty() || self.uri.len() > 32768 || self.uri.contains('\0') {
            return Err(invalid(
                "storage locator is empty, oversized or contains NUL",
            ));
        }
        Ok(())
    }
}
impl fmt::Debug for StorageEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageEndpoint").finish_non_exhaustive()
    }
}

/// Explicit native synchronization direction. Mirror deletion is a separate flag.
#[derive(Clone, Copy, Debug, Serialize)]
pub enum LocalSyncMode {
    /// Mirror side A to B, preserving extraneous data unless explicitly enabled.
    #[serde(rename = "mirror_a_to_b")]
    MirrorAToB,
    /// Mirror side B to A, with the same separate deletion choice.
    #[serde(rename = "mirror_b_to_a")]
    MirrorBToA,
    /// Native two-way baseline/conflict behavior; separate acceptance is required.
    #[serde(rename = "bisync")]
    Bidirectional,
}
/// Explicit job creation settings. No automatic startup, schedule or watch is
/// enabled. Creating a registration does not preview or execute it.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateLocalSyncJob {
    side_a: StorageEndpoint,
    side_b: StorageEndpoint,
    mode: LocalSyncMode,
    label: String,
    group: String,
    enabled: bool,
    sync_on_startup: bool,
    delete_extraneous: bool,
    ignore_perms: bool,
    watch_changes: bool,
    schedule_mode: &'static str,
    parallel_file_ops: u8,
}
impl CreateLocalSyncJob {
    /// Select both explicit endpoints and a native direction. Permission copying
    /// follows the native default; no deletion of extraneous data is enabled.
    ///
    /// ```no_run
    /// use verysync_sidecar::{Client, CreateLocalSyncJob, LocalSyncMode,
    ///     LocalSyncOperation, Result, StorageEndpoint, TargetPath};
    /// # async fn analyze(client: &Client, source: TargetPath, target: TargetPath)
    /// # -> Result<LocalSyncOperation> {
    /// let options = CreateLocalSyncJob::new(
    ///     StorageEndpoint::local(source)?, StorageEndpoint::local(target)?,
    ///     LocalSyncMode::MirrorAToB,
    /// );
    /// let job = client.create_local_sync_job(&options).await?;
    /// // Analysis is explicit and does not execute the resulting actions.
    /// let operation = client.start_local_sync_preview(&job.job_id).await?;
    /// # Ok(operation)
    /// # }
    /// ```
    pub fn new(side_a: StorageEndpoint, side_b: StorageEndpoint, mode: LocalSyncMode) -> Self {
        Self {
            side_a,
            side_b,
            mode,
            label: String::new(),
            group: String::new(),
            enabled: true,
            sync_on_startup: false,
            delete_extraneous: false,
            ignore_perms: false,
            watch_changes: false,
            schedule_mode: "off",
            parallel_file_ops: 1,
        }
    }
    /// Set an exact label, bounded to 4096 bytes without control characters.
    pub fn label(mut self, label: impl Into<String>) -> Result<Self> {
        self.label = bounded_text(label.into())?;
        Ok(self)
    }
    /// Set an exact group name under the same bound as a label.
    pub fn group(mut self, group: impl Into<String>) -> Result<Self> {
        self.group = bounded_text(group.into())?;
        Ok(self)
    }
    /// Explicitly allow or disable native permission synchronization.
    pub fn ignore_permissions(mut self, ignore: bool) -> Self {
        self.ignore_perms = ignore;
        self
    }
    /// Explicitly permit mirror removal of destination-only data. This is
    /// destructive and has no SDK backup/rollback. Two-way mode refuses this flag.
    pub fn delete_extraneous(mut self, allow: bool) -> Result<Self> {
        if allow && matches!(self.mode, LocalSyncMode::Bidirectional) {
            return Err(invalid("mirror deletion is not a two-way job setting"));
        }
        self.delete_extraneous = allow;
        Ok(self)
    }
    pub(crate) fn endpoints(&self) -> (&StorageEndpoint, &StorageEndpoint) {
        (&self.side_a, &self.side_b)
    }
}
impl fmt::Debug for CreateLocalSyncJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateLocalSyncJob")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// Observed native Local Sync availability, independent of protocol acceptance.
#[derive(Deserialize)]
pub struct LocalSyncHealth {
    /// Actual target-reported availability, not an SDK support inference.
    pub available: bool,
    /// Additional private upstream conditions.
    #[serde(flatten)]
    pub extra: Extra,
}
/// A full native job. Unknown settings and private endpoint options are retained
/// so a scoped update need not reconstruct defaults or discard other fields.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalSyncJob {
    /// Exact registration identity.
    pub job_id: LocalSyncJobId,
    /// Private display label.
    pub label: String,
    /// Private group label.
    pub group: String,
    /// First explicit storage endpoint.
    pub side_a: StorageEndpoint,
    /// Second explicit storage endpoint.
    pub side_b: StorageEndpoint,
    /// Native mode, preserving unknown future values.
    pub mode: String,
    /// Whether native job execution is enabled.
    pub enabled: bool,
    /// Whether target startup can trigger execution.
    pub sync_on_startup: bool,
    /// Native mirror deletion choice, separate from registration deletion.
    pub delete_extraneous: bool,
    /// Unknown settings, native timestamps and protocol-specific data.
    #[serde(flatten)]
    pub extra: Extra,
}
/// The complete native job configuration and its native schema version.
#[derive(Deserialize)]
pub struct LocalSyncConfiguration {
    /// Target-reported configuration schema version.
    pub version: u64,
    /// Actual observed job list, including a known empty list.
    pub jobs: Vec<LocalSyncJob>,
    /// Additional private native settings.
    #[serde(flatten)]
    pub extra: Extra,
}
/// A scoped job update. Fields not selected remain exactly as read from the core.
#[derive(Clone, Default)]
pub struct LocalSyncJobPatch {
    pub(crate) label: Option<String>,
    pub(crate) group: Option<String>,
    pub(crate) enabled: Option<bool>,
}
impl LocalSyncJobPatch {
    /// Select an exact bounded label.
    pub fn label(mut self, value: impl Into<String>) -> Result<Self> {
        self.label = Some(bounded_text(value.into())?);
        Ok(self)
    }
    /// Select an exact bounded group.
    pub fn group(mut self, value: impl Into<String>) -> Result<Self> {
        self.group = Some(bounded_text(value.into())?);
        Ok(self)
    }
    /// Select whether native execution is enabled, without starting a run.
    pub fn enabled(mut self, value: bool) -> Self {
        self.enabled = Some(value);
        self
    }
}
/// A scoped update and actual readback, rather than proof of future sync effects.
pub struct LocalSyncJobUpdate {
    /// Full observed configuration after the request.
    pub configuration: LocalSyncJob,
    /// Whether all explicitly selected fields match their requested values.
    pub requested_fields_match: bool,
}
/// Native registration deletion observed in the subsequent complete job list.
pub struct LocalSyncJobRemoval {
    /// Exact identity observed absent; source/target data are not deletion targets.
    pub job_id: LocalSyncJobId,
}
/// Native task acknowledgement. Observe the exact operation before inferring completion.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalSyncOperation {
    /// Native operation identity, distinct from the later preview/run ID.
    pub id: LocalSyncOperationId,
    /// Exact job selected by the operation.
    pub job_id: LocalSyncJobId,
    /// Additional private native fields.
    #[serde(flatten)]
    pub extra: Extra,
}
/// A point-in-time native job state. Unknown state/progress fields remain intact.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalSyncStatus {
    /// Exact native job identity.
    pub job_id: LocalSyncJobId,
    /// Actual native state; it is not normalized into an invented success.
    pub state: String,
    /// Native operation identity. Missing/null/empty native values mean that
    /// no operation identity has been assigned, not that work completed.
    #[serde(default, deserialize_with = "optional_operation")]
    pub operation_id: Option<LocalSyncOperationId>,
    /// Native error text, private and not printed by Debug.
    pub last_error: Option<String>,
    /// Native counts, watch state, progress and future metadata.
    #[serde(flatten)]
    pub extra: Extra,
}
/// A completed native preview snapshot. Expiry and external writers can still
/// invalidate it; starting or reading it does not change source/target data.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalSyncPreview {
    /// Exact preview identity needed by a separately explicit run.
    pub id: LocalSyncPreviewId,
    /// Registration that was analyzed.
    pub job_id: LocalSyncJobId,
    /// Operation that produced this snapshot.
    pub operation_id: LocalSyncOperationId,
    /// Total native preview actions; zero is a known empty preview.
    pub count: u64,
    /// Native RFC3339 expiry text; no controller clock substitution occurs.
    pub expires_at: String,
    /// Native scan issue count, separate from action count.
    pub scan_issue_count: u64,
    /// Native per-action totals and future fields.
    #[serde(flatten)]
    pub extra: Extra,
}
/// One native preview action, preserving untrusted path/kind/direction metadata.
#[derive(Deserialize)]
pub struct LocalSyncAction {
    /// Exact numeric action ID; zero is valid.
    pub id: u64,
    /// Native volume-relative path, never opened on the controller.
    pub path: String,
    /// Native action kind, retaining future values.
    pub kind: String,
    /// Optional source side, such as `a` or `b`.
    pub from: Option<String>,
    /// Optional destination side.
    pub to: Option<String>,
    /// Private metadata, including source/target snapshots and conflict details.
    #[serde(flatten)]
    pub extra: Extra,
}
/// Actual native execution summary; successful HTTP does not imply zero failures.
#[derive(Clone, Debug, Deserialize)]
pub struct LocalSyncSummary {
    /// Actual completed native actions.
    pub completed: u64,
    /// Actual failed native actions.
    pub failed: u64,
    /// Actual skipped native actions.
    pub skipped: u64,
}
/// A run receipt or later snapshot. Check the native finished timestamp and
/// summary separately; acknowledgement is not a completed-data receipt.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalSyncRun {
    /// Exact execution identity used for paged results.
    pub id: LocalSyncRunId,
    /// Registration being executed.
    pub job_id: LocalSyncJobId,
    /// Native start timestamp.
    pub started: String,
    /// Native finish timestamp; the native zero time means unfinished.
    pub finished: String,
    /// Native action count, with no SDK assertion that every action succeeded.
    pub count: u64,
    /// Actual success/failure/skip counters.
    pub summary: LocalSyncSummary,
    /// Native error/stopped fields and future metadata.
    #[serde(flatten)]
    pub extra: Extra,
}
/// One native execution result; private errors and unmodeled fields remain intact.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalSyncActionResult {
    /// Exact action ID, including zero.
    pub action_id: u64,
    /// Native relative path; no controller filesystem access occurs.
    pub path: String,
    /// Native action kind.
    pub kind: String,
    /// Actual transferred byte count if reported; absent is not zero.
    pub bytes: Option<u64>,
    /// Direction, elapsed time, failure text and future metadata.
    #[serde(flatten)]
    pub extra: Extra,
}
/// One native storage-directory entry, distinct from a file-manager volume path.
#[derive(Deserialize)]
pub struct StorageEntry {
    /// Native logical slash-separated path.
    pub path: String,
    /// Actual directory classification.
    pub directory: bool,
    /// Native reported size, without inventing directory-byte meaning.
    pub size: u64,
    /// Native modification timestamp text.
    pub modified: String,
    /// Future private metadata.
    #[serde(flatten)]
    pub extra: Extra,
}
/// One bounded native storage listing. No absent listing becomes an empty success.
#[derive(Deserialize)]
pub struct StorageDirectory {
    /// Exact native logical subpath.
    pub path: String,
    /// Actual entries returned for this listing.
    pub entries: Vec<StorageEntry>,
    /// Additional private native fields.
    #[serde(flatten)]
    pub extra: Extra,
}
/// Exact capabilities reported by one native endpoint probe. Protocol effect
/// acceptance is separate; these flags do not implement SDK fallback operations.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageProbe {
    /// Native permission support claim.
    pub file_permissions: bool,
    /// Native timestamp precision label, without SDK unit conversion.
    pub time_precision: String,
    /// Native move support claim.
    pub r#move: bool,
    /// Native atomic-replacement support claim, not an SDK transaction promise.
    pub atomic_replace: bool,
    /// Native modification-time preservation claim.
    pub preserves_mod_time: bool,
    /// Unknown private native fields.
    #[serde(flatten)]
    pub extra: Extra,
}
/// Actual native history page. Native action history is independent of file versions.
#[derive(Deserialize)]
pub struct LocalSyncHistory {
    /// Native total row count, not just this page's length.
    pub total: u64,
    /// Returned native history records.
    pub records: Vec<LocalSyncHistoryRecord>,
    /// Future private native fields.
    #[serde(flatten)]
    pub extra: Extra,
}
/// One native operation-history record, preserving its exact target path and time.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalSyncHistoryRecord {
    /// Job that produced this history row.
    pub job_id: LocalSyncJobId,
    /// Native relative path.
    pub path: String,
    /// Native affected side.
    pub side: String,
    /// Native action kind.
    pub action: String,
    /// Native timestamp text.
    pub time: String,
    /// Unknown private native fields.
    #[serde(flatten)]
    pub extra: Extra,
}

macro_rules! private_debug {
    ($($ty:ty),+ $(,)?) => { $(impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct(stringify!($ty)).finish_non_exhaustive()
        }
    })+ };
}
private_debug!(
    LocalSyncHealth,
    LocalSyncJob,
    LocalSyncConfiguration,
    LocalSyncJobPatch,
    LocalSyncJobUpdate,
    LocalSyncJobRemoval,
    LocalSyncOperation,
    LocalSyncStatus,
    LocalSyncPreview,
    LocalSyncAction,
    LocalSyncRun,
    LocalSyncActionResult,
    StorageEntry,
    StorageDirectory,
    StorageProbe,
    LocalSyncHistory,
    LocalSyncHistoryRecord
);

pub(crate) fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfiguration { reason }
}
fn optional_operation<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<LocalSyncOperationId>, D::Error> {
    let value = Option::<String>::deserialize(d)?;
    value
        .filter(|v| !v.is_empty())
        .map(LocalSyncOperationId::parse)
        .transpose()
        .map_err(|_| serde::de::Error::custom("invalid Local Sync operation identity"))
}
fn bounded_text(value: String) -> Result<String> {
    if value.len() > 4096 || value.chars().any(char::is_control) {
        Err(invalid(
            "Local Sync label/group exceeds its bound or contains controls",
        ))
    } else {
        Ok(value)
    }
}
pub(crate) fn logical_subpath(value: &str) -> Result<()> {
    if value.len() > 32768
        || value.contains('\0')
        || value.starts_with('/')
        || value.contains('\\')
        || (!value.is_empty()
            && value
                .split('/')
                .any(|p| p.is_empty() || matches!(p, "." | "..")))
    {
        return Err(invalid(
            "storage subpath must contain bounded explicit non-dot logical components",
        ));
    }
    Ok(())
}
