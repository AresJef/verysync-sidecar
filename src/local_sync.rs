//! Native Local Sync jobs and observations, distinct from P2P registrations.
use crate::{Error, PathStyle, Result, TargetPath};
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::BTreeMap, fmt};

type Extra = BTreeMap<String, serde_json::Value>;

/// Explicit native remote backend; a URI does not prove data-effect acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageProtocol {
    /// Native SSH File Transfer Protocol backend.
    Sftp,
    /// Native FTP backend.
    Ftp,
    /// Native SMB backend.
    Smb,
    /// Native HTTP or HTTPS WebDAV backend.
    WebDav,
}

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
    /// Select a remote URI without embedded credentials, query or fragment.
    /// This does not connect, download a client or start a server.
    pub fn remote(protocol: StorageProtocol, uri: &str) -> Result<Self> {
        if uri.len() > 32768 || uri.chars().any(char::is_control) {
            return Err(invalid(
                "storage URI exceeds its bound or contains controls",
            ));
        }
        let url = url::Url::parse(uri).map_err(|_| invalid("invalid remote storage URI"))?;
        let (kind, schemes): (&str, &[&str]) = match protocol {
            StorageProtocol::Sftp => ("sftp", &["sftp"]),
            StorageProtocol::Ftp => ("ftp", &["ftp"]),
            StorageProtocol::Smb => ("smb", &["smb"]),
            StorageProtocol::WebDav => ("webdav", &["http", "https"]),
        };
        if !schemes.contains(&url.scheme())
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid("storage URI scheme, authority or private selectors differ from its explicit protocol"));
        }
        Ok(Self {
            fs_type: kind.to_owned(),
            uri: url.to_string(),
            transfers: 4,
            extra: Extra::new(),
            input_style: None,
        })
    }
    /// Select native username/password credentials without adding URI userinfo.
    /// Explicit serialization can expose them; default Debug omits all values.
    pub fn credentials(
        mut self,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self> {
        if self.fs_type == "basic" {
            return Err(invalid("basic endpoints do not take remote credentials"));
        }
        let (user, password) = (user.into(), password.into());
        if user.is_empty()
            || user.len() > 4096
            || password.len() > 65536
            || user.contains('\0')
            || password.contains('\0')
        {
            return Err(invalid(
                "storage credentials are empty, oversized or contain NUL",
            ));
        }
        self.extra.insert("user".to_owned(), user.into());
        self.extra.insert("password".to_owned(), password.into());
        Ok(self)
    }
    /// Set native connection timeout seconds. Zero retains the native default;
    /// the management request still has its separately configured deadline.
    pub fn connection_timeout_seconds(mut self, seconds: u16) -> Self {
        self.extra
            .insert("connectTimeoutSec".to_owned(), seconds.into());
        self
    }
    /// Explicitly select the native insecureTls option for SFTP or WebDAV.
    /// This can disable target-side identity checks without changing controller
    /// trust stores. Its effects need separate per-protocol acceptance.
    pub fn insecure_tls(mut self, allow: bool) -> Result<Self> {
        if !matches!(self.fs_type.as_str(), "sftp" | "webdav") {
            return Err(invalid(
                "insecureTls is not a verified option for this storage protocol",
            ));
        }
        self.extra.insert("insecureTls".to_owned(), allow.into());
        Ok(self)
    }
    /// Select an explicit target-system SFTP private-key file. The SDK opens no
    /// key file or SSH configuration on the controller.
    pub fn private_key_file(mut self, path: TargetPath) -> Result<Self> {
        if self.fs_type != "sftp" {
            return Err(invalid("private key files require an SFTP endpoint"));
        }
        let value = path.to_protocol()?;
        if value.len() > 32768 {
            return Err(invalid("SFTP private key path exceeds its bound"));
        }
        self.extra.insert("privateKey".to_owned(), value.into());
        self.input_style = Some(path.style());
        Ok(self)
    }
    /// Explicit native SMB guest selection; actual server permissions and
    /// separate positive guest acceptance still apply.
    pub fn smb_guest(mut self, guest: bool) -> Result<Self> {
        if self.fs_type != "smb" {
            return Err(invalid("guest authentication requires an SMB endpoint"));
        }
        self.extra.insert("guest".to_owned(), guest.into());
        Ok(self)
    }
    /// Select an SMB domain/workgroup without consulting controller settings.
    pub fn smb_domain(mut self, domain: impl Into<String>) -> Result<Self> {
        if self.fs_type != "smb" {
            return Err(invalid("domain selection requires an SMB endpoint"));
        }
        let domain = bounded_text(domain.into())?;
        self.extra.insert("domain".to_owned(), domain.into());
        Ok(self)
    }
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
                "storage filesystem path syntax differs from the selected core",
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
/// Explicit native policy for simultaneous two-way changes.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalSyncConflictPolicy {
    /// Select the native newer modification-time policy.
    Newer,
    /// Select the native larger-file policy.
    Larger,
    /// Preserve conflicts for separately explicit manual resolution.
    Manual,
}

/// One inclusive native action-ID range; numeric action zero is valid.
#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub struct LocalSyncActionRange([u64; 2]);
impl LocalSyncActionRange {
    /// Select a non-reversed range whose inclusive length fits a u64.
    pub fn new(first: u64, last: u64) -> Result<Self> {
        if last
            .checked_sub(first)
            .and_then(|n| n.checked_add(1))
            .is_none()
        {
            return Err(invalid("Local Sync action range is reversed or overflows"));
        }
        Ok(Self([first, last]))
    }
    /// Select one exact action ID without expanding a range into a list.
    pub fn single(id: u64) -> Self {
        Self([id, id])
    }
    /// First inclusive action ID.
    pub fn first(&self) -> u64 {
        self.0[0]
    }
    /// Last inclusive action ID.
    pub fn last(&self) -> u64 {
        self.0[1]
    }
}

/// Explicit bounded selection within one separately identified preview.
/// Empty includes select none; executing an empty selection is refused.
#[derive(Clone, Debug, Serialize)]
pub struct LocalSyncSelection {
    all: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    include: Vec<LocalSyncActionRange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    exclude: Vec<LocalSyncActionRange>,
}
impl LocalSyncSelection {
    /// Select every action in the exact preview supplied to a client method.
    pub fn all() -> Self {
        Self {
            all: true,
            include: Vec::new(),
            exclude: Vec::new(),
        }
    }
    /// Include only explicit ascending, disjoint inclusive ranges (at most 10000).
    /// No range is silently sorted, merged, expanded or clipped.
    pub fn including(ranges: Vec<LocalSyncActionRange>) -> Result<Self> {
        Self::ranges(false, ranges)
    }
    /// Select all actions except these ascending, disjoint inclusive ranges.
    pub fn all_except(ranges: Vec<LocalSyncActionRange>) -> Result<Self> {
        Self::ranges(true, ranges)
    }
    fn ranges(all: bool, ranges: Vec<LocalSyncActionRange>) -> Result<Self> {
        if ranges.len() > 10000 || ranges.windows(2).any(|w| w[0].last() >= w[1].first()) {
            return Err(invalid(
                "Local Sync ranges must be bounded, ascending and disjoint",
            ));
        }
        let (include, exclude) = if all {
            (Vec::new(), ranges)
        } else {
            (ranges, Vec::new())
        };
        Ok(Self {
            all,
            include,
            exclude,
        })
    }
    pub(crate) fn selected_count(&self, count: u64) -> Result<u64> {
        let ranges = if self.all {
            &self.exclude
        } else {
            &self.include
        };
        let mut covered = 0u64;
        for range in ranges {
            if range.last() >= count {
                return Err(invalid("Local Sync range is outside the exact preview"));
            }
            covered = covered
                .checked_add(range.last() - range.first() + 1)
                .ok_or_else(|| invalid("Local Sync selected count overflows"))?;
        }
        if self.all {
            count
                .checked_sub(covered)
                .ok_or_else(|| invalid("Local Sync excluded count exceeds preview"))
        } else {
            Ok(covered)
        }
    }
}

/// Actual native action totals for an exact preview selection, without execution.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalSyncSelectionSummary {
    /// Actual selected previously resolved conflicts.
    pub resolved_conflicts: u64,
    /// Actual selected file permission operations.
    pub permission_files: u64,
    /// Actual selected file copies.
    pub copy_files: u64,
    /// Actual selected file deletions.
    pub delete_files: u64,
    /// Actual selected directory creations.
    pub create_directories: u64,
    /// Actual selected directory deletions.
    pub delete_directories: u64,
    /// Actual selected unresolved conflicts.
    pub conflicts: u64,
    /// Native predicted copy bytes, separate from completed transfer bytes.
    pub copy_bytes: u64,
    /// Additional private native totals.
    #[serde(flatten)]
    pub extra: Extra,
}

/// Explicit winning side for a manual conflict. A missing winning object can
/// produce a native deletion action; resolving a preview executes no action.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LocalSyncConflictSide {
    /// Choose side A's actual current state, including an observed deletion.
    A,
    /// Choose side B's actual current state, including an observed deletion.
    B,
}
/// One explicit native preview conflict resolution, with private target paths.
#[derive(Clone, Serialize)]
pub struct LocalSyncConflictResolution {
    path: String,
    recursive: bool,
    side: LocalSyncConflictSide,
}
impl LocalSyncConflictResolution {
    /// Resolve exactly one nonempty logical path in a reviewed preview.
    pub fn at_path(path: impl Into<String>, side: LocalSyncConflictSide) -> Result<Self> {
        let path = path.into();
        logical_subpath(&path)?;
        if path.is_empty() {
            return Err(invalid(
                "single conflict resolution requires a nonempty path",
            ));
        }
        Ok(Self {
            path,
            recursive: false,
            side,
        })
    }
    /// Resolve one explicit subtree; an empty path deliberately selects the root.
    pub fn subtree(path: impl Into<String>, side: LocalSyncConflictSide) -> Result<Self> {
        let path = path.into();
        logical_subpath(&path)?;
        Ok(Self {
            path,
            recursive: true,
            side,
        })
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    enabled: bool,
    sync_on_startup: bool,
    delete_extraneous: bool,
    ignore_perms: bool,
    watch_changes: bool,
    schedule_mode: &'static str,
    parallel_file_ops: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    conflict_policy: Option<LocalSyncConflictPolicy>,
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
    ///     "Explicit storage analysis",
    ///     StorageEndpoint::local(source)?, StorageEndpoint::local(target)?,
    ///     LocalSyncMode::MirrorAToB,
    /// )?;
    /// let job = client.create_local_sync_job(&options).await?;
    /// // Analysis is explicit and does not execute the resulting actions.
    /// let operation = client.start_local_sync_preview(&job.job_id).await?;
    /// # Ok(operation)
    /// # }
    /// ```
    pub fn new(
        label: impl Into<String>,
        side_a: StorageEndpoint,
        side_b: StorageEndpoint,
        mode: LocalSyncMode,
    ) -> Result<Self> {
        Ok(Self {
            side_a,
            side_b,
            mode,
            label: job_label(label.into())?,
            group: None,
            enabled: true,
            sync_on_startup: false,
            delete_extraneous: false,
            ignore_perms: false,
            watch_changes: false,
            schedule_mode: "off",
            parallel_file_ops: 1,
            conflict_policy: None,
        })
    }
    /// Select the native simultaneous-change policy for a two-way job.
    /// No conflict is resolved or file changed by constructing this option.
    pub fn conflict_policy(mut self, policy: LocalSyncConflictPolicy) -> Result<Self> {
        if !matches!(self.mode, LocalSyncMode::Bidirectional) {
            return Err(invalid("conflict policy requires a two-way Local Sync job"));
        }
        self.conflict_policy = Some(policy);
        Ok(self)
    }
    /// Set a bounded group name; an empty group selects no named group.
    pub fn group(mut self, group: impl Into<String>) -> Result<Self> {
        let group = bounded_text(group.into())?;
        self.group = if group.is_empty() { None } else { Some(group) };
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
    /// Private group label when present. Native ungrouped jobs omit this field;
    /// absence is retained and full-object updates omit it again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
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
        self.label = Some(job_label(value.into())?);
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
/// An explicit control for the currently identified native job operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalSyncOperationControl {
    /// Request a pause; read actual state and in-flight effects separately.
    Pause,
    /// Request resumption of the same identified operation.
    Resume,
    /// Request cancellation; this is not rollback or proof of immediate I/O stop.
    Stop,
}
/// A known native control acknowledgement and a separately read status snapshot.
#[derive(Debug)]
pub struct LocalSyncControlReceipt {
    /// Exact target registration.
    pub job_id: LocalSyncJobId,
    /// Operation checked before and after the command.
    pub operation_id: LocalSyncOperationId,
    /// Caller-selected control.
    pub control: LocalSyncOperationControl,
    /// Actual readback; acknowledgement alone does not promise a target state.
    pub observed: LocalSyncStatus,
}
/// Actual native transfer counters. Reported bytes are not durable file proof.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalSyncProgress {
    /// Reported start time, when present.
    pub started: Option<String>,
    /// Reported planned bytes, when known.
    pub planned_bytes: Option<u64>,
    /// Reported planned action count, when known.
    pub planned_actions: Option<u64>,
    /// Reported finished actions; not inferred from missing values.
    pub finished_actions: Option<u64>,
    /// Reported finished files.
    pub finished_files: Option<u64>,
    /// Native transfer counter; it may include work that is later cancelled.
    pub bytes_transferred: Option<u64>,
    /// Current private path and future native progress values.
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
    /// Actual native execution counters, when supplied.
    pub summary: Option<LocalSyncSummary>,
    /// Actual native progress without inferring transferred or durable bytes.
    pub progress: Option<LocalSyncProgress>,
    /// Whether the latest native run was cancelled, when reported.
    pub last_run_cancelled: Option<bool>,
    /// Native counts, watch state and future metadata.
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
    /// Whether this native run was cancelled, when explicitly reported.
    pub cancelled: Option<bool>,
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
    /// Native signed size. FTP directories can report -1 for unknown; this is
    /// preserved rather than changed to zero or an invented byte count.
    pub size: i64,
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
    LocalSyncSelectionSummary,
    LocalSyncConflictResolution,
    LocalSyncJobPatch,
    LocalSyncJobUpdate,
    LocalSyncJobRemoval,
    LocalSyncOperation,
    LocalSyncStatus,
    LocalSyncProgress,
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
fn job_label(value: String) -> Result<String> {
    let value = bounded_text(value)?;
    if value.trim().is_empty() {
        return Err(invalid(
            "Local Sync requires an explicit nonempty job label",
        ));
    }
    Ok(value)
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

#[cfg(test)]
mod contract_tests {
    use super::*;
    #[test]
    fn explicit_remote_protocol_rejects_ambiguous_secrets_and_selectors() {
        for (protocol, uri) in [
            (StorageProtocol::Ftp, "sftp://host/root"),
            (StorageProtocol::Sftp, "sftp://user:secret@host/root"),
            (StorageProtocol::Smb, "smb://host/share?password=secret"),
            (StorageProtocol::WebDav, "https://host/root#private"),
            (StorageProtocol::Ftp, "ftp://host/\nroot"),
        ] {
            assert!(StorageEndpoint::remote(protocol, uri).is_err());
        }
        let endpoint =
            StorageEndpoint::remote(StorageProtocol::Sftp, "sftp://example.invalid:2222/root")
                .unwrap()
                .credentials("synthetic-user", "synthetic-password")
                .unwrap();
        let encoded = serde_json::to_value(&endpoint).unwrap();
        assert_eq!(encoded["user"], "synthetic-user");
        assert_eq!(encoded["password"], "synthetic-password");
        assert!(!endpoint.uri().contains("synthetic"));
        let debug = format!("{endpoint:?}");
        for private in [
            "example.invalid",
            "synthetic-user",
            "synthetic-password",
            "root",
        ] {
            assert!(!debug.contains(private));
        }
        assert!(endpoint.clone().smb_guest(true).is_err());
        assert!(endpoint.credentials("", "password").is_err());
        assert!(
            StorageEndpoint::remote(StorageProtocol::Ftp, "ftp://example.invalid/")
                .unwrap()
                .insecure_tls(true)
                .is_err()
        );
    }

    #[test]
    fn native_unknown_size_and_ungrouped_registration_are_retained() {
        let endpoint =
            StorageEndpoint::remote(StorageProtocol::Ftp, "ftp://example.invalid/").unwrap();
        let options = CreateLocalSyncJob::new(
            "explicit",
            endpoint.clone(),
            endpoint,
            LocalSyncMode::MirrorAToB,
        )
        .unwrap();
        let mut value = serde_json::to_value(options).unwrap();
        assert!(value.get("group").is_none());
        value["jobId"] = "synthetic-job".into();
        let job: LocalSyncJob = serde_json::from_value(value).unwrap();
        assert!(job.group.is_none());
        assert!(serde_json::to_value(job).unwrap().get("group").is_none());
        let directory: StorageEntry = serde_json::from_value(serde_json::json!({
            "path":"directory", "directory":true,"size":-1,"modified":"native-time"}))
        .unwrap();
        assert_eq!(directory.size, -1);
        assert!(serde_json::from_value::<StorageEntry>(
            serde_json::json!({"path":"missing-size","directory":true,"modified":"native-time"})
        )
        .is_err());
    }
    #[test]
    fn selection_ranges_keep_zero_and_refuse_overflow_overlap_and_outside_ids() {
        assert!(LocalSyncActionRange::new(2, 1).is_err());
        assert!(LocalSyncActionRange::new(0, u64::MAX).is_err());
        assert!(LocalSyncSelection::including(vec![
            LocalSyncActionRange::new(0, 2).unwrap(),
            LocalSyncActionRange::single(2)
        ])
        .is_err());
        assert!(LocalSyncSelection::including(vec![
            LocalSyncActionRange::single(2),
            LocalSyncActionRange::single(0)
        ])
        .is_err());
        assert!(
            LocalSyncSelection::including(vec![LocalSyncActionRange::single(0); 10001]).is_err()
        );
        let zero = LocalSyncSelection::including(vec![LocalSyncActionRange::single(0)]).unwrap();
        assert_eq!(zero.selected_count(1).unwrap(), 1);
        assert!(zero.selected_count(0).is_err());
        let excluded =
            LocalSyncSelection::all_except(vec![LocalSyncActionRange::single(0)]).unwrap();
        assert_eq!(excluded.selected_count(1).unwrap(), 0);
        assert_eq!(
            LocalSyncSelection::including(Vec::new())
                .unwrap()
                .selected_count(10)
                .unwrap(),
            0
        );
        let wide =
            LocalSyncSelection::including(vec![LocalSyncActionRange::new(0, 999999999).unwrap()])
                .unwrap();
        assert_eq!(wide.selected_count(1000000000).unwrap(), 1000000000);
    }
}
