//! Scoped advanced folder selections, shared with creation templates.
use crate::{DiskFreeRequirement, Error, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// Actual native selections. Missing fields remain absent rather than becoming
/// false or zero. Matching configuration is not proof of platform or data effects.
#[derive(Clone, Deserialize)]
pub struct FolderAdvancedConfig {
    /// Actual native folder type, independent of sharing-key permission.
    #[serde(rename = "type")]
    pub folder_type: Option<crate::FolderType>,
    /// Configured native block pull order.
    #[serde(rename = "blockPullOrder")]
    pub block_pull_order: Option<crate::BlockPullOrder>,
    /// Configured native copy strategy; not proof of its actual syscall path.
    #[serde(rename = "copyRangeMethod")]
    pub copy_range_method: Option<crate::CopyRangeMethod>,
    /// Actual ordered native extended-attribute filter and size selectors.
    #[serde(rename = "xattrFilter")]
    pub extended_attribute_filter: Option<crate::ExtendedAttributeFilter>,
    /// Native permission-bit ignore selection.
    #[serde(rename = "ignorePerms")]
    pub ignore_permissions: Option<bool>,
    /// Native filename normalization selection.
    #[serde(rename = "autoNormalize")]
    pub auto_normalize: Option<bool>,
    /// Minimum free space on the target folder volume; does not reserve space.
    #[serde(rename = "minDiskFree")]
    pub minimum_disk_free: Option<DiskFreeRequirement>,
    /// Native copier worker selection; zero retains native policy.
    #[serde(rename = "copiers")]
    pub copiers: Option<u32>,
    /// Observed legacy pending budget. Nonzero edits were normalized to zero
    /// by the selected native baseline; this field has no typed setter.
    #[serde(rename = "pullerMaxPendingKiB")]
    pub puller_max_pending_kib: Option<u32>,
    /// Native hashing worker selection; zero retains native policy.
    #[serde(rename = "hashers")]
    pub hashers: Option<u32>,
    /// Ignore selection for remotely announced deletions.
    #[serde(rename = "ignoreDelete")]
    pub ignore_delete: Option<bool>,
    /// Native pull retry pause in whole seconds.
    #[serde(rename = "pullerPauseS")]
    pub puller_pause_seconds: Option<u32>,
    /// Native pull delay in whole seconds.
    #[serde(rename = "pullerDelayS")]
    pub puller_delay_seconds: Option<u32>,
    /// Retained conflict-copy limit; minus one requests no numeric limit.
    #[serde(rename = "maxConflicts")]
    pub max_conflicts: Option<i32>,
    /// Native sparse-file disable selection.
    #[serde(rename = "disableSparseFiles")]
    pub disable_sparse_files: Option<bool>,
    /// Native parent-ownership selection; OS effects require separate verification.
    #[serde(rename = "copyOwnershipFromParent")]
    pub copy_ownership_from_parent: Option<bool>,
    /// Signed native modification-time comparison window in seconds.
    #[serde(rename = "modTimeWindowS")]
    pub modification_time_window_seconds: Option<i32>,
    /// Native concurrent-write selection; zero retains native policy.
    #[serde(rename = "maxConcurrentWrites")]
    pub max_concurrent_writes: Option<u32>,
    /// Native fsync disable selection; enabling can affect durability.
    #[serde(rename = "disableFsync")]
    pub disable_fsync: Option<bool>,
    /// Native case-sensitivity selection; does not inspect the controller filesystem.
    #[serde(rename = "caseSensitiveFS")]
    pub case_sensitive_filesystem: Option<bool>,
    /// Native directory-junction traversal selection.
    #[serde(rename = "junctionsAsDirs")]
    pub junctions_as_directories: Option<bool>,
    /// Native ownership synchronization selection.
    #[serde(rename = "syncOwnership")]
    pub sync_ownership: Option<bool>,
    /// Native ownership publication selection.
    #[serde(rename = "sendOwnership")]
    pub send_ownership: Option<bool>,
    /// Native extended-attribute synchronization selection.
    #[serde(rename = "syncXattrs")]
    pub sync_extended_attributes: Option<bool>,
    /// Native extended-attribute publication selection.
    #[serde(rename = "sendXattrs")]
    pub send_extended_attributes: Option<bool>,
    /// Native block-indexing selection.
    #[serde(rename = "blockIndexing")]
    pub block_indexing: Option<bool>,
    /// Native backup-only selection, distinct from the folder type.
    #[serde(rename = "backuponly")]
    pub backup_only: Option<bool>,
    /// Native automatic marker-repair selection; the wire spelling is intentional.
    #[serde(rename = "autoRepairtMarker")]
    pub auto_repair_marker: Option<bool>,
    /// Native puller-session selection.
    #[serde(rename = "pullerSessionEnabled")]
    pub puller_session_enabled: Option<bool>,
    /// Native alternate-puller selection.
    #[serde(rename = "antsPullerEnabled")]
    pub ants_puller_enabled: Option<bool>,
    /// Native Live Photo ignore selection.
    #[serde(rename = "ignoreLivePhotos")]
    pub ignore_live_photos: Option<bool>,
    /// Explicit target labels; values are omitted from Debug.
    #[serde(rename = "tags")]
    pub tags: Option<Vec<String>>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for FolderAdvancedConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderAdvancedConfig")
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// Explicit advanced changes. Omitted fields are never submitted. The native
/// target determines applicability; no migration, repair, restart or local I/O
/// is implied. In particular, disabling fsync can reduce target durability.
#[derive(Clone, Default, Serialize)]
pub struct FolderAdvancedPatch {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    folder_type: Option<crate::FolderType>,
    #[serde(rename = "blockPullOrder", skip_serializing_if = "Option::is_none")]
    block_pull_order: Option<crate::BlockPullOrder>,
    #[serde(rename = "copyRangeMethod", skip_serializing_if = "Option::is_none")]
    copy_range_method: Option<crate::CopyRangeMethod>,
    #[serde(rename = "xattrFilter", skip_serializing_if = "Option::is_none")]
    extended_attribute_filter: Option<crate::ExtendedAttributeFilter>,
    #[serde(rename = "ignorePerms", skip_serializing_if = "Option::is_none")]
    ignore_permissions: Option<bool>,
    #[serde(rename = "autoNormalize", skip_serializing_if = "Option::is_none")]
    auto_normalize: Option<bool>,
    #[serde(rename = "minDiskFree", skip_serializing_if = "Option::is_none")]
    minimum_disk_free: Option<DiskFreeRequirement>,
    #[serde(rename = "copiers", skip_serializing_if = "Option::is_none")]
    copiers: Option<u32>,
    #[serde(rename = "hashers", skip_serializing_if = "Option::is_none")]
    hashers: Option<u32>,
    #[serde(rename = "ignoreDelete", skip_serializing_if = "Option::is_none")]
    ignore_delete: Option<bool>,
    #[serde(rename = "pullerPauseS", skip_serializing_if = "Option::is_none")]
    puller_pause_seconds: Option<u32>,
    #[serde(rename = "pullerDelayS", skip_serializing_if = "Option::is_none")]
    puller_delay_seconds: Option<u32>,
    #[serde(rename = "maxConflicts", skip_serializing_if = "Option::is_none")]
    max_conflicts: Option<i32>,
    #[serde(rename = "disableSparseFiles", skip_serializing_if = "Option::is_none")]
    disable_sparse_files: Option<bool>,
    #[serde(
        rename = "copyOwnershipFromParent",
        skip_serializing_if = "Option::is_none"
    )]
    copy_ownership_from_parent: Option<bool>,
    #[serde(rename = "modTimeWindowS", skip_serializing_if = "Option::is_none")]
    modification_time_window_seconds: Option<i32>,
    #[serde(
        rename = "maxConcurrentWrites",
        skip_serializing_if = "Option::is_none"
    )]
    max_concurrent_writes: Option<u32>,
    #[serde(rename = "disableFsync", skip_serializing_if = "Option::is_none")]
    disable_fsync: Option<bool>,
    #[serde(rename = "caseSensitiveFS", skip_serializing_if = "Option::is_none")]
    case_sensitive_filesystem: Option<bool>,
    #[serde(rename = "junctionsAsDirs", skip_serializing_if = "Option::is_none")]
    junctions_as_directories: Option<bool>,
    #[serde(rename = "syncOwnership", skip_serializing_if = "Option::is_none")]
    sync_ownership: Option<bool>,
    #[serde(rename = "sendOwnership", skip_serializing_if = "Option::is_none")]
    send_ownership: Option<bool>,
    #[serde(rename = "syncXattrs", skip_serializing_if = "Option::is_none")]
    sync_extended_attributes: Option<bool>,
    #[serde(rename = "sendXattrs", skip_serializing_if = "Option::is_none")]
    send_extended_attributes: Option<bool>,
    #[serde(rename = "blockIndexing", skip_serializing_if = "Option::is_none")]
    block_indexing: Option<bool>,
    #[serde(rename = "backuponly", skip_serializing_if = "Option::is_none")]
    backup_only: Option<bool>,
    #[serde(rename = "autoRepairtMarker", skip_serializing_if = "Option::is_none")]
    auto_repair_marker: Option<bool>,
    #[serde(
        rename = "pullerSessionEnabled",
        skip_serializing_if = "Option::is_none"
    )]
    puller_session_enabled: Option<bool>,
    #[serde(rename = "antsPullerEnabled", skip_serializing_if = "Option::is_none")]
    ants_puller_enabled: Option<bool>,
    #[serde(rename = "ignoreLivePhotos", skip_serializing_if = "Option::is_none")]
    ignore_live_photos: Option<bool>,
    #[serde(rename = "tags", skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
}
impl FolderAdvancedPatch {
    /// Select native folder type. Existing transitions to/from receive-encrypted
    /// are refused; select it during initial registration instead.
    pub fn folder_type(mut self, value: crate::FolderType) -> Self {
        self.folder_type = Some(value);
        self
    }
    /// Select native block order without claiming a particular transfer order.
    pub fn block_pull_order(mut self, value: crate::BlockPullOrder) -> Self {
        self.block_pull_order = Some(value);
        self
    }
    /// Select a native copy method without assuming platform/filesystem support.
    pub fn copy_range_method(mut self, value: crate::CopyRangeMethod) -> Self {
        self.copy_range_method = Some(value);
        self
    }
    /// Replace ordered attribute rules and explicit native size selectors.
    pub fn extended_attribute_filter(mut self, value: crate::ExtendedAttributeFilter) -> Self {
        self.extended_attribute_filter = Some(value);
        self
    }
    /// Native permission-bit ignore selection.
    pub fn ignore_permissions(mut self, value: bool) -> Self {
        self.ignore_permissions = Some(value);
        self
    }
    /// Native filename normalization selection.
    pub fn auto_normalize(mut self, value: bool) -> Self {
        self.auto_normalize = Some(value);
        self
    }
    /// Minimum free space on the target folder volume; does not reserve space.
    pub fn minimum_disk_free(mut self, value: DiskFreeRequirement) -> Self {
        self.minimum_disk_free = Some(value);
        self
    }
    /// Native copier worker selection; zero retains native policy.
    pub fn copiers(mut self, value: u32) -> Self {
        self.copiers = Some(value);
        self
    }
    /// Native hashing worker selection; zero retains native policy.
    pub fn hashers(mut self, value: u32) -> Self {
        self.hashers = Some(value);
        self
    }
    /// Ignore selection for remotely announced deletions.
    pub fn ignore_delete(mut self, value: bool) -> Self {
        self.ignore_delete = Some(value);
        self
    }
    /// Native pull retry pause in whole seconds.
    pub fn puller_pause_seconds(mut self, value: u32) -> Self {
        self.puller_pause_seconds = Some(value);
        self
    }
    /// Native pull delay in whole seconds.
    pub fn puller_delay_seconds(mut self, value: u32) -> Self {
        self.puller_delay_seconds = Some(value);
        self
    }
    /// Retained conflict-copy limit; minus one requests no numeric limit.
    pub fn max_conflicts(mut self, value: i32) -> Self {
        self.max_conflicts = Some(value);
        self
    }
    /// Native sparse-file disable selection.
    pub fn disable_sparse_files(mut self, value: bool) -> Self {
        self.disable_sparse_files = Some(value);
        self
    }
    /// Native parent-ownership selection; OS effects require separate verification.
    pub fn copy_ownership_from_parent(mut self, value: bool) -> Self {
        self.copy_ownership_from_parent = Some(value);
        self
    }
    /// Signed native modification-time comparison window in seconds.
    pub fn modification_time_window_seconds(mut self, value: i32) -> Self {
        self.modification_time_window_seconds = Some(value);
        self
    }
    /// Native concurrent-write selection; zero retains native policy.
    pub fn max_concurrent_writes(mut self, value: u32) -> Self {
        self.max_concurrent_writes = Some(value);
        self
    }
    /// Native fsync disable selection; enabling can affect durability.
    pub fn disable_fsync(mut self, value: bool) -> Self {
        self.disable_fsync = Some(value);
        self
    }
    /// Native case-sensitivity selection; does not inspect the controller filesystem.
    pub fn case_sensitive_filesystem(mut self, value: bool) -> Self {
        self.case_sensitive_filesystem = Some(value);
        self
    }
    /// Native directory-junction traversal selection.
    pub fn junctions_as_directories(mut self, value: bool) -> Self {
        self.junctions_as_directories = Some(value);
        self
    }
    /// Native ownership synchronization selection.
    pub fn sync_ownership(mut self, value: bool) -> Self {
        self.sync_ownership = Some(value);
        self
    }
    /// Native ownership publication selection.
    pub fn send_ownership(mut self, value: bool) -> Self {
        self.send_ownership = Some(value);
        self
    }
    /// Native extended-attribute synchronization selection.
    pub fn sync_extended_attributes(mut self, value: bool) -> Self {
        self.sync_extended_attributes = Some(value);
        self
    }
    /// Native extended-attribute publication selection.
    pub fn send_extended_attributes(mut self, value: bool) -> Self {
        self.send_extended_attributes = Some(value);
        self
    }
    /// Native block-indexing selection.
    pub fn block_indexing(mut self, value: bool) -> Self {
        self.block_indexing = Some(value);
        self
    }
    /// Native backup-only selection, distinct from the folder type.
    pub fn backup_only(mut self, value: bool) -> Self {
        self.backup_only = Some(value);
        self
    }
    /// Native automatic marker-repair selection; the wire spelling is intentional.
    pub fn auto_repair_marker(mut self, value: bool) -> Self {
        self.auto_repair_marker = Some(value);
        self
    }
    /// Native puller-session selection.
    pub fn puller_session_enabled(mut self, value: bool) -> Self {
        self.puller_session_enabled = Some(value);
        self
    }
    /// Native alternate-puller selection.
    pub fn ants_puller_enabled(mut self, value: bool) -> Self {
        self.ants_puller_enabled = Some(value);
        self
    }
    /// Native Live Photo ignore selection.
    pub fn ignore_live_photos(mut self, value: bool) -> Self {
        self.ignore_live_photos = Some(value);
        self
    }
    /// Explicit target labels; values are omitted from Debug.
    pub fn tags(mut self, value: Vec<String>) -> Self {
        self.tags = Some(value);
        self
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if matches!(self.folder_type, Some(crate::FolderType::Unknown(_)))
            || matches!(
                self.block_pull_order,
                Some(crate::BlockPullOrder::Unknown(_))
            )
            || matches!(
                self.copy_range_method,
                Some(crate::CopyRangeMethod::Unknown(_))
            )
        {
            return Err(invalid(
                "unknown folder policy cannot be submitted by a typed mutation",
            ));
        }
        if let Some(filter) = &self.extended_attribute_filter {
            filter.validate()?;
        }
        if [
            self.copiers,
            self.hashers,
            self.puller_pause_seconds,
            self.puller_delay_seconds,
            self.max_concurrent_writes,
        ]
        .into_iter()
        .flatten()
        .any(|v| v > i32::MAX as u32)
            || self.max_conflicts.is_some_and(|v| v < -1)
            || self.tags.as_ref().is_some_and(|values| {
                values.len() > 256
                    || values
                        .iter()
                        .any(|v| v.len() > 1024 || v.chars().any(char::is_control))
            })
        {
            return Err(invalid(
                "advanced folder selection exceeds its explicit bounds",
            ));
        }
        if let Some(value) = &self.minimum_disk_free {
            value.validate()?;
        }
        let body = serde_json::to_value(self)
            .map_err(|_| invalid("advanced folder patch cannot be encoded"))?;
        if body.as_object().is_none_or(|fields| fields.is_empty()) {
            return Err(invalid(
                "advanced folder patch must contain at least one field",
            ));
        }
        Ok(())
    }
    pub(crate) fn body(&self) -> Result<serde_json::Value> {
        self.validate()?;
        serde_json::to_value(self).map_err(|_| invalid("advanced folder patch cannot be encoded"))
    }
    pub(crate) fn validate_existing(&self, current: &crate::FolderConfig) -> Result<()> {
        if let Some(desired) = &self.folder_type {
            let previous = current
                .extra
                .get("type")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| invalid("existing folder type is absent or invalid"))?;
            if previous != desired.native_name()
                && (previous == "receiveencrypted"
                    || matches!(desired, crate::FolderType::ReceiveEncrypted))
            {
                return Err(invalid(
                    "existing folder cannot transition to or from receive-encrypted",
                ));
            }
        }
        Ok(())
    }
}
impl fmt::Debug for FolderAdvancedPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderAdvancedPatch")
            .finish_non_exhaustive()
    }
}
fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfiguration { reason }
}
