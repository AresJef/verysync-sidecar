//! Folder configuration inputs and readback, preserving upstream defaults.

use crate::{FolderId, PathStyle, Result, TargetPath};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Inputs for registering a new synchronization folder.
///
/// Unspecified settings come from this instance's upstream folder defaults.
/// The target interprets paths; this controller does not access or expand them.
#[derive(Clone, Debug)]
pub struct CreateFolderOptions {
    pub(crate) id: FolderId,
    pub(crate) path: TargetPath,
    pub(crate) label: Option<String>,
    pub(crate) paused: Option<bool>,
    pub(crate) allow_shared_path: bool,
}
impl CreateFolderOptions {
    /// Choose an explicit new ID and target path, retaining other engine defaults.
    pub fn new(id: FolderId, path: TargetPath) -> Self {
        Self {
            id,
            path,
            label: None,
            paused: None,
            allow_shared_path: false,
        }
    }
    /// Override the upstream default label.
    pub fn label(mut self, value: impl Into<String>) -> Self {
        self.label = Some(value.into());
        self
    }
    /// Override the upstream default paused setting.
    pub fn paused(mut self, value: bool) -> Self {
        self.paused = Some(value);
        self
    }
    /// Explicitly permit another configured ID with the identical path string.
    ///
    /// The default rejects exact matches. Neither setting detects filesystem
    /// aliases, resolves symlinks, or provides atomicity against external writers.
    pub fn allow_shared_path(mut self, value: bool) -> Self {
        self.allow_shared_path = value;
        self
    }
    /// The explicit requested folder ID, useful when reconciling cancellation.
    pub fn id(&self) -> &FolderId {
        &self.id
    }
}

/// A partial folder update. Unspecified fields are never sent or replaced.
///
/// This initial typed surface changes the display label and folder-level pause
/// setting. It does not change device-level or instance-level state.
#[derive(Clone, Debug, Default, Serialize)]
pub struct FolderPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) paused: Option<bool>,
}
impl FolderPatch {
    /// Set the display label, including an explicitly empty label.
    pub fn label(mut self, value: impl Into<String>) -> Self {
        self.label = Some(value.into());
        self
    }
    /// Request this folder's pause setting without changing other pause layers.
    pub fn paused(mut self, value: bool) -> Self {
        self.paused = Some(value);
        self
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.label.is_none() && self.paused.is_none()
    }
    pub(crate) fn matches(&self, config: &FolderConfig) -> bool {
        self.label
            .as_ref()
            .is_none_or(|label| label == &config.label)
            && self.paused.is_none_or(|paused| paused == config.paused)
    }
}

/// Configuration observed after one PATCH, separate from runtime activity.
#[derive(Clone, Debug)]
pub struct FolderUpdate {
    /// The actual configuration read back after the modifying request.
    pub configuration: FolderConfig,
    /// Whether every requested field equals the readback at this instant.
    ///
    /// False can mean pending application or another writer's change. True
    /// confirms configuration only, not that transfers stopped or completed.
    pub requested_fields_match: bool,
}

/// Readback after unregistering a folder without requesting file deletion.
#[derive(Clone, Debug)]
pub struct FolderRemoval {
    /// The configuration observed immediately before the DELETE request.
    pub previous_configuration: FolderConfig,
    /// Whether the ID is absent from the subsequent configuration snapshot.
    ///
    /// False can indicate pending application or an independent writer. This
    /// observes configuration only; the library never inspects/deletes paths.
    pub configuration_absent: bool,
}

/// Current configuration of one folder, not a directory/transfer readiness receipt.
///
/// Paths returned by the target retain its syntax. Unknown fields can include
/// sharing credentials and must be inspected explicitly; Debug omits their values.
#[derive(Clone)]
pub struct FolderConfig {
    /// Configured upstream identifier.
    pub id: FolderId,
    /// Configured display label.
    pub label: String,
    /// Target-reported path, represented with that target's syntax.
    pub path: TargetPath,
    /// Configured pause setting.
    pub paused: bool,
    /// Other upstream configuration fields, retained without replacing defaults.
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for FolderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderConfig")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("path", &self.path)
            .field("paused", &self.paused)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
pub(crate) struct WireFolderIndex {
    pub(crate) folders: Vec<WireFolder>,
}
#[derive(Deserialize)]
pub(crate) struct WireFolder {
    id: FolderId,
    label: String,
    path: String,
    paused: bool,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}
impl WireFolder {
    pub(crate) fn into_config(self, style: PathStyle) -> Result<FolderConfig> {
        Ok(FolderConfig {
            id: self.id,
            label: self.label,
            path: TargetPath::remote(style, self.path)?,
            paused: self.paused,
            extra: self.extra,
        })
    }
}
