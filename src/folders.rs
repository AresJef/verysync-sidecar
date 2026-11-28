//! Folder configuration inputs and readback, preserving upstream defaults.

use crate::{
    Error, FolderId, FolderState, FolderStatus, ManagementWriteEvidence, OperationCompletion,
    PathStyle, Result, TargetPath,
};
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
    pub(crate) advanced: Option<crate::FolderAdvancedPatch>,
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
            advanced: None,
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
    /// Select explicit advanced initial settings while preserving all other
    /// instance defaults. This can choose receive-encrypted on a new folder;
    /// it never changes the shared creation template or an existing registration.
    pub fn advanced_configuration(mut self, patch: crate::FolderAdvancedPatch) -> Result<Self> {
        patch.validate()?;
        self.advanced = Some(patch);
        Ok(self)
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

/// What the SDK can establish about the requested folder fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FolderConfigurationOutcome {
    /// The selected fields already matched before a modification.
    AlreadyMatched,
    /// A later read of the selected folder reports all the requested values.
    CurrentMatches,
    /// The correct folder was read and at least one requested value differs.
    CurrentDiffers,
    /// The operation ended before submitting its change.
    NotSubmitted,
    /// The endpoint returned a complete authentication or permission refusal.
    Rejected,
    /// No trustworthy read of the current fields is available.
    Unconfirmed,
}

/// A finite observation of the folder's reported activity.
pub struct FolderRuntimeObservation {
    /// The state the caller asked to observe.
    pub expected: FolderState,
    /// The expected state was observed for this folder.
    pub expected_state_observed: bool,
    /// Last authenticated snapshot, if one was available.
    pub last_snapshot: Option<FolderStatus>,
    /// A read error, cancellation or deadline that ended the observation.
    pub source: Option<Error>,
}

impl fmt::Debug for FolderRuntimeObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderRuntimeObservation")
            .field("expected_state_observed", &self.expected_state_observed)
            .field("has_snapshot", &self.last_snapshot.is_some())
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// The original folder write and the current configuration observed afterward.
#[non_exhaustive]
pub struct FolderConfigurationReport {
    /// Confirmation status of the requested fields.
    pub outcome: FolderConfigurationOutcome,
    /// Request and response facts, independent of the field readback.
    pub write: ManagementWriteEvidence,
    /// Original request result or preflight error. Empty for an already matching target.
    pub original: Option<Result<()>>,
    /// The same selected folder's current configuration, if it could be checked.
    pub observed: Option<FolderConfig>,
    /// Failure to establish a trustworthy current configuration.
    pub observation_error: Option<Error>,
    /// Explicit optional runtime observation after confirming the configuration.
    pub runtime: Option<FolderRuntimeObservation>,
}

impl FolderConfigurationReport {
    /// Summarize both the configured fields and an optional activity goal.
    pub fn completion(&self) -> OperationCompletion {
        match self.outcome {
            FolderConfigurationOutcome::AlreadyMatched
            | FolderConfigurationOutcome::CurrentMatches => {
                if self
                    .runtime
                    .as_ref()
                    .is_some_and(|runtime| !runtime.expected_state_observed)
                {
                    OperationCompletion::PartiallyCompleted
                } else {
                    OperationCompletion::Completed
                }
            }
            FolderConfigurationOutcome::Unconfirmed => OperationCompletion::Unconfirmed,
            _ => OperationCompletion::GoalNotMet,
        }
    }
}

impl fmt::Debug for FolderConfigurationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderConfigurationReport")
            .field("outcome", &self.outcome)
            .field("write", &self.write)
            .field("original", &self.original)
            .field("configuration_observed", &self.observed.is_some())
            .field("observation_error", &self.observation_error)
            .field("runtime", &self.runtime)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for FolderConfigurationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let configuration = match self.outcome {
            FolderConfigurationOutcome::AlreadyMatched => "The selected folder settings already match.",
            FolderConfigurationOutcome::CurrentMatches => "The selected folder currently reports the requested settings.",
            FolderConfigurationOutcome::CurrentDiffers => "The selected folder currently reports different settings. Review them before making another change.",
            FolderConfigurationOutcome::NotSubmitted => "The call ended before submitting a folder change.",
            FolderConfigurationOutcome::Rejected => "VerySync declined the folder change. Check the credentials and management permissions.",
            FolderConfigurationOutcome::Unconfirmed => "The current folder settings could not be verified. Check the selected folder before sending another change.",
        };
        f.write_str(configuration)?;
        if self.outcome == FolderConfigurationOutcome::NotSubmitted {
            if let Some(Err(source)) = &self.original {
                write!(f, " {source}")?;
            }
        }
        if let Some(runtime) = &self.runtime {
            f.write_str(if runtime.expected_state_observed {
                " The engine reported the requested activity state."
            } else {
                " The requested activity state was not confirmed."
            })?;
        }
        Ok(())
    }
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

impl FolderConfig {
    /// Decode actual advanced selections, retaining absence and hiding private
    /// upstream fields from Debug. This does not perform another request.
    pub fn advanced_configuration(&self) -> Result<crate::FolderAdvancedConfig> {
        serde_json::from_value(serde_json::to_value(&self.extra).map_err(|_| {
            crate::Error::InvalidConfiguration {
                reason: "advanced folder configuration cannot be encoded",
            }
        })?)
        .map_err(|_| crate::Error::InvalidConfiguration {
            reason: "advanced folder configuration does not match its native schema",
        })
    }
}

#[derive(Deserialize)]
pub(crate) struct WireFolderIndex {
    pub(crate) folders: Vec<WireFolder>,
}
#[derive(Deserialize)]
pub(crate) struct WireFolder {
    pub(crate) id: FolderId,
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
