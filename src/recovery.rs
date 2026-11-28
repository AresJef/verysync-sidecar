//! A marker-service acknowledgement, separate from filesystem recovery.
use serde::Deserialize;
use std::{collections::BTreeMap, fmt};

/// The fixed engine's marker-repair response. Success reports the service's
/// acknowledgement; observe folder state/files separately for actual recovery.
#[derive(Clone, Deserialize)]
pub struct MarkerRepairResult {
    /// Actual engine success flag. The typed method rejects false responses.
    pub success: bool,
    /// Actual error text, potentially containing private paths; hidden in Debug.
    pub error: String,
    /// Unmodeled fields, potentially private.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for MarkerRepairResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MarkerRepairResult")
            .field("success", &self.success)
            .field("has_error", &!self.error.is_empty())
            .finish_non_exhaustive()
    }
}

/// The original marker repair reply and independently observed marker state.
#[derive(Debug)]
#[non_exhaustive]
pub struct MarkerRepairReport {
    /// Dispatch and response evidence for the optional repair.
    pub write: crate::ManagementWriteEvidence,
    /// Original result. An inner empty value means the marker was already there.
    pub original: crate::Result<Option<MarkerRepairResult>>,
    /// Whether the expected marker directory was observed on the same mount.
    pub marker_present: Option<bool>,
    /// Independently reported folder activity after checking the marker.
    pub folder_status: Option<crate::FolderStatus>,
    /// Why the selected marker could not be checked after submission.
    pub observation_error: Option<crate::Error>,
    /// Why folder activity was unavailable.
    pub status_error: Option<crate::Error>,
}

impl MarkerRepairReport {
    /// Classify the marker state without implying synchronization resumed.
    pub fn completion(&self) -> crate::OperationCompletion {
        use crate::OperationCompletion as Completion;
        match self.marker_present {
            Some(true) => Completion::Completed,
            Some(false) => Completion::GoalNotMet,
            None if !self.write.dispatched
                || (self.write.response_complete
                    && matches!(
                        self.original,
                        Err(crate::Error::Authentication { .. } | crate::Error::AccessDenied { .. })
                    )) =>
            {
                Completion::GoalNotMet
            }
            None => Completion::Unconfirmed,
        }
    }
}
