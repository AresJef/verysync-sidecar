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

/// A whole-folder native recovery request, with explicit files to verify.
#[non_exhaustive]
pub enum FolderRecovery<'a> {
    /// Revert receive-only changes and read selected files on this instance.
    Revert {
        /// Exact local receive-only folder.
        folder: &'a crate::FolderId,
        /// Expected file bytes at the receiving folder.
        files: &'a [crate::DeliveryFile],
    },
    /// Publish the send-only folder's authority and observe selected receivers.
    Override {
        /// Exact source, files and recipient folder IDs.
        batch: &'a crate::DeliveryBatch,
        /// Explicit authorized management connections for recipient reads.
        receivers: &'a [&'a crate::Client],
        /// Whether receiver reads must be available before dispatch.
        verification: crate::DeliveryVerification,
    },
}

/// Observed length and digest result for a selected local recovery file.
#[derive(Debug)]
#[non_exhaustive]
pub struct RecoveredFile {
    /// The file's input-list index.
    pub file_index: usize,
    /// Whether actual current bytes match the supplied length and digest.
    pub matches: Option<bool>,
    /// Why the file was not readable.
    pub error: Option<crate::Error>,
}

/// A file observation on the receive-only instance or on specified peers.
#[derive(Debug)]
#[non_exhaustive]
pub enum RecoveryReadback {
    /// Exact local observations in supplied order.
    Local(Vec<RecoveredFile>),
    /// Independent reads on the explicitly selected receiving instances.
    Receivers(crate::DeliveryReport),
}

impl RecoveryReadback {
    /// Classify only the selected files at the selected read locations.
    pub fn completion(&self) -> crate::OperationCompletion {
        use crate::OperationCompletion as Completion;
        match self {
            Self::Receivers(report) => report.completion(),
            Self::Local(files) => {
                let matched = files
                    .iter()
                    .filter(|file| file.matches == Some(true))
                    .count();
                if matched == files.len() && !files.is_empty() {
                    Completion::Completed
                } else if matched > 0 {
                    Completion::PartiallyCompleted
                } else if files.iter().all(|file| file.matches == Some(false)) {
                    Completion::GoalNotMet
                } else {
                    Completion::Unconfirmed
                }
            }
        }
    }
}

/// Original native recovery request and current facts for the selected files.
#[derive(Debug)]
#[non_exhaustive]
pub struct FolderRecoveryReport {
    /// Original dispatch and response facts.
    pub write: crate::ManagementWriteEvidence,
    /// Original native response. No response in a success means zero writes.
    pub original: crate::Result<Option<crate::ResponseDiagnostic>>,
    /// Readable file state at the selected locations before dispatch.
    pub before: Option<RecoveryReadback>,
    /// Latest trusted file observations after dispatch.
    pub current: Option<RecoveryReadback>,
    /// Why the selected effects were not fully observed.
    pub observation_error: Option<crate::Error>,
}

impl FolderRecoveryReport {
    /// Classify the explicitly selected file contents, not the whole folder.
    pub fn completion(&self) -> crate::OperationCompletion {
        use crate::OperationCompletion as Completion;
        if let Some(current) = &self.current {
            current.completion()
        } else if !self.write.dispatched {
            if self.original.is_ok()
                && self
                    .before
                    .as_ref()
                    .is_some_and(|before| before.completion() == Completion::Completed)
            {
                Completion::Completed
            } else {
                Completion::GoalNotMet
            }
        } else if self.write.response_complete
            && matches!(
                self.original,
                Err(crate::Error::Authentication { .. } | crate::Error::AccessDenied { .. })
            )
        {
            Completion::GoalNotMet
        } else {
            Completion::Unconfirmed
        }
    }
}
