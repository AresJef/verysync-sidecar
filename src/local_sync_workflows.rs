//! Bounded, application-owned Local Sync operation receipts and results.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{
    DeviceId, Error, LocalSyncAction, LocalSyncActionResult, LocalSyncJobId, LocalSyncOperation,
    LocalSyncPreview, LocalSyncPreviewId, LocalSyncRun, LocalSyncRunId, LocalSyncSummary,
    ManagementWriteEvidence, OperationCompletion, OperationOptions, Result,
};

/// A shared deadline and explicit result limits for a Local Sync workflow.
#[derive(Clone, Debug)]
pub struct LocalSyncWorkflowOptions {
    pub(crate) operation: OperationOptions,
    pub(crate) max_results: u64,
    pub(crate) page_size: u16,
}

impl LocalSyncWorkflowOptions {
    /// Select the maximum number of records to retain, up to 50,000.
    /// A run that requires a larger result set is refused before submission.
    pub fn new(max_results: u64, operation: OperationOptions) -> Self {
        Self {
            operation,
            max_results,
            page_size: 100,
        }
    }

    /// Select a native page size from 1 through 1,000. Smaller pages are
    /// useful for management connections with a small response bound.
    pub fn page_size(mut self, page_size: u16) -> Self {
        self.page_size = page_size;
        self
    }

    pub(crate) fn verify_limits(&self) -> Result<()> {
        if !(1..=50_000).contains(&self.max_results) || !(1..=1000).contains(&self.page_size) {
            return Err(crate::local_sync::invalid(
                "Local Sync workflow record or page bound is outside its supported range",
            ));
        }
        Ok(())
    }
}

/// The evidence available after one Local Sync execution or observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LocalSyncRunOutcome {
    /// The SDK verified the terminal run and all of its action results.
    Completed,
    /// The exact run has some completed actions but other actions or checks remain.
    PartiallyCompleted,
    /// The terminal run reports failed or skipped work, with no completed actions.
    Failed,
    /// The original run reported cancellation. Some actions may have completed.
    Cancelled,
    /// The workflow ended before submitting a run.
    NotSubmitted,
    /// The selected endpoint returned a complete authentication or license refusal.
    Rejected,
    /// The original run or its result cannot be established from available evidence.
    Unconfirmed,
}

/// An application-owned reference to one acknowledged run. Store the encoded
/// form in a private location. It contains IDs but no credentials or authority
/// to submit another run. A later observer uses an independently selected client.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSyncRunReceipt {
    pub(crate) schema: u16,
    pub(crate) device: DeviceId,
    pub(crate) version_sha256: [u8; 32],
    pub(crate) job: LocalSyncJobId,
    pub(crate) preview: LocalSyncPreviewId,
    pub(crate) run: LocalSyncRunId,
    pub(crate) started: String,
    pub(crate) selection_count: u64,
    pub(crate) preview_count: u64,
}

impl LocalSyncRunReceipt {
    /// The acknowledged job.
    pub fn job(&self) -> &LocalSyncJobId {
        &self.job
    }
    /// The preview the caller authorized.
    pub fn preview(&self) -> &LocalSyncPreviewId {
        &self.preview
    }
    /// The exact acknowledged run.
    pub fn run(&self) -> &LocalSyncRunId {
        &self.run
    }

    /// Encode a bounded, versioned reference for private persistence.
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|_| crate::local_sync::invalid("could not encode the Local Sync run receipt"))
    }

    /// Read a previously persisted version-1 receipt.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 32 * 1024 {
            return Err(crate::local_sync::invalid(
                "the Local Sync run receipt exceeds its size limit",
            ));
        }
        let receipt: Self = serde_json::from_slice(bytes).map_err(|_| {
            crate::local_sync::invalid("the Local Sync run receipt has an invalid format")
        })?;
        if receipt.schema != 1
            || !(1..=50_000).contains(&receipt.selection_count)
            || receipt.selection_count > receipt.preview_count
            || crate::timestamps::parse_rfc3339(&receipt.started).is_none()
        {
            return Err(crate::local_sync::invalid(
                "the Local Sync run receipt has unsupported version or fields",
            ));
        }
        Ok(receipt)
    }
}

impl fmt::Debug for LocalSyncRunReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSyncRunReceipt")
            .field("schema", &self.schema)
            .field("selection_count", &self.selection_count)
            .finish_non_exhaustive()
    }
}

/// Original response and observed effects of one exact Local Sync execution.
#[derive(Debug)]
#[non_exhaustive]
pub struct LocalSyncRunReport {
    /// The available terminal classification.
    pub outcome: LocalSyncRunOutcome,
    /// Dispatch and response facts from this invocation. A read-only observation has no dispatch.
    pub write: ManagementWriteEvidence,
    /// The acknowledgement or original error. A read-only observation leaves this unset.
    pub initial: Option<Result<LocalSyncRun>>,
    /// Reference to the one identified run, when available.
    pub receipt: Option<LocalSyncRunReceipt>,
    /// Exact terminal snapshot if it could be established.
    pub terminal: Option<LocalSyncRun>,
    /// Counts for the selected work when the native summary covers the
    /// exclusions. The native summary can count unselected actions as skipped.
    pub selected_summary: Option<LocalSyncSummary>,
    /// Individually checked action rows already obtained for the acknowledged run.
    pub results: Vec<LocalSyncActionResult>,
    /// The observation error, including an expired deadline or replaced run.
    pub observation_error: Option<Error>,
}

impl Default for LocalSyncRunReport {
    fn default() -> Self {
        Self {
            outcome: LocalSyncRunOutcome::NotSubmitted,
            write: Default::default(),
            initial: None,
            receipt: None,
            terminal: None,
            selected_summary: None,
            results: Vec::new(),
            observation_error: None,
        }
    }
}

impl LocalSyncRunReport {
    /// Give a summary of native action results. Independent file delivery checks
    /// can still be required by the caller after the engine finishes.
    pub fn completion(&self) -> OperationCompletion {
        match self.outcome {
            LocalSyncRunOutcome::Completed => OperationCompletion::Completed,
            LocalSyncRunOutcome::PartiallyCompleted => OperationCompletion::PartiallyCompleted,
            LocalSyncRunOutcome::Cancelled
                if self
                    .terminal
                    .as_ref()
                    .is_some_and(|run| run.summary.completed > 0) =>
            {
                OperationCompletion::PartiallyCompleted
            }
            LocalSyncRunOutcome::Unconfirmed => OperationCompletion::Unconfirmed,
            _ => OperationCompletion::GoalNotMet,
        }
    }
}

impl fmt::Display for LocalSyncRunReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self.outcome {
            LocalSyncRunOutcome::Completed => "VerySync completed the selected run and its action results were verified.",
            LocalSyncRunOutcome::PartiallyCompleted => "The selected run has a partial result. Review the action rows and any observation error.",
            LocalSyncRunOutcome::Failed => "The selected run ended with unsuccessful actions. Review the action results.",
            LocalSyncRunOutcome::Cancelled => "VerySync reports that the selected run was cancelled. Review the actions it already performed.",
            LocalSyncRunOutcome::NotSubmitted => "The call ended before submitting the Local Sync run.",
            LocalSyncRunOutcome::Rejected => "VerySync declined the run. Check the selected job's permissions and license.",
            LocalSyncRunOutcome::Unconfirmed => "The selected run could not be confirmed. Check the job before submitting another execution.",
        };
        f.write_str(text)?;
        if let Some(summary) = &self.selected_summary {
            write!(
                f,
                " Among selected actions, VerySync reports {} completed, {} failed and {} skipped.",
                summary.completed, summary.failed, summary.skipped
            )?;
        } else if let Some(run) = &self.terminal {
            write!(
                f,
                " The full preview summary reports {} completed, {} failed and {} skipped.",
                run.summary.completed, run.summary.failed, run.summary.skipped
            )?;
        }
        if self.outcome == LocalSyncRunOutcome::NotSubmitted {
            if let Some(Err(source)) = &self.initial {
                write!(f, " {source}")?;
            }
        }
        Ok(())
    }
}

/// One preview operation, its proven identity and its inspected action pages.
#[derive(Debug)]
#[non_exhaustive]
pub struct LocalSyncPreviewReport {
    /// Dispatch and completeness of the single preview request.
    pub write: ManagementWriteEvidence,
    /// Original acknowledgement or error.
    pub initial: Result<LocalSyncOperation>,
    /// The exact produced preview, when it could be established.
    pub preview: Option<LocalSyncPreview>,
    /// Action rows already checked against the identified preview.
    pub actions: Vec<LocalSyncAction>,
    /// A failure to observe the preview or obtain all its action rows.
    pub observation_error: Option<Error>,
}

impl LocalSyncPreviewReport {
    /// Summarize the preview readback. This workflow executes no file actions.
    pub fn completion(&self) -> OperationCompletion {
        if self.preview.is_some() {
            if self.observation_error.is_none() {
                OperationCompletion::Completed
            } else {
                OperationCompletion::PartiallyCompleted
            }
        } else if self.write.dispatched {
            OperationCompletion::Unconfirmed
        } else {
            OperationCompletion::GoalNotMet
        }
    }
}
