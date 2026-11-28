//! Explicit collision and deletion intent for native resource mutations.
use crate::{
    Error, ManagementWriteEvidence, OperationCompletion, ResourceFileState, ResourceInfo,
    ResourcePath, Result,
};

/// Native collision policy. Parent/metadata preflights are observations, not
/// transactions against external filesystem or management writers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceConflictPolicy {
    /// Refuse an already observed destination before sending a mutation.
    RejectExisting,
    /// Overwrite colliding files; merge directory trees while retaining
    /// destination-only children. This does not replace an entire directory.
    OverwriteAndMerge,
    /// Preserve the requested existing target and let the kernel choose a new
    /// name. Require one unambiguous new parent entry after acknowledgement.
    KeepBoth,
}
/// Explicit deletion scope; neither choice may address a volume root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceDeleteScope {
    /// Require a file snapshot; refuse a currently observed directory.
    File,
    /// Require a directory snapshot and explicitly permit recursive data removal.
    RecursiveDirectory,
}
/// Fresh destination metadata after a known native acknowledgement. This is
/// not a transaction or a recursive content-hash verification receipt.
#[derive(Debug)]
pub struct ResourceMutation {
    /// Actual observed destination, including an unambiguous generated name.
    pub destination: ResourcePath,
    /// Actual metadata after the change; remote names/content remain untrusted.
    pub metadata: ResourceInfo,
    /// Whether the observed destination differs from the requested destination.
    pub generated_name: bool,
}
/// The exact resource was observed absent after its deletion acknowledgement.
/// Other writers can recreate it later; deletion is not a synchronization detach.
#[derive(Debug)]
pub struct ResourceRemoval {
    /// Snapshot read before the destructive request; no local backup is created.
    pub previous: ResourceInfo,
}

/// Byte and path evidence for one regular-file copy or move.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResourceRelocationOutcome {
    /// The copied bytes, and the requested source and conflict behavior, match.
    ExpectedStateObserved,
    /// At least one changed path matches, while another is different or unknown.
    PartiallyObserved,
    /// A fresh observation shows the expected state was not reached.
    CurrentStateDiffers,
    /// No request was dispatched.
    NotSubmitted,
    /// The endpoint sent a complete authorization refusal.
    Rejected,
    /// Readback could not establish the state of the selected paths.
    Unconfirmed,
}

/// Initial request and later independently read state for one file relocation.
#[derive(Debug)]
#[non_exhaustive]
pub struct ResourceRelocationReport {
    /// Classification from the separately available facts.
    pub outcome: ResourceRelocationOutcome,
    /// Original transport dispatch and response.
    pub write: ManagementWriteEvidence,
    /// Acknowledgement or error from the original request, including preflight.
    pub original: Result<()>,
    /// Whole-file identity observed before dispatch.
    pub source_before: Option<ResourceFileState>,
    /// Source file or its absence after the request.
    pub source_after: Option<Result<ResourceFileState>>,
    /// The destination path determined by the selected conflict policy.
    pub destination: Option<ResourcePath>,
    /// Whole-file identity at the chosen destination, when available.
    pub destination_after: Option<Result<ResourceFileState>>,
    /// Original requested target preserved by KeepBoth, when it existed.
    pub kept_target_after: Option<Result<ResourceFileState>>,
    /// Error that prevented safely completing verification.
    pub observation_error: Option<Error>,
}

impl ResourceRelocationReport {
    /// Classify current file effects. Inspect `original` to check acknowledgment.
    pub fn completion(&self) -> OperationCompletion {
        match self.outcome {
            ResourceRelocationOutcome::ExpectedStateObserved => OperationCompletion::Completed,
            ResourceRelocationOutcome::PartiallyObserved => OperationCompletion::PartiallyCompleted,
            ResourceRelocationOutcome::CurrentStateDiffers
            | ResourceRelocationOutcome::NotSubmitted
            | ResourceRelocationOutcome::Rejected => OperationCompletion::GoalNotMet,
            ResourceRelocationOutcome::Unconfirmed => OperationCompletion::Unconfirmed,
        }
    }
}
