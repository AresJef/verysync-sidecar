//! Evidence from one explicitly requested kernel query or upgrade.

use crate::{DeviceId, Error, Result};
use serde::Serialize;
use std::{
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// The caller's selected route and action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UpgradeAction {
    /// Read the management upgrade provider's current candidate.
    ManagementCheck,
    /// Ask the running engine to install the provider's chosen release.
    ManagementProvider,
    /// Upload a verified fixed archive to the running engine.
    ManagementArchive,
    /// Ask the normally stopped engine's CLI to check its provider.
    CliCheck,
    /// Run the normally stopped engine's provider installation command.
    CliProvider,
    /// Run the normally stopped engine's installation command for a supplied URL.
    CliFromUrl,
}

impl UpgradeAction {
    pub(crate) fn is_query(self) -> bool {
        matches!(self, Self::ManagementCheck | Self::CliCheck)
    }
}

/// The furthest observed operation boundary. Preliminary management status reads
/// are outside this stage: it records the selected query or upgrade itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
#[non_exhaustive]
pub enum UpgradeDispatch {
    /// The selected request or native command did not reach its dispatch step.
    Preparing,
    /// The request was handed to the HTTP client. Server receipt is unknown.
    Http {
        /// The status in the received headers, if seen.
        status: Option<u16>,
        /// The entire response fit the bound and was read.
        complete: bool,
    },
    /// The CLI worker reached native process creation without confirming
    /// a successfully contained helper. Partial native creation is possible.
    CliSpawnUnconfirmed,
    /// A successfully contained helper started. No exit was observed.
    CliStarted,
    /// The worker observed an actual child exit.
    CliExited {
        /// The exit code, if the operating system reported one.
        code: Option<i32>,
        /// Whether the helper and its contained descendants were confirmed out.
        tree_stopped: bool,
    },
}

/// What the initiating invocation can establish about its own result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UpgradeOutcome {
    /// The query returned a version result or a successful CLI check exit.
    Queried,
    /// No version result was established by the query.
    QueryFailed,
    /// The engine returned its known no-matching-release diagnostic.
    ReleaseUnavailable,
    /// The modifying operation stopped before it reached the dispatch step.
    NotSubmitted,
    /// A complete response expressly rejected the request.
    Rejected,
    /// The engine acknowledged restart or the CLI exited successfully.
    /// The new program file and a future startup require separate verification.
    Acknowledged,
    /// The SDK cannot confirm the outcome of a possible modification.
    Unknown,
}

/// A bounded, versioned summary of one attempt. It contains no credentials,
/// URLs, local paths, or authority to run another upgrade. The serialized
/// record is suitable for private storage as evidence.
#[derive(Clone, Serialize)]
pub struct UpgradeReceipt {
    schema_version: u16,
    operation_id: [u8; 16],
    device_id: DeviceId,
    action: UpgradeAction,
    started_at_unix_millis: u64,
    timeout_millis: u64,
    elapsed_millis: u64,
    dispatch: UpgradeDispatch,
    outcome: UpgradeOutcome,
    previous_program_sha256: Option<[u8; 32]>,
    owner_generation: Option<[u8; 32]>,
    archive_sha256: Option<[u8; 32]>,
    target_program_sha256: Option<[u8; 32]>,
    #[serde(skip)]
    pub(crate) observation_scope: Option<crate::managed::UpgradeObservationScope>,
}

impl UpgradeReceipt {
    /// The local correlation ID. It is not an engine task or idempotency key.
    pub fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }
    /// The device selected by the caller's connection or owning handle.
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }
    /// The selected operation.
    pub fn action(&self) -> UpgradeAction {
        self.action
    }
    /// Start time in Unix epoch milliseconds, or zero before the epoch.
    pub fn started_at_unix_millis(&self) -> u64 {
        self.started_at_unix_millis
    }
    /// The caller's time allowance in milliseconds. Contained cleanup can take longer.
    pub fn timeout_millis(&self) -> u64 {
        self.timeout_millis
    }
    /// Elapsed monotonic time observed before the receipt returned.
    pub fn elapsed_millis(&self) -> u64 {
        self.elapsed_millis
    }
    /// The observed dispatch and response boundary.
    pub fn dispatch(&self) -> UpgradeDispatch {
        self.dispatch
    }
    /// The original attempt's outcome, independent of any later observation.
    pub fn outcome(&self) -> UpgradeOutcome {
        self.outcome
    }
    /// The previous executable's verified digest, if the stopped CLI checked it.
    pub fn previous_program_sha256(&self) -> Option<[u8; 32]> {
        self.previous_program_sha256
    }
    /// Opaque ID of the original owned startup, when observed on that owner.
    pub fn owner_generation(&self) -> Option<[u8; 32]> {
        self.owner_generation
    }
    /// The selected fixed archive's catalog digest, before any validation.
    /// This identifies the archive, not the executable inside it.
    pub fn archive_sha256(&self) -> Option<[u8; 32]> {
        self.archive_sha256
    }
    /// The preselected target executable digest, distinct from the archive digest.
    pub fn target_program_sha256(&self) -> Option<[u8; 32]> {
        self.target_program_sha256
    }

    pub(crate) fn bind_observation(
        &mut self,
        generation: [u8; 32],
        scope: crate::managed::UpgradeObservationScope,
    ) {
        self.owner_generation = Some(generation);
        self.previous_program_sha256 = Some(scope.previous);
        self.target_program_sha256 = Some(scope.target);
        self.observation_scope = Some(scope);
    }
}

impl fmt::Debug for UpgradeReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpgradeReceipt")
            .field("operation_id", &self.operation_id)
            .field("action", &self.action)
            .field("dispatch", &self.dispatch)
            .field("outcome", &self.outcome)
            .field("elapsed_millis", &self.elapsed_millis)
            .finish_non_exhaustive()
    }
}

/// The receipt and the original result of the same call.
#[derive(Debug)]
pub struct UpgradeOperationResult<T> {
    /// Evidence from the initiating operation.
    pub receipt: UpgradeReceipt,
    /// The same result contract and source errors as the original entry point.
    pub result: Result<T>,
}

#[derive(Clone)]
pub(crate) struct UpgradeProgress(Arc<Mutex<Progress>>);

struct Progress {
    dispatch: UpgradeDispatch,
    previous_program_sha256: Option<[u8; 32]>,
}

impl UpgradeProgress {
    pub(crate) fn dispatch(&self, dispatch: UpgradeDispatch) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).dispatch = dispatch;
    }

    pub(crate) fn verified_program(&self, sha: [u8; 32]) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .previous_program_sha256 = Some(sha);
    }
}

pub(crate) struct UpgradeAttempt {
    pub(crate) deadline: Instant,
    start: Instant,
    receipt: UpgradeReceipt,
    pub(crate) progress: UpgradeProgress,
}

impl UpgradeAttempt {
    pub(crate) fn new(
        action: UpgradeAction,
        device_id: DeviceId,
        timeout: Duration,
    ) -> Result<Self> {
        let start = Instant::now();
        let deadline = start
            .checked_add(timeout)
            .filter(|_| !timeout.is_zero())
            .ok_or(Error::InvalidConfiguration {
                reason: "upgrade deadline must be positive and representable",
            })?;
        let mut operation_id = [0; 16];
        getrandom::fill(&mut operation_id).map_err(|_| Error::ManagedFailure {
            reason: "could not create an upgrade receipt ID",
        })?;
        Ok(Self {
            deadline,
            start,
            receipt: UpgradeReceipt {
                schema_version: 1,
                operation_id,
                device_id,
                action,
                started_at_unix_millis: milliseconds(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default(),
                ),
                timeout_millis: milliseconds(timeout),
                elapsed_millis: 0,
                dispatch: UpgradeDispatch::Preparing,
                outcome: UpgradeOutcome::NotSubmitted,
                previous_program_sha256: None,
                owner_generation: None,
                archive_sha256: None,
                target_program_sha256: None,
                observation_scope: None,
            },
            progress: UpgradeProgress(Arc::new(Mutex::new(Progress {
                dispatch: UpgradeDispatch::Preparing,
                previous_program_sha256: None,
            }))),
        })
    }

    pub(crate) fn repeat_read(&self) -> Self {
        debug_assert!(self.receipt.action.is_query());
        Self {
            deadline: self.deadline,
            start: self.start,
            receipt: self.receipt.clone(),
            progress: UpgradeProgress(Arc::new(Mutex::new(Progress {
                dispatch: UpgradeDispatch::Preparing,
                previous_program_sha256: None,
            }))),
        }
    }

    pub(crate) fn operation_id(&self) -> [u8; 16] {
        self.receipt.operation_id
    }

    pub(crate) fn set_owner_generation(&mut self, generation: [u8; 32]) {
        self.receipt.owner_generation = Some(generation);
    }

    pub(crate) fn set_archive(&mut self, sha256: [u8; 32]) {
        self.receipt.archive_sha256 = Some(sha256);
    }

    pub(crate) fn bind_observation(
        &mut self,
        generation: [u8; 32],
        scope: crate::managed::UpgradeObservationScope,
    ) {
        self.receipt.bind_observation(generation, scope);
    }

    pub(crate) fn dispatch(&self) -> UpgradeDispatch {
        self.progress
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .dispatch
    }

    pub(crate) fn finish<T>(
        mut self,
        result: Result<T>,
        classify: impl FnOnce(&T) -> UpgradeOutcome,
    ) -> UpgradeOperationResult<T> {
        use UpgradeOutcome::*;
        let progress = self.progress.0.lock().unwrap_or_else(|e| e.into_inner());
        let receipt = &mut self.receipt;
        receipt.dispatch = progress.dispatch;
        if progress.previous_program_sha256.is_some() {
            receipt.previous_program_sha256 = progress.previous_program_sha256;
        }
        receipt.elapsed_millis = milliseconds(self.start.elapsed());
        receipt.outcome = match &result {
            Ok(value) => classify(value),
            Err(Error::UpgradeReleaseUnavailable { .. }) => ReleaseUnavailable,
            Err(_) if receipt.action.is_query() => QueryFailed,
            Err(_) if receipt.dispatch == UpgradeDispatch::Preparing => NotSubmitted,
            Err(
                Error::Authentication { .. }
                | Error::AccessDenied { .. }
                | Error::LicenseRequired { .. },
            ) if matches!(
                receipt.dispatch,
                UpgradeDispatch::Http { complete: true, .. }
            ) =>
            {
                Rejected
            }
            Err(_) => Unknown,
        };
        UpgradeOperationResult {
            receipt: self.receipt,
            result,
        }
    }
}

fn milliseconds(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}
