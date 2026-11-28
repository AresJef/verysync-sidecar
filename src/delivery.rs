//! Expected file batches and evidence recorded at each selected receiver.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::SystemTime,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    CompletionSnapshot, DeviceId, Error, FolderId, OperationCompletion, ResourceFileState, Result,
};

/// A full file's expected length and SHA-256 within a delivery batch.
#[derive(Clone, Serialize)]
pub struct DeliveryFile {
    pub(crate) components: Vec<String>,
    pub(crate) bytes: u64,
    pub(crate) sha256: [u8; 32],
}

impl DeliveryFile {
    /// Record an expected portable folder-relative path and its content.
    /// Slash separates components. Dot segments, backslashes and empty
    /// components are rejected; individual targets can have stricter rules.
    pub fn new(path: &str, bytes: u64, sha256: [u8; 32]) -> Result<Self> {
        let components: Vec<_> = path.split('/').map(str::to_owned).collect();
        if path.len() > 4096
            || components.len() > 128
            || components.iter().any(|part| {
                part.is_empty()
                    || matches!(part.as_str(), "." | "..")
                    || part.contains(['\\', '\0'])
            })
        {
            return Err(Error::InvalidPath {
                reason: "delivery files require bounded portable relative paths",
            });
        }
        Ok(Self {
            components,
            bytes,
            sha256,
        })
    }

    /// Expected length in bytes, including zero for a real empty file.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Expected SHA-256 of the complete source file.
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// The exact portable relative components, in path order.
    pub fn components(&self) -> &[String] {
        &self.components
    }
}

impl fmt::Debug for DeliveryFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeliveryFile")
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

/// One source folder, selected files and exact receiver registrations. The
/// engine can assign a different local folder ID to each join of a share.
#[derive(Clone)]
pub struct DeliveryBatch {
    pub(crate) source: DeviceId,
    pub(crate) folder: FolderId,
    pub(crate) files: Vec<DeliveryFile>,
    pub(crate) targets: BTreeMap<DeviceId, FolderId>,
    pub(crate) fingerprint: [u8; 32],
}

impl DeliveryBatch {
    /// Select up to 1,024 distinct paths and 16 distinct receiving devices.
    /// Expectations must come from a trusted source. A later byte match does
    /// not establish which transport supplied those bytes or caused a write.
    pub fn new(
        source: DeviceId,
        folder: FolderId,
        files: Vec<DeliveryFile>,
        recipients: impl IntoIterator<Item = (DeviceId, FolderId)>,
    ) -> Result<Self> {
        let distinct: BTreeSet<_> = files.iter().map(|file| &file.components).collect();
        if !(1..=1024).contains(&files.len()) || distinct.len() != files.len() {
            return Err(invalid("delivery requires 1 through 1024 distinct files"));
        }
        let mut targets = BTreeMap::new();
        for (recipient, recipient_folder) in recipients {
            if targets.len() == 16
                || recipient == source
                || targets.insert(recipient, recipient_folder).is_some()
            {
                return Err(invalid("delivery receivers must be distinct from each other and the source, with a limit of 16"));
            }
        }
        if targets.is_empty() {
            return Err(invalid("delivery requires at least one selected receiver"));
        }
        let bytes =
            serde_json::to_vec(&("verysync-delivery-v1", &source, &folder, &files, &targets))
                .map_err(|_| invalid("could not encode the delivery batch fingerprint"))?;
        Ok(Self {
            source,
            folder,
            files,
            targets,
            fingerprint: Sha256::digest(&bytes).into(),
        })
    }

    /// A content identity for this exact batch, including its selected targets.
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// The files in receipt-index order.
    pub fn files(&self) -> &[DeliveryFile] {
        &self.files
    }
}

impl fmt::Debug for DeliveryBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeliveryBatch")
            .field("file_count", &self.files.len())
            .field("recipient_count", &self.targets.len())
            .finish_non_exhaustive()
    }
}

/// A receiving-end observation that the application chooses to trust. A
/// receipt carries no credentials or control authority. Its encoding does
/// not authenticate the person or service that produced it.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryReceipt {
    pub(crate) schema: u16,
    pub(crate) batch: [u8; 32],
    pub(crate) device: DeviceId,
    pub(crate) folder: FolderId,
    pub(crate) file: usize,
    pub(crate) started: SystemTime,
    pub(crate) finished: SystemTime,
    pub(crate) received: ResourceFileState,
}

impl DeliveryReceipt {
    /// Bind trusted receiving-side evidence to a selected file and recipient.
    /// The start and finish are the observation interval on a clock comparable
    /// with the caller's. An instantaneous reading can use the same time twice.
    pub fn witnessed(
        batch: &DeliveryBatch,
        device: DeviceId,
        file: usize,
        started: SystemTime,
        finished: SystemTime,
        received: ResourceFileState,
    ) -> Result<Self> {
        let folder = batch
            .targets
            .get(&device)
            .ok_or_else(|| invalid("the witness device is not a selected receiver"))?
            .clone();
        let receipt = Self {
            schema: 1,
            batch: batch.fingerprint,
            device,
            folder,
            file,
            started,
            finished,
            received,
        };
        receipt.validate_for(batch)?;
        Ok(receipt)
    }

    /// Bounds of the recorded observation. Separate windows can reveal change.
    pub fn observation_interval(&self) -> (SystemTime, SystemTime) {
        (self.started, self.finished)
    }

    /// The selected receipt's complete file observation.
    pub fn received(&self) -> ResourceFileState {
        self.received
    }

    /// Store a versioned evidence record. Treat the bytes as application data.
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| invalid("could not encode the delivery receipt"))
    }

    /// Read a versioned receipt and validate its batch, path index and receiver.
    /// The application still decides whether to trust its storage or producer.
    pub fn decode(batch: &DeliveryBatch, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 8192 {
            return Err(invalid("the delivery receipt exceeds its size limit"));
        }
        let receipt: Self = serde_json::from_slice(bytes)
            .map_err(|_| invalid("the delivery receipt could not be decoded"))?;
        receipt.validate_for(batch)?;
        Ok(receipt)
    }

    pub(crate) fn validate_for(&self, batch: &DeliveryBatch) -> Result<()> {
        if self.schema != 1
            || self.batch != batch.fingerprint
            || batch.targets.get(&self.device) != Some(&self.folder)
            || self.file >= batch.files.len()
            || self.started > self.finished
        {
            return Err(invalid(
                "the delivery receipt does not match this batch, receiver, file, or time interval",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for DeliveryReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeliveryReceipt")
            .field("file_index", &self.file)
            .field("started", &self.started)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

/// How the receiving-side fact was supplied to this call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DeliveryEvidenceSource {
    /// The SDK read the exact resource through the selected receiver connection.
    RecipientRead,
    /// The caller supplied and trusts this witness.
    CallerWitness,
}

/// One qualifying receiving-end observation, retained alongside alternatives.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DeliveryEvidence {
    /// Origin for this observation.
    pub source: DeliveryEvidenceSource,
    /// File fact, receiver identity, and time interval.
    pub receipt: DeliveryReceipt,
}

/// Current evidence for one file at the selected receiver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DeliveryFileOutcome {
    /// The latest qualified observation reports the exact expected bytes.
    Matched,
    /// The latest qualified observation reports absence or different content.
    Differs,
    /// Qualified, overlapping observations disagree about the same file.
    Conflicting,
    /// No qualifying receiving-side observation was available.
    Unobserved,
}

/// Giving progress or evidence for a file does not prove arrival at other peers.
#[derive(Debug)]
#[non_exhaustive]
pub struct DeliveryFileReport {
    /// Position in the selected manifest.
    pub file_index: usize,
    /// Classification of the actual receiving-side evidence.
    pub outcome: DeliveryFileOutcome,
    /// All qualified observations used, including conflicts and earlier results.
    pub evidence: Vec<DeliveryEvidence>,
    /// Receiver read rejection if no safe conclusion could be drawn from that read.
    pub read_error: Option<Error>,
}

/// Evidence for one selected receiving device.
#[derive(Debug)]
#[non_exhaustive]
pub struct DeliveryRecipientReport {
    /// Sender-side model progress, when available. It does not prove file bytes.
    pub source_progress: Option<CompletionSnapshot>,
    /// Independent report for every selected file.
    pub files: Vec<DeliveryFileReport>,
    /// A failure establishing or retaining the receiver's identity and scope.
    pub read_error: Option<Error>,
}

/// Read-only result for the exact delivery batch. The SDK does not start a
/// scan, issue a second transfer, or claim that it caused a pre-existing match.
#[derive(Debug)]
#[non_exhaustive]
pub struct DeliveryReport {
    /// The selected batch identity.
    pub batch_fingerprint: [u8; 32],
    /// Actual observations for every selected receiver.
    pub recipients: BTreeMap<DeviceId, DeliveryRecipientReport>,
    /// Sender-side progress error; independent receiving-side evidence remains usable.
    pub source_progress_error: Option<Error>,
    /// The overall receiver observation ended before all selected reads returned.
    pub observation_error: Option<Error>,
}

/// Verification required for a scan requested to deliver a known file batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DeliveryVerification {
    /// Obtain an authorized receiving-side observation for every file
    /// before dispatching a scan whose effects need verification.
    RequireReceiverReads,
    /// Allow the scan to proceed when receiving-side observations are missing.
    BestEffort,
}

/// One source scan request and the receiving evidence that was available.
#[derive(Debug)]
#[non_exhaustive]
pub struct DeliveryScanReport {
    /// Policy selected for missing recipient access.
    pub verification: DeliveryVerification,
    /// What was confirmed on the recipients before deciding whether to submit.
    pub before: DeliveryReport,
    /// Whether one source scan was dispatched, and which reply was available.
    pub write: crate::ManagementWriteEvidence,
    /// Original reply or preflight error. An inner empty value means the
    /// file state already matched everywhere without a new scan.
    pub original: Result<Option<crate::ResponseDiagnostic>>,
    /// Most recent receiving-side verification after submission, if available.
    pub observed: Option<DeliveryReport>,
    /// Why observation stopped before a complete batch could be verified.
    pub observation_error: Option<Error>,
}

impl DeliveryScanReport {
    /// Classify actual recipient evidence independently of the scan reply.
    pub fn completion(&self) -> OperationCompletion {
        if let Some(observed) = &self.observed {
            return observed.completion();
        }
        if !self.write.dispatched && matches!(self.original, Ok(None)) {
            self.before.completion()
        } else if self.write.dispatched
            && !(self.write.response_complete
                && matches!(
                    self.original,
                    Err(Error::Authentication { .. } | Error::AccessDenied { .. })
                ))
        {
            OperationCompletion::Unconfirmed
        } else {
            OperationCompletion::GoalNotMet
        }
    }
}

impl DeliveryReport {
    /// Report completion only when every file matches at every selected receiver.
    pub fn completion(&self) -> OperationCompletion {
        let mut outcomes = self.recipients.values().flat_map(|peer| &peer.files);
        let mut matched = false;
        let mut differs = false;
        let mut unknown = false;
        for file in &mut outcomes {
            match file.outcome {
                DeliveryFileOutcome::Matched => matched = true,
                DeliveryFileOutcome::Differs => differs = true,
                DeliveryFileOutcome::Conflicting | DeliveryFileOutcome::Unobserved => {
                    unknown = true
                }
            }
        }
        if matched && (differs || unknown) {
            OperationCompletion::PartiallyCompleted
        } else if matched {
            OperationCompletion::Completed
        } else if differs && !unknown {
            OperationCompletion::GoalNotMet
        } else {
            OperationCompletion::Unconfirmed
        }
    }
}

pub(crate) fn reconcile_delivery(
    file: &DeliveryFile,
    evidence: &mut [DeliveryEvidence],
) -> DeliveryFileOutcome {
    evidence.sort_by_key(|item| item.receipt.finished);
    let Some(latest) = evidence.last().map(|item| &item.receipt) else {
        return DeliveryFileOutcome::Unobserved;
    };
    // Earlier non-overlapping observations can legitimately differ from later ones.
    if evidence.iter().any(|other| {
        other.receipt.finished >= latest.started && other.receipt.received != latest.received
    }) {
        return DeliveryFileOutcome::Conflicting;
    }
    match latest.received {
        ResourceFileState::Present { bytes, sha256 }
            if bytes == file.bytes && sha256 == file.sha256 =>
        {
            DeliveryFileOutcome::Matched
        }
        _ => DeliveryFileOutcome::Differs,
    }
}

fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfiguration { reason }
}
