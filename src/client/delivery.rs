//! Read the selected delivery targets without starting or retrying transfers.

use std::{collections::BTreeSet, sync::Arc, time::SystemTime};

use tokio::task::JoinSet;

use super::Client;
use crate::{
    delivery::reconcile_delivery, DeliveryBatch, DeliveryEvidence, DeliveryEvidenceSource,
    DeliveryFileOutcome, DeliveryFileReport, DeliveryReceipt, DeliveryRecipientReport,
    DeliveryReport, DeviceId, Error, FolderId, OperationOptions, OperationPhase, PathStyle,
    ResourcePath, Result,
};

const RECEIVE: &str = "verify delivered files on the selected receiving instances";

type ReceiverSnapshot = Result<Vec<Result<DeliveryReceipt>>>;

impl Client {
    /// Read current progress and verify a fixed batch on each available
    /// receiving connection. Supply only explicitly authorized recipient
    /// clients. The SDK reads under the selected folder's native local volume.
    /// A trusted external receipt can supply evidence where direct reads are
    /// unavailable. The earliest observation time scopes this invocation.
    /// This operation performs one read round and never starts transfers.
    pub async fn observe_delivery_batch(
        &self,
        batch: &DeliveryBatch,
        receivers: &[&Client],
        witnesses: &[DeliveryReceipt],
        observed_since: SystemTime,
        options: OperationOptions,
    ) -> Result<DeliveryReport> {
        let context = options.start()?;
        self.require_delivery_source(batch)?;
        let mut chosen = BTreeSet::new();
        for receiver in receivers {
            let device = &receiver.instance().device_id;
            if !batch.targets.contains_key(device) || !chosen.insert(device.clone()) {
                return Err(invalid(
                    "each receiver connection must belong to one distinct selected device",
                ));
            }
        }
        let now = SystemTime::now();
        let slots = batch.targets.len() * batch.files.len();
        if witnesses.len() > slots * 4 || observed_since > now {
            return Err(invalid(
                "the receipt count or earliest delivery observation time is invalid",
            ));
        }
        let mut report = DeliveryReport {
            batch_fingerprint: batch.fingerprint,
            recipients: batch
                .targets
                .keys()
                .map(|id| {
                    let files = (0..batch.files.len())
                        .map(|file_index| DeliveryFileReport {
                            file_index,
                            outcome: DeliveryFileOutcome::Unobserved,
                            evidence: Vec::new(),
                            read_error: None,
                        })
                        .collect();
                    (
                        id.clone(),
                        DeliveryRecipientReport {
                            source_progress: None,
                            files,
                            read_error: None,
                        },
                    )
                })
                .collect(),
            source_progress_error: None,
            observation_error: None,
        };
        for witness in witnesses {
            witness.validate_for(batch)?;
            if witness.started < observed_since || witness.finished > now {
                return Err(invalid(
                    "a receiving witness falls outside the requested observation interval",
                ));
            }
            let peer = report
                .recipients
                .get_mut(&witness.device)
                .ok_or_else(|| invalid("the witness device is outside the selected batch"))?;
            peer.files[witness.file].evidence.push(DeliveryEvidence {
                source: DeliveryEvidenceSource::CallerWitness,
                receipt: witness.clone(),
            });
        }
        context.phase(OperationPhase::Checking);
        // Admit the selected source before starting any receiver I/O.
        context
            .wait(
                context.deadline,
                "check the selected source of the delivery batch",
                async {
                    self.observe_control_identity().await?;
                    self.folder(&batch.folder).await?;
                    Ok(())
                },
            )
            .await?;
        let batch = Arc::new(batch.clone());
        let mut tasks = JoinSet::new();
        for receiver in receivers {
            let client = (*receiver).clone();
            let device = client.instance().device_id.clone();
            let batch = batch.clone();
            tasks.spawn(async move {
                let observation = client.read_delivery_target(&batch, &device).await;
                (device, observation)
            });
        }
        context.phase(OperationPhase::Verifying);
        let receiver_result = context.wait(context.deadline, RECEIVE, async {
            while let Some(task) = tasks.join_next().await {
                let (device, observation) = task
                    .map_err(|_| invalid("a receiving observation task ended before reporting"))?;
                let peer = report
                    .recipients
                    .get_mut(&device)
                    .ok_or_else(|| invalid("a receiving result no longer belongs to the batch"))?;
                match observation {
                    Err(error) => peer.read_error = Some(error),
                    Ok(files) => {
                        for (file, read) in peer.files.iter_mut().zip(files) {
                            match read {
                                Ok(receipt) => file.evidence.push(DeliveryEvidence {
                                    source: DeliveryEvidenceSource::RecipientRead,
                                    receipt,
                                }),
                                Err(error) => file.read_error = Some(error),
                            }
                        }
                    }
                }
            }
            Ok(())
        });
        let source_result = context.wait(
            context.deadline,
            "read sender progress for the selected batch",
            async { self.folder_completions(&batch.folder).await },
        );
        let (receiving, progress) = tokio::join!(receiver_result, source_result);
        // Dropping the scoped task set cancels outstanding HTTP reads only.
        drop(tasks);
        report.observation_error = receiving.err();
        match progress {
            Ok(mut snapshots) => {
                for (id, peer) in &mut report.recipients {
                    peer.source_progress = snapshots.remove(id);
                }
            }
            Err(error) => report.source_progress_error = Some(error),
        }
        for peer in report.recipients.values_mut() {
            for file in &mut peer.files {
                file.outcome =
                    reconcile_delivery(&batch.files[file.file_index], &mut file.evidence);
            }
        }
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    fn require_delivery_source(&self, batch: &DeliveryBatch) -> Result<()> {
        if self.instance().device_id != batch.source {
            return Err(Error::IdentityMismatch {
                expected: batch.source.clone(),
                actual: self.instance().device_id.clone(),
            });
        }
        Ok(())
    }

    async fn read_delivery_target(
        &self,
        batch: &DeliveryBatch,
        device: &DeviceId,
    ) -> ReceiverSnapshot {
        let folder = batch
            .targets
            .get(device)
            .ok_or_else(|| invalid("the receiving connection does not belong to the batch"))?;
        self.observe_control_identity().await?;
        let start = self
            .system_status()
            .await?
            .start_time
            .ok_or_else(|| invalid("the receiving engine did not identify its start time"))?;
        let initial = self.delivery_folder_base(folder).await?;
        let mut records = Vec::with_capacity(batch.files.len());
        for (file, expected) in batch.files.iter().enumerate() {
            let read = async {
                let resource = expected
                    .components
                    .iter()
                    .try_fold(initial.clone(), |path, component| path.child(component))?;
                let started = SystemTime::now();
                let received = self.resource_file_state(&resource).await?;
                DeliveryReceipt::witnessed(
                    batch,
                    device.clone(),
                    file,
                    started,
                    SystemTime::now(),
                    received,
                )
            }
            .await;
            records.push(read);
        }
        let current = self.delivery_folder_base(folder).await?;
        self.observe_control_identity().await?;
        if self.system_status().await?.start_time.as_deref() != Some(&start)
            || (initial.volume, initial.style, initial.components)
                != (current.volume, current.style, current.components)
        {
            return Err(Error::ConfigurationChanged);
        }
        Ok(records)
    }

    async fn delivery_folder_base(&self, folder: &FolderId) -> Result<ResourcePath> {
        let folder = self.folder(folder).await?;
        let style = folder.path.style();
        let configured = native_path_parts(style, folder.path.to_protocol()?).ok_or_else(|| {
            invalid("the receiver folder path has no verified absolute local mount")
        })?;
        let volumes = self.resource_volumes().await?;
        let mut matching: Vec<_> = volumes
            .iter()
            .filter(|volume| volume.kind == "local")
            .filter_map(|volume| {
                let prefix = native_path_parts(style, &volume.path)?;
                configured
                    .strip_prefix(prefix.as_slice())
                    .map(|suffix| (volume, prefix.len(), suffix))
            })
            .collect();
        matching.sort_by_key(|(_, depth, _)| std::cmp::Reverse(*depth));
        let (volume, length, suffix) = matching
            .first()
            .ok_or_else(|| invalid("no local file-manager volume contains the receiving folder"))?;
        if matching.get(1).is_some_and(|(_, depth, _)| depth == length) {
            return Err(invalid(
                "the file-manager mount for the receiving folder is ambiguous",
            ));
        }
        suffix.iter().try_fold(
            ResourcePath::root(volume.id.clone(), style),
            |path, component| path.child(*component),
        )
    }
}

/// Only use an exact lexical mapping between two native absolute paths.
fn native_path_parts(style: PathStyle, path: &str) -> Option<Vec<&str>> {
    let separator = |c| c == '/' || (style == PathStyle::Windows && c == '\\');
    let (prefix, path) = match style {
        PathStyle::Unix if !path.starts_with("//") => ("/", path.strip_prefix('/')?),
        PathStyle::Windows => match path.as_bytes() {
            [letter, b':', b'\\' | b'/', ..] if letter.is_ascii_alphabetic() => {
                (&path[..2], &path[3..])
            }
            [b'\\', b'\\', ..] if !path.starts_with(r"\\?\") && !path.starts_with(r"\\.\") => {
                ("UNC", &path[2..])
            }
            _ => return None,
        },
        _ => return None,
    };
    let mut parts = vec![prefix];
    let path = path.trim_end_matches(separator);
    if !path.is_empty() {
        for part in path.split(separator) {
            if part.is_empty() || matches!(part, "." | "..") {
                return None;
            }
            parts.push(part);
        }
    }
    if prefix == "UNC" && parts.len() < 3 {
        return None;
    }
    Some(parts)
}

fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfiguration { reason }
}
