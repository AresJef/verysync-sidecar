//! Read the selected delivery targets without starting or retrying transfers.

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, SystemTime},
};

use tokio::{task::JoinSet, time::Instant};

use super::{workflow_write_result, Client};
use crate::{
    delivery::reconcile_delivery, operation_options::OperationContext, DeliveryBatch,
    DeliveryEvidence, DeliveryEvidenceSource, DeliveryFileOutcome, DeliveryFileReport,
    DeliveryReceipt, DeliveryRecipientReport, DeliveryReport, DeliveryScanReport,
    DeliveryVerification, DeviceId, Error, FolderId, OperationCompletion, OperationOptions,
    OperationPhase, PathStyle, ResourceFileState, ResourcePath, ResponseDiagnostic, Result,
    TargetPath,
};

const RECEIVE: &str = "verify delivered files on the selected receiving instances";
const SCAN: &str = "request one scan of the selected source files";

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
        let observation = self
            .delivery_observation_round(
                batch,
                receivers,
                witnesses,
                observed_since,
                &context,
                context.deadline,
            )
            .await;
        context.phase(OperationPhase::Finished);
        observation
    }

    /// Request one scan at the source, then check the selected recipients'
    /// bytes. Set up the folder registrations and sharing before calling.
    /// This accepts at most 256 source paths. Existing native sharing rules
    /// govern delivery, including any recipients outside this batch.
    ///
    /// Strict verification requires usable read access to each receiver at
    /// admission. Best effort can proceed with missing read access. If the
    /// requested state already matches, the SDK can return without a scan.
    pub async fn scan_delivery_batch_and_verify(
        &self,
        batch: &DeliveryBatch,
        receivers: &[&Client],
        witnessed_before: &[DeliveryReceipt],
        observed_since: SystemTime,
        verification: DeliveryVerification,
        options: OperationOptions,
    ) -> Result<DeliveryScanReport> {
        if batch.files.len() > 256 {
            return Err(invalid(
                "one native delivery scan accepts at most 256 selected paths",
            ));
        }
        self.require_delivery_source(batch)?;
        let context = options.start()?;
        let qualification = context.started
            + context
                .deadline
                .duration_since(context.started)
                .mul_f64(1.0 / 3.0);
        let generation = context
            .wait(qualification, SCAN, async {
                self.system_status()
                    .await?
                    .start_time
                    .ok_or_else(|| invalid("the source did not report its start time"))
            })
            .await?;
        let before = self
            .delivery_observation_round(
                batch,
                receivers,
                witnessed_before,
                observed_since,
                &context,
                qualification,
            )
            .await?;
        let mut report = DeliveryScanReport {
            verification,
            before,
            write: Default::default(),
            original: Ok(None),
            observed: None,
            observation_error: None,
        };
        if report.before.completion() == OperationCompletion::Completed {
            context.phase(OperationPhase::Finished);
            return Ok(report);
        }
        if verification == DeliveryVerification::RequireReceiverReads
            && !report.before.recipients.values().all(|receiver| {
                receiver.files.iter().all(|file| {
                    file.outcome != DeliveryFileOutcome::Conflicting
                        && file
                            .evidence
                            .iter()
                            .any(|item| item.source == DeliveryEvidenceSource::RecipientRead)
                })
            })
        {
            report.original = Err(invalid(
                "at least one selected receiver cannot be verified with the supplied access",
            ));
            context.phase(OperationPhase::Finished);
            return Ok(report);
        }

        let style = self.folder_path_style()?;
        let separator = if style == PathStyle::Windows {
            "\\"
        } else {
            "/"
        };
        let paths = batch
            .files
            .iter()
            .map(|file| TargetPath::remote(style, file.components.join(separator)))
            .collect::<Result<Vec<_>>>()?;
        let query = self.scan_subpath_query(&batch.folder, &paths)?;
        let url = self.connection.management_url("rest/db/scan", &query)?;
        let dispatch = context.dispatch_deadline();
        let result = context
            .wait(dispatch, SCAN, async {
                context.phase(OperationPhase::Checking);
                let _guard = self.connection.mutation_lock.lock().await;
                self.observe_control_identity().await?;
                let folder = self.folder(&batch.folder).await?;
                if folder.paused {
                    return Err(Error::ScanNotIdle);
                }
                let peers = folder
                    .extra
                    .get("devices")
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(|| {
                        invalid("the selected folder did not report its device associations")
                    })?;
                if !batch.targets.keys().all(|id| {
                    peers.iter().any(|peer| {
                        peer.get("deviceID").and_then(serde_json::Value::as_str)
                            == Some(id.as_str())
                    })
                }) {
                    return Err(invalid(
                        "the source folder is not configured for every selected receiver",
                    ));
                }
                let base = self.delivery_folder_base(&batch.folder).await?;
                for file in &batch.files {
                    let path = delivery_resource_path(&base, &file.components)?;
                    let expected = ResourceFileState::Present {
                        bytes: file.bytes,
                        sha256: file.sha256,
                    };
                    if self.resource_file_state(&path).await? != expected {
                        return Err(invalid("a source file differs from the selected batch"));
                    }
                }
                let current = self.delivery_folder_base(&batch.folder).await?;
                let current_folder = self.folder(&batch.folder).await?;
                if !same_resource(&base, &current)
                    || current_folder.path != folder.path
                    || current_folder.paused
                    || current_folder.extra.get("devices") != folder.extra.get("devices")
                {
                    return Err(Error::ConfigurationChanged);
                }
                self.check_delivery_generation(&generation).await?;
                if Instant::now() >= dispatch {
                    return Err(Error::Timeout { operation: SCAN });
                }
                let request = self
                    .connection
                    .authorized_request(reqwest::Method::POST, url, None);
                let reply = self
                    .connection
                    .send_workflow_write(SCAN, request, &context, &mut report.write)
                    .await?;
                Ok(Some(ResponseDiagnostic::new(reply.status, reply.body)))
            })
            .await;
        report.original = workflow_write_result(SCAN, report.write, result);
        let refused = report.write.response_complete
            && matches!(
                report.original,
                Err(Error::Authentication { .. } | Error::AccessDenied { .. })
            );
        if report.write.dispatched && !refused && !receivers.is_empty() {
            let started = SystemTime::now();
            report.observation_error = context
                .wait(context.deadline, RECEIVE, async {
                    loop {
                        self.check_delivery_generation(&generation).await?;
                        let latest = self
                            .delivery_observation_round(
                                batch,
                                receivers,
                                &[],
                                started,
                                &context,
                                context.deadline,
                            )
                            .await?;
                        self.check_delivery_generation(&generation).await?;
                        let checked = receivers.iter().all(|client| {
                            latest
                                .recipients
                                .get(&client.instance().device_id)
                                .is_some_and(|peer| {
                                    peer.files
                                        .iter()
                                        .all(|file| file.outcome == DeliveryFileOutcome::Matched)
                                })
                        });
                        let unavailable = latest.observation_error.is_some()
                            || latest.recipients.values().any(|recipient| {
                                recipient.read_error.is_some()
                                    || recipient.files.iter().any(|file| file.read_error.is_some())
                            });
                        report.observed = Some(latest);
                        if checked || unavailable {
                            return Ok(());
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                })
                .await
                .err();
        }
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn check_delivery_generation(&self, expected: &str) -> Result<()> {
        if self.system_status().await?.start_time.as_deref() != Some(expected) {
            return Err(Error::ConfigurationChanged);
        }
        Ok(())
    }

    async fn delivery_observation_round(
        &self,
        batch: &DeliveryBatch,
        receivers: &[&Client],
        witnesses: &[DeliveryReceipt],
        observed_since: SystemTime,
        context: &OperationContext,
        deadline: Instant,
    ) -> Result<DeliveryReport> {
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
                deadline,
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
        let receiver_result = context.wait(deadline, RECEIVE, async {
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
            deadline,
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
                let resource = delivery_resource_path(&initial, &expected.components)?;
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
            || !same_resource(&initial, &current)
        {
            return Err(Error::ConfigurationChanged);
        }
        Ok(records)
    }

    pub(super) async fn delivery_folder_base(&self, folder: &FolderId) -> Result<ResourcePath> {
        let folder = self.folder(folder).await?;
        self.local_file_manager_base(&folder.path).await
    }

    pub(super) async fn local_file_manager_base(
        &self,
        path: &crate::TargetPath,
    ) -> Result<ResourcePath> {
        let style = path.style();
        let configured = native_path_parts(style, path.to_protocol()?)
            .ok_or_else(|| invalid("the folder path has no verified absolute local mount"))?;
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
            .ok_or_else(|| invalid("no local file-manager volume contains the selected folder"))?;
        if matching.get(1).is_some_and(|(_, depth, _)| depth == length) {
            return Err(invalid(
                "the file-manager mount for the selected folder is ambiguous",
            ));
        }
        suffix.iter().try_fold(
            ResourcePath::root(volume.id.clone(), style),
            |path, component| path.child(*component),
        )
    }
}

fn delivery_resource_path(base: &ResourcePath, components: &[String]) -> Result<ResourcePath> {
    components
        .iter()
        .try_fold(base.clone(), |path, component| path.child(component))
}

pub(super) fn same_resource(first: &ResourcePath, second: &ResourcePath) -> bool {
    first.volume == second.volume
        && first.style == second.style
        && first.components == second.components
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
