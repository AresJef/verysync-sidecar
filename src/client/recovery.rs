//! Explicit potentially destructive recovery requests without write retries.
use super::{
    delivery::{delivery_resource_path, same_resource},
    workflow_write_result, Client,
};
use crate::{
    operation_options::OperationContext, DeliveryEvidenceSource, DeliveryFile, DeliveryFileOutcome,
    DeliveryVerification, FolderConfig, FolderRecovery, FolderRecoveryReport, OperationCompletion,
    RecoveredFile, RecoveryReadback, ResourceFileState,
};
use crate::{
    Error, FolderId, MarkerRepairReport, MarkerRepairResult, OperationOptions, OperationPhase,
    ResourcePath, ResponseDiagnostic, Result, TargetPath,
};
use reqwest::Method;
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};
use tokio::time::Instant;

impl Client {
    /// Request a whole-folder receive-only revert or send-only override once.
    /// Review the folder's role and keep copies of edits before confirming it.
    /// The engine may change files beyond those listed for verification. The
    /// report compares only the selected bytes, using the original namespace
    /// and explicit connections. It does not pause peers or replay recovery.
    pub async fn recover_folder_and_verify(
        &self,
        expected_path: &TargetPath,
        recovery: FolderRecovery<'_>,
        options: OperationOptions,
    ) -> Result<FolderRecoveryReport> {
        const RECOVER: &str = "request selected native folder recovery";
        const VERIFY: &str = "verify selected recovered folder files";
        let (folder, files, mode, route) = match &recovery {
            FolderRecovery::Revert { folder, files } => {
                (*folder, *files, "receiveonly", "rest/db/revert")
            }
            FolderRecovery::Override { batch, .. } => {
                self.require_delivery_source(batch)?;
                (
                    &batch.folder,
                    batch.files.as_slice(),
                    "sendonly",
                    "rest/db/override",
                )
            }
        };
        let unique: BTreeSet<_> = files.iter().map(|file| file.components()).collect();
        if !(1..=1024).contains(&files.len()) || unique.len() != files.len() {
            return Err(Error::InvalidConfiguration {
                reason: "recovery requires 1 through 1024 distinct files to verify",
            });
        }
        let context = options.start()?;
        let url = self
            .connection
            .management_url(route, &[("folder", folder.as_str())])?;
        let mut guard = None;
        let mut write = Default::default();
        let mut before = None;
        let mut selected = None;
        let attempted = context.wait(context.dispatch_deadline(), RECOVER, async {
            context.phase(OperationPhase::Checking);
            guard = Some(self.connection.mutation_lock.lock().await);
            self.observe_control_identity().await?;
            let generation = self.system_status().await?.start_time.ok_or(Error::InvalidConfiguration {
                reason: "the selected engine did not report its start time",
            })?;
            let config = self.folder(folder).await?;
            if config.paused {
                return Err(Error::FolderPaused { id: folder.clone() });
            }
            if config.extra.get("type").and_then(serde_json::Value::as_str) != Some(mode)
                || config.path.style() != expected_path.style()
                || config.path.to_protocol()? != expected_path.to_protocol()?
            {
                return Err(Error::ConfigurationChanged);
            }
            let base = self.local_file_manager_base(&config.path).await?;
            let round = self.recovery_readback(&recovery, &base, &context, context.dispatch_deadline()).await?;
            let complete = round.completion() == OperationCompletion::Completed;
            let readable = recovery_readable(&round);
            before = Some(round);
            self.require_recovery_scope(folder, &config, &base, &generation).await?;
            if complete {
                return Ok(None);
            }
            if !readable && !matches!(&recovery, FolderRecovery::Override { verification: DeliveryVerification::BestEffort, .. }) {
                return Err(Error::InvalidConfiguration { reason: "at least one selected file cannot be verified with the supplied access" });
            }
            if let FolderRecovery::Override { batch, .. } = &recovery {
                let peers = config.extra.get("devices").and_then(serde_json::Value::as_array)
                    .ok_or(Error::InvalidConfiguration { reason: "the selected authority folder has no observable peer list" })?;
                if batch.targets.keys().any(|id| !peers.iter().any(|peer| peer["deviceID"].as_str() == Some(id.as_str()))) {
                    return Err(Error::ConfigurationChanged);
                }
                for file in files {
                    let path = delivery_resource_path(&base, file.components())?;
                    if !recovery_matches(self.resource_file_state(&path).await?, file) {
                        return Err(Error::InvalidConfiguration { reason: "an authority file differs from the expected content" });
                    }
                }
                self.require_recovery_scope(folder, &config, &base, &generation).await?;
            }
            if Instant::now() >= context.dispatch_deadline() {
                return Err(Error::Timeout { operation: RECOVER });
            }
            selected = Some((generation, config, base));
            let request = self.connection.authorized_request(Method::POST, url, None);
            let reply = self.connection.send_workflow_write(RECOVER, request, &context, &mut write).await?;
            validate_recovery_reply(RECOVER, reply.status, &reply.body)?;
            Ok(Some(ResponseDiagnostic::new(reply.status, reply.body)))
        }).await;
        let original = workflow_write_result(RECOVER, write, attempted);
        let refused = write.response_complete
            && matches!(
                original,
                Err(Error::Authentication { .. } | Error::AccessDenied { .. })
            );
        let mut report = FolderRecoveryReport {
            write,
            original,
            before,
            current: None,
            observation_error: None,
        };
        if let Some((generation, config, base)) = selected.filter(|_| write.dispatched && !refused)
        {
            context.phase(OperationPhase::Verifying);
            report.observation_error = context
                .wait(context.deadline, VERIFY, async {
                    loop {
                        self.require_recovery_scope(folder, &config, &base, &generation)
                            .await?;
                        let round = self
                            .recovery_readback(&recovery, &base, &context, context.deadline)
                            .await?;
                        self.require_recovery_scope(folder, &config, &base, &generation)
                            .await?;
                        let stop = round.completion() == OperationCompletion::Completed
                            || !recovery_readable(&round);
                        report.current = Some(round);
                        if stop {
                            return Ok(());
                        }
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                })
                .await
                .err();
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn require_recovery_scope(
        &self,
        folder: &FolderId,
        initial: &FolderConfig,
        mount: &ResourcePath,
        generation: &str,
    ) -> Result<()> {
        let now = self.folder(folder).await?;
        if now.paused
            || now.path != initial.path
            || now.extra.get("type") != initial.extra.get("type")
            || now.extra.get("devices") != initial.extra.get("devices")
            || !same_resource(mount, &self.local_file_manager_base(&now.path).await?)
        {
            return Err(Error::ConfigurationChanged);
        }
        self.require_configuration_generation(generation).await
    }

    async fn recovery_readback(
        &self,
        recovery: &FolderRecovery<'_>,
        base: &ResourcePath,
        context: &OperationContext,
        deadline: Instant,
    ) -> Result<RecoveryReadback> {
        match recovery {
            FolderRecovery::Override {
                batch, receivers, ..
            } => Ok(RecoveryReadback::Receivers(
                self.delivery_observation_round(
                    batch,
                    receivers,
                    &[],
                    SystemTime::now(),
                    context,
                    deadline,
                )
                .await?,
            )),
            FolderRecovery::Revert { files, .. } => {
                let mut observed = Vec::with_capacity(files.len());
                for (file_index, file) in files.iter().enumerate() {
                    let path = delivery_resource_path(base, file.components())?;
                    let (matches, error) = match self.resource_file_state(&path).await {
                        Ok(ResourceFileState::OtherKind) => {
                            (None, Some(Error::ResourceAlreadyExists))
                        }
                        Ok(state) => (Some(recovery_matches(state, file)), None),
                        Err(error) => (None, Some(error)),
                    };
                    observed.push(RecoveredFile {
                        file_index,
                        matches,
                        error,
                    });
                }
                Ok(RecoveryReadback::Local(observed))
            }
        }
    }

    /// Verify the exact folder path and its native local mount before asking
    /// VerySync to repair a missing marker. An existing marker requires no
    /// write. The report separates the marker directory from folder activity.
    pub async fn repair_folder_marker_and_verify(
        &self,
        folder: &FolderId,
        expected_path: &TargetPath,
        options: OperationOptions,
    ) -> Result<MarkerRepairReport> {
        const REPAIR: &str = "repair the selected folder marker";
        const CHECK: &str = "check the selected folder marker";
        let url = self
            .connection
            .management_url("rest/folder/marker/repair", &[("folder", folder.as_str())])?;
        let context = options.start()?;
        let mut write = Default::default();
        let mut scope = None;
        let mut guarded = None;
        let mut marker_present = None;
        let attempt =
            context
                .wait(context.dispatch_deadline(), REPAIR, async {
                    context.phase(OperationPhase::Checking);
                    guarded = Some(self.connection.mutation_lock.lock().await);
                    self.observe_control_identity().await?;
                    let generation = self.system_status().await?.start_time.ok_or(
                        Error::InvalidConfiguration {
                            reason: "the selected instance did not report its start time",
                        },
                    )?;
                    let coordinate = self
                        .marker_resource(folder, expected_path, &generation)
                        .await?;
                    let present = self.marker_directory_present(&coordinate).await?;
                    let current = self
                        .marker_resource(folder, expected_path, &generation)
                        .await?;
                    if !same_resource(&coordinate, &current) {
                        return Err(Error::ConfigurationChanged);
                    }
                    scope = Some((generation, coordinate));
                    if present {
                        marker_present = Some(true);
                        return Ok(None);
                    }
                    if Instant::now() >= context.dispatch_deadline() {
                        return Err(Error::Timeout { operation: REPAIR });
                    }
                    let request = self.connection.authorized_request(Method::POST, url, None);
                    let response = self
                        .connection
                        .send_workflow_write(REPAIR, request, &context, &mut write)
                        .await?;
                    decode_marker_reply(REPAIR, response.status, response.body).map(Some)
                })
                .await;
        let mut report = MarkerRepairReport {
            write,
            original: workflow_write_result(REPAIR, write, attempt),
            marker_present,
            folder_status: None,
            observation_error: None,
            status_error: None,
        };
        let refused = write.response_complete
            && matches!(
                report.original,
                Err(Error::Authentication { .. } | Error::AccessDenied { .. })
            );
        if let Some((generation, coordinate)) =
            scope.filter(|_| !refused && (write.dispatched || marker_present == Some(true)))
        {
            context.phase(OperationPhase::Verifying);
            if write.dispatched {
                let observed = context
                    .wait(context.deadline, CHECK, async {
                        let before = self
                            .marker_resource(folder, expected_path, &generation)
                            .await?;
                        if !same_resource(&coordinate, &before) {
                            return Err(Error::ConfigurationChanged);
                        }
                        let present = self.marker_directory_present(&coordinate).await?;
                        let after = self
                            .marker_resource(folder, expected_path, &generation)
                            .await?;
                        if !same_resource(&coordinate, &after) {
                            return Err(Error::ConfigurationChanged);
                        }
                        Ok(present)
                    })
                    .await;
                match observed {
                    Ok(present) => report.marker_present = Some(present),
                    Err(source) => report.observation_error = Some(source),
                }
            }
            if report.marker_present.is_some() {
                let observed = context
                    .wait(
                        context.deadline,
                        "observe the selected folder activity",
                        async {
                            let status = self.folder_status(folder).await?;
                            let current = self
                                .marker_resource(folder, expected_path, &generation)
                                .await?;
                            if !same_resource(&coordinate, &current) {
                                return Err(Error::ConfigurationChanged);
                            }
                            Ok(status)
                        },
                    )
                    .await;
                match observed {
                    Ok(status) => report.folder_status = Some(status),
                    Err(source) => report.status_error = Some(source),
                }
            }
        }
        drop(guarded);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn marker_resource(
        &self,
        id: &FolderId,
        expected: &TargetPath,
        generation: &str,
    ) -> Result<ResourcePath> {
        let folder = self.folder(id).await?;
        if folder.path.style() != expected.style()
            || folder.path.to_protocol()? != expected.to_protocol()?
        {
            return Err(Error::ConfigurationChanged);
        }
        let marker = folder
            .extra
            .get("markerName")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::InvalidConfiguration {
                reason: "the selected folder did not report its marker name",
            })?;
        let base = self.local_file_manager_base(&folder.path).await?;
        let directory = self.resource_info(&base).await?;
        if !directory.is_dir || directory.mode & (1 << 27) != 0 {
            return Err(Error::InvalidConfiguration {
                reason: "the selected folder has no regular directory on its native mount",
            });
        }
        let resource = base.child(marker)?;
        if self.system_status().await?.start_time.as_deref() != Some(generation) {
            return Err(Error::ConfigurationChanged);
        }
        Ok(resource)
    }

    async fn marker_directory_present(&self, path: &ResourcePath) -> Result<bool> {
        match self.resource_info(path).await {
            Ok(info) if info.is_dir && info.mode & (1 << 27) == 0 => Ok(true),
            Ok(_) => Err(Error::InvalidConfiguration {
                reason: "a non-directory resource occupies the folder marker path",
            }),
            Err(Error::Http { response }) if response.status() == 404 => Ok(false),
            Err(source) => Err(source),
        }
    }
    /// Request receive-only local-change reversion once. This can overwrite
    /// edits. Unindexed local additions have a separate engine policy; this
    /// is not a filesystem reset. The fixed engine can restore RO-key
    /// deletions before this request. Ok acknowledges
    /// the request, not completion; observe actual files and local changes.
    pub async fn request_revert_local_changes(&self, folder: &FolderId) -> Result<()> {
        self.request_recovery_action(
            folder,
            "receiveonly",
            "rest/db/revert",
            "request receive-only revert",
        )
        .await
    }
    /// Request send-only authority override once. This can replace other peers'
    /// versions with the current local version. Ok is not peer completion.
    pub async fn request_override_remote_changes(&self, folder: &FolderId) -> Result<()> {
        self.request_recovery_action(
            folder,
            "sendonly",
            "rest/db/override",
            "request send-only override",
        )
        .await
    }
    async fn request_recovery_action(
        &self,
        folder: &FolderId,
        mode: &'static str,
        route: &'static str,
        operation: &'static str,
    ) -> Result<()> {
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let config = self.folder(folder).await?;
        if config.paused {
            return Err(Error::FolderPaused { id: folder.clone() });
        }
        if config.extra.get("type").and_then(serde_json::Value::as_str) != Some(mode) {
            return Err(Error::InvalidConfiguration {
                reason: "recovery request requires the corresponding verified folder mode",
            });
        }
        let url = self
            .connection
            .management_url(route, &[("folder", folder.as_str())])?;
        let (status, bytes) = self
            .connection
            .request_bytes(operation, reqwest::Method::POST, url, None, true)
            .await?;
        validate_recovery_reply(operation, status, &bytes)
    }

    /// Ask the engine to repair this configured folder's marker. The SDK never
    /// inspects, removes or creates paths itself. Inspect actual folder state
    /// afterward; a reported success is distinct from restored data/identity.
    pub async fn request_marker_repair(&self, folder: &FolderId) -> Result<MarkerRepairResult> {
        let operation = "request folder marker repair";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.folder(folder).await?;
        let url = self
            .connection
            .management_url("rest/folder/marker/repair", &[("folder", folder.as_str())])?;
        let (status, bytes) = self
            .connection
            .request_bytes(operation, reqwest::Method::POST, url, None, true)
            .await?;
        decode_marker_reply(operation, status, bytes)
    }
}

fn decode_marker_reply(
    operation: &'static str,
    status: u16,
    bytes: Vec<u8>,
) -> Result<MarkerRepairResult> {
    let result: MarkerRepairResult =
        serde_json::from_slice(&bytes).map_err(|_| Error::MutationOutcomeUnknown {
            operation,
            source: Box::new(Error::InvalidResponse {
                operation,
                response: ResponseDiagnostic::new(status, bytes.clone()),
            }),
        })?;
    if !result.success || !result.error.is_empty() {
        return Err(Error::MutationOutcomeUnknown {
            operation,
            source: Box::new(Error::Api {
                operation,
                response: ResponseDiagnostic::new(status, bytes),
            }),
        });
    }
    Ok(result)
}

fn validate_recovery_reply(operation: &'static str, status: u16, bytes: &[u8]) -> Result<()> {
    if !bytes.is_empty() {
        return Err(Error::MutationOutcomeUnknown {
            operation,
            source: Box::new(Error::InvalidResponse {
                operation,
                response: ResponseDiagnostic::new(status, bytes.to_vec()),
            }),
        });
    }
    Ok(())
}

fn recovery_matches(state: ResourceFileState, file: &DeliveryFile) -> bool {
    state
        == ResourceFileState::Present {
            bytes: file.bytes(),
            sha256: *file.sha256(),
        }
}

fn recovery_readable(readback: &RecoveryReadback) -> bool {
    match readback {
        RecoveryReadback::Local(files) => files.iter().all(|file| file.error.is_none()),
        RecoveryReadback::Receivers(report) => {
            report.observation_error.is_none()
                && report.recipients.values().all(|receiver| {
                    receiver.files.iter().all(|file| {
                        file.outcome != DeliveryFileOutcome::Conflicting
                            && file.evidence.iter().any(|record| {
                                record.source == DeliveryEvidenceSource::RecipientRead
                            })
                    })
                })
        }
    }
}
