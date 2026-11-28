//! Explicit potentially destructive recovery requests without write retries.
use super::{delivery::same_resource, workflow_write_result, Client};
use crate::{
    Error, FolderId, MarkerRepairReport, MarkerRepairResult, OperationOptions, OperationPhase,
    ResourcePath, ResponseDiagnostic, Result, TargetPath,
};
use reqwest::Method;
use tokio::time::Instant;

impl Client {
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
        if !bytes.is_empty() {
            return Err(Error::MutationOutcomeUnknown {
                operation,
                source: Box::new(Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                }),
            });
        }
        Ok(())
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
