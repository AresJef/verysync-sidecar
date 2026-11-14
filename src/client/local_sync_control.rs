//! Authenticated native Local Sync control; no controller filesystem fallback.
use super::{mutation_error, Client};
use crate::local_sync::{invalid, logical_subpath};
use crate::{
    CreateLocalSyncJob, Error, LocalSyncAction, LocalSyncActionResult, LocalSyncConfiguration,
    LocalSyncConflictResolution, LocalSyncHealth, LocalSyncHistory, LocalSyncJob, LocalSyncJobId,
    LocalSyncJobPatch, LocalSyncJobRemoval, LocalSyncJobUpdate, LocalSyncOperation,
    LocalSyncPreview, LocalSyncPreviewId, LocalSyncRun, LocalSyncRunId, LocalSyncSelection,
    LocalSyncSelectionSummary, LocalSyncStatus, ResponseDiagnostic, Result, StorageDirectory,
    StorageEndpoint, StorageEntry, StorageProbe,
};
use crate::{LocalSyncControlReceipt, LocalSyncOperationControl, LocalSyncOperationId};
use serde::de::DeserializeOwned;

impl Client {
    /// Read one native Local Sync event response after an explicit sequence.
    /// Wait is 0..=55 seconds, separately bounded by the selected management
    /// deadline. Returned cursor/reset/missed flags are not normalized away.
    pub async fn local_sync_events(
        &self,
        after: u64,
        wait_seconds: u8,
    ) -> Result<crate::LocalSyncEventBatch> {
        if wait_seconds > 55 {
            return Err(invalid("Local Sync event wait exceeds native bound"));
        }
        self.local_sync_read(
            "read native Local Sync events",
            &["events"],
            &[
                ("after", &after.to_string()),
                ("wait", &wait_seconds.to_string()),
            ],
        )
        .await
    }
    /// Read actual native Local Sync availability, independent of entitlement or
    /// evidence for an individual storage protocol.
    pub async fn local_sync_health(&self) -> Result<LocalSyncHealth> {
        self.local_sync_read("read Local Sync health", &["health"], &[])
            .await
    }
    /// Read the complete native configuration without changing jobs or schedules.
    pub async fn local_sync_configuration(&self) -> Result<LocalSyncConfiguration> {
        self.local_sync_read("read Local Sync configuration", &["config"], &[])
            .await
    }
    /// Read the actual complete job list. A missing/malformed list is an error.
    pub async fn local_sync_jobs(&self) -> Result<Vec<LocalSyncJob>> {
        self.local_sync_read("read Local Sync jobs", &["jobs"], &[])
            .await
    }
    /// Read all actual native job states, retaining unknown states and unassigned
    /// operation identities. This observation starts no job.
    pub async fn local_sync_statuses(&self) -> Result<Vec<LocalSyncStatus>> {
        self.local_sync_read("read all Local Sync job states", &["status"], &[])
            .await
    }
    /// Read one exact opaque registration without addressing a P2P folder ID.
    pub async fn local_sync_job(&self, id: &LocalSyncJobId) -> Result<LocalSyncJob> {
        let job: LocalSyncJob = self
            .local_sync_read("read Local Sync job", &["jobs", id.as_str()], &[])
            .await?;
        if &job.job_id != id {
            return Err(invalid("native Local Sync job identity differs"));
        }
        Ok(job)
    }
    /// Register both explicit endpoints. Automatic triggers default off; explicit
    /// startup/watch/schedule choices can cause native writes. On any uncertain
    /// write, reconcile the job list; the SDK never retries creation.
    pub async fn create_local_sync_job(
        &self,
        options: &CreateLocalSyncJob,
    ) -> Result<LocalSyncJob> {
        let style = self.folder_path_style()?;
        let (a, b) = options.endpoints();
        a.validate_target(style)?;
        b.validate_target(style)?;
        let body = value(options)?;
        let _guard = self.connection.mutation_lock.lock().await;
        let operation = "create Local Sync job";
        let job: LocalSyncJob = self
            .local_sync_json(
                operation,
                reqwest::Method::POST,
                &["jobs"],
                &[],
                Some(&body),
                true,
            )
            .await?;
        let observed = self
            .local_sync_job(&job.job_id)
            .await
            .map_err(|e| unknown(operation, e))?;
        if !requested_subset(&body, &value(&observed).map_err(|e| unknown(operation, e))?) {
            return Err(unknown(
                operation,
                invalid("created Local Sync settings differ from the request"),
            ));
        }
        Ok(observed)
    }
    /// Replace selected labels, enablement or automatic triggers in a freshly read full
    /// native object, preserving endpoint credentials and unknown options. This
    /// is serialized for clones, but does not lock other management writers.
    pub async fn update_local_sync_job(
        &self,
        id: &LocalSyncJobId,
        patch: &LocalSyncJobPatch,
    ) -> Result<LocalSyncJobUpdate> {
        if patch.label.is_none()
            && patch.group.is_none()
            && patch.enabled.is_none()
            && patch.settings.is_empty()
        {
            return Err(invalid("Local Sync update must select at least one field"));
        }
        let _guard = self.connection.mutation_lock.lock().await;
        let mut job = self.local_sync_job(id).await?;
        if let Some(label) = &patch.label {
            job.label = label.clone();
        }
        if let Some(group) = &patch.group {
            job.group = if group.is_empty() {
                None
            } else {
                Some(group.clone())
            };
        }
        if let Some(enabled) = patch.enabled {
            job.enabled = enabled;
        }
        let mut body = value(&job)?;
        for (key, val) in &patch.settings {
            body[key] = val.clone();
        }
        let operation = "update Local Sync job";
        let acknowledged: LocalSyncJob = self
            .local_sync_json(
                operation,
                reqwest::Method::PUT,
                &["jobs", id.as_str()],
                &[],
                Some(&body),
                true,
            )
            .await?;
        if &acknowledged.job_id != id {
            return Err(unknown(
                operation,
                invalid("native Local Sync update acknowledges a different job"),
            ));
        }
        let configuration = self
            .local_sync_job(id)
            .await
            .map_err(|e| unknown(operation, e))?;
        let observed_value = value(&configuration).map_err(|e| unknown(operation, e))?;
        let requested_fields_match = patch
            .label
            .as_ref()
            .is_none_or(|v| v == &configuration.label)
            && patch
                .group
                .as_ref()
                .is_none_or(|v| v.as_str() == configuration.group.as_deref().unwrap_or_default())
            && patch.enabled.is_none_or(|v| v == configuration.enabled)
            && patch
                .settings
                .iter()
                .all(|(k, v)| observed_value.get(k) == Some(v));
        Ok(LocalSyncJobUpdate {
            configuration,
            requested_fields_match,
        })
    }
    /// Delete one native job registration, then require its actual absence.
    /// Coordinate active work separately: this is not a rollback, file deletion
    /// or proof that an already started native operation stopped.
    pub async fn delete_local_sync_job(&self, id: &LocalSyncJobId) -> Result<LocalSyncJobRemoval> {
        let _guard = self.connection.mutation_lock.lock().await;
        self.local_sync_job(id).await?;
        let operation = "delete Local Sync job";
        let ack: serde_json::Value = self
            .local_sync_json(
                operation,
                reqwest::Method::DELETE,
                &["jobs", id.as_str()],
                &[],
                None,
                true,
            )
            .await?;
        if ack.as_object().is_none_or(|object| !object.is_empty()) {
            return Err(unknown(
                operation,
                invalid("Local Sync deletion acknowledgement differs from the known empty object"),
            ));
        }
        if self
            .local_sync_jobs()
            .await
            .map_err(|e| unknown(operation, e))?
            .iter()
            .any(|j| &j.job_id == id)
        {
            return Err(unknown(
                operation,
                invalid("deleted Local Sync registration is still observed"),
            ));
        }
        Ok(LocalSyncJobRemoval { job_id: id.clone() })
    }
    /// Probe one explicit target-side endpoint. Native capability flags are
    /// observations, not proof of all data operations or an SDK fallback.
    pub async fn probe_storage_endpoint(&self, endpoint: &StorageEndpoint) -> Result<StorageProbe> {
        endpoint.validate_target(self.folder_path_style()?)?;
        let _guard = self.connection.mutation_lock.lock().await;
        // A native probe may create/remove a temporary target object.
        self.local_sync_json(
            "probe native storage endpoint",
            reqwest::Method::POST,
            &["probe"],
            &[],
            Some(&value(endpoint)?),
            true,
        )
        .await
    }
    /// List a bounded logical subpath on one explicit endpoint. The subpath is
    /// interpreted by the target backend, never by the controller filesystem.
    pub async fn browse_storage_endpoint(
        &self,
        endpoint: &StorageEndpoint,
        path: &str,
    ) -> Result<StorageDirectory> {
        logical_subpath(path)?;
        endpoint.validate_target(self.folder_path_style()?)?;
        self.local_sync_json(
            "browse native storage endpoint",
            reqwest::Method::POST,
            &["browse"],
            &[],
            Some(&serde_json::json!({"side":endpoint,"path":path})),
            false,
        )
        .await
    }
    /// Create one directory below an explicit logical parent, then independently
    /// browse the parent and require an actual matching directory. No retries,
    /// controller mkdir, rollback or backup occur.
    pub async fn create_storage_directory(
        &self,
        endpoint: &StorageEndpoint,
        parent: &str,
        name: &str,
    ) -> Result<StorageEntry> {
        logical_subpath(parent)?;
        logical_subpath(name)?;
        if name.is_empty() || name.contains('/') {
            return Err(invalid(
                "storage directory name must be one nonempty component",
            ));
        }
        endpoint.validate_target(self.folder_path_style()?)?;
        let _guard = self.connection.mutation_lock.lock().await;
        let operation = "create native storage directory";
        let entry: StorageEntry = self
            .local_sync_json(
                operation,
                reqwest::Method::POST,
                &["mkdir"],
                &[],
                Some(&serde_json::json!({"side":endpoint,"parent":parent,"name":name})),
                true,
            )
            .await?;
        let expected = if parent.is_empty() {
            name.to_owned()
        } else {
            format!("{parent}/{name}")
        };
        let listing = self
            .browse_storage_endpoint(endpoint, parent)
            .await
            .map_err(|e| unknown(operation, e))?;
        if entry.path != expected
            || !entry.directory
            || !listing
                .entries
                .iter()
                .any(|e| e.path == expected && e.directory)
        {
            return Err(unknown(
                operation,
                invalid("created storage directory was not independently observed"),
            ));
        }
        Ok(entry)
    }
    /// Read a point-in-time job state and verify its exact registration identity.
    /// A state string alone does not identify a particular completed operation.
    pub async fn local_sync_status(&self, id: &LocalSyncJobId) -> Result<LocalSyncStatus> {
        let status: LocalSyncStatus = self
            .local_sync_read(
                "read Local Sync job status",
                &["jobs", id.as_str(), "status"],
                &[],
            )
            .await?;
        if &status.job_id != id {
            return Err(invalid("native Local Sync status identity differs"));
        }
        Ok(status)
    }
    /// Control only the currently identified operation of this job. Clone writers
    /// serialize the preflight, known empty acknowledgement and fresh readback;
    /// other management writers still require caller coordination. A receipt is
    /// not proof that in-flight I/O stopped or that prior writes were rolled back.
    pub async fn control_local_sync_operation(
        &self,
        id: &LocalSyncJobId,
        expected: &LocalSyncOperationId,
        control: LocalSyncOperationControl,
    ) -> Result<LocalSyncControlReceipt> {
        let _guard = self.connection.mutation_lock.lock().await;
        if self.local_sync_status(id).await?.operation_id.as_ref() != Some(expected) {
            return Err(invalid(
                "Local Sync operation changed before explicit control",
            ));
        }
        let route = match control {
            LocalSyncOperationControl::Pause => "pause",
            LocalSyncOperationControl::Resume => "resume",
            LocalSyncOperationControl::Stop => "stop",
        };
        let operation = "control exact native Local Sync operation";
        let ack: serde_json::Value = self
            .local_sync_json(
                operation,
                reqwest::Method::POST,
                &["jobs", id.as_str(), route],
                &[],
                None,
                true,
            )
            .await?;
        if ack.as_object().is_none_or(|v| !v.is_empty()) {
            return Err(unknown(
                operation,
                invalid("native Local Sync control acknowledgement differs"),
            ));
        }
        let observed = self
            .local_sync_status(id)
            .await
            .map_err(|e| unknown(operation, e))?;
        if observed.operation_id.as_ref() != Some(expected) {
            return Err(unknown(
                operation,
                invalid("Local Sync operation changed before control readback"),
            ));
        }
        Ok(LocalSyncControlReceipt {
            job_id: id.clone(),
            operation_id: expected.clone(),
            control,
            observed,
        })
    }
    /// Explicitly rebuild native endpoint markers for a reviewed job snapshot.
    /// The entire fresh configuration must still match that snapshot and the
    /// native operation must be quiescent. This deliberately repairs a safety
    /// marker; verify endpoint ownership and mounts before calling. No endpoint
    /// directory creation, host filesystem fallback, retry or run is performed
    /// by the SDK. The acknowledgement/status are separate from filesystem proof.
    pub async fn rebuild_local_sync_markers(
        &self,
        expected: &LocalSyncJob,
    ) -> Result<crate::LocalSyncMarkerRepair> {
        let _guard = self.connection.mutation_lock.lock().await;
        let current = self.local_sync_repair_snapshot(expected).await?;
        let operation = "rebuild native Local Sync markers";
        let ack: serde_json::Value = self
            .local_sync_json(
                operation,
                reqwest::Method::POST,
                &["jobs", current.job_id.as_str(), "markers", "rebuild"],
                &[],
                Some(&serde_json::json!({"confirmed":true,"job":current})),
                true,
            )
            .await?;
        if ack.as_object().is_none_or(|o| !o.is_empty()) {
            return Err(unknown(
                operation,
                invalid(
                    "native marker rebuild acknowledgement differs from the known empty object",
                ),
            ));
        }
        let observed = self
            .local_sync_status(&expected.job_id)
            .await
            .map_err(|e| unknown(operation, e))?;
        Ok(crate::LocalSyncMarkerRepair {
            job_id: expected.job_id.clone(),
            observed,
        })
    }
    /// Explicitly discard an incompatible two-way baseline and return a native
    /// recovery preview for the entire reviewed job snapshot. This can change
    /// deletion/conflict interpretation. It is not backup restoration or file
    /// execution; review the new preview and choose a separate explicit run.
    /// Current settings must still match and work must be quiescent. No retries,
    /// automatic run, controller baseline edits or filesystem fallback occur.
    pub async fn recover_local_sync_baseline(
        &self,
        expected: &LocalSyncJob,
    ) -> Result<LocalSyncPreview> {
        if expected.mode != "bisync" {
            return Err(invalid("native baseline recovery requires a two-way job"));
        }
        let _guard = self.connection.mutation_lock.lock().await;
        let current = self.local_sync_repair_snapshot(expected).await?;
        let operation = "recover native Local Sync baseline";
        let preview: LocalSyncPreview = self
            .local_sync_json(
                operation,
                reqwest::Method::POST,
                &["jobs", current.job_id.as_str(), "baseline", "recover"],
                &[],
                Some(&serde_json::json!({"confirmed":true,"job":current})),
                true,
            )
            .await?;
        if preview.job_id != expected.job_id {
            return Err(unknown(
                operation,
                invalid("native baseline recovery selects a different job"),
            ));
        }
        let observed = self
            .local_sync_preview(&expected.job_id)
            .await
            .map_err(|e| unknown(operation, e))?;
        if observed.id != preview.id || observed.operation_id != preview.operation_id {
            return Err(unknown(
                operation,
                invalid("native baseline recovery preview changed before readback"),
            ));
        }
        Ok(observed)
    }
    async fn local_sync_repair_snapshot(&self, expected: &LocalSyncJob) -> Result<LocalSyncJob> {
        let current = self.local_sync_job(&expected.job_id).await?;
        if value(&current)? != value(expected)? {
            return Err(invalid(
                "native repair configuration changed since the reviewed snapshot",
            ));
        }
        current.side_a.validate_target(self.folder_path_style()?)?;
        current.side_b.validate_target(self.folder_path_style()?)?;
        let status = self.local_sync_status(&expected.job_id).await?;
        if !matches!(status.state.as_str(), "idle" | "error") {
            return Err(invalid(
                "native repair requires a known quiescent operation state",
            ));
        }
        Ok(current)
    }
    /// Explicitly start analysis only. This acknowledges an operation; poll its
    /// exact identity and read the completed preview before choosing execution.
    pub async fn start_local_sync_preview(
        &self,
        id: &LocalSyncJobId,
    ) -> Result<LocalSyncOperation> {
        let _guard = self.connection.mutation_lock.lock().await;
        self.local_sync_job(id).await?;
        let operation = "start Local Sync preview";
        let ack: LocalSyncOperation = self
            .local_sync_json(
                operation,
                reqwest::Method::POST,
                &["jobs", id.as_str(), "preview"],
                &[],
                None,
                true,
            )
            .await?;
        if &ack.job_id != id {
            return Err(unknown(
                operation,
                invalid("native preview acknowledgement selects a different job"),
            ));
        }
        Ok(ack)
    }
    /// Read the current native preview. Compare its operation with the explicit
    /// start acknowledgement; another writer may have replaced the operation.
    pub async fn local_sync_preview(&self, id: &LocalSyncJobId) -> Result<LocalSyncPreview> {
        let preview: LocalSyncPreview = self
            .local_sync_read(
                "read Local Sync preview",
                &["jobs", id.as_str(), "preview"],
                &[],
            )
            .await?;
        if &preview.job_id != id {
            return Err(invalid("native Local Sync preview identity differs"));
        }
        Ok(preview)
    }
    /// Read a bounded page of the exact preview's actions. An action ID of zero
    /// is valid. No filtering or automatic execution occurs.
    pub async fn local_sync_preview_actions(
        &self,
        id: &LocalSyncJobId,
        preview: &LocalSyncPreviewId,
        offset: u64,
        limit: u16,
    ) -> Result<Vec<LocalSyncAction>> {
        page_limit(limit)?;
        self.local_sync_read(
            "page Local Sync preview actions",
            &["jobs", id.as_str(), "previews", preview.as_str(), "actions"],
            &[
                ("offset", &offset.to_string()),
                ("limit", &limit.to_string()),
            ],
        )
        .await
    }
    /// Explicitly execute every action in one exact preview. Mirror deletion,
    /// permission changes and conflicts follow that job's native settings.
    /// Preflight requires the still-current preview identity and no scan issues;
    /// expiry/races remain authoritative on the target. This is an initial run
    /// receipt, not completed-data proof. Cancellation does not imply native stop.
    ///
    /// ```no_run
    /// use verysync_sidecar::{Client, LocalSyncJobId, LocalSyncPreviewId,
    ///     LocalSyncRun, Result};
    /// # async fn execute(client: &Client, job: &LocalSyncJobId,
    /// # reviewed_preview: &LocalSyncPreviewId) -> Result<LocalSyncRun> {
    /// let receipt = client.run_local_sync_preview_all(job, reviewed_preview).await?;
    /// // Observe this exact receipt.id and actual target data separately.
    /// # Ok(receipt)
    /// # }
    /// ```
    pub async fn run_local_sync_preview_all(
        &self,
        id: &LocalSyncJobId,
        preview: &LocalSyncPreviewId,
    ) -> Result<LocalSyncRun> {
        self.run_local_sync_preview(id, preview, &LocalSyncSelection::all())
            .await
    }
    /// Read native totals for an explicit selection without running it. The body
    /// is a selection object; predicted bytes are not transferred-data evidence.
    pub async fn local_sync_selection_summary(
        &self,
        id: &LocalSyncJobId,
        preview: &LocalSyncPreviewId,
        selection: &LocalSyncSelection,
    ) -> Result<LocalSyncSelectionSummary> {
        let current = self.local_sync_preview(id).await?;
        if &current.id != preview {
            return Err(invalid(
                "Local Sync preview changed before selection summary",
            ));
        }
        selection.selected_count(current.count)?;
        self.local_sync_json(
            "read native Local Sync selection totals",
            reqwest::Method::POST,
            &[
                "jobs",
                id.as_str(),
                "previews",
                preview.as_str(),
                "selection-summary",
            ],
            &[],
            Some(&value(selection)?),
            false,
        )
        .await
    }
    /// Resolve reviewed conflicts in one exact preview without executing them.
    /// The native core returns its replacement preview; the SDK independently
    /// reads that identity back. A selected missing side can plan deletions.
    pub async fn resolve_local_sync_conflict(
        &self,
        id: &LocalSyncJobId,
        preview: &LocalSyncPreviewId,
        resolution: &LocalSyncConflictResolution,
    ) -> Result<LocalSyncPreview> {
        let _guard = self.connection.mutation_lock.lock().await;
        if &self.local_sync_preview(id).await?.id != preview {
            return Err(invalid(
                "Local Sync preview changed before conflict resolution",
            ));
        }
        let operation = "resolve exact native Local Sync conflicts";
        let ack: LocalSyncPreview = self
            .local_sync_json(
                operation,
                reqwest::Method::POST,
                &[
                    "jobs",
                    id.as_str(),
                    "previews",
                    preview.as_str(),
                    "resolve-conflicts",
                ],
                &[],
                Some(&value(resolution)?),
                true,
            )
            .await?;
        if &ack.job_id != id {
            return Err(unknown(
                operation,
                invalid("native conflict resolution selects another job"),
            ));
        }
        let observed = self
            .local_sync_preview(id)
            .await
            .map_err(|e| unknown(operation, e))?;
        if observed.id != ack.id {
            return Err(unknown(
                operation,
                invalid("native resolved preview changed before readback"),
            ));
        }
        Ok(observed)
    }
    /// Execute only the explicit ranges in one still-current preview. The SDK
    /// rejects out-of-range/empty selections and scan issues before native POST;
    /// expiry, native dependencies and races remain authoritative on the core.
    /// No automatic action expansion, conflict resolution, retry or rollback.
    pub async fn run_local_sync_preview(
        &self,
        id: &LocalSyncJobId,
        preview: &LocalSyncPreviewId,
        selection: &LocalSyncSelection,
    ) -> Result<LocalSyncRun> {
        let _guard = self.connection.mutation_lock.lock().await;
        let current = self.local_sync_preview(id).await?;
        if &current.id != preview || current.scan_issue_count != 0 {
            return Err(invalid(
                "Local Sync preview changed or has unresolved scan issues",
            ));
        }
        if selection.selected_count(current.count)? == 0 {
            return Err(invalid(
                "Local Sync execution requires a nonempty exact selection",
            ));
        }
        let operation = "run exact Local Sync preview selection";
        let run: LocalSyncRun = self
            .local_sync_json(
                operation,
                reqwest::Method::POST,
                &["jobs", id.as_str(), "run"],
                &[],
                Some(&serde_json::json!({"previewId":preview,"selection":selection})),
                true,
            )
            .await?;
        if &run.job_id != id {
            return Err(unknown(
                operation,
                invalid("native run acknowledgement selects a different job"),
            ));
        }
        Ok(run)
    }
    /// Read the current run snapshot; compare the exact run ID with its start
    /// receipt before interpreting its finish timestamp, summary or results.
    pub async fn local_sync_run(&self, id: &LocalSyncJobId) -> Result<LocalSyncRun> {
        let run: LocalSyncRun = self
            .local_sync_read("read Local Sync run", &["jobs", id.as_str(), "run"], &[])
            .await?;
        if &run.job_id != id {
            return Err(invalid("native Local Sync run identity differs"));
        }
        Ok(run)
    }
    /// Page the exact native execution results. Failed action details remain
    /// private metadata; an HTTP success is not an all-actions-success claim.
    pub async fn local_sync_run_results(
        &self,
        id: &LocalSyncJobId,
        run: &LocalSyncRunId,
        offset: u64,
        limit: u16,
    ) -> Result<Vec<LocalSyncActionResult>> {
        page_limit(limit)?;
        self.local_sync_read(
            "page Local Sync run results",
            &["jobs", id.as_str(), "runs", run.as_str(), "results"],
            &[
                ("offset", &offset.to_string()),
                ("limit", &limit.to_string()),
            ],
        )
        .await
    }
    /// Read a bounded history page, optionally for one explicit job. Native
    /// history rows are operation records, not file-version archives.
    pub async fn local_sync_history(
        &self,
        id: Option<&LocalSyncJobId>,
        page: u64,
        limit: u16,
    ) -> Result<LocalSyncHistory> {
        page_limit(limit)?;
        if page == 0 {
            return Err(invalid("Local Sync history pages start at one"));
        }
        let page = page.to_string();
        let limit = limit.to_string();
        let mut query = vec![("page", page.as_str()), ("limit", limit.as_str())];
        if let Some(id) = id {
            query.push(("jobId", id.as_str()));
        }
        self.local_sync_read("read Local Sync operation history", &["history"], &query)
            .await
    }
    async fn local_sync_read<T: DeserializeOwned>(
        &self,
        operation: &'static str,
        parts: &[&str],
        query: &[(&str, &str)],
    ) -> Result<T> {
        self.local_sync_json(operation, reqwest::Method::GET, parts, query, None, false)
            .await
    }
    async fn local_sync_json<T: DeserializeOwned>(
        &self,
        operation: &'static str,
        method: reqwest::Method,
        parts: &[&str],
        query: &[(&str, &str)],
        body: Option<&serde_json::Value>,
        mutation: bool,
    ) -> Result<T> {
        self.system_status().await?;
        let mut url = self.connection.management_url("rest/localsync/", query)?;
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| invalid("Local Sync URL cannot hold components"))?;
            path.pop_if_empty();
            for part in parts {
                path.push(part);
            }
        }
        let (status, bytes) = self
            .connection
            .request_bytes(operation, method, url, body, mutation)
            .await?;
        let decoded: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
            mutation_error(
                operation,
                mutation,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes.clone()),
                },
            )
        })?;
        // Local Sync also uses HTTP-success error envelopes; preserve any extra
        // native error-code fields rather than accepting a malformed success.
        if decoded
            .get("error")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|e| !e.is_empty())
        {
            return Err(mutation_error(
                operation,
                mutation,
                Error::Api {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                },
            ));
        }
        serde_json::from_value(decoded).map_err(|_| {
            mutation_error(
                operation,
                mutation,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                },
            )
        })
    }
}
fn value(v: &impl serde::Serialize) -> Result<serde_json::Value> {
    serde_json::to_value(v).map_err(|_| invalid("Local Sync input cannot be represented as JSON"))
}
fn page_limit(limit: u16) -> Result<()> {
    if !(1..=1000).contains(&limit) {
        Err(invalid("Local Sync page limit must be 1..=1000"))
    } else {
        Ok(())
    }
}
fn requested_subset(expected: &serde_json::Value, actual: &serde_json::Value) -> bool {
    match (expected, actual) {
        (serde_json::Value::Object(a), serde_json::Value::Object(b)) => a
            .iter()
            .all(|(key, v)| b.get(key).is_some_and(|actual| requested_subset(v, actual))),
        _ => expected == actual,
    }
}
fn unknown(operation: &'static str, source: Error) -> Error {
    mutation_error(operation, true, source)
}
