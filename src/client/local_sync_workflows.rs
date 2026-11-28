//! Compose existing, identity-checked native Local Sync operations.

use std::{collections::HashSet, time::Duration};

use reqwest::Method;
use tokio::time::Instant;

use super::local_sync_control::{
    decode_local_sync_json, local_sync_control_route, local_sync_job_patch_body,
    local_sync_job_patch_matches, requested_subset,
};
use super::{mutation_error, workflow_write_result, Client};
use crate::{
    control_operation::version_fingerprint, local_sync::invalid,
    operation_options::OperationContext, timestamps::parse_rfc3339, Error, LocalSyncJobId,
    LocalSyncOperation, LocalSyncPreview, LocalSyncPreviewId, LocalSyncPreviewReport, LocalSyncRun,
    LocalSyncRunOutcome, LocalSyncRunReceipt, LocalSyncRunReport, LocalSyncSelection,
    LocalSyncSummary, LocalSyncWorkflowOptions, ManagementWriteEvidence, OperationPhase, Result,
};
use crate::{
    CreateLocalSyncJob, LocalSyncAction, LocalSyncActionRange, LocalSyncConflictReport,
    LocalSyncConflictResolution, LocalSyncJob, LocalSyncOperationControl, LocalSyncOperationId,
    LocalSyncRegistrationChange, LocalSyncRegistrationChangeReport, LocalSyncRegistrationOutcome,
    LocalSyncRegistrationReport, LocalSyncRunControlOutcome, LocalSyncRunControlReport,
    LocalSyncRunId, LocalSyncStatus, OperationOptions,
};

const RUN: &str = "submit the selected Local Sync preview for execution";
const CHECK_RUN: &str = "check the exact Local Sync run";
const PREVIEW: &str = "start the selected Local Sync preview";
const CHECK_PREVIEW: &str = "check the selected Local Sync preview";
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const UNFINISHED: &str = "0001-01-01T00:00:00Z";
const CONTROL: &str = "control the selected Local Sync run";
const CHECK_CONTROL: &str = "observe the selected Local Sync run state";
const RESOLVE: &str = "resolve conflicts in the reviewed Local Sync preview";
const RECHECK: &str = "verify conflicts in the acknowledged replacement preview";

impl Client {
    /// Change only the requested conflict path or subtree in the exact reviewed
    /// preview. Verify the replacement's selected and remaining conflicts.
    /// This prepares a new plan. Execute that plan in a separate explicit call.
    pub async fn resolve_local_sync_conflict_and_verify(
        &self,
        job: &LocalSyncJobId,
        expected: &LocalSyncPreviewId,
        resolution: &LocalSyncConflictResolution,
        options: LocalSyncWorkflowOptions,
    ) -> Result<LocalSyncConflictReport> {
        options.verify_limits()?;
        let context = options.operation.clone().start()?;
        let mut guard = None;
        let mut generation = None;
        let mut write = ManagementWriteEvidence::default();
        let mut selected_before = None;
        let result = context
            .wait(context.dispatch_deadline(), RESOLVE, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                self.observe_control_identity().await?;
                let start = self.system_status().await?.start_time.ok_or_else(|| {
                    invalid("the Local Sync instance did not report its start time")
                })?;
                let preview = self.local_sync_preview(job).await?;
                if &preview.id != expected {
                    return Err(invalid(
                        "the selected Local Sync preview is no longer current",
                    ));
                }
                require_unexpired(&preview)?;
                let count = self
                    .conflicts_in_scope(&preview, resolution, &options)
                    .await?;
                self.confirm_current_preview(&preview).await?;
                self.require_local_sync_generation(&start).await?;
                selected_before = Some(count);
                if count == 0 {
                    return Ok(None);
                }
                if Instant::now() >= context.dispatch_deadline() {
                    return Err(Error::Timeout { operation: RESOLVE });
                }
                let url = self.local_sync_url(
                    &[
                        "jobs",
                        job.as_str(),
                        "previews",
                        expected.as_str(),
                        "resolve-conflicts",
                    ],
                    &[],
                )?;
                let body = serde_json::to_value(resolution)
                    .map_err(|_| invalid("could not encode the selected conflict scope"))?;
                let request = self
                    .connection
                    .authorized_request(Method::POST, url, Some(&body));
                generation = Some(start);
                let response = self
                    .connection
                    .send_workflow_write(RESOLVE, request, &context, &mut write)
                    .await?;
                let acknowledged: LocalSyncPreview =
                    decode_local_sync_json(RESOLVE, response.status, response.body, true, false)?;
                if &acknowledged.job_id != job || &acknowledged.id == expected {
                    return Err(mutation_error(
                        RESOLVE,
                        true,
                        invalid("the reply did not identify a replacement for the selected job"),
                    ));
                }
                Ok(Some(acknowledged))
            })
            .await;
        let mut report = LocalSyncConflictReport {
            write,
            original: workflow_write_result(RESOLVE, write, result),
            selected_before,
            replacement: None,
            selected_remaining: None,
            all_remaining: None,
            observation_error: None,
        };
        if let (Some(generation), Ok(Some(ack))) = (generation, &report.original) {
            context.phase(OperationPhase::Verifying);
            let checked = context
                .wait(context.deadline, RECHECK, async {
                    self.require_local_sync_generation(&generation).await?;
                    let current = self.confirm_current_preview(ack).await?;
                    let selected = self
                        .conflicts_in_scope(&current, resolution, &options)
                        .await?;
                    let all = if current.count == 0 {
                        0
                    } else {
                        self.local_sync_selection_summary(
                            job,
                            &current.id,
                            &LocalSyncSelection::all(),
                        )
                        .await?
                        .conflicts
                    };
                    if selected > all {
                        return Err(invalid(
                            "the selected conflict count exceeds the replacement's total",
                        ));
                    }
                    let current = self.confirm_current_preview(&current).await?;
                    self.require_local_sync_generation(&generation).await?;
                    Ok((current, selected, all))
                })
                .await;
            match checked {
                Ok((preview, selected, all)) => {
                    report.replacement = Some(preview);
                    report.selected_remaining = Some(selected);
                    report.all_remaining = Some(all);
                }
                Err(source) => report.observation_error = Some(source),
            }
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn conflicts_in_scope(
        &self,
        preview: &LocalSyncPreview,
        resolution: &LocalSyncConflictResolution,
        options: &LocalSyncWorkflowOptions,
    ) -> Result<u64> {
        let mut actions = Vec::new();
        self.read_local_sync_preview_actions(preview, options, &mut actions)
            .await?;
        let selected: Vec<_> = actions
            .iter()
            .filter(|action| resolution.selects(&action.path))
            .map(|action| LocalSyncActionRange::single(action.id))
            .collect();
        let mut conflicts = 0u64;
        for ranges in selected.chunks(10_000) {
            let selection = LocalSyncSelection::including(ranges.to_vec())?;
            let summary = self
                .local_sync_selection_summary(&preview.job_id, &preview.id, &selection)
                .await?;
            if summary.conflicts > ranges.len() as u64 {
                return Err(invalid(
                    "the conflict count exceeds the number of selected actions",
                ));
            }
            conflicts += summary.conflicts;
        }
        Ok(conflicts)
    }

    async fn confirm_current_preview(
        &self,
        expected: &LocalSyncPreview,
    ) -> Result<LocalSyncPreview> {
        let current = self.local_sync_preview(&expected.job_id).await?;
        if current.id != expected.id
            || current.operation_id != expected.operation_id
            || current.count != expected.count
            || current.expires_at != expected.expires_at
        {
            return Err(invalid(
                "another Local Sync preview replaced the reviewed plan",
            ));
        }
        require_unexpired(&current)?;
        Ok(current)
    }

    async fn read_local_sync_preview_actions(
        &self,
        preview: &LocalSyncPreview,
        options: &LocalSyncWorkflowOptions,
        actions: &mut Vec<LocalSyncAction>,
    ) -> Result<()> {
        if preview.count > options.max_results {
            return Err(invalid(
                "the Local Sync preview exceeds the selected record limit",
            ));
        }
        while (actions.len() as u64) < preview.count {
            let offset = actions.len() as u64;
            let limit = (preview.count - offset).min(u64::from(options.page_size)) as u16;
            let page = self
                .local_sync_preview_actions(&preview.job_id, &preview.id, offset, limit)
                .await?;
            if page.is_empty()
                || page.len() > usize::from(limit)
                || page
                    .iter()
                    .enumerate()
                    .any(|(index, action)| action.id != offset + index as u64)
            {
                return Err(invalid(
                    "the Local Sync preview has a missing, repeated or out-of-order action",
                ));
            }
            actions.extend(page);
        }
        Ok(())
    }

    /// Pause, resume or stop the selected, currently identified run. The
    /// engine's paused status can precede completion of writes already in
    /// flight. Confirm a stop only on a terminal cancellation of that run.
    /// A timeout or cancellation of this SDK wait sends no second command.
    pub async fn control_local_sync_run_and_verify(
        &self,
        job: &LocalSyncJobId,
        operation: &LocalSyncOperationId,
        run: &LocalSyncRunId,
        control: LocalSyncOperationControl,
        options: OperationOptions,
    ) -> Result<LocalSyncRunControlReport> {
        use LocalSyncRunControlOutcome as Outcome;
        let context = options.start()?;
        let mut write = ManagementWriteEvidence::default();
        let mut before = None;
        let mut observed = None;
        let mut observed_run = None;
        let mut original = context
            .wait(context.dispatch_deadline(), CONTROL, async {
                context.phase(OperationPhase::Checking);
                let _guard = self.connection.mutation_lock.lock().await;
                self.observe_control_identity().await?;
                let generation = self.system_status().await?.start_time.ok_or_else(|| {
                    invalid("the Local Sync instance did not report its start time")
                })?;
                let status = self.exact_local_sync_operation(job, operation).await?;
                let current = self.local_sync_run(job).await?;
                if &current.id != run || parse_rfc3339(&current.started).is_none() {
                    return Err(invalid(
                        "the selected Local Sync run changed before control",
                    ));
                }
                self.require_local_sync_generation(&generation).await?;
                if local_sync_control_outcome(control, &status, &current) == Some(Outcome::Observed)
                {
                    observed = Some(status);
                    observed_run = Some(current);
                    return Ok(());
                }
                if !matches!(status.state.as_str(), "running" | "paused")
                    || current.finished != UNFINISHED
                {
                    return Err(invalid("the selected Local Sync run is no longer active"));
                }
                before = Some((generation, current.started));
                let route = self.local_sync_url(
                    &["jobs", job.as_str(), local_sync_control_route(control)],
                    &[],
                )?;
                if Instant::now() >= context.dispatch_deadline() {
                    return Err(Error::Timeout { operation: CONTROL });
                }
                let request = self
                    .connection
                    .authorized_request(Method::POST, route, None);
                let response = self
                    .connection
                    .send_workflow_write(CONTROL, request, &context, &mut write)
                    .await?;
                let ack: serde_json::Value =
                    decode_local_sync_json(CONTROL, response.status, response.body, true, false)?;
                if ack.as_object().is_none_or(|object| !object.is_empty()) {
                    return Err(mutation_error(
                        CONTROL,
                        true,
                        invalid("the Local Sync control reply was not the expected empty object"),
                    ));
                }
                Ok(())
            })
            .await;
        original = workflow_write_result(CONTROL, write, original);
        let mut outcome = if !write.dispatched {
            if observed_run.is_some() {
                Outcome::AlreadyMatched
            } else {
                Outcome::NotSubmitted
            }
        } else if write.response_complete
            && matches!(
                &original,
                Err(Error::Authentication { .. }
                    | Error::AccessDenied { .. }
                    | Error::LicenseRequired { .. })
            )
        {
            Outcome::Rejected
        } else {
            Outcome::Unconfirmed
        };
        let mut observation_error = None;
        if let Some((generation, started)) =
            before.filter(|_| outcome == Outcome::Unconfirmed && write.dispatched)
        {
            context.phase(OperationPhase::Verifying);
            let result = context
                .wait(context.deadline, CHECK_CONTROL, async {
                    loop {
                        self.require_local_sync_generation(&generation).await?;
                        let status = self.exact_local_sync_operation(job, operation).await?;
                        let candidate = match control {
                            LocalSyncOperationControl::Pause => status.state == "paused",
                            LocalSyncOperationControl::Resume => status.state == "running",
                            LocalSyncOperationControl::Stop => false,
                        };
                        if candidate || matches!(status.state.as_str(), "idle" | "error") {
                            let current = self.local_sync_run(job).await?;
                            if &current.id != run || current.started != started {
                                return Err(invalid(
                                    "another Local Sync run replaced the selected result",
                                ));
                            }
                            self.require_local_sync_generation(&generation).await?;
                            let reached = local_sync_control_outcome(control, &status, &current);
                            observed_run = Some(current);
                            observed = Some(status);
                            if let Some(reached) = reached {
                                return Ok(reached);
                            }
                        } else {
                            observed_run = None;
                            observed = Some(status);
                        }
                        tokio::time::sleep(POLL_INTERVAL).await;
                    }
                })
                .await;
            match result {
                Ok(reached) => outcome = reached,
                Err(source) => observation_error = Some(source),
            }
        }
        context.phase(OperationPhase::Finished);
        Ok(LocalSyncRunControlReport {
            job: job.clone(),
            operation: operation.clone(),
            run: run.clone(),
            control,
            outcome,
            write,
            original,
            observed,
            observed_run,
            observation_error,
        })
    }

    async fn exact_local_sync_operation(
        &self,
        job: &LocalSyncJobId,
        operation: &LocalSyncOperationId,
    ) -> Result<LocalSyncStatus> {
        let status = self.local_sync_status(job).await?;
        if status.operation_id.as_ref() != Some(operation) {
            return Err(invalid(
                "the selected Local Sync operation is no longer current",
            ));
        }
        Ok(status)
    }

    async fn require_local_sync_generation(&self, expected: &str) -> Result<()> {
        if self.system_status().await?.start_time.as_deref() != Some(expected) {
            return Err(invalid(
                "the Local Sync instance restarted during observation",
            ));
        }
        Ok(())
    }
    /// Register one native storage job and check the exact endpoints and
    /// settings. For an unanswered request, the SDK compares the earlier job
    /// list with a fresh one. A matching label alone cannot identify a new job.
    /// Automatic triggers follow the supplied job settings.
    pub async fn create_local_sync_job_and_verify(
        &self,
        input: &CreateLocalSyncJob,
        options: OperationOptions,
    ) -> Result<LocalSyncRegistrationReport> {
        use LocalSyncRegistrationOutcome as Outcome;
        const REGISTER: &str = "register the selected Local Sync job";
        const VERIFY: &str = "identify the new Local Sync job";
        let body = self.preflight_local_sync_job(input)?;
        let context = options.start()?;
        let deadline = context.dispatch_deadline();
        let mut guard = None;
        let mut write = ManagementWriteEvidence::default();
        let mut before = HashSet::new();
        let mut generation = None;
        let submission = context
            .wait(deadline, REGISTER, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                self.observe_control_identity().await?;
                let start =
                    self.system_status().await?.start_time.ok_or_else(|| {
                        invalid("the selected engine did not report its start time")
                    })?;
                for job in self.local_sync_jobs().await? {
                    if !before.insert(job.job_id.as_str().to_owned()) {
                        return Err(invalid(
                            "the existing Local Sync list contains duplicate job IDs",
                        ));
                    }
                }
                self.require_configuration_generation(&start).await?;
                let url = self.local_sync_url(&["jobs"], &[])?;
                if Instant::now() >= deadline {
                    return Err(Error::Timeout {
                        operation: REGISTER,
                    });
                }
                generation = Some(start);
                let outgoing = self
                    .connection
                    .authorized_request(Method::POST, url, Some(&body));
                let response = self
                    .connection
                    .send_workflow_write(REGISTER, outgoing, &context, &mut write)
                    .await?;
                let job: LocalSyncJob =
                    decode_local_sync_json(REGISTER, response.status, response.body, true, false)?;
                if before.contains(job.job_id.as_str()) {
                    return Err(super::mutation_error(
                        REGISTER,
                        true,
                        invalid(
                            "the acknowledgement referred to an already registered Local Sync job",
                        ),
                    ));
                }
                Ok(job)
            })
            .await;
        let original = workflow_write_result(REGISTER, write, submission);
        let mut report = LocalSyncRegistrationReport {
            outcome: Outcome::NotSubmitted,
            write,
            original,
            observed: None,
            observation_error: None,
        };
        if write.response_complete
            && matches!(
                report.original,
                Err(Error::Authentication { .. }
                    | Error::AccessDenied { .. }
                    | Error::LicenseRequired { .. })
            )
        {
            report.outcome = Outcome::Rejected;
        } else if write.dispatched {
            context.phase(OperationPhase::Verifying);
            let completion = context
                .wait(context.deadline, VERIFY, async {
                    let start = generation.as_deref().ok_or_else(|| {
                        invalid("the original engine generation was not recorded")
                    })?;
                    self.require_configuration_generation(start).await?;
                    if let Ok(accepted) = &report.original {
                        let observed = self.local_sync_job(&accepted.job_id).await?;
                        let outcome = if local_job_matches(&body, &observed)? {
                            Outcome::CurrentMatches
                        } else {
                            Outcome::CurrentDiffers
                        };
                        self.require_configuration_generation(start).await?;
                        return Ok((outcome, observed));
                    }
                    let mut latest = HashSet::new();
                    let mut matched = None;
                    for job in self.local_sync_jobs().await? {
                        if !latest.insert(job.job_id.as_str().to_owned()) {
                            return Err(invalid(
                                "the current Local Sync list contains duplicate job IDs",
                            ));
                        }
                        if !before.contains(job.job_id.as_str())
                            && local_job_matches(&body, &job)?
                            && matched.replace(job).is_some()
                        {
                            return Err(invalid(
                                "several new Local Sync jobs match the requested settings",
                            ));
                        }
                    }
                    let candidate = matched.ok_or_else(|| {
                        invalid("no new Local Sync job matched the requested settings")
                    })?;
                    let observed = self.local_sync_job(&candidate.job_id).await?;
                    if !local_job_matches(&body, &observed)? {
                        return Err(Error::ConfigurationChanged);
                    }
                    self.require_configuration_generation(start).await?;
                    Ok((Outcome::MatchingNewRegistrationObserved, observed))
                })
                .await;
            match completion {
                Ok((outcome, observed)) => {
                    report.outcome = outcome;
                    report.observed = Some(observed);
                }
                Err(source) => {
                    report.outcome = Outcome::Unconfirmed;
                    report.observation_error = Some(source);
                }
            }
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    /// Update or remove one reviewed registration and verify that exact ID.
    /// Reject a changed registration before sending a PUT or DELETE. A
    /// matching update or absent registration requires no write. Automatic
    /// execution follows the selected native settings. Removing a job does
    /// not establish that an existing run stopped or that files were removed.
    pub async fn change_local_sync_registration_and_verify(
        &self,
        change: LocalSyncRegistrationChange<'_>,
        options: OperationOptions,
    ) -> Result<LocalSyncRegistrationChangeReport> {
        const SUBMIT: &str = "change the selected Local Sync job";
        const READ: &str = "verify the selected Local Sync job";
        let (expected, patch) = match change {
            LocalSyncRegistrationChange::Update { expected, patch } => {
                self.validate_local_sync_job_patch(patch)?;
                (expected, Some(patch))
            }
            LocalSyncRegistrationChange::Remove(expected) => (expected, None),
        };
        let id = &expected.job_id;
        let style = self.folder_path_style()?;
        expected.side_a.validate_target(style)?;
        expected.side_b.validate_target(style)?;
        let snapshot = local_job_document(expected)?;
        let url = self.local_sync_url(&["jobs", id.as_str()], &[])?;
        let context = options.start()?;
        let mut write = Default::default();
        let mut guard = None;
        let mut selected = None;
        let mut unchanged = None;
        let attempted = context
            .wait(context.dispatch_deadline(), SUBMIT, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                self.observe_control_identity().await?;
                let generation =
                    self.system_status().await?.start_time.ok_or_else(|| {
                        invalid("the selected engine did not report its start time")
                    })?;
                let current = self.read_selected_local_sync_job(id).await?;
                self.require_configuration_generation(&generation).await?;
                let Some(current) = current else {
                    return if patch.is_none() {
                        unchanged = Some(None);
                        Ok(None)
                    } else {
                        Err(Error::ConfigurationChanged)
                    };
                };
                if local_job_document(&current)? != snapshot {
                    return Err(Error::ConfigurationChanged);
                }
                let (method, body) = if let Some(patch) = patch {
                    if local_sync_job_patch_matches(patch, &current)? {
                        unchanged = Some(Some(current));
                        return Ok(None);
                    }
                    (
                        Method::PUT,
                        Some(local_sync_job_patch_body(patch, current)?),
                    )
                } else {
                    (Method::DELETE, None)
                };
                if Instant::now() >= context.dispatch_deadline() {
                    return Err(Error::Timeout { operation: SUBMIT });
                }
                selected = Some(generation);
                let request = self
                    .connection
                    .authorized_request(method, url, body.as_ref());
                let reply = self
                    .connection
                    .send_workflow_write(SUBMIT, request, &context, &mut write)
                    .await?;
                let parsed: serde_json::Value =
                    decode_local_sync_json(SUBMIT, reply.status, reply.body.clone(), true, false)?;
                if patch.is_none() {
                    if parsed.as_object().is_none_or(|body| !body.is_empty()) {
                        return Err(mutation_error(
                            SUBMIT,
                            true,
                            invalid("native job removal did not acknowledge the selected request"),
                        ));
                    }
                } else {
                    let current: LocalSyncJob = serde_json::from_value(parsed).map_err(|_| {
                        mutation_error(
                            SUBMIT,
                            true,
                            invalid("native job update did not report a registration"),
                        )
                    })?;
                    if current.job_id != *id {
                        return Err(mutation_error(
                            SUBMIT,
                            true,
                            invalid("native job update acknowledged a different ID"),
                        ));
                    }
                }
                Ok(Some(crate::ResponseDiagnostic::new(
                    reply.status,
                    reply.body,
                )))
            })
            .await;
        let original = workflow_write_result(SUBMIT, write, attempted);
        let refused = write.response_complete
            && matches!(
                original,
                Err(Error::Authentication { .. }
                    | Error::AccessDenied { .. }
                    | Error::LicenseRequired { .. })
            );
        let mut report = LocalSyncRegistrationChangeReport {
            write,
            original,
            registration_present: unchanged.as_ref().map(Option::is_some),
            requested_fields_match: unchanged
                .as_ref()
                .and_then(|current| current.as_ref().map(|_| true)),
            current: unchanged.flatten(),
            observation_error: None,
            remove: patch.is_none(),
        };
        if let Some(generation) = selected.filter(|_| write.dispatched && !refused) {
            context.phase(OperationPhase::Verifying);
            let verified = context
                .wait(context.deadline, READ, async {
                    self.require_configuration_generation(&generation).await?;
                    let current = self.read_selected_local_sync_job(id).await?;
                    let matched = patch
                        .map(|patch| {
                            current
                                .as_ref()
                                .map_or(Ok(false), |job| local_sync_job_patch_matches(patch, job))
                        })
                        .transpose()?;
                    self.require_configuration_generation(&generation).await?;
                    Ok((current, matched))
                })
                .await;
            match verified {
                Ok((current, matched)) => {
                    report.registration_present = Some(current.is_some());
                    report.current = current;
                    report.requested_fields_match = matched;
                }
                Err(error) => report.observation_error = Some(error),
            }
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn read_selected_local_sync_job(
        &self,
        id: &LocalSyncJobId,
    ) -> Result<Option<LocalSyncJob>> {
        let listed = self.local_sync_jobs().await?;
        let mut found = listed.iter().filter(|job| job.job_id == *id);
        let Some(job) = found.next() else {
            return Ok(None);
        };
        if found.next().is_some() {
            return Err(invalid(
                "the current Local Sync list contains duplicate job IDs",
            ));
        }
        let current = self.local_sync_job(id).await?;
        if local_job_document(job)? != local_job_document(&current)? {
            return Err(Error::ConfigurationChanged);
        }
        Ok(Some(current))
    }

    /// Execute an already reviewed preview once and observe its terminal run.
    ///
    /// The workflow checks the preview identity, issue count, expiry against
    /// the controller's clock, and selection before POST. The engine still
    /// decides whether the preview is usable. A lost or invalid acknowledgement
    /// without the native run ID cannot establish which run belongs to this
    /// request. The SDK returns an uncertain result and sends no new execution.
    /// File delivery to the chosen target requires its own evidence.
    pub async fn execute_local_sync_preview(
        &self,
        job: &LocalSyncJobId,
        preview: &LocalSyncPreviewId,
        selection: &LocalSyncSelection,
        options: LocalSyncWorkflowOptions,
    ) -> Result<LocalSyncRunReport> {
        options.verify_limits()?;
        let page = options.page_size;
        let context = options.operation.start()?;
        let mut report = LocalSyncRunReport::default();
        let dispatch_deadline = context.dispatch_deadline();
        let mut guard = None;
        let attempt = context
            .wait(dispatch_deadline, RUN, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                let current = self.local_sync_preview(job).await?;
                if &current.id != preview || current.scan_issue_count != 0 {
                    return Err(invalid(
                        "the Local Sync preview changed or has unresolved scan issues",
                    ));
                }
                let count = selection.selected_count(current.count)?;
                if count == 0 || count > options.max_results {
                    return Err(invalid(
                        "the selected Local Sync actions exceed the result limit or are empty",
                    ));
                }
                self.system_status().await?;
                require_unexpired(&current)?;
                let url = self.local_sync_url(&["jobs", job.as_str(), "run"], &[])?;
                let body = serde_json::json!({"previewId":preview,"selection":selection});
                let request = self
                    .connection
                    .authorized_request(Method::POST, url, Some(&body));
                if Instant::now() >= dispatch_deadline {
                    return Err(Error::Timeout { operation: RUN });
                }
                let response = self
                    .connection
                    .send_workflow_write(RUN, request, &context, &mut report.write)
                    .await?;
                let run: LocalSyncRun =
                    decode_local_sync_json(RUN, response.status, response.body, true, true)?;
                if &run.job_id != job
                    || !matches_run_count(&run, count)
                    || parse_rfc3339(&run.started).is_none()
                {
                    return Err(super::mutation_error(
                        RUN,
                        true,
                        invalid(
                            "the run acknowledgement has an unexpected job, count, or start time",
                        ),
                    ));
                }
                report.receipt = Some(LocalSyncRunReceipt {
                    schema: 1,
                    device: self.instance().device_id.clone(),
                    version_sha256: version_fingerprint(&self.instance().version.version),
                    job: job.clone(),
                    preview: preview.clone(),
                    run: run.id.clone(),
                    started: run.started.clone(),
                    selection_count: count,
                    preview_count: current.count,
                });
                Ok(run)
            })
            .await;
        let original = workflow_write_result(RUN, report.write, attempt);
        report.outcome = match &original {
            _ if !report.write.dispatched => LocalSyncRunOutcome::NotSubmitted,
            Err(
                Error::Authentication { .. }
                | Error::AccessDenied { .. }
                | Error::LicenseRequired { .. },
            ) => LocalSyncRunOutcome::Rejected,
            _ => LocalSyncRunOutcome::Unconfirmed,
        };
        report.initial = Some(original);
        if let Some(receipt) = report.receipt.clone() {
            self.finish_local_sync_run(&receipt, page, &context, &mut report)
                .await;
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    /// Read the run from a persisted application receipt without submitting
    /// any action. Select the trusted management client independently. The
    /// current run can change or its result pages can disappear.
    pub async fn observe_local_sync_execution(
        &self,
        receipt: &LocalSyncRunReceipt,
        options: LocalSyncWorkflowOptions,
    ) -> Result<LocalSyncRunReport> {
        options.verify_limits()?;
        if receipt.selection_count > options.max_results {
            return Err(invalid(
                "the original run exceeds the selected observation limit",
            ));
        }
        if receipt.device != self.instance().device_id {
            return Err(Error::IdentityMismatch {
                expected: receipt.device.clone(),
                actual: self.instance().device_id.clone(),
            });
        }
        if receipt.version_sha256 != version_fingerprint(&self.instance().version.version) {
            return Err(invalid(
                "the Local Sync run receipt belongs to a different engine version",
            ));
        }
        let context = options.operation.start()?;
        context
            .wait(context.deadline, CHECK_RUN, async {
                self.observe_control_identity().await.map(|_| ())
            })
            .await?;
        let mut report = LocalSyncRunReport {
            outcome: LocalSyncRunOutcome::Unconfirmed,
            receipt: Some(receipt.clone()),
            ..LocalSyncRunReport::default()
        };
        self.finish_local_sync_run(receipt, options.page_size, &context, &mut report)
            .await;
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn finish_local_sync_run(
        &self,
        receipt: &LocalSyncRunReceipt,
        page_size: u16,
        context: &OperationContext,
        report: &mut LocalSyncRunReport,
    ) {
        context.phase(OperationPhase::Verifying);
        let result = context
            .wait(context.deadline, CHECK_RUN, async {
                let terminal = loop {
                    let run = self.local_sync_run(&receipt.job).await?;
                    check_run_identity(&run, receipt)?;
                    if run.finished != UNFINISHED {
                        break run;
                    }
                    tokio::time::sleep(POLL_INTERVAL).await;
                };
                let completed = terminal.summary.completed;
                let failed = terminal.summary.failed;
                let native_skipped = terminal.summary.skipped;
                let action_total = completed
                    .checked_add(failed)
                    .filter(|count| *count <= receipt.selection_count)
                    .ok_or_else(|| {
                        invalid("the Local Sync result counts exceed the selected actions")
                    })?;
                let native_total = action_total
                    .checked_add(native_skipped)
                    .filter(|count| *count <= receipt.preview_count)
                    .ok_or_else(|| {
                        invalid("the Local Sync terminal counts exceed the reviewed preview")
                    })?;
                let has_native_error = terminal
                    .error
                    .as_deref()
                    .is_some_and(|text| !text.is_empty());
                let cancelled = terminal.cancelled == Some(true);
                let excluded = receipt.preview_count - receipt.selection_count;
                let selected_skipped = native_skipped.checked_sub(excluded);
                let accounted = native_total
                    .checked_sub(excluded)
                    .filter(|_| selected_skipped.is_some());
                let result_count = terminal.count;
                report.selected_summary = selected_skipped.map(|skipped| LocalSyncSummary {
                    completed,
                    failed,
                    skipped,
                });
                report.terminal = Some(terminal);
                if (accounted != Some(receipt.selection_count) && !cancelled && !has_native_error)
                    || accounted.is_some_and(|count| result_count > count)
                {
                    return Err(invalid(
                        "the Local Sync run ended with incomplete action counts",
                    ));
                }
                let mut offset = 0;
                let mut read_ids = HashSet::new();
                while offset < result_count {
                    let limit = u64::from(page_size).min(result_count - offset) as u16;
                    let results = self
                        .local_sync_run_results(&receipt.job, &receipt.run, offset, limit)
                        .await?;
                    if results.is_empty() || results.len() > usize::from(limit) {
                        return Err(invalid(
                            "the terminal Local Sync results page has an unexpected length",
                        ));
                    }
                    let mut next_ids = HashSet::with_capacity(results.len());
                    if results.iter().any(|action| {
                        action.action_id >= receipt.preview_count
                            || read_ids.contains(&action.action_id)
                            || !next_ids.insert(action.action_id)
                    }) {
                        return Err(invalid(
                            "the Local Sync results repeat an action or select a different plan",
                        ));
                    }
                    read_ids.extend(next_ids);
                    offset += results.len() as u64;
                    report.results.extend(results);
                }
                let final_check = self.local_sync_run(&receipt.job).await?;
                check_run_identity(&final_check, receipt)?;
                let original = report
                    .terminal
                    .as_ref()
                    .expect("terminal snapshot was set before paging");
                if !same_terminal_run(original, &final_check) {
                    return Err(invalid(
                        "the Local Sync terminal snapshot changed while reading results",
                    ));
                }
                Ok(if cancelled {
                    LocalSyncRunOutcome::Cancelled
                } else if failed == 0
                    && selected_skipped == Some(0)
                    && !has_native_error
                    && result_count == receipt.selection_count
                {
                    LocalSyncRunOutcome::Completed
                } else if completed != 0 {
                    LocalSyncRunOutcome::PartiallyCompleted
                } else {
                    LocalSyncRunOutcome::Failed
                })
            })
            .await;
        match result {
            Ok(outcome) => report.outcome = outcome,
            Err(source) => {
                if let Some(terminal) = &report.terminal {
                    report.outcome = if terminal.cancelled == Some(true) {
                        LocalSyncRunOutcome::Cancelled
                    } else if terminal.summary.completed > 0 {
                        LocalSyncRunOutcome::PartiallyCompleted
                    } else {
                        LocalSyncRunOutcome::Unconfirmed
                    };
                }
                report.observation_error = Some(source);
            }
        }
    }

    /// Generate and read one Local Sync preview without executing the planned
    /// actions. The SDK binds the returned preview to the acknowledged analysis
    /// operation and verifies every page it reads. Scan issues remain visible
    /// and prevent the checked execution entry point from submitting the plan.
    pub async fn preview_local_sync_and_verify(
        &self,
        job: &LocalSyncJobId,
        options: LocalSyncWorkflowOptions,
    ) -> Result<LocalSyncPreviewReport> {
        options.verify_limits()?;
        let context = options.operation.clone().start()?;
        let dispatch_deadline = context.dispatch_deadline();
        let mut write = ManagementWriteEvidence::default();
        let mut guard = None;
        let initial: Result<LocalSyncOperation> = context
            .wait(dispatch_deadline, PREVIEW, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                self.local_sync_job(job).await?;
                self.system_status().await?;
                let url = self.local_sync_url(&["jobs", job.as_str(), "preview"], &[])?;
                let outgoing = self.connection.authorized_request(Method::POST, url, None);
                if Instant::now() >= dispatch_deadline {
                    return Err(Error::Timeout { operation: PREVIEW });
                }
                let response = self
                    .connection
                    .send_workflow_write(PREVIEW, outgoing, &context, &mut write)
                    .await?;
                let operation: LocalSyncOperation =
                    decode_local_sync_json(PREVIEW, response.status, response.body, true, false)?;
                if &operation.job_id != job {
                    return Err(super::mutation_error(
                        PREVIEW,
                        true,
                        invalid("the preview acknowledgement selected a different job"),
                    ));
                }
                Ok(operation)
            })
            .await;
        let mut report = LocalSyncPreviewReport {
            write,
            initial: workflow_write_result(PREVIEW, write, initial),
            preview: None,
            actions: Vec::new(),
            observation_error: None,
        };
        if let Ok(operation) = &report.initial {
            context.phase(OperationPhase::Verifying);
            let result = context
                .wait(context.deadline, CHECK_PREVIEW, async {
                    loop {
                        let status = self.local_sync_status(job).await?;
                        if status
                            .operation_id
                            .as_ref()
                            .is_some_and(|current| *current != operation.id)
                        {
                            return Err(invalid(
                                "a different Local Sync operation replaced the submitted preview",
                            ));
                        }
                        if status.operation_id.as_ref() == Some(&operation.id) {
                            if status.state == "error" {
                                return Err(invalid(
                                    "the selected native Local Sync analysis reported an error",
                                ));
                            }
                            if status.state == "idle" {
                                break;
                            }
                        }
                        tokio::time::sleep(POLL_INTERVAL).await;
                    }
                    let preview = self.local_sync_preview(job).await?;
                    if preview.operation_id != operation.id {
                        return Err(invalid(
                            "the current Local Sync preview belongs to another operation",
                        ));
                    }
                    require_unexpired(&preview)?;
                    let observed = report.preview.insert(preview);
                    self.read_local_sync_preview_actions(observed, &options, &mut report.actions)
                        .await?;
                    self.confirm_current_preview(observed).await?;
                    Ok(())
                })
                .await;
            report.observation_error = result.err();
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }
}

fn local_sync_control_outcome(
    control: LocalSyncOperationControl,
    status: &LocalSyncStatus,
    run: &LocalSyncRun,
) -> Option<LocalSyncRunControlOutcome> {
    use LocalSyncRunControlOutcome as Outcome;
    if run.finished == UNFINISHED {
        return match (control, status.state.as_str()) {
            (LocalSyncOperationControl::Pause, "paused")
            | (LocalSyncOperationControl::Resume, "running") => Some(Outcome::Observed),
            _ => None,
        };
    }
    if !matches!(status.state.as_str(), "idle" | "error")
        || !parse_rfc3339(&run.finished)
            .zip(parse_rfc3339(&run.started))
            .is_some_and(|(finished, started)| finished >= started)
    {
        return None;
    }
    if control == LocalSyncOperationControl::Stop
        && run.cancelled == Some(true)
        && status.last_run_cancelled == Some(true)
    {
        Some(Outcome::Observed)
    } else {
        Some(Outcome::EndedWithoutGoal)
    }
}

fn require_unexpired(preview: &LocalSyncPreview) -> Result<()> {
    if parse_rfc3339(&preview.expires_at).is_some_and(|expiry| expiry > jiff::Timestamp::now()) {
        Ok(())
    } else {
        Err(invalid(
            "the Local Sync preview is expired or its expiry cannot be verified",
        ))
    }
}

fn local_job_matches(expected: &serde_json::Value, observed: &LocalSyncJob) -> Result<bool> {
    let value = serde_json::to_value(observed)
        .map_err(|_| invalid("the authenticated Local Sync job cannot be compared"))?;
    Ok(requested_subset(expected, &value))
}

fn check_run_identity(run: &LocalSyncRun, receipt: &LocalSyncRunReceipt) -> Result<()> {
    if run.id != receipt.run
        || run.job_id != receipt.job
        || run.started != receipt.started
        || !matches_run_count(run, receipt.selection_count)
    {
        return Err(invalid(
            "the current Local Sync result is not from the acknowledged run",
        ));
    }
    if run.finished != UNFINISHED {
        let started = parse_rfc3339(&run.started);
        let finished = parse_rfc3339(&run.finished);
        if !matches!((started, finished), (Some(started), Some(finished)) if finished >= started) {
            return Err(invalid(
                "the Local Sync run returned an invalid terminal time",
            ));
        }
    }
    Ok(())
}

fn matches_run_count(run: &LocalSyncRun, selected: u64) -> bool {
    // The fixed native engine reports the number of result rows that have
    // materialized. The accepted 202 can have none.
    run.count <= selected
}

fn same_terminal_run(a: &LocalSyncRun, b: &LocalSyncRun) -> bool {
    a.count == b.count
        && a.finished == b.finished
        && a.cancelled == b.cancelled
        && a.error == b.error
        && a.summary.completed == b.summary.completed
        && a.summary.failed == b.summary.failed
        && a.summary.skipped == b.summary.skipped
}

fn local_job_document(job: &LocalSyncJob) -> Result<serde_json::Value> {
    serde_json::to_value(job).map_err(|_| invalid("Local Sync registration cannot be encoded"))
}
