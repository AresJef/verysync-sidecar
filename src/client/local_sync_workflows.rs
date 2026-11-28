//! Compose existing, identity-checked native Local Sync operations.

use std::{collections::HashSet, time::Duration};

use reqwest::Method;
use tokio::time::Instant;

use super::{local_sync_control::decode_local_sync_json, workflow_write_result, Client};
use crate::{
    control_operation::version_fingerprint, local_sync::invalid,
    operation_options::OperationContext, timestamps::parse_rfc3339, Error, LocalSyncJobId,
    LocalSyncOperation, LocalSyncPreview, LocalSyncPreviewId, LocalSyncPreviewReport, LocalSyncRun,
    LocalSyncRunOutcome, LocalSyncRunReceipt, LocalSyncRunReport, LocalSyncSelection,
    LocalSyncSummary, LocalSyncWorkflowOptions, ManagementWriteEvidence, OperationPhase, Result,
};

const RUN: &str = "submit the selected Local Sync preview for execution";
const CHECK_RUN: &str = "check the exact Local Sync run";
const PREVIEW: &str = "start the selected Local Sync preview";
const CHECK_PREVIEW: &str = "check the selected Local Sync preview";
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const UNFINISHED: &str = "0001-01-01T00:00:00Z";

impl Client {
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
        let dispatch_deadline = dispatch_limit(&context);
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
        let context = options.operation.start()?;
        let dispatch_deadline = dispatch_limit(&context);
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
            let result = context.wait(context.deadline, CHECK_PREVIEW, async {
                loop {
                    let status = self.local_sync_status(job).await?;
                    if status.operation_id.as_ref().is_some_and(|current| *current != operation.id) {
                        return Err(invalid("a different Local Sync operation replaced the submitted preview"));
                    }
                    if status.operation_id.as_ref() == Some(&operation.id) {
                        if status.state == "error" {
                            return Err(invalid("the selected native Local Sync analysis reported an error"));
                        }
                        if status.state == "idle" {
                            break;
                        }
                    }
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
                let preview = self.local_sync_preview(job).await?;
                if preview.operation_id != operation.id {
                    return Err(invalid("the current Local Sync preview belongs to another operation"));
                }
                require_unexpired(&preview)?;
                let count = preview.count;
                let id = preview.id.clone();
                report.preview = Some(preview);
                if count > options.max_results {
                    return Err(invalid("the Local Sync preview exceeds the selected record limit"));
                }
                while (report.actions.len() as u64) < count {
                    let offset = report.actions.len() as u64;
                    let limit = (count - offset).min(u64::from(options.page_size)) as u16;
                    let actions = self.local_sync_preview_actions(job, &id, offset, limit).await?;
                    if actions.is_empty() || actions.len() > usize::from(limit)
                        || actions.iter().enumerate().any(|(index, action)| action.id != offset + index as u64)
                    {
                        return Err(invalid("the Local Sync preview has a missing, repeated or out-of-order action"));
                    }
                    report.actions.extend(actions);
                }
                let current = self.local_sync_preview(job).await?;
                if current.id != id || current.operation_id != operation.id || current.count != count {
                    return Err(invalid("the Local Sync preview changed while reading its pages"));
                }
                require_unexpired(&current)?;
                Ok(())
            }).await;
            report.observation_error = result.err();
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }
}

fn dispatch_limit(context: &OperationContext) -> Instant {
    context.started
        + context
            .deadline
            .duration_since(context.started)
            .mul_f64(2.0 / 3.0)
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
