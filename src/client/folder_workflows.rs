//! Whole folder configuration operations with one modifying dispatch.

use std::time::Duration;

use reqwest::Method;

use super::{workflow_write_result, Client};
use crate::{
    operation_options::OperationContext, Error, FolderConfig, FolderConfigurationOutcome,
    FolderConfigurationReport, FolderId, FolderPatch, FolderRuntimeObservation, FolderState,
    FolderUnregistrationOutcome, FolderUnregistrationReport, ManagementWriteEvidence,
    OperationOptions, OperationPhase, Result,
};

const CHANGE: &str = "apply the requested folder settings";
const VERIFY: &str = "confirm the selected folder settings";
const ACTIVITY: &str = "observe the selected folder activity";
const UNREGISTER: &str = "unregister the selected folder";
const CHECK_UNREGISTERED: &str = "confirm the selected folder is unregistered";

impl Client {
    /// Apply the selected fields once and check the current configuration on
    /// the original device. If the fields already match, the SDK skips writing.
    /// A later matching snapshot can coexist with an unknown original response.
    pub async fn update_folder_and_verify(
        &self,
        folder: &FolderId,
        patch: &FolderPatch,
        options: OperationOptions,
    ) -> Result<FolderConfigurationReport> {
        self.change_folder(folder, patch, None, options).await
    }

    /// Set the folder pause flag and optionally observe a specific runtime
    /// state within the same timeout. The pause configuration and the last
    /// reported state are separate facts. A folder state alone cannot verify
    /// a file delivery, drained connections, or another device's activity.
    pub async fn set_folder_pause_and_verify(
        &self,
        folder: &FolderId,
        paused: bool,
        expected_runtime: Option<FolderState>,
        options: OperationOptions,
    ) -> Result<FolderConfigurationReport> {
        self.change_folder(
            folder,
            &FolderPatch::default().paused(paused),
            expected_runtime,
            options,
        )
        .await
    }

    async fn change_folder(
        &self,
        folder: &FolderId,
        patch: &FolderPatch,
        expected_runtime: Option<FolderState>,
        options: OperationOptions,
    ) -> Result<FolderConfigurationReport> {
        if patch.is_empty() {
            return Err(Error::InvalidConfiguration {
                reason: "folder patch must contain at least one field",
            });
        }
        let url = self.connection.folder_url(folder)?;
        let body = Self::folder_patch_body(patch)?;
        let context = options.start()?;
        let mut report = FolderConfigurationReport {
            outcome: FolderConfigurationOutcome::NotSubmitted,
            write: Default::default(),
            original: None,
            observed: None,
            observation_error: None,
            runtime: None,
        };
        let write_deadline = context.started
            + context
                .deadline
                .duration_since(context.started)
                .mul_f64(2.0 / 3.0);
        let mut previous = None;
        let mut mutation_guard = None;
        let attempt = context
            .wait(write_deadline, CHANGE, async {
                context.phase(OperationPhase::Checking);
                mutation_guard = Some(self.connection.mutation_lock.lock().await);
                self.observe_control_identity().await?;
                let current = self.folder(folder).await?;
                self.system_status().await?;
                if patch.matches(&current) {
                    return Ok(Some(current));
                }
                previous = Some(current);
                if tokio::time::Instant::now() >= write_deadline {
                    return Err(Error::Timeout { operation: CHANGE });
                }
                let request = self
                    .connection
                    .authorized_request(Method::PATCH, url, Some(&body));
                self.connection
                    .send_workflow_write(CHANGE, request, &context, &mut report.write)
                    .await?;
                Ok(None)
            })
            .await;
        match attempt {
            Ok(Some(current)) => {
                report.outcome = FolderConfigurationOutcome::AlreadyMatched;
                report.observed = Some(current);
            }
            result => {
                report.original = Some(workflow_write_result(
                    CHANGE,
                    report.write,
                    result.map(|_| ()),
                ));
                if let Some(before) = previous.as_ref().filter(|_| report.write.dispatched) {
                    self.confirm_folder_change(folder, patch, before, &context, &mut report)
                        .await;
                }
            }
        }
        drop(mutation_guard);
        if let (Some(expected), Some(selected)) = (expected_runtime, report.observed.as_ref()) {
            if matches!(
                report.outcome,
                FolderConfigurationOutcome::AlreadyMatched
                    | FolderConfigurationOutcome::CurrentMatches
            ) {
                report.runtime = Some(
                    self.wait_for_folder_activity(folder, selected, expected, &context)
                        .await,
                );
            }
        }
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn confirm_folder_change(
        &self,
        folder: &FolderId,
        patch: &FolderPatch,
        before: &FolderConfig,
        context: &OperationContext,
        report: &mut FolderConfigurationReport,
    ) {
        if permission_refused(report.write, report.original.as_ref()) {
            report.outcome = FolderConfigurationOutcome::Rejected;
            return;
        }
        let current = context
            .wait(context.deadline, VERIFY, async {
                context.phase(OperationPhase::Verifying);
                self.observe_control_identity().await?;
                let current = self.folder(folder).await?;
                self.system_status().await?;
                if current.path != before.path {
                    return Err(Error::ConfigurationChanged);
                }
                Ok(current)
            })
            .await;
        match current {
            Ok(current) => {
                report.outcome = if patch.matches(&current) {
                    FolderConfigurationOutcome::CurrentMatches
                } else {
                    FolderConfigurationOutcome::CurrentDiffers
                };
                report.observed = Some(current);
            }
            Err(source) => {
                report.outcome = FolderConfigurationOutcome::Unconfirmed;
                report.observation_error = Some(source);
            }
        }
    }

    async fn wait_for_folder_activity(
        &self,
        folder: &FolderId,
        selected: &FolderConfig,
        expected: FolderState,
        context: &OperationContext,
    ) -> FolderRuntimeObservation {
        let mut last_snapshot = None;
        let observed = context
            .wait(context.deadline, ACTIVITY, async {
                loop {
                    self.system_status().await?;
                    let status = self.folder_status(folder).await?;
                    let current = self.folder(folder).await?;
                    self.system_status().await?;
                    if current.path != selected.path || current.paused != selected.paused {
                        return Err(Error::ConfigurationChanged);
                    }
                    let matched = status.state.as_ref() == Some(&expected);
                    last_snapshot = Some(status);
                    if matched {
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await;
        FolderRuntimeObservation {
            expected,
            expected_state_observed: observed.is_ok(),
            last_snapshot,
            source: observed.err(),
        }
    }

    /// Unregister the exact folder ID and check its current registration.
    ///
    /// The SDK sends at most one configuration DELETE with no file arguments.
    /// If the ID is already absent, it skips the request. The original response
    /// and the later registration snapshot are reported separately. Inspect file
    /// contents on the device if you also need independent retention evidence.
    pub async fn unregister_folder_and_verify(
        &self,
        folder: &FolderId,
        options: OperationOptions,
    ) -> Result<FolderUnregistrationReport> {
        let url = self.connection.folder_url(folder)?;
        let context = options.start()?;
        let mut report = FolderUnregistrationReport {
            outcome: FolderUnregistrationOutcome::NotSubmitted,
            write: ManagementWriteEvidence::default(),
            original: None,
            previous: None,
            current: None,
            observation_error: None,
        };
        let write_deadline = context.started
            + context
                .deadline
                .duration_since(context.started)
                .mul_f64(2.0 / 3.0);
        let mut mutation_guard = None;
        let attempt = context
            .wait(write_deadline, UNREGISTER, async {
                context.phase(OperationPhase::Checking);
                mutation_guard = Some(self.connection.mutation_lock.lock().await);
                let current = self.current_registration(folder).await?;
                let Some(current) = current else {
                    return Ok(false);
                };
                report.previous = Some(current);
                if tokio::time::Instant::now() >= write_deadline {
                    return Err(Error::Timeout {
                        operation: UNREGISTER,
                    });
                }
                let request = self
                    .connection
                    .authorized_request(Method::DELETE, url, None);
                self.connection
                    .send_workflow_write(UNREGISTER, request, &context, &mut report.write)
                    .await?;
                Ok(true)
            })
            .await;
        if matches!(attempt, Ok(false)) {
            report.outcome = FolderUnregistrationOutcome::AlreadyAbsent;
        } else {
            report.original = Some(workflow_write_result(
                UNREGISTER,
                report.write,
                attempt.map(|_| ()),
            ));
            if permission_refused(report.write, report.original.as_ref()) {
                report.outcome = FolderUnregistrationOutcome::Rejected;
            } else if report.write.dispatched {
                context.phase(OperationPhase::Verifying);
                match context
                    .wait(
                        context.deadline,
                        CHECK_UNREGISTERED,
                        self.current_registration(folder),
                    )
                    .await
                {
                    Ok(current) => {
                        report.outcome = if current.is_none() {
                            FolderUnregistrationOutcome::Absent
                        } else {
                            FolderUnregistrationOutcome::RegistrationPresent
                        };
                        report.current = current;
                    }
                    Err(source) => {
                        report.outcome = FolderUnregistrationOutcome::Unconfirmed;
                        report.observation_error = Some(source);
                    }
                }
            }
        }
        drop(mutation_guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn current_registration(&self, folder: &FolderId) -> Result<Option<FolderConfig>> {
        self.observe_control_identity().await?;
        let selected = self
            .folders()
            .await?
            .into_iter()
            .find(|config| config.id == *folder);
        self.system_status().await?;
        Ok(selected)
    }
}

fn permission_refused(evidence: ManagementWriteEvidence, original: Option<&Result<()>>) -> bool {
    evidence.response_complete
        && matches!(
            original,
            Some(Err(
                Error::Authentication { .. } | Error::AccessDenied { .. }
            ))
        )
}
