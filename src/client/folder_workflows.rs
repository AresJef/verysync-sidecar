//! Whole folder configuration operations with one modifying dispatch.

use std::time::Duration;

use reqwest::Method;

use super::{workflow_write_result, Client};
use crate::{
    operation_options::OperationContext, CreateFolderOptions, Error, FolderConfig,
    FolderConfigurationOutcome, FolderConfigurationReport, FolderId, FolderPatch,
    FolderRuntimeObservation, FolderState, FolderUnregistrationOutcome, FolderUnregistrationReport,
    JoinFolderOptions, ManagementWriteEvidence, OperationOptions, OperationPhase, Result,
};

const CHANGE: &str = "apply the requested folder settings";
const VERIFY: &str = "confirm the selected folder settings";
const ACTIVITY: &str = "observe the selected folder activity";
const UNREGISTER: &str = "unregister the selected folder";
const CHECK_UNREGISTERED: &str = "confirm the selected folder is unregistered";
const REGISTER: &str = "register the selected synchronization folder";
const CHECK_REGISTERED: &str = "confirm the selected folder registration";

#[derive(Clone, Copy)]
enum Registration<'a> {
    Create(&'a CreateFolderOptions),
    Join(&'a JoinFolderOptions),
}

impl Client {
    /// Create a new explicit registration once and read back its requested
    /// fields within the same deadline. A previously registered ID cannot
    /// serve as proof of a new creation. File activity and peer acceptance
    /// require additional observations.
    pub async fn create_folder_and_verify(
        &self,
        options: &CreateFolderOptions,
        operation: OperationOptions,
    ) -> Result<FolderConfigurationReport> {
        self.register_folder_workflow(Registration::Create(options), operation)
            .await
    }

    /// Register a previously validated share once and check the exact ID,
    /// path, requested settings and share keys on this same device.
    pub async fn join_folder_and_verify(
        &self,
        options: &JoinFolderOptions,
        operation: OperationOptions,
    ) -> Result<FolderConfigurationReport> {
        self.register_folder_workflow(Registration::Join(options), operation)
            .await
    }

    async fn register_folder_workflow(
        &self,
        inputs: Registration<'_>,
        options: OperationOptions,
    ) -> Result<FolderConfigurationReport> {
        let (path, advanced) = match inputs {
            Registration::Create(options) => self.created_folder_inputs(options)?,
            Registration::Join(options) => (self.join_folder_path(options)?, None),
        };
        let (id, label, paused) = match inputs {
            Registration::Create(options) => {
                (&options.id, options.label.as_deref(), options.paused)
            }
            Registration::Join(options) => (
                &options.share.registration_id,
                options.label.as_deref(),
                options.paused,
            ),
        };
        let context = options.start()?;
        let mut report = FolderConfigurationReport {
            outcome: FolderConfigurationOutcome::NotSubmitted,
            write: Default::default(),
            original: None,
            observed: None,
            observation_error: None,
            runtime: None,
        };
        let dispatch = context.dispatch_deadline();
        let mut guard = None;
        let result = context
            .wait(dispatch, REGISTER, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                let body = match inputs {
                    Registration::Create(options) => {
                        self.prepare_folder_creation(options, path, advanced.as_ref())
                            .await?
                    }
                    Registration::Join(options) => self.prepare_folder_join(options, path).await?,
                };
                self.system_status().await?;
                if tokio::time::Instant::now() >= dispatch {
                    return Err(Error::Timeout {
                        operation: REGISTER,
                    });
                }
                let url = self.connection.management_url("rest/config/folders", &[])?;
                let request = self
                    .connection
                    .authorized_request(Method::POST, url, Some(&body));
                self.connection
                    .send_workflow_write(REGISTER, request, &context, &mut report.write)
                    .await?;
                Ok(())
            })
            .await;
        report.original = Some(workflow_write_result(REGISTER, report.write, result));
        if permission_refused(report.write, report.original.as_ref()) {
            report.outcome = FolderConfigurationOutcome::Rejected;
        } else if report.write.dispatched {
            context.phase(OperationPhase::Verifying);
            let verified = context
                .wait(context.deadline, CHECK_REGISTERED, async {
                    let registered = self.current_registration(id).await?;
                    let Some(registered) = registered else {
                        return Ok((None, false));
                    };
                    let mut fields_match = registered.path.to_protocol()? == path
                        && label.is_none_or(|expected| expected == registered.label)
                        && paused.is_none_or(|expected| expected == registered.paused);
                    if let Some(fields) = advanced.as_ref().and_then(serde_json::Value::as_object) {
                        registered.advanced_configuration()?;
                        fields_match &= fields
                            .iter()
                            .all(|(key, value)| registered.extra.get(key) == Some(value));
                    }
                    if let Registration::Join(options) = inputs {
                        let details = Self::joined_folder_result(options, registered);
                        fields_match &= details.submitted_key_matches
                            && details.read_only_key_matches
                            && details.read_write_key_matches;
                        Ok((Some(details.configuration), fields_match))
                    } else {
                        Ok((Some(registered), fields_match))
                    }
                })
                .await;
            match verified {
                Ok((observed, matches)) => {
                    report.outcome = if matches {
                        FolderConfigurationOutcome::CurrentMatches
                    } else {
                        FolderConfigurationOutcome::CurrentDiffers
                    };
                    report.observed = observed;
                }
                Err(source) => {
                    report.outcome = FolderConfigurationOutcome::Unconfirmed;
                    report.observation_error = Some(source);
                }
            }
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

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
        let write_deadline = context.dispatch_deadline();
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
        let write_deadline = context.dispatch_deadline();
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
