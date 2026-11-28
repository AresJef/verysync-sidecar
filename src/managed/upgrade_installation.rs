//! Verify the effect of one fixed archive upload on its original owned program.

use std::{fmt, path::PathBuf};

use tokio::time::Instant;

use super::{
    ManagedExit, ManagedInstance, ProgramTransition, UpgradeProgramMatch, UpgradeProgramObservation,
};
use crate::{
    client::{retry_delay, retryable_read},
    operation_options::OperationContext,
    upgrade_receipt::UpgradeAttempt,
    Client, Error, LocalProgram, OfficialProgram, OperationOptions, OperationPhase, Result,
    UpgradeAction, UpgradeDispatch, UpgradeOperationResult, UpgradeOutcome,
};

const CHECK: &str = "check the running VerySync program before installation";
const UPLOAD: &str = "upload fixed kernel upgrade";
const VERIFY: &str = "verify the selected program after installation";
const START: &str = "start and authenticate the installed VerySync program";

/// What the SDK can establish about the caller's selected program on disk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KernelInstallationOutcome {
    /// The trusted file already matched the target; no installation was submitted.
    AlreadyInstalled,
    /// The original writer exited and the file matches the target digest.
    Installed,
    /// The original writer exited and the file still matches the previous digest.
    PreviousProgramRemains,
    /// Preconditions failed or the native engine explicitly rejected the request.
    NotInstalled,
    /// The original operation or subsequent disk state could not be confirmed.
    Unconfirmed,
}

impl fmt::Display for KernelInstallationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AlreadyInstalled => "The target version was already installed. No new installation was submitted.",
            Self::Installed => "The target version is installed on disk.",
            Self::PreviousProgramRemains => "The upgrade did not reach the target version. The program file still matches the previous version.",
            Self::NotInstalled => "The installation did not complete. Check the request result before trying again.",
            Self::Unconfirmed => "The installed version could not be confirmed. Check the original instance and program file before sending another installation request.",
        })
    }
}

/// The original upload result and any later read-only facts about this owner.
#[derive(Debug)]
#[non_exhaustive]
pub struct KernelInstallationReport {
    /// The business result on disk; readiness is a separate claim.
    pub outcome: KernelInstallationOutcome,
    /// The original request, response boundary and cause, including preflight failures.
    pub installation: UpgradeOperationResult<()>,
    /// Number of logical admission reads started. Each can read version and identity.
    pub admission_attempts: u8,
    /// The cause that triggered an additional admission read, if applicable.
    pub first_admission_failure: Option<Error>,
    /// Confirmed original process-tree exit and release before disk inspection.
    pub original_exit: Option<ManagedExit>,
    /// The verified program comparison, or a reason it could not be made.
    pub disk: Option<UpgradeProgramObservation>,
    /// A wait or inspection error before a disk report could be produced.
    pub verification_error: Option<Error>,
}

/// Whether the selected program was installed and authenticated on its state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KernelReadinessOutcome {
    /// The same owned instance was already ready with the selected program.
    AlreadyReady,
    /// The SDK started and authenticated the selected program.
    Ready,
    /// The selected file was verified, but the SDK could not confirm readiness.
    InstalledReadinessUnconfirmed,
    /// The installation did not establish the selected program on disk.
    InstallationUnconfirmed,
}

impl fmt::Display for KernelReadinessOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AlreadyReady => "The target version is already running and ready.",
            Self::Ready => "The target version is installed and ready.",
            Self::InstalledReadinessUnconfirmed =>
                "The target version is installed. Verify that this instance started and is responding before using it.",
            Self::InstallationUnconfirmed =>
                "The target version was not confirmed on disk. Check the installation report before starting it.",
        })
    }
}

/// The disk result and the separately authorized startup of the same state.
#[derive(Debug)]
#[non_exhaustive]
pub struct KernelReadinessReport {
    /// Whether the final instance was authenticated and ready.
    pub outcome: KernelReadinessOutcome,
    /// The original upload and program-file verification.
    pub installation: KernelInstallationReport,
    /// The SDK initiated startup after confirming file and owned exit.
    pub sdk_start_attempted: bool,
    /// The two owned generations when the SDK confirmed the transition.
    pub transition: Option<ProgramTransition>,
    /// The startup or readiness error, if one was observed.
    pub readiness_error: Option<Error>,
}

enum UploadResult {
    AlreadyInstalled,
    Acknowledged,
}

impl ManagedInstance {
    /// Install the selected fixed archive on this running owner and verify the
    /// program file. This requires a dedicated, writable executable and a
    /// catalogued target for the owner's architecture. Keep the archive
    /// immutable for the call.
    ///
    /// The SDK verifies the selected version and device, submits at most one
    /// upload, and reserves time to observe the original writer's exit and
    /// compare the file, even if the response was lost. It never requests
    /// shutdown or launches a program in this flow. Native restart behavior
    /// can occur as part of the accepted upload. Inspect the report before
    /// making another installation decision.
    pub async fn install_kernel_upgrade(
        &self,
        archive: impl Into<PathBuf>,
        target: &OfficialProgram,
        options: OperationOptions,
    ) -> Result<KernelInstallationReport> {
        let context = options.start()?;
        let result = self
            .install_fixed_kernel(archive.into(), target, &context, context.deadline)
            .await;
        context.phase(OperationPhase::Finished);
        result
    }

    /// Install and verify the fixed program, then start it on the same private
    /// state when needed. This permits one SDK startup after the old writer
    /// exits. The loaded program must match the target digest and authenticate
    /// with the original device identity. An installation failure or unknown
    /// disk state prevents startup.
    ///
    /// Save an offline state backup before changing versions. Readiness
    /// establishes management access and executable identity; application data
    /// and database compatibility require their own checks.
    pub async fn upgrade_kernel_and_wait_ready(
        &mut self,
        archive: impl Into<PathBuf>,
        target: &OfficialProgram,
        options: OperationOptions,
    ) -> Result<KernelReadinessReport> {
        let context = options.start()?;
        let result = self
            .upgrade_fixed_kernel_ready(archive.into(), target, &context)
            .await;
        context.phase(OperationPhase::Finished);
        result
    }

    async fn upgrade_fixed_kernel_ready(
        &mut self,
        archive: PathBuf,
        target: &OfficialProgram,
        context: &OperationContext,
    ) -> Result<KernelReadinessReport> {
        let installation_deadline = context.started
            + context
                .deadline
                .duration_since(context.started)
                .mul_f64(3.0 / 4.0);
        let original_identity = self.client().instance().device_id.clone();
        let installation = self
            .install_fixed_kernel(archive, target, context, installation_deadline)
            .await?;
        let mut report = KernelReadinessReport {
            outcome: KernelReadinessOutcome::InstallationUnconfirmed,
            installation,
            sdk_start_attempted: false,
            transition: None,
            readiness_error: None,
        };
        match report.installation.outcome {
            KernelInstallationOutcome::AlreadyInstalled => {
                report.outcome = KernelReadinessOutcome::InstalledReadinessUnconfirmed;
                let result = context
                    .wait(context.deadline, START, async {
                        let identity = self.observe_owned_control_identity().await?;
                        if identity.engine_version().version != target.version().as_str() {
                            return Err(Error::ManagedFailure {
                                reason: "running versions do not match the verified target program",
                            });
                        }
                        Ok(())
                    })
                    .await;
                match result {
                    Ok(()) => report.outcome = KernelReadinessOutcome::AlreadyReady,
                    Err(source) => report.readiness_error = Some(source),
                }
            }
            KernelInstallationOutcome::Installed => {
                report.outcome = KernelReadinessOutcome::InstalledReadinessUnconfirmed;
                let result = context.wait(context.deadline, START, async {
                    let expected = report.installation.installation.receipt.target_program_sha256()
                        .ok_or(Error::ManagedFailure {
                            reason: "the verified installation has no target executable digest",
                        })?;
                    let program = LocalProgram::new(self.selected_program().path())?
                        .expected_sha256(expected);
                    if Instant::now() >= context.deadline {
                        return Err(Error::Timeout { operation: START });
                    }
                    context.phase(OperationPhase::Starting);
                    report.sdk_start_attempted = true;
                    let transition = self.restart_with_program(
                        program,
                        context.deadline.saturating_duration_since(Instant::now()),
                    ).await?;
                    let current = self.client().instance();
                    if current.device_id != original_identity
                        || current.version.version != target.version().as_str()
                        || transition.current_program.sha256 != expected
                    {
                        return Err(Error::ManagedFailure {
                            reason: "the newly started owner did not authenticate as the requested device and program",
                        });
                    }
                    Ok(transition)
                }).await;
                match result {
                    Ok(transition) => {
                        report.transition = Some(transition);
                        report.outcome = KernelReadinessOutcome::Ready;
                    }
                    Err(source) => report.readiness_error = Some(source),
                }
            }
            _ => {}
        }
        Ok(report)
    }

    async fn install_fixed_kernel(
        &self,
        archive: PathBuf,
        target: &OfficialProgram,
        context: &OperationContext,
        deadline: Instant,
    ) -> Result<KernelInstallationReport> {
        let client = self.client();
        let generation = self.control_generation();
        let mut attempt = UpgradeAttempt::new(
            UpgradeAction::ManagementArchive,
            client.instance().device_id.clone(),
            deadline.duration_since(context.started),
        )?;
        attempt.set_owner_generation(self.generation);
        attempt.set_archive(target.archive_sha256());
        let mut admission_attempts = 0;
        let mut first_admission_failure = None;
        let mut already_installed = false;

        let prepared = context
            .wait(deadline, CHECK, async {
                context.phase(OperationPhase::Checking);
                let _lock = client.lock_for_kernel_upgrade().await;
                self.require_control_generation(&generation)?;
                let scope = self
                    .bind_upgrade_position(target, deadline.into_std(), true)
                    .await?;
                let current_target = scope.previous == scope.target;
                attempt.bind_observation(self.generation, scope);

                // Verify all local bytes before the last remote identity check.
                let file = if current_target {
                    None
                } else {
                    Some(Client::prepare_kernel_archive(archive, target).await?)
                };
                let now = Instant::now();
                let available = deadline.saturating_duration_since(now);
                let dispatch_deadline = now + available.mul_f64(2.0 / 3.0);
                let retry = context.read_retries_enabled(self.options.transient_read_retries);
                let read_deadline = if retry {
                    now + dispatch_deadline.duration_since(now).mul_f64(1.0 / 2.0)
                } else {
                    dispatch_deadline
                };
                let first = context
                    .wait(read_deadline, CHECK, async {
                        admission_attempts = 1;
                        self.observe_owned_control_identity().await
                    })
                    .await;
                if let Err(source) = first {
                    let delay = retry_delay(attempt.operation_id());
                    if !retry
                        || !retryable_read(&source)
                        || dispatch_deadline.saturating_duration_since(Instant::now()) <= delay
                    {
                        return Err(source);
                    }
                    first_admission_failure = Some(source);
                    context.phase(OperationPhase::WaitingToRetry);
                    context
                        .wait(dispatch_deadline, CHECK, async {
                            tokio::time::sleep(delay).await;
                            self.require_control_generation(&generation)?;
                            admission_attempts = 2;
                            context.phase(OperationPhase::Checking);
                            self.observe_owned_control_identity().await
                        })
                        .await?;
                }
                self.require_control_generation(&generation)?;
                let Some(file) = file else {
                    return Ok(UploadResult::AlreadyInstalled);
                };
                context
                    .wait(dispatch_deadline, UPLOAD, async {
                        client
                            .upload_prepared_kernel_archive(
                                file,
                                target,
                                Some(&attempt.progress),
                                Some(context),
                            )
                            .await?;
                        Ok(UploadResult::Acknowledged)
                    })
                    .await
            })
            .await;

        let result = prepared
            .map(|result| {
                already_installed = matches!(result, UploadResult::AlreadyInstalled);
            })
            .map_err(|source| {
                if matches!(attempt.dispatch(), UpgradeDispatch::Http { .. })
                    && matches!(
                        source,
                        Error::Timeout { .. } | Error::OperationWaitCancelled { .. }
                    )
                {
                    Error::MutationOutcomeUnknown {
                        operation: UPLOAD,
                        source: Box::new(source),
                    }
                } else {
                    source
                }
            });
        let installation = attempt.finish(result, |_| {
            if already_installed {
                UpgradeOutcome::NotSubmitted
            } else {
                UpgradeOutcome::Acknowledged
            }
        });
        let mut report = KernelInstallationReport {
            outcome: KernelInstallationOutcome::NotInstalled,
            installation,
            admission_attempts,
            first_admission_failure,
            original_exit: None,
            disk: None,
            verification_error: None,
        };
        if already_installed {
            report.outcome = KernelInstallationOutcome::AlreadyInstalled;
        } else if matches!(
            report.installation.receipt.outcome(),
            UpgradeOutcome::Acknowledged | UpgradeOutcome::Unknown
        ) {
            report.outcome = KernelInstallationOutcome::Unconfirmed;
            let verified = context
                .wait(deadline, VERIFY, async {
                    context.phase(OperationPhase::Verifying);
                    report.original_exit = Some(self.observe_exit().await?);
                    self.observe_bound_upgrade_program(
                        &report.installation.receipt,
                        deadline.saturating_duration_since(Instant::now()),
                        true,
                    )
                    .await
                })
                .await;
            match verified {
                Ok(final_disk) => {
                    report.outcome = match final_disk.comparison {
                        UpgradeProgramMatch::Target => KernelInstallationOutcome::Installed,
                        UpgradeProgramMatch::Previous => {
                            KernelInstallationOutcome::PreviousProgramRemains
                        }
                        _ => KernelInstallationOutcome::Unconfirmed,
                    };
                    report.disk = Some(final_disk);
                }
                Err(source) => report.verification_error = Some(source),
            }
        }
        Ok(report)
    }
}
