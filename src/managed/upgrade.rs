//! Explicit stopped-state CLI upgrades with exact child containment.
use super::ManagedInstance;
use crate::{
    upgrade_receipt::UpgradeAttempt, Error, OfficialProgram, ProcessDiagnostic, Result,
    UpgradeAction, UpgradeOperationResult, UpgradeOutcome,
};
use std::{fmt, path::PathBuf, time::Duration};
use url::Url;

/// Explicit native CLI operation. Provider/from-URL modes can overwrite the
/// selected executable; they do not use the SDK's checksum-pinned downloader.
#[derive(Clone)]
pub enum KernelUpgradeCommand {
    /// Run only the kernel provider availability check.
    Check,
    /// Perform the upgrade selected by the kernel's current provider.
    Provider,
    /// Force the explicitly supplied HTTP(S) archive URL. The kernel handles
    /// transport/extraction; this is not an SDK SHA-256 validation guarantee.
    FromUrl(Url),
}
impl fmt::Debug for KernelUpgradeCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Check => "Check",
            Self::Provider => "Provider",
            Self::FromUrl(_) => "FromUrl([REDACTED])",
        })
    }
}
/// Actual contained CLI exit and bounded private output. Exit zero alone does
/// not establish replacement, database compatibility or future readiness.
#[derive(Debug)]
pub struct KernelUpgradeExit {
    /// Actual native exit code; provider check may use a nonzero available code.
    pub code: Option<i32>,
    /// Exact helper containment has ended, including descendant cleanup.
    pub tree_stopped: bool,
    /// True only for native exit 1 containing the fixed kernel's exact known
    /// no-matching-release diagnostic. Other failures remain unclassified.
    pub release_unavailable: bool,
    /// Output can contain private data; explicitly inspect only when needed.
    pub diagnostic: ProcessDiagnostic,
}
impl ManagedInstance {
    /// Run one CLI upgrade/check against this already normally stopped owner.
    /// The SDK state lease remains held through contained CLI exit. The upstream
    /// lock is checked, then released before spawn so the CLI can own it itself.
    /// No implicit stop/start, retry, fallback or rollback occurs. Select a
    /// dedicated writable program copy for modifying commands, never a shared
    /// cache generation. Supply the new hash explicitly before restarting.
    ///
    /// Cancellation/deadline requests exact helper cleanup; the private worker
    /// retains locks until cleanup ends. A mutation may already have occurred.
    /// This invalidates the old clean-generation backup claim even for checks;
    /// successfully start and normally stop again before taking a new snapshot.
    pub async fn run_cli_upgrade(
        &mut self,
        command: KernelUpgradeCommand,
        timeout: Duration,
    ) -> Result<KernelUpgradeExit> {
        self.run_cli_upgrade_inner(command, timeout, None).await
    }

    /// Run one stopped-state CLI operation and return evidence of actual spawn,
    /// exit and cleanup observations together with the original result.
    /// A CLI acknowledgement alone does not establish program replacement.
    pub async fn run_cli_upgrade_with_receipt(
        &mut self,
        command: KernelUpgradeCommand,
        timeout: Duration,
    ) -> Result<UpgradeOperationResult<KernelUpgradeExit>> {
        self.run_cli_upgrade_receipt_inner(command, timeout, None)
            .await
    }

    /// Record a stopped CLI attempt and bind a trusted target executable
    /// before it can modify the caller's dedicated program copy.
    ///
    /// Use the same stopped owner and its receipt with
    /// [ManagedInstance::observe_upgrade_program] after an uncertain result.
    /// The target identifies a program for later comparison. It does not
    /// control which archive the explicit CLI command obtains.
    pub async fn run_cli_upgrade_with_target_receipt(
        &mut self,
        command: KernelUpgradeCommand,
        target: &OfficialProgram,
        timeout: Duration,
    ) -> Result<UpgradeOperationResult<KernelUpgradeExit>> {
        self.run_cli_upgrade_receipt_inner(command, timeout, Some(target))
            .await
    }

    /// Upload the selected fixed archive to this running owner and bind its
    /// trusted executable digest to the same attempt. Use a dedicated, writable
    /// local executable that no other application manages.
    ///
    /// After an uncertain result, use [ManagedInstance::observe_upgrade_program]
    /// when the original tree and its state lease have finished naturally.
    pub async fn upload_kernel_upgrade_with_target_receipt(
        &self,
        archive: impl Into<PathBuf>,
        target: &OfficialProgram,
        timeout: Duration,
    ) -> Result<UpgradeOperationResult<()>> {
        let generation = self.control_generation();
        let mut attempt = UpgradeAttempt::new(
            UpgradeAction::ManagementArchive,
            self.client().instance().device_id.clone(),
            timeout,
        )?;
        attempt.set_owner_generation(self.generation);
        attempt.set_archive(target.archive_sha256());
        let binding = async {
            self.require_control_generation(&generation)?;
            let scope = self
                .bind_upgrade_observation(target, attempt.deadline)
                .await?;
            self.require_control_generation(&generation)?;
            Ok(scope)
        }
        .await;
        match binding {
            Ok(scope) => attempt.bind_observation(self.generation, scope),
            Err(source) => return Ok(attempt.finish(Err(source), |_| UpgradeOutcome::Acknowledged)),
        }
        Ok(self
            .client()
            .upload_kernel_upgrade_attempt(archive.into(), target, attempt)
            .await)
    }

    async fn run_cli_upgrade_receipt_inner(
        &mut self,
        command: KernelUpgradeCommand,
        timeout: Duration,
        target: Option<&OfficialProgram>,
    ) -> Result<UpgradeOperationResult<KernelUpgradeExit>> {
        let action = match &command {
            KernelUpgradeCommand::Check => UpgradeAction::CliCheck,
            KernelUpgradeCommand::Provider => UpgradeAction::CliProvider,
            KernelUpgradeCommand::FromUrl(_) => UpgradeAction::CliFromUrl,
        };
        let mut attempt =
            UpgradeAttempt::new(action, self.client().instance().device_id.clone(), timeout)?;
        attempt.set_owner_generation(self.generation);
        if let Some(target) = target {
            if action.is_query() {
                return Ok(attempt.finish(
                    Err(Error::InvalidConfiguration {
                        reason: "target receipts are for explicit modifying CLI commands",
                    }),
                    |_| UpgradeOutcome::Queried,
                ));
            }
            attempt.set_archive(target.archive_sha256());
            match self
                .bind_upgrade_observation(target, attempt.deadline)
                .await
            {
                Ok(scope) => attempt.bind_observation(self.generation, scope),
                Err(source) => {
                    return Ok(attempt.finish(Err(source), |_| UpgradeOutcome::Acknowledged))
                }
            }
        }
        let result = self
            .run_cli_upgrade_inner(command, timeout, Some(&attempt))
            .await;
        Ok(attempt.finish(result, |exit| {
            if exit.release_unavailable {
                UpgradeOutcome::ReleaseUnavailable
            } else if action.is_query() {
                if exit.code == Some(0) {
                    UpgradeOutcome::Queried
                } else {
                    UpgradeOutcome::QueryFailed
                }
            } else if exit.code == Some(0) {
                UpgradeOutcome::Acknowledged
            } else {
                UpgradeOutcome::Unknown
            }
        }))
    }

    async fn run_cli_upgrade_inner(
        &mut self,
        command: KernelUpgradeCommand,
        timeout: Duration,
        attempt: Option<&UpgradeAttempt>,
    ) -> Result<KernelUpgradeExit> {
        if !self.state_ready_for_backup
            || !self.exit_snapshot().is_some_and(|e| {
                e.tree_stopped && e.state_released && !e.forced && e.code == Some(0)
            })
        {
            return Err(Error::ManagedFailure {
                reason: "CLI upgrade requires a known normally stopped owner",
            });
        }
        if let KernelUpgradeCommand::FromUrl(url) = &command {
            if !matches!(url.scheme(), "https" | "http")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(Error::InvalidConfiguration { reason: "CLI upgrade requires an explicit HTTP(S) archive URL without credentials or fragment" });
            }
        }
        let mut arguments = vec!["upgrade".to_owned()];
        match &command {
            KernelUpgradeCommand::Check => arguments.push("--check-only".to_owned()),
            KernelUpgradeCommand::Provider => {}
            KernelUpgradeCommand::FromUrl(url) => {
                arguments.extend(["--from".to_owned(), url.as_str().to_owned()])
            }
        }
        let exit = self
            .run_stopped_cli_observed(
                super::command::CliPlan {
                    arguments,
                    positional: Vec::new(),
                    operation: "run kernel CLI upgrade",
                    may_modify: !matches!(command, KernelUpgradeCommand::Check),
                    clean_stop_required: true,
                },
                timeout,
                attempt,
            )
            .await?;
        Ok(KernelUpgradeExit {
            code: exit.code,
            tree_stopped: exit.tree_stopped,
            release_unavailable: !matches!(command, KernelUpgradeCommand::FromUrl(_))
                && exit.code == Some(1)
                && exit
                    .diagnostic
                    .body_bytes()
                    .windows(crate::upgrades::NO_MATCHING_RELEASE.len())
                    .any(|w| w == crate::upgrades::NO_MATCHING_RELEASE),
            diagnostic: exit.diagnostic,
        })
    }
}
