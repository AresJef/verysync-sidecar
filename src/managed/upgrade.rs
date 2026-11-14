//! Explicit stopped-state CLI upgrades with exact child containment.
use super::ManagedInstance;
use crate::{Error, ProcessDiagnostic, Result};
use std::{fmt, time::Duration};
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
        if !self.state_ready_for_backup
            || !self
                .exit_snapshot()
                .is_some_and(|e| e.tree_stopped && !e.forced && e.code == Some(0))
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
            .run_stopped_cli(
                super::command::CliPlan {
                    arguments,
                    positional: Vec::new(),
                    operation: "run kernel CLI upgrade",
                    may_modify: !matches!(command, KernelUpgradeCommand::Check),
                    clean_stop_required: true,
                },
                timeout,
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
