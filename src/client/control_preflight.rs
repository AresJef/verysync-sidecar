//! Selected control-operation preflights consist only of documented reads.
use super::{Client, EngineVersion};
use crate::{
    BuildVariant, Capability, Error, OfficialProgram, OperationPreflightReport,
    PreflightObservation, PreflightReads, ProgramTarget, Result, UpgradePreflightSource,
    UpgradeSourceEvidence, BASELINE_ENGINE_VERSION,
};

impl Client {
    /// Inspect listener-change prerequisites without preparing or sending a PATCH.
    ///
    /// With selected reads, the existing connection checks version and device,
    /// reads the current listener configuration, then checks version and device
    /// again. A successful read establishes current read access. The permission
    /// to change the listener, TLS configuration and ability to bind a new
    /// address remain untested.
    pub async fn preflight_gui_listener(&self, reads: PreflightReads) -> OperationPreflightReport {
        let mut report = self.preflight_report(Capability::GuiListener);
        if reads == PreflightReads::SelectedOperation {
            report.observation = Some(match self.preflight_identity().await {
                Ok(()) => {
                    let read = self.gui_listener().await.map(|_| ());
                    match self.preflight_identity().await {
                        Ok(()) => PreflightObservation::from_read(read, true, false),
                        Err(error) => PreflightObservation::from_read(Err(error), false, false),
                    }
                }
                Err(error) => PreflightObservation::from_read(Err(error), false, false),
            });
        }
        report
    }

    /// Inspect exactly one upgrade path without triggering an upgrade.
    ///
    /// For a fixed catalog or URL path, selected reads confirm the management
    /// identity and version. The local filesystem and URL are never opened.
    /// For the server provider, selected reads also perform one native provider
    /// check, which may contact the engine's configured release feed.
    /// Installation permission, the requested archive's contents, and whether
    /// an upgrade succeeds remain separate checks.
    pub async fn preflight_upgrade(
        &self,
        source: UpgradePreflightSource<'_>,
        reads: PreflightReads,
    ) -> Result<OperationPreflightReport> {
        let mut report = self.preflight_report(Capability::EngineDownloadUpgrade);
        let version = &self.instance().version;
        let mut source_evidence = match source {
            UpgradePreflightSource::ServerProvider => UpgradeSourceEvidence::ServerProvider {
                recorded_windows_arm64_gap: version.version == BASELINE_ENGINE_VERSION
                    && version.os == "windows"
                    && version.arch == "arm64",
                observed_release: None,
            },
            UpgradePreflightSource::FixedArchive {
                version: pinned,
                target,
            } => match OfficialProgram::select(pinned, target) {
                Ok(program) => UpgradeSourceEvidence::FixedArchiveListed {
                    program: Box::new(program),
                    matches_target_os_arch: matches_target_os_arch(version, target),
                },
                Err(Error::UnlistedProgramVersion) => UpgradeSourceEvidence::FixedArchiveUnlisted {
                    version_listed: false,
                },
                Err(Error::UnsupportedProgramTarget { .. }) => {
                    UpgradeSourceEvidence::FixedArchiveUnlisted {
                        version_listed: true,
                    }
                }
                Err(error) => return Err(error),
            },
            UpgradePreflightSource::ExplicitUrl => UpgradeSourceEvidence::ExplicitUrlUninspected,
        };
        if reads == PreflightReads::SelectedOperation {
            report.observation = Some(match self.preflight_identity().await {
                Ok(()) => {
                    if let UpgradeSourceEvidence::ServerProvider {
                        observed_release, ..
                    } = &mut source_evidence
                    {
                        let read = self.check_kernel_upgrade().await;
                        match self.preflight_identity().await {
                            Ok(()) => {
                                let read = read.map(|metadata| *observed_release = Some(metadata));
                                PreflightObservation::from_read(read, true, false)
                            }
                            Err(error) => PreflightObservation::from_read(Err(error), false, false),
                        }
                    } else {
                        PreflightObservation::from_read(Ok(()), true, false)
                    }
                }
                Err(error) => PreflightObservation::from_read(Err(error), false, false),
            });
        }
        report.upgrade_source = Some(source_evidence);
        Ok(report)
    }

    fn preflight_report(&self, capability: Capability) -> OperationPreflightReport {
        OperationPreflightReport::new(
            capability,
            self.instance(),
            self.connection.endpoint_kind,
            self.connection.base.scheme() == "https",
        )
    }

    async fn preflight_identity(&self) -> Result<()> {
        let observed = self.observe_control_identity().await?;
        compare_preflight_platform(observed.engine_version(), &self.instance().version)
    }
}

pub(super) fn compare_preflight_platform(
    actual: &EngineVersion,
    expected: &EngineVersion,
) -> Result<()> {
    if actual.os != expected.os || actual.arch != expected.arch {
        return Err(Error::InvalidConfiguration {
            reason: "the engine OS or architecture changed since connection",
        });
    }
    Ok(())
}

fn matches_target_os_arch(version: &EngineVersion, target: ProgramTarget) -> bool {
    let os = match version.os.as_str() {
        "darwin" => "macos",
        other => other,
    };
    let variant = match target.variant() {
        BuildVariant::Standard => "standard",
        BuildVariant::Legacy => "legacy",
    };
    target.id() == format!("{os}-{}-{variant}", version.arch)
}
