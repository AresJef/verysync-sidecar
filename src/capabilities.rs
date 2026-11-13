//! Library implementation, recorded validation and unprobed instance conditions.

use crate::{EndpointKind, InstanceInfo, BASELINE_ENGINE_VERSION};
use std::fmt;

/// A library capability family. Raw transport does not implement other families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    /// Authenticated connection and identity/version policy.
    Connection,
    /// Fresh version queries.
    Version,
    /// Fresh system status.
    SystemStatus,
    /// Folder activity/counter snapshots.
    FolderStatus,
    /// Folder configuration queries.
    FolderConfiguration,
    /// Guarded folder registration.
    FolderCreation,
    /// Partial label and folder-pause settings.
    FolderLabelPause,
    /// Unregistering while retaining files.
    FolderUnregisterKeepFiles,
    /// Management failure, deadline and cancellation semantics.
    ManagementErrors,
    /// Explicit constrained raw requests.
    RawManagement,
    /// Owned startup, shutdown and restart; full lifecycle validation is pending.
    ManagedRuntime,
    /// Resumable engine events.
    Events,
    /// Observable long-running work.
    ObservableTasks,
    /// Peer sharing and P2P controls.
    PeerSharing,
    /// Remote device configuration, distinct from live connection or transfer state.
    DeviceConfiguration,
    /// Pending folder offers, per-peer ignores and explicit local folder associations.
    FolderInvitations,
    /// Pending-device records; nonempty native validation remains pending.
    PendingDeviceRecords,
    /// Persistent ignored identities; live rejection remains a separate observation.
    DeviceIgnores,
    /// Network settings and actual TCP, listener and discovery-cache snapshots.
    /// Local discovery, announcements and other transports have separate gates.
    NetworkControl,
    /// Explicit transport settings and actual tracker/NAT snapshots; positive
    /// registration, mapping and WAN traversal have separate evidence gates.
    TransportControl,
    /// Official relay server settings, runtime and explicit network probes.
    RelayServer,
    /// Fresh completion, need/change pages, statistics and actual file errors.
    SyncObservation,
    /// Relative subpath/all-folder scan requests and partial scan scheduling.
    ScanControl,
    /// Explicit fixed-program acquisition and upgrades.
    EngineDownloadUpgrade,
    /// File management and history.
    FileHistory,
    /// Remaining advanced folder settings.
    AdvancedFolderSettings,
    /// Account, configuration and commercial authorization.
    AccountLicense,
    /// Storage protocol integrations.
    StorageProtocols,
    /// LocalSync controls.
    LocalSync,
    /// Enterprise and official remote management.
    EnterpriseRemoteManagement,
    /// Other explicit system and resource operations.
    AuxiliaryControls,
}

/// What this library currently provides for a family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImplementationStatus {
    /// Typed callable interfaces exist for the stated narrow family.
    Typed,
    /// Transport passthrough exists, with caller-interpreted protocol results.
    RawTransport,
    /// Product interfaces for this family have not been implemented.
    NotImplemented,
}

/// Recorded library validation, independent of a current instance's permissions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationStatus {
    /// Real public API effects passed in the stated native scope.
    NativeEvidence {
        /// The exact engine baseline.
        engine_version: &'static str,
        /// The source-linked native workflow run.
        evidence_url: &'static str,
        /// The actual platform/transport scope of that evidence.
        scope: &'static str,
    },
    /// Source exists while required final-source evidence remains pending.
    Pending,
    /// No product acceptance has run for this unimplemented family.
    NotRun,
}

/// One immutable entry in the library's narrow implementation catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LibraryCapability {
    /// The family being described.
    pub capability: Capability,
    /// Code availability, separate from verification or runtime permission.
    pub implementation: ImplementationStatus,
    /// Recorded acceptance and its explicit limits.
    pub verification: VerificationStatus,
}

const NATIVE_SCOPE: &str = "Default TLS-feature build; matched controller/engine macOS, Windows or Linux on amd64/arm64; Unix sockets on macOS/Linux and loopback HTTP on Windows; selected modern hosted runners, not minimum-OS or cross-network acceptance";
const CORE_EVIDENCE: &str = "https://github.com/AresJef/verysync-sidecar/actions/runs/43212477622";
const fn typed(capability: Capability) -> LibraryCapability {
    LibraryCapability {
        capability,
        implementation: ImplementationStatus::Typed,
        verification: VerificationStatus::NativeEvidence {
            engine_version: BASELINE_ENGINE_VERSION,
            evidence_url: CORE_EVIDENCE,
            scope: NATIVE_SCOPE,
        },
    }
}
const fn planned(capability: Capability) -> LibraryCapability {
    LibraryCapability {
        capability,
        implementation: ImplementationStatus::NotImplemented,
        verification: VerificationStatus::NotRun,
    }
}
static CATALOG: &[LibraryCapability] = &[
    typed(Capability::Connection),
    typed(Capability::Version),
    typed(Capability::SystemStatus),
    typed(Capability::FolderStatus),
    typed(Capability::FolderConfiguration),
    typed(Capability::FolderCreation),
    typed(Capability::FolderLabelPause),
    typed(Capability::FolderUnregisterKeepFiles),
    typed(Capability::ManagementErrors),
    LibraryCapability {
        capability: Capability::RawManagement,
        implementation: ImplementationStatus::RawTransport,
        verification: VerificationStatus::NativeEvidence {
            engine_version: BASELINE_ENGINE_VERSION,
            evidence_url: CORE_EVIDENCE,
            scope: NATIVE_SCOPE,
        },
    },
    LibraryCapability {
        capability: Capability::ManagedRuntime,
        implementation: ImplementationStatus::Typed,
        verification: VerificationStatus::Pending,
    },
    LibraryCapability {
        capability: Capability::Events,
        implementation: ImplementationStatus::Typed,
        verification: VerificationStatus::Pending,
    },
    LibraryCapability {
        capability: Capability::ObservableTasks,
        implementation: ImplementationStatus::Typed,
        verification: VerificationStatus::Pending,
    },
    LibraryCapability {
        capability: Capability::PeerSharing,
        implementation: ImplementationStatus::Typed,
        verification: VerificationStatus::Pending,
    },
    LibraryCapability {
        capability: Capability::DeviceConfiguration,
        implementation: ImplementationStatus::Typed,
        verification: VerificationStatus::Pending,
    },
    LibraryCapability {
        capability: Capability::FolderInvitations,
        implementation: ImplementationStatus::Typed,
        verification: VerificationStatus::Pending,
    },
    LibraryCapability {
        capability: Capability::PendingDeviceRecords,
        implementation: ImplementationStatus::Typed,
        verification: VerificationStatus::Pending,
    },
    LibraryCapability {
        capability: Capability::DeviceIgnores,
        implementation: ImplementationStatus::Typed,
        verification: VerificationStatus::Pending,
    },
    planned(Capability::EngineDownloadUpgrade),
    LibraryCapability {
        capability: Capability::NetworkControl,
        implementation: ImplementationStatus::Typed,
        verification: VerificationStatus::Pending,
    },
    planned(Capability::FileHistory),
    LibraryCapability {
        capability: Capability::TransportControl,
        implementation: ImplementationStatus::Typed,
        verification: VerificationStatus::Pending,
    },
    LibraryCapability {
        capability: Capability::RelayServer,
        implementation: ImplementationStatus::Typed,
        verification: VerificationStatus::Pending,
    },
    planned(Capability::AdvancedFolderSettings),
    LibraryCapability {
        capability: Capability::SyncObservation,
        implementation: ImplementationStatus::Typed,
        verification: VerificationStatus::Pending,
    },
    planned(Capability::AccountLicense),
    LibraryCapability {
        capability: Capability::ScanControl,
        implementation: ImplementationStatus::Typed,
        verification: VerificationStatus::Pending,
    },
    planned(Capability::StorageProtocols),
    planned(Capability::LocalSync),
    planned(Capability::EnterpriseRemoteManagement),
    planned(Capability::AuxiliaryControls),
];

/// Inspect library code/evidence without I/O or a running engine.
pub fn library_capabilities() -> &'static [LibraryCapability] {
    CATALOG
}

/// Whether a handshake snapshot falls inside the recorded native test scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetValidation {
    /// Version, OS/architecture and transport coordinates match recorded scope.
    ///
    /// This does not verify the current OS version, translation environment or
    /// network. Those remain limited to the evidence's stated runner scope.
    MatchesRecordedCoordinates,
    /// This combination is unverified; this does not mean it is unsupported.
    OutsideNativeEvidence,
}

/// An instance condition, distinct from code availability and test history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstanceObservation {
    /// This specific condition was observed during connection, not probed again.
    ObservedAtHandshake,
    /// No applicable observation is available; no availability is inferred.
    Unknown,
    /// Explicit negative evidence establishes that a condition is unavailable.
    KnownUnavailable,
}

/// Conditions observed or left unknown for this connection's instance snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstanceConditions {
    /// Management authentication was observed at connection time.
    pub authentication: InstanceObservation,
    /// Per-operation permissions have not been probed by this report.
    pub operation_authorization: InstanceObservation,
    /// Commercial license status has not been inferred from status or HTTP 403.
    pub commercial_license: InstanceObservation,
}

/// Target/controller values used to compare the handshake to recorded scope.
#[derive(Clone)]
pub struct TargetSnapshot {
    /// Actual upstream version captured during connection.
    pub engine_version: String,
    /// Actual upstream OS captured during connection.
    pub engine_os: String,
    /// Actual upstream architecture captured during connection.
    pub engine_arch: String,
    /// The controller binary's OS.
    pub controller_os: &'static str,
    /// The controller binary's architecture.
    pub controller_arch: &'static str,
    /// Selected connection transport class, without an address or credential.
    pub transport: EndpointKind,
    /// Whether this connection's HTTP scheme uses TLS.
    pub https: bool,
    /// Whether this build enables the TLS feature used in native acceptance.
    pub tls_feature: bool,
}
impl fmt::Debug for TargetSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TargetSnapshot")
            .field("controller_os", &self.controller_os)
            .field("controller_arch", &self.controller_arch)
            .field("transport", &self.transport)
            .field("https", &self.https)
            .field("tls_feature", &self.tls_feature)
            .finish_non_exhaustive()
    }
}

/// Snapshot report; obtaining it sends no request or commercial-feature probe.
#[derive(Clone, Debug)]
pub struct CapabilityReport {
    /// This crate's version, independent of the engine version.
    pub library_version: &'static str,
    /// Exact narrow implementation and recorded validation entries.
    pub library: &'static [LibraryCapability],
    /// The connection-time target/controller snapshot.
    pub target: TargetSnapshot,
    /// Whether that snapshot is in the stated native test scope.
    pub target_validation: TargetValidation,
    /// Instance authentication and explicitly unknown optional conditions.
    pub instance: InstanceConditions,
}
impl CapabilityReport {
    pub(crate) fn build(instance: &InstanceInfo, transport: EndpointKind, https: bool) -> Self {
        let target = TargetSnapshot {
            engine_version: instance.version.version.clone(),
            engine_os: instance.version.os.clone(),
            engine_arch: instance.version.arch.clone(),
            controller_os: std::env::consts::OS,
            controller_arch: std::env::consts::ARCH,
            transport,
            https,
            tls_feature: cfg!(feature = "tls"),
        };
        let target_validation = classify_target(&target);
        Self {
            library_version: env!("CARGO_PKG_VERSION"),
            library: CATALOG,
            target,
            target_validation,
            instance: InstanceConditions {
                authentication: InstanceObservation::ObservedAtHandshake,
                operation_authorization: InstanceObservation::Unknown,
                commercial_license: InstanceObservation::Unknown,
            },
        }
    }
}
fn classify_target(target: &TargetSnapshot) -> TargetValidation {
    let os = match target.controller_os {
        "macos" => "darwin",
        other => other,
    };
    let arch = match target.controller_arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    let transport = match os {
        "darwin" | "linux" => target.transport == EndpointKind::UnixSocket,
        "windows" => target.transport == EndpointKind::LoopbackTcp && !target.https,
        _ => false,
    };
    if target.tls_feature
        && target.engine_version == BASELINE_ENGINE_VERSION
        && target.engine_os == os
        && target.engine_arch == arch
        && matches!(arch, "amd64" | "arm64")
        && transport
    {
        TargetValidation::MatchesRecordedCoordinates
    } else {
        TargetValidation::OutsideNativeEvidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validation_scope_does_not_promote_unverified_transports_versions_or_remote_pairs() {
        let mut target = TargetSnapshot {
            engine_version: BASELINE_ENGINE_VERSION.to_owned(),
            engine_os: "linux".to_owned(),
            engine_arch: "arm64".to_owned(),
            controller_os: "linux",
            controller_arch: "aarch64",
            transport: EndpointKind::UnixSocket,
            https: false,
            tls_feature: true,
        };
        assert_eq!(
            classify_target(&target),
            TargetValidation::MatchesRecordedCoordinates
        );
        target.tls_feature = false;
        assert_eq!(
            classify_target(&target),
            TargetValidation::OutsideNativeEvidence
        );
        target.tls_feature = true;
        target.transport = EndpointKind::RemoteHttp;
        assert_eq!(
            classify_target(&target),
            TargetValidation::OutsideNativeEvidence
        );
        target.transport = EndpointKind::UnixSocket;
        target.engine_version = "v9.0.0".to_owned();
        assert_eq!(
            classify_target(&target),
            TargetValidation::OutsideNativeEvidence
        );
        target.engine_version = BASELINE_ENGINE_VERSION.to_owned();
        target.controller_os = "macos";
        assert_eq!(
            classify_target(&target),
            TargetValidation::OutsideNativeEvidence
        );
    }
}
