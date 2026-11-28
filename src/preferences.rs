//! Typed preference edits with original responses and independent readback.

use crate::{
    BandwidthPatch, ConfigurationSyncState, ConnectionSnapshot, CrashReportingPatch,
    DeviceDefaults, DevicePatch, DiagnosticsOptions, DiscoveryRecord, Error, FolderDefaults,
    FolderDefaultsPatch, GeneralOptions, GeneralOptionsPatch, GlobalBandwidthConfig,
    GuiPreferences, GuiPreferencesPatch, LdapConfiguration, LdapPatch, ListenerStatus,
    ManagementWriteEvidence, NetworkConfig, NetworkPatch, OperationCompletion, RelayServerConfig,
    RelayServerPatch, RelayServerStatus, ResponseDiagnostic, Result, SystemPreferences,
    SystemPreferencesPatch, TransportConfig, TransportPatch, TransportStatus,
};
use std::collections::BTreeMap;

/// One scope of explicitly selected native preference fields.
#[non_exhaustive]
pub enum PreferenceChange<'a> {
    /// General application settings.
    General(&'a GeneralOptionsPatch),
    /// System, event log, thumbnail or proxy settings.
    System(&'a SystemPreferencesPatch),
    /// Appearance and other GUI handler preferences.
    Gui(&'a GuiPreferencesPatch),
    /// Crash reporting preferences.
    CrashReporting(&'a CrashReportingPatch),
    /// Template for new folder registrations.
    FolderDefaults(&'a FolderDefaultsPatch),
    /// Template for new device registrations.
    DeviceDefaults(&'a DevicePatch),
    /// Directory-service configuration. Does not attempt a directory login.
    Ldap(&'a LdapPatch),
    /// Listener and discovery settings.
    Network(&'a NetworkPatch),
    /// Native TCP, QUIC, tracker and NAT policy.
    Transport(&'a TransportPatch),
    /// Global byte-rate controls.
    Bandwidth(&'a BandwidthPatch),
    /// Stored relay-server settings.
    RelayServer(&'a RelayServerPatch),
}

/// Typed settings of the requested scope from the original engine generation.
#[derive(Debug)]
#[non_exhaustive]
pub enum PreferenceReadback {
    /// Actual general settings.
    General(GeneralOptions),
    /// Actual system settings, including target-syntax paths.
    System(SystemPreferences),
    /// Actual GUI handler preferences.
    Gui(GuiPreferences),
    /// Actual diagnostic settings and engine capability indications.
    CrashReporting(DiagnosticsOptions),
    /// Actual future-folder template.
    FolderDefaults(FolderDefaults),
    /// Actual future-device template.
    DeviceDefaults(DeviceDefaults),
    /// Actual stored directory-service configuration.
    Ldap(LdapConfiguration),
    /// Actual listener and discovery settings.
    Network(NetworkConfig),
    /// Actual transport policy.
    Transport(TransportConfig),
    /// Actual global transfer limits.
    Bandwidth(GlobalBandwidthConfig),
    /// Actual stored relay-server settings.
    RelayServer(RelayServerConfig),
}

/// Native live observations collected separately from the stored settings.
#[derive(Debug)]
#[non_exhaustive]
pub enum PreferenceRuntime {
    /// Current native listeners and discovery cache, without sending a probe.
    Network {
        /// Actual known native listener state.
        listeners: Result<BTreeMap<String, ListenerStatus>>,
        /// Actual cache entries. Empty is distinct from an error.
        discovery: Result<BTreeMap<String, DiscoveryRecord>>,
    },
    /// Current native transport status and peer connections.
    Transport {
        /// Tracker and NAT status from the engine.
        status: Result<TransportStatus>,
        /// Current peer connection observations.
        connections: Result<ConnectionSnapshot>,
    },
    /// Current relay server runtime state.
    RelayServer(RelayServerStatus),
}

/// Native preference change, later readback and available live facts.
#[derive(Debug)]
#[non_exhaustive]
pub struct PreferenceReport {
    /// Dispatch and response evidence for the optional native PATCH.
    pub write: ManagementWriteEvidence,
    /// Original result. A success containing no reply means zero writes.
    pub original: Result<Option<ResponseDiagnostic>>,
    /// Number of explicitly requested fields in the patch.
    pub selected_fields: usize,
    /// Count of requested fields that match the later verified read.
    pub matching_fields: Option<usize>,
    /// Typed current settings.
    pub current: Option<PreferenceReadback>,
    /// Why the selected settings could not be verified afterward.
    pub observation_error: Option<Error>,
    /// Native application flag, when it was read.
    pub application: Option<Result<ConfigurationSyncState>>,
    /// Separately sampled runtime for network, transport or relay changes.
    pub runtime: Option<Result<PreferenceRuntime>>,
}

impl PreferenceReport {
    /// Classify the selected configuration fields. Runtime facts are separate.
    pub fn completion(&self) -> OperationCompletion {
        match self.matching_fields {
            Some(matched) if matched == self.selected_fields => OperationCompletion::Completed,
            Some(0) => OperationCompletion::GoalNotMet,
            Some(_) => OperationCompletion::PartiallyCompleted,
            None if !self.write.dispatched
                || (self.write.response_complete
                    && matches!(
                        self.original,
                        Err(Error::Authentication { .. } | Error::AccessDenied { .. })
                    )) =>
            {
                OperationCompletion::GoalNotMet
            }
            None => OperationCompletion::Unconfirmed,
        }
    }
}
