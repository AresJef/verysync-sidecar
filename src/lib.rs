//! Asynchronous management of the official VerySync program.
//!
//! This crate is under development. It provides explicit endpoint/path values
//! authenticated management connections with version and identity checks, and
//! fresh typed system/folder status reads, and folder registration/configuration.
//! Adding this dependency or compiling it does not download or
//! start VerySync, install services, or configure global logging or signals.
//!
//! All public interfaces are unstable during alpha.
//!
//! ```
//! use verysync_sidecar::{EndpointKind, ManagementEndpoint, PathStyle, TargetPath};
//!
//! let endpoint = ManagementEndpoint::http("https://synthetic.invalid/control")?;
//! assert_eq!(endpoint.kind(), EndpointKind::RemoteHttp);
//! let path = TargetPath::remote(PathStyle::Windows, r"C:\Synthetic Data")?;
//! assert_eq!(path.to_protocol()?, r"C:\Synthetic Data");
//! # Ok::<(), verysync_sidecar::Error>(())
//! ```

#![doc = include_str!("../docs/public/getting-started.md")]
#![doc = include_str!("../docs/public/managed-instances.md")]
#![doc = include_str!("../docs/public/events.md")]
#![doc = include_str!("../docs/public/long-running-operations.md")]
#![doc = include_str!("../docs/public/sharing.md")]
#![doc = include_str!("../docs/public/devices.md")]
#![doc = include_str!("../docs/public/invitations.md")]
#![doc = include_str!("../docs/public/network.md")]
#![doc = include_str!("../docs/public/transports.md")]
#![doc = include_str!("../docs/public/relay.md")]
#![doc = include_str!("../docs/public/sync-observation.md")]
#![doc = include_str!("../docs/public/scan-control.md")]
#![doc = include_str!("../docs/public/ignore-patterns.md")]
#![doc = include_str!("../docs/public/scheduling.md")]
#![doc = include_str!("../docs/public/selective-sync.md")]
#![doc = include_str!("../docs/public/recovery.md")]
#![doc = include_str!("../docs/public/three-node-relay.md")]
#![doc = include_str!("../docs/public/program-sources.md")]
#![doc = include_str!("../docs/public/program-preparation.md")]
#![doc = include_str!("../docs/public/program-cache.md")]
#![doc = include_str!("../docs/public/program-upgrades.md")]
#![doc = include_str!("../docs/public/file-resources.md")]
#![doc = include_str!("../docs/public/file-transfers.md")]
#![doc = include_str!("../docs/public/file-history.md")]
#![doc = include_str!("../docs/public/configuration.md")]
#![doc = include_str!("../docs/public/management-authentication.md")]
#![doc = include_str!("../docs/public/official-accounts.md")]
#![doc = include_str!("../docs/public/licenses.md")]
#![doc = include_str!("../docs/public/remote-management.md")]
#![doc = include_str!("../docs/public/management-transport.md")]
#![doc = include_str!("../docs/public/gui-listener.md")]

mod auth;
mod capabilities;
mod client;
mod configuration;
mod device_options;
mod devices;
mod diagnostics_preferences;
mod endpoint;
mod engine_source;
mod error;
mod events;
mod file_history;
mod file_mutations;
mod file_transfers;
mod files;
mod folder_options;
mod folder_policies;
mod folders;
mod gui_listener;
mod gui_preferences;
mod gui_session;
mod ignores;
mod invitations;
mod ldap;
mod licenses;
mod local_sync;
mod local_sync_events;
mod maintenance;
mod managed;
mod management_auth;
mod management_transport;
mod network;
mod official_account;
mod operations;
mod path;
mod raw;
mod recovery;
mod relay;
mod releases;
mod remote_management;
mod scans;
mod scheduling;
mod selective;
mod sharing;
mod status;
mod sync_observation;
mod system_preferences;
mod transports;
mod upgrades;

pub use auth::{ApiKey, DeviceId};
pub use capabilities::{
    library_capabilities, Capability, CapabilityReport, ImplementationStatus, InstanceConditions,
    InstanceObservation, LibraryCapability, TargetSnapshot, TargetValidation, VerificationStatus,
};
pub use client::{
    Client, ConnectOptions, EngineVersion, InstanceInfo, VersionCompatibility, VersionPolicy,
};
pub use configuration::{
    ConfigurationSectionUpdate, ConfigurationSnapshot, ConfigurationSyncState, ConfigurationUpdate,
    DiskFreeRequirement, DiskSpaceUnit, FolderDefaults, FolderDefaultsPatch, GeneralOptions,
    GeneralOptionsPatch,
};
pub use device_options::{DeviceAdvancedConfig, DeviceAdvancedPatch, IntroductionSource};
pub use devices::{
    CreateDeviceOptions, DeviceCompression, DeviceConfig, DeviceDefaults, DevicePatch,
    DeviceRemoval, DeviceUpdate,
};
pub use diagnostics_preferences::{CrashReportingPatch, DiagnosticsOptions};
pub use endpoint::{EndpointKind, ManagementEndpoint};
pub use engine_source::{EngineSource, LocalProgram, ProgramInfo};
pub use error::{Error, ManagedStateLock, ProcessDiagnostic, ResponseDiagnostic, Result};
pub use events::{
    EngineEvent, EventCursor, EventGap, EventGapReason, EventKind, EventOptions, EventStreamItem,
    EventSubscription,
};
pub use file_history::{
    ArchivedFileVersion, AuditHistoryPage, AuditHistorySettings, AuditHistoryUpdate,
    DirectoryVersionOrder, ExternalVersioningCommand, FileVersionRestore, FileVersionRestoreReport,
    FolderVersionHistory, FolderVersioningConfiguration, FolderVersioningPolicy,
    FolderVersioningUpdate, VersionArchiveLocation, VersionedDirectory,
};
pub use file_mutations::{
    ResourceConflictPolicy, ResourceDeleteScope, ResourceMutation, ResourceRemoval,
};
pub use file_transfers::{
    ResourceArchiveFormat, ResourceByteRange, ResourceDownload, ResourceTransferOptions,
    ResourceUpload, ResourceUploadConflict,
};
pub use files::{
    ResourceChecksum, ResourceInfo, ResourcePath, ResourcePreview, ResourceVolume, ResourceVolumeId,
};
pub use folder_options::{FolderAdvancedConfig, FolderAdvancedPatch};
pub use folder_policies::{
    BlockPullOrder, CopyRangeMethod, ExtendedAttributeFilter, ExtendedAttributeRule, FolderType,
};
pub use folders::{CreateFolderOptions, FolderConfig, FolderPatch, FolderRemoval, FolderUpdate};
pub use gui_listener::{
    GuiListenAddress, GuiListenerConfig, GuiListenerPatch, GuiListenerUpdate, GuiSocketPermissions,
};
pub use gui_preferences::{GuiPreferences, GuiPreferencesPatch, GuiPreferencesUpdate};
pub use gui_session::{
    GuiCredentialUpdate, GuiCredentials, GuiLoginOptions, GuiLogoutReceipt, GuiSession,
};
pub use ignores::{IgnorePatterns, IgnoreSnapshot, IgnoreUpdate};
pub use invitations::{
    DeviceIgnoreUpdate, FolderPeerUpdate, IgnoredDevice, IgnoredFolder, IgnoredFolderUpdate,
    PendingDeviceInfo, PendingDismissal, PendingFolderOffer, PendingFolderOffers,
};
pub use ldap::{GuiAuthModeUpdate, LdapConfiguration, LdapPatch, LdapTransport};
pub use licenses::{
    LicenseChange, LicenseEntries, LicenseExpiry, LicenseRecord, LicenseRequestKind, LicenseStatus,
};
pub use local_sync::{
    CreateLocalSyncJob, LocalSyncAction, LocalSyncActionRange, LocalSyncActionResult,
    LocalSyncCalendarRule, LocalSyncCalendarRuleInfo, LocalSyncConfiguration,
    LocalSyncConflictPolicy, LocalSyncConflictResolution, LocalSyncConflictSide,
    LocalSyncControlReceipt, LocalSyncHealth, LocalSyncHistory, LocalSyncHistoryRecord,
    LocalSyncJob, LocalSyncJobId, LocalSyncJobPatch, LocalSyncJobRemoval, LocalSyncJobUpdate,
    LocalSyncMarkerRepair, LocalSyncMode, LocalSyncOperation, LocalSyncOperationControl,
    LocalSyncOperationId, LocalSyncPreview, LocalSyncPreviewId, LocalSyncProgress, LocalSyncRun,
    LocalSyncRunId, LocalSyncSchedule, LocalSyncSelection, LocalSyncSelectionSummary,
    LocalSyncStatus, LocalSyncSummary, StorageDirectory, StorageEndpoint, StorageEntry,
    StorageProbe, StorageProtocol,
};
pub use local_sync_events::{
    LocalSyncEvent, LocalSyncEventBatch, LocalSyncEventCancellation, LocalSyncEventCursor,
    LocalSyncEventGap, LocalSyncEventOptions, LocalSyncEventStreamItem, LocalSyncEventSubscription,
};
pub use maintenance::{
    CoreDiagnostics, CoreErrorLog, CoreLogEntry, CoreLogLevel, CoreLogLevelUpdate, CoreLogLevels,
    CoreLogSnapshot, CoreMetricsSnapshot, CoreProfile, CoreProfileRequest,
    IndexResetAcknowledgement, IndexResetScope,
};
#[cfg(feature = "download")]
pub use managed::{CachePolicy, CacheStatus, CachedProgram, ProgramCache};
pub use managed::{
    DatabaseCommand, DatabaseCommandExit, DatabaseCommandOutcome, DatabaseCountRow,
    KernelUpgradeCommand, KernelUpgradeExit, ManagedExit, ManagedInstance, ManagedLifetime,
    ManagedOptions, ManagedUpgradeChecks, ProgramTransition, StateBackup, StateBackupInfo,
    StateBackupOptions,
};
#[cfg(feature = "download")]
pub use managed::{DownloadOptions, PreparedProgram};
pub use management_auth::{ApiKeyRotation, GuiAuthMode, GuiAuthenticationConfig};
pub use management_transport::{ManagementProxy, ManagementTransport};
pub use network::{
    ConnectionSnapshot, ConnectionTotals, DeviceTransport, DiscoveryRecord, ListenerStatus,
    NetworkConfig, NetworkPatch, NetworkUpdate, PeerConnection, PeerConnectionType,
};
pub use official_account::{
    OfficialAccountChange, OfficialAccountCredentials, OfficialAccountState, OfficialAccountStatus,
};
pub use operations::{ScanCompletion, ScanObservation, ScanPhase, ScanProgress, ScanUpdate};
pub use path::{PathStyle, TargetPath};
pub use raw::{RawMethod, RawRequest, RawResponse, RequestEffect};
pub use recovery::MarkerRepairResult;
pub use relay::{
    RelayProbe, RelayProbeResult, RelayRuntimeOptions, RelayServerConfig, RelayServerPatch,
    RelayServerStatus, RelayServerUpdate,
};
pub use releases::{
    official_programs, ArchiveFormat, BuildVariant, OfficialProgram, PinnedVersion, ProgramAbi,
    ProgramArchitecture, ProgramOs, ProgramTarget,
};
pub use remote_management::DeviceTunnelProbe;
pub use scans::{FolderScanConfig, FolderScanPatch, FolderScanUpdate};
pub use scheduling::{
    BandwidthPatch, BandwidthUpdate, FolderPullOrder, FolderSchedulingConfig,
    FolderSchedulingUpdate, GlobalBandwidthConfig,
};
pub use selective::{
    FolderSelectiveConfig, FolderSelectiveUpdate, SelectiveAcknowledgement, SelectiveAction,
    SelectiveBrowseOptions, SelectiveEntry, SelectiveMatch, SelectiveScope, SelectiveSearchOptions,
    SelectiveSearchPage, SelectiveTree,
};
pub use sharing::{
    GeneratedShare, JoinFolderOptions, JoinFolderResult, JoinPeerObservation, ShareKey,
    SharePermission, ValidatedShare,
};
pub use status::{FolderId, FolderState, FolderStatus, SystemStatus};
pub use sync_observation::{
    CompletionSnapshot, DeviceStatistics, FolderErrorPage, FolderStatistics, FolderSyncError,
    LastFileObservation, ListPage, NeedPage, SyncFile, SyncFileKind, SyncFilePage,
};
pub use system_preferences::{NativePathSelection, SystemPreferences, SystemPreferencesPatch};
pub use transports::{
    TrackerStatus, TransportConfig, TransportPatch, TransportStatus, TransportUpdate,
};
pub use upgrades::KernelUpgradeCheck;

/// The fixed upstream version selected for initial compatibility acceptance.
///
/// This identifies a test baseline, not an automatic download or a claim that
/// every feature and platform has passed acceptance.
pub const BASELINE_ENGINE_VERSION: &str = "v2.33.2";
