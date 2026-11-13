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

mod auth;
mod capabilities;
mod client;
mod endpoint;
mod engine_source;
mod error;
mod events;
mod folders;
mod managed;
mod operations;
mod path;
mod raw;
mod sharing;
mod status;

pub use auth::{ApiKey, DeviceId};
pub use capabilities::{
    library_capabilities, Capability, CapabilityReport, ImplementationStatus, InstanceConditions,
    InstanceObservation, LibraryCapability, TargetSnapshot, TargetValidation, VerificationStatus,
};
pub use client::{
    Client, ConnectOptions, EngineVersion, InstanceInfo, VersionCompatibility, VersionPolicy,
};
pub use endpoint::{EndpointKind, ManagementEndpoint};
pub use engine_source::{LocalProgram, ProgramInfo};
pub use error::{Error, ProcessDiagnostic, ResponseDiagnostic, Result};
pub use events::{
    EngineEvent, EventCursor, EventGap, EventGapReason, EventKind, EventOptions, EventStreamItem,
    EventSubscription,
};
pub use folders::{CreateFolderOptions, FolderConfig, FolderPatch, FolderRemoval, FolderUpdate};
pub use managed::{ManagedExit, ManagedInstance, ManagedLifetime, ManagedOptions};
pub use operations::{ScanCompletion, ScanObservation, ScanPhase, ScanProgress, ScanUpdate};
pub use path::{PathStyle, TargetPath};
pub use raw::{RawMethod, RawRequest, RawResponse, RequestEffect};
pub use sharing::{
    GeneratedShare, JoinFolderOptions, JoinFolderResult, JoinPeerObservation, ShareKey,
    SharePermission, ValidatedShare,
};
pub use status::{FolderId, FolderState, FolderStatus, SystemStatus};

/// The fixed upstream version selected for initial compatibility acceptance.
///
/// This identifies a test baseline, not an automatic download or a claim that
/// every feature and platform has passed acceptance.
pub const BASELINE_ENGINE_VERSION: &str = "v2.33.2";
