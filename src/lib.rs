//! Asynchronous management of the official VerySync program.
//!
//! This crate is under development. It provides explicit endpoint/path values
//! and authenticated management connections with version and identity checks.
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

mod auth;
mod client;
mod endpoint;
mod error;
mod path;

pub use auth::{ApiKey, DeviceId};
pub use client::{
    Client, ConnectOptions, EngineVersion, InstanceInfo, VersionCompatibility, VersionPolicy,
};
pub use endpoint::{EndpointKind, ManagementEndpoint};
pub use error::{Error, ResponseDiagnostic, Result};
pub use path::{PathStyle, TargetPath};

/// The fixed upstream version selected for initial compatibility acceptance.
///
/// This identifies a test baseline, not an automatic download or a claim that
/// every feature and platform has passed acceptance.
pub const BASELINE_ENGINE_VERSION: &str = "v2.33.2";
