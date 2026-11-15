//! Target-side directory helpers, independent of file-manager mounts.
use crate::TargetPath;
use serde::Deserialize;
use std::{collections::BTreeMap, fmt};

/// Exact status text from the target's native HTTP health handler.
#[derive(Clone, Eq, PartialEq)]
pub enum NativeHealthStatus {
    /// The fixed handler's explicit `OK` token.
    Ok,
    /// Other native status text, preserved without interpreting readiness.
    Other(String),
}
impl NativeHealthStatus {
    /// Borrow the exact native status token. Unknown text is not normalized.
    pub fn native_value(&self) -> &str {
        match self {
            Self::Ok => "OK",
            Self::Other(value) => value,
        }
    }
}
impl fmt::Debug for NativeHealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => f.write_str("Ok"),
            Self::Other(_) => f.write_str("Other(..)"),
        }
    }
}

/// One native HTTP health snapshot. This does not observe folder completion,
/// operation authorization or the outcome of a task started by a caller.
#[derive(Clone)]
pub struct NativeHealth {
    /// Exact native health status, including unrecognized future tokens.
    pub status: NativeHealthStatus,
    /// Other native response fields; ordinary Debug omits their private values.
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for NativeHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeHealth")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// Native configuration/data locations, interpreted on the connected target.
/// These observations do not read or create controller files.
#[derive(Clone)]
pub struct NativeSystemPaths {
    /// Native `baseDir-config` location.
    pub configuration_directory: TargetPath,
    /// Native `baseDir-data` location.
    pub data_directory: TargetPath,
    /// Native process profile home, independent of the controller's home.
    pub user_home_directory: TargetPath,
    /// Native `config` file location.
    pub configuration_file: TargetPath,
    /// Native active database location, without opening it on the controller.
    pub database_directory: TargetPath,
    /// Other exact native values. These can be filename templates or `-` for
    /// standard output, so they are not automatically converted to paths.
    pub extra: BTreeMap<String, String>,
}
impl fmt::Debug for NativeSystemPaths {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeSystemPaths").finish_non_exhaustive()
    }
}

/// Receipt for one explicit native temporary-file cleanup request. It reports
/// neither a removal count nor proof that every native removal succeeded.
#[derive(Clone)]
pub struct FolderTemporaryCleanup {
    /// Exact opaque registration selected for the native request.
    pub folder: crate::FolderId,
    /// Additional private native acknowledgement fields.
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for FolderTemporaryCleanup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderTemporaryCleanup")
            .finish_non_exhaustive()
    }
}

/// One native directory-picker starting location. A location is a target path,
/// not a file-manager volume or a path on a remote caller's machine.
#[derive(Clone)]
pub struct TargetDirectoryLocation {
    /// Exact native path, interpreted using the connected target's syntax.
    pub path: TargetPath,
    /// Native display title, potentially localized and private.
    pub title: String,
    /// Additional bounded native fields, retained without interpretation.
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for TargetDirectoryLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TargetDirectoryLocation")
            .finish_non_exhaustive()
    }
}

/// One native directory-picker entry. Names are untrusted data; this value
/// neither joins paths nor accesses the caller's filesystem.
#[derive(Clone, Deserialize)]
pub struct TargetDirectoryEntry {
    /// Exact native child name; do not treat it as a trusted path component.
    pub name: String,
    /// Native `folder` indicator. The verified `d` filter selects directories.
    #[serde(rename = "folder")]
    pub is_directory: bool,
    /// Additional bounded native fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for TargetDirectoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TargetDirectoryEntry")
            .field("is_directory", &self.is_directory)
            .finish_non_exhaustive()
    }
}

/// A native directory-creation acknowledgement followed by a successful
/// directory read on the requested target path. No local controller I/O occurs.
#[derive(Clone)]
pub struct TargetDirectoryCreation {
    /// Native returned path. The engine can canonicalize aliases or separators.
    pub path: TargetPath,
    /// Native localized success message; it is not a machine-readable code.
    pub native_message: String,
    /// Additional bounded native acknowledgement fields.
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for TargetDirectoryCreation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TargetDirectoryCreation")
            .finish_non_exhaustive()
    }
}

/// Target-side IP lookup data. Empty location text is valid for addresses such
/// as loopback. Results are native data, not an independently verified location.
#[derive(Clone)]
pub struct TargetIpLocation {
    /// Address echoed and checked against the explicitly requested IP.
    pub ip: std::net::IpAddr,
    /// Native `pro` field, potentially empty or localized.
    pub province: String,
    /// Native city text, potentially empty or localized.
    pub city: String,
    /// Native `addr` description, potentially empty or localized.
    pub description: String,
    /// Additional native fields, without interpretation.
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for TargetIpLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TargetIpLocation").finish_non_exhaustive()
    }
}

/// A native usage-report snapshot collected on explicit request. Collection is
/// separate from enabling or sending usage reports. All values are private.
#[derive(Clone, Deserialize)]
pub struct NativeUsageReport {
    /// Native program version, including its prefix.
    pub version: String,
    /// Native OS/architecture description.
    pub platform: String,
    /// Native configured-device count, including the local device.
    #[serde(rename = "numDevices")]
    pub device_count: u64,
    /// Native report identifier, when present; not the certificate device ID.
    #[serde(rename = "uniqueID")]
    pub unique_id: Option<String>,
    /// Other native report fields and counters. No performance claim is inferred.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for NativeUsageReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeUsageReport").finish_non_exhaustive()
    }
}

/// A native GUI-link snapshot. Retrieving it never opens or follows the link,
/// registers a folder, or accepts a sharing key on the caller's behalf.
#[derive(Clone)]
pub struct PendingNativeLink {
    pub(crate) link: Option<String>,
    /// Other private native fields, preserved without interpretation.
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl PendingNativeLink {
    /// Borrow the exact nonempty native text. It is untrusted and can include
    /// sharing credentials. An empty native string is represented as `None`.
    pub fn link(&self) -> Option<&str> {
        self.link.as_deref()
    }
}
impl fmt::Debug for PendingNativeLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingNativeLink")
            .field("present", &self.link.is_some())
            .finish_non_exhaustive()
    }
}

/// Private GUI metadata returned by the native `meta.js` resource. The library
/// parses its fixed JSON assignment without evaluating JavaScript.
#[derive(Clone, Deserialize)]
pub struct NativeGuiMetadata {
    /// Native authentication observation for this request.
    pub authenticated: bool,
    /// Native certificate identity, checked against the connected instance.
    #[serde(rename = "deviceID")]
    pub device_id: crate::DeviceId,
    /// Native short display identity, not a globally unique lookup key.
    #[serde(rename = "deviceIDShort")]
    pub short_device_id: String,
    /// Whether the native GUI reports authentication enabled.
    #[serde(rename = "isAuthEnabled")]
    pub authentication_enabled: bool,
    /// Other bounded native metadata, retained as private data.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for NativeGuiMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeGuiMetadata")
            .field("authenticated", &self.authenticated)
            .field("authentication_enabled", &self.authentication_enabled)
            .finish_non_exhaustive()
    }
}

/// The native QR resource's bounded PNG bytes. The data can encode private
/// sharing credentials. Its signature/IHDR and declared media type are checked;
/// the library does not decode images or display them on the caller's system.
#[derive(Clone)]
pub struct NativeQrCode {
    pub(crate) bytes: Vec<u8>,
    /// Width from the PNG's IHDR, in pixels.
    pub width: u32,
    /// Height from the PNG's IHDR, in pixels.
    pub height: u32,
}
impl NativeQrCode {
    /// Explicitly borrow the private native image bytes.
    pub fn png_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl fmt::Debug for NativeQrCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeQrCode")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("byte_count", &self.bytes.len())
            .finish()
    }
}
