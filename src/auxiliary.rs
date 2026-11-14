//! Target-side directory helpers, independent of file-manager mounts.
use crate::TargetPath;
use serde::Deserialize;
use std::{collections::BTreeMap, fmt};

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
