//! Logical remote file-manager volumes and bounded resource metadata.
use crate::{Error, PathStyle, Result, TargetPath};
use serde::{Deserialize, Deserializer};
use std::{collections::BTreeMap, fmt};

/// An opaque file-manager mount ID, distinct from a synchronization FolderId.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct ResourceVolumeId(String);
impl ResourceVolumeId {
    /// Preserve one nonempty bounded mount ID; never accept path separators.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 1024
            || matches!(value.as_str(), "." | "..")
            || value
                .chars()
                .any(|c| c.is_control() || matches!(c, '/' | '\\'))
        {
            return Err(Error::InvalidPath {
                reason: "file-manager volume ID must be one bounded non-dot component",
            });
        }
        Ok(Self(value))
    }
    /// Borrow the exact upstream mount identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for ResourceVolumeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResourceVolumeId([REDACTED])")
    }
}
impl<'de> Deserialize<'de> for ResourceVolumeId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Self::parse(String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("invalid resource volume ID"))
    }
}
/// One logical mounted volume; its path may be a target filesystem path or a
/// storage-backend locator and is never interpreted using the controller's OS.
#[derive(Clone, Deserialize)]
pub struct ResourceVolume {
    /// Opaque file-manager ID, not a synchronization folder ID.
    pub id: ResourceVolumeId,
    /// Exact server-provided path/locator; private and untrusted.
    pub path: String,
    /// Actual display name, potentially private.
    pub name: String,
    /// Engine-provided backend category; unknown values remain intact.
    pub kind: String,
    /// Additional upstream fields, including backend-specific type information.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for ResourceVolume {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceVolume").finish_non_exhaustive()
    }
}
/// A bounded logical path within one selected remote volume. It does not access
/// local files or infer target syntax from the controller's operating system.
#[derive(Clone)]
pub struct ResourcePath {
    pub(crate) volume: ResourceVolumeId,
    pub(crate) style: PathStyle,
    pub(crate) components: Vec<String>,
}
impl ResourcePath {
    /// Address the selected volume root in an explicitly selected target syntax.
    pub fn root(volume: ResourceVolumeId, style: PathStyle) -> Self {
        Self {
            volume,
            style,
            components: Vec::new(),
        }
    }
    /// Split an explicitly relative target path using its own syntax. Local
    /// callers can pass TargetPath::local with a native Path/PathBuf. Dot/parent,
    /// empty and rooted components are refused rather than normalized.
    pub fn relative(volume: ResourceVolumeId, path: &TargetPath) -> Result<Self> {
        let style = path.style();
        let value = path.to_protocol()?;
        let mut result = Self::root(volume, style);
        let parts: Vec<_> = match style {
            PathStyle::Unix => value.split('/').collect(),
            PathStyle::Windows => value.split(['/', '\\']).collect(),
        };
        for component in parts {
            result = result.child(component)?;
        }
        Ok(result)
    }
    /// Append exactly one native target filename, preserving percent/Unicode
    /// characters. Windows separators, drive/stream syntax and invalid native
    /// filename characters are refused on Windows targets only.
    pub fn child(mut self, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
        let reserved_windows = matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|tail| {
                matches!(
                    tail,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        });
        let invalid_windows = self.style == PathStyle::Windows
            && (name.chars().any(|c| {
                c.is_control() || matches!(c, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*')
            }) || name.ends_with(['.', ' '])
                || reserved_windows);
        if name.is_empty()
            || matches!(name.as_str(), "." | "..")
            || name.contains('/')
            || name.contains('\0')
            || invalid_windows
            || self.components.len() >= 128
            || name.len() > 4096
        {
            return Err(Error::InvalidPath {
                reason: "resource path requires bounded non-dot target filename components",
            });
        }
        self.components.push(name);
        Ok(self)
    }
    /// Return the logical parent, including the volume root for a direct child.
    /// A volume root has no parent; no native filesystem is accessed.
    pub fn parent(&self) -> Option<Self> {
        if self.components.is_empty() {
            return None;
        }
        let mut parent = self.clone();
        parent.components.pop();
        Some(parent)
    }
    /// Borrow the explicit mount ID without exposing a local filesystem path.
    pub fn volume(&self) -> &ResourceVolumeId {
        &self.volume
    }
    /// The explicitly selected remote native syntax.
    pub fn style(&self) -> PathStyle {
        self.style
    }
}
impl fmt::Debug for ResourcePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourcePath")
            .field("style", &self.style)
            .field("components", &self.components.len())
            .finish_non_exhaustive()
    }
}

/// Actual bounded resource metadata. Directory sizes/modes retain the upstream
/// numeric representation; returned paths/names are untrusted protocol data.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    /// Server-relative path, never automatically resolved on the caller's OS.
    pub path: String,
    /// Actual resource filename, potentially private.
    pub name: String,
    /// Native upstream size snapshot, not a completed transfer byte count.
    pub size: u64,
    /// Actual native mode bits reported by the engine.
    pub mode: u32,
    /// Engine timestamp string with its original precision and offset.
    pub modified: String,
    /// True for a directory; independent of whether an items list is present.
    pub is_dir: bool,
    /// Directory entries; missing/null is distinct from an observed empty list.
    pub items: Option<Vec<ResourceInfo>>,
    /// Inline text content, if the engine returned it within the response limit.
    pub content: Option<String>,
    /// Requested checksum values; absent is not an empty successful checksum.
    #[serde(default)]
    pub checksums: BTreeMap<String, String>,
    /// Additional metadata, potentially private.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for ResourceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceInfo")
            .field("is_dir", &self.is_dir)
            .field("size", &self.size)
            .field("items", &self.items.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}
/// Explicit native checksum request; MD5/SHA-1 are compatibility checksums, not
/// authentication or recommended cryptographic integrity mechanisms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceChecksum {
    /// Native MD5 checksum.
    Md5,
    /// Native SHA-1 checksum.
    Sha1,
    /// Native SHA-256 checksum.
    Sha256,
    /// Native SHA-512 checksum.
    Sha512,
}
impl ResourceChecksum {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
    pub(crate) fn hex_len(self) -> usize {
        match self {
            Self::Md5 => 32,
            Self::Sha1 => 40,
            Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }
}

/// One bounded native image-preview response. Source image and response bytes
/// can be private; Debug exposes only the byte count.
#[derive(Clone)]
pub struct ResourcePreview {
    pub(crate) media_type: String,
    pub(crate) bytes: Vec<u8>,
}
impl ResourcePreview {
    /// Actual engine-provided image Content-Type, including retained parameters.
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
    /// Inspect the complete bounded native preview bytes explicitly.
    pub fn body_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl fmt::Debug for ResourcePreview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourcePreview")
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
