//! Paths interpreted by the target instance, with no host-based guessing.

use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// The filesystem syntax used by the target instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathStyle {
    /// Unix path syntax, including macOS and Linux.
    Unix,
    /// Windows path syntax.
    Windows,
}

/// A native local path or an explicitly described remote target path.
///
/// This value performs no filesystem access, canonicalization, separator
/// substitution, or relative-path expansion. In particular, `..` is preserved:
/// resolving it lexically could change the meaning of a path with symlinks.
/// Whether an operation permits a relative path is part of that operation's
/// contract. A remote path is never passed through the caller's `Path` rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetPath(PathValue);

#[derive(Clone, Debug, Eq, PartialEq)]
enum PathValue {
    Local(PathBuf),
    Remote { style: PathStyle, value: String },
}

impl TargetPath {
    /// Retain a local filesystem path without converting its native encoding.
    ///
    /// Conversion is checked only when [`Self::to_protocol`] is called. Use
    /// native `Path` operations such as `join` before constructing this value.
    pub fn local(path: impl Into<PathBuf>) -> Self {
        Self(PathValue::Local(path.into()))
    }

    /// Retain a remote path in the explicitly selected target's syntax.
    ///
    /// Empty strings and NUL characters are rejected. Other characters are
    /// preserved exactly; the target engine interprets them, including relative
    /// paths and separators. The library never infers the style from the host.
    pub fn remote(style: PathStyle, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_protocol_path(&value)?;
        Ok(Self(PathValue::Remote { style, value }))
    }

    /// The syntax of the stored path, using the host only for a native path.
    pub fn style(&self) -> PathStyle {
        match &self.0 {
            PathValue::Local(_) => {
                if cfg!(windows) {
                    PathStyle::Windows
                } else {
                    PathStyle::Unix
                }
            }
            PathValue::Remote { style, .. } => *style,
        }
    }

    /// Borrow the native path, if this value was created with [`Self::local`].
    ///
    /// A remote path has no native host representation and returns `None`.
    pub fn local_path(&self) -> Option<&Path> {
        match &self.0 {
            PathValue::Local(path) => Some(path),
            PathValue::Remote { .. } => None,
        }
    }

    /// Borrow an exact UTF-8 representation for the management protocol.
    ///
    /// Native paths with invalid UTF-8 or unpaired UTF-16 surrogates return
    /// [`Error::PathEncoding`]. No replacement characters are introduced.
    /// Empty paths and embedded NUL characters return [`Error::InvalidPath`].
    pub fn to_protocol(&self) -> Result<&str> {
        let value = match &self.0 {
            PathValue::Local(path) => path.to_str().ok_or(Error::PathEncoding)?,
            PathValue::Remote { value, .. } => value,
        };
        validate_protocol_path(value)?;
        Ok(value)
    }
}

fn validate_protocol_path(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidPath {
            reason: "path must not be empty",
        });
    }
    if value.contains('\0') {
        return Err(Error::InvalidPath {
            reason: "NUL characters are not permitted",
        });
    }
    Ok(())
}
