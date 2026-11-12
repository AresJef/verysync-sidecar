//! Caller-selected local programs; construction performs no I/O or execution.

use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// An explicit absolute path to a caller-provided official program.
///
/// This value neither downloads nor runs a program. Managed startup verifies its
/// actual SHA-256 and fixed version before configuring the private instance.
#[derive(Clone, Debug)]
pub struct LocalProgram {
    pub(crate) path: PathBuf,
    pub(crate) expected_sha256: Option<[u8; 32]>,
}

impl LocalProgram {
    /// Select an absolute native executable path without accessing it.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if !path.is_absolute() || path.as_os_str().as_encoded_bytes().contains(&0) {
            return Err(Error::InvalidConfiguration {
                reason: "program path must be absolute and contain no NUL",
            });
        }
        Ok(Self {
            path,
            expected_sha256: None,
        })
    }

    /// Require this exact executable SHA-256 before any program execution.
    pub fn expected_sha256(mut self, digest: [u8; 32]) -> Self {
        self.expected_sha256 = Some(digest);
        self
    }

    /// Borrow the exact caller-selected native path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Identity of the executable actually inspected during managed startup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramInfo {
    /// The actual SHA-256 of the selected executable.
    pub sha256: [u8; 32],
    /// The checked fixed baseline version.
    pub version: String,
}
