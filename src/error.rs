//! Matchable errors for control inputs and operations.

use std::fmt;

/// An error returned by the control library.
///
/// Error messages never include management credentials. Alpha variants may
/// change; callers should handle the cases relevant to their operation.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A management address violates the documented endpoint contract.
    InvalidEndpoint {
        /// A credential-free description of the invalid input.
        reason: &'static str,
    },
    /// A path cannot be sent to the management protocol.
    InvalidPath {
        /// A description that does not include the path's contents.
        reason: &'static str,
    },
    /// A native path cannot be represented as UTF-8 without changing it.
    PathEncoding,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint { reason } => {
                write!(formatter, "invalid management endpoint: {reason}")
            }
            Self::InvalidPath { reason } => write!(formatter, "invalid target path: {reason}"),
            Self::PathEncoding => formatter.write_str(
                "native path cannot be represented losslessly by the UTF-8 management protocol",
            ),
        }
    }
}

impl std::error::Error for Error {}

/// A result returned by the control library.
pub type Result<T> = std::result::Result<T, Error>;
