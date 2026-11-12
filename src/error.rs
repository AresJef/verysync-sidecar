//! Matchable errors for control inputs and operations.

use std::fmt;

use crate::{DeviceId, FolderId};

/// Bounded upstream response bytes, excluded from ordinary debug/display output.
///
/// Callers may explicitly inspect the body for diagnostics. It may contain
/// sensitive upstream data and should not be logged without review.
pub struct ResponseDiagnostic {
    status: u16,
    body: Vec<u8>,
}

impl ResponseDiagnostic {
    pub(crate) fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }
    /// The upstream HTTP status code.
    pub fn status(&self) -> u16 {
        self.status
    }
    /// Inspect the exact bounded upstream bytes explicitly.
    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for ResponseDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseDiagnostic")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// An error returned by the control library.
///
/// Error messages never include management credentials. Alpha variants may
/// change; callers should handle the cases relevant to their operation.
#[non_exhaustive]
pub enum Error {
    /// A connection setting is invalid; no operation has started.
    InvalidConfiguration {
        /// A credential-free description of the setting.
        reason: &'static str,
    },
    /// A management credential cannot be sent safely.
    InvalidCredential {
        /// A description that excludes the supplied credential.
        reason: &'static str,
    },
    /// A supplied or returned identity does not have the expected layout.
    InvalidIdentity {
        /// A description that excludes the input value.
        reason: &'static str,
    },
    /// The authenticated identity differs from the explicitly expected one.
    IdentityMismatch {
        /// The identity supplied by the caller.
        expected: DeviceId,
        /// The identity returned by the authenticated target.
        actual: DeviceId,
    },
    /// The engine does not match the fixed validated version policy.
    IncompatibleVersion {
        /// The returned version, with any management key occurrence redacted.
        actual: String,
    },
    /// A transport is unavailable on this platform or feature configuration.
    UnsupportedTransport {
        /// The unavailable transport, without an address or credential.
        transport: &'static str,
    },
    /// The endpoint explicitly requires authentication (HTTP 401).
    Authentication {
        /// The HTTP authentication status.
        status: u16,
    },
    /// The endpoint denied access (HTTP 403).
    ///
    /// This alone does not distinguish an invalid key from permission or
    /// feature-license restrictions. Inspect bounded diagnostics explicitly;
    /// the library does not infer a commercial-license requirement from 403.
    AccessDenied {
        /// Exact status and bounded body, omitted from ordinary Debug/Display.
        response: ResponseDiagnostic,
    },
    /// A bounded management request did not finish before its deadline.
    Timeout {
        /// The operation that timed out.
        operation: &'static str,
    },
    /// The management response exceeded the configured buffer bound.
    ResponseTooLarge {
        /// The configured maximum number of bytes.
        limit: usize,
    },
    /// A non-success HTTP response, with bounded diagnostics available explicitly.
    Http {
        /// Status and body, with the body excluded from debug output.
        response: ResponseDiagnostic,
    },
    /// A successful HTTP status carried a nonempty error-only JSON envelope.
    ///
    /// An ordinary status object that also contains an error description is
    /// preserved as data. This classification does not guess feature codes.
    Api {
        /// The operation whose response contained the failure envelope.
        operation: &'static str,
        /// Exact status and bounded error body, omitted from ordinary logs.
        response: ResponseDiagnostic,
    },
    /// A success response did not match the operation's expected JSON schema.
    InvalidResponse {
        /// The operation whose response could not be decoded.
        operation: &'static str,
        /// Status and body, with the body excluded from debug output.
        response: ResponseDiagnostic,
    },
    /// A transport failure with the request URL removed from its source.
    Transport {
        /// The operation that failed.
        operation: &'static str,
        /// The underlying transport error, without its request URL.
        source: reqwest::Error,
    },
    /// A folder identifier cannot be used as a protocol value.
    InvalidFolderId {
        /// A description that excludes the supplied identifier.
        reason: &'static str,
    },
    /// The requested folder is absent from the authenticated configuration.
    FolderNotFound {
        /// The requested opaque identifier.
        id: FolderId,
    },
    /// Creation would replace an already configured folder ID.
    FolderAlreadyExists {
        /// The existing opaque identifier.
        id: FolderId,
    },
    /// Another configured ID has the exact requested protocol path string.
    FolderPathAlreadyConfigured {
        /// The existing configuration using that path string.
        id: FolderId,
    },
    /// A modifying request or its verification failed after a write could start.
    ///
    /// Reconcile by reading configuration before retrying. The engine may have
    /// applied the request even though no successful readback was obtained.
    MutationOutcomeUnknown {
        /// The attempted operation, without arguments or credentials.
        operation: &'static str,
        /// The bounded, credential-safe underlying failure.
        source: Box<Error>,
    },
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

impl fmt::Debug for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Domain identifiers and upstream diagnostics may reflect credentials.
        // Default Debug uses only the credential-free Display contract; typed
        // fields and bounded response bytes remain explicitly inspectable.
        write!(formatter, "Error({self})")
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration { reason } => {
                write!(formatter, "invalid configuration: {reason}")
            }
            Self::InvalidCredential { reason } => {
                write!(formatter, "invalid management credential: {reason}")
            }
            Self::InvalidIdentity { reason } => {
                write!(formatter, "invalid device identity: {reason}")
            }
            Self::IdentityMismatch { .. } => formatter
                .write_str("authenticated device identity did not match the expected identity"),
            Self::IncompatibleVersion { actual } => write!(
                formatter,
                "engine version {actual} has not passed compatibility acceptance"
            ),
            Self::UnsupportedTransport { transport } => {
                write!(formatter, "unsupported management transport: {transport}")
            }
            Self::Authentication { status } => write!(
                formatter,
                "management authentication rejected (HTTP {status})"
            ),
            Self::AccessDenied { .. } => formatter.write_str("management access denied (HTTP 403); authentication or permissions require inspection"),
            Self::Timeout { operation } => write!(
                formatter,
                "management deadline exceeded while attempting to {operation}"
            ),
            Self::ResponseTooLarge { limit } => {
                write!(formatter, "management response exceeded {limit} bytes")
            }
            Self::Http { response } => write!(
                formatter,
                "management endpoint returned HTTP {}",
                response.status
            ),
            Self::Api { operation, .. } => write!(formatter, "management API reported a body failure while attempting to {operation}"),
            Self::InvalidResponse { operation, .. } => write!(
                formatter,
                "invalid management response while attempting to {operation}"
            ),
            Self::Transport { operation, .. } => write!(
                formatter,
                "management transport failed while attempting to {operation}"
            ),
            Self::InvalidFolderId { reason } => {
                write!(formatter, "invalid folder identifier: {reason}")
            }
            Self::FolderNotFound {..}=>formatter.write_str("folder is not configured"),
            Self::FolderAlreadyExists {..}=>formatter.write_str("folder ID is already configured; creation did not start"),
            Self::FolderPathAlreadyConfigured {..}=>formatter.write_str("target path string is already configured; creation did not start"),
            Self::MutationOutcomeUnknown {operation,..}=>write!(formatter,"outcome is unknown after attempting to {operation}; read current configuration before retrying"),
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

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport { source, .. } => Some(source),
            Self::MutationOutcomeUnknown { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// A result returned by the control library.
pub type Result<T> = std::result::Result<T, Error>;
