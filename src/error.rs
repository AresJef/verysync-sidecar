//! Matchable errors for control inputs and operations.

use std::fmt;

use crate::{DeviceId, FolderId};

/// Bounded private program output, available only through explicit inspection.
///
/// Upstream output may contain sensitive state. Ordinary Debug/Display never
/// include its bytes; review and redact before copying it into logs.
#[derive(Clone, Eq, PartialEq)]
pub struct ProcessDiagnostic(Vec<u8>);
impl ProcessDiagnostic {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    /// Inspect captured upstream bytes explicitly; these may contain secrets.
    pub fn body_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for ProcessDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessDiagnostic")
            .field("bytes", &self.0.len())
            .finish()
    }
}

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
    /// No complete program for the exact asset is available in offline cache.
    CacheMiss,
    /// A cache index or program does not match its recorded fixed identity.
    CacheCorrupt {
        /// Description without caller paths or source URLs.
        reason: &'static str,
    },
    /// A directory or cache request is not admissible; caller data is preserved.
    CacheRejected {
        /// Description without caller paths or source URLs.
        reason: &'static str,
    },
    /// Explicit program preparation rejected an unsafe or mismatched artifact.
    DownloadRejected {
        /// A bounded description excluding source URLs and local paths.
        reason: &'static str,
    },
    /// The explicit program source returned a non-success status.
    DownloadHttp {
        /// Actual HTTP status; response bodies are not buffered or logged.
        status: u16,
    },
    /// The explicitly pinned requested version has no verified release catalog.
    UnlistedProgramVersion,
    /// No artifact is listed for this exact OS/architecture/build tuple.
    UnsupportedProgramTarget {
        /// Explicit requested tuple; no host-based fallback was applied.
        target: crate::ProgramTarget,
    },
    /// The engine explicitly rejected a sharing key, including HTTP-200 rejection.
    ShareKeyRejected {
        /// Bounded original rejection payload, omitted from ordinary formatting.
        response: ResponseDiagnostic,
    },
    /// This sharing group is already registered locally; no POST was sent.
    ShareAlreadyConfigured {
        /// Actual existing local registration ID.
        id: FolderId,
    },
    /// A modifying ignore-file response reports a parser rejection. Rules may
    /// already be stored; inspect or explicitly replace/reset them before retry.
    IgnorePatternsRejected {
        /// Actual returned state and private parser diagnostic, hidden in Debug.
        snapshot: Box<crate::IgnoreSnapshot>,
    },
    /// The selected local executable failed a baseline or checksum check.
    ProgramRejected {
        /// A description excluding paths, arguments and captured program output.
        reason: &'static str,
    },
    /// An owned program exited before the required managed operation completed.
    ManagedProcessExited {
        /// The credential-free stage that could not complete.
        operation: &'static str,
        /// Its actual normal exit code, absent for a signal termination.
        code: Option<i32>,
        /// Optional bounded private program output, omitted from Debug/Display.
        diagnostic: Option<ProcessDiagnostic>,
    },
    /// A managed-state or lifecycle invariant could not be established.
    ManagedFailure {
        /// A description excluding credentials and captured output.
        reason: &'static str,
    },
    /// The dedicated state already has an exclusive library owner.
    ManagedStateInUse,
    /// The supplied directory is not an admissible library-owned state.
    UnmanagedState,
    /// A native filesystem or process operation failed without echoing arguments.
    LocalIo {
        /// The credential-free operation name.
        operation: &'static str,
        /// The original I/O error, available for explicit diagnosis.
        source: std::io::Error,
    },
    /// A connection setting is invalid; no operation has started.
    InvalidConfiguration {
        /// A credential-free description of the setting.
        reason: &'static str,
    },
    /// An explicitly owned event task failed while being joined.
    EventSubscriptionFailure,
    /// The engine's reported generation changed across an event snapshot read.
    EventGenerationChanged,
    /// A next-scan observation cannot begin while the target is not idle.
    ScanNotIdle,
    /// Gaps or missing transitions prevent this local observation establishing a full scan cycle.
    ScanObservationLost,
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
    /// The fixed engine rejected a typed operation with its known commercial
    /// feature-license envelope, even if HTTP status was successful.
    LicenseRequired {
        /// Actual engine rejection code; currently verified as 3000 for Pro.
        code: i64,
        /// Original bounded response, hidden from ordinary formatting.
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
    /// The exact peer identity is absent from current configuration.
    DeviceNotFound {
        /// Explicit requested identity, omitted from ordinary formatting.
        id: DeviceId,
    },
    /// Creating this identity would replace an existing peer; no POST was sent.
    DeviceAlreadyExists {
        /// Existing identity, omitted from ordinary formatting.
        id: DeviceId,
    },
    /// A remote-device mutation targeted the connected instance's own identity.
    LocalDeviceProtected,
    /// The exact remote offer is absent; no modifying request was sent.
    PendingOfferNotFound,
    /// This peer has no persistent ignored-folder entry for the requested ID.
    FolderNotIgnored,
    /// The requested identity has no persistent ignore record.
    DeviceNotIgnored,
    /// Device ignore cannot implicitly unregister a configured remote peer.
    ConfiguredDeviceCannotBeIgnored {
        /// Existing configured identity, omitted from ordinary formatting.
        id: DeviceId,
    },
    /// The requested folder is absent from the authenticated configuration.
    FolderNotFound {
        /// The requested opaque identifier.
        id: FolderId,
    },
    /// The requested operation requires an unpaused configured folder.
    FolderPaused {
        /// Exact requested folder, omitted from ordinary formatting.
        id: FolderId,
    },
    /// A response identified a different folder from the requested one.
    FolderIdentityMismatch {
        /// Requested opaque identifier, omitted from ordinary formatting.
        expected: FolderId,
        /// Actual response identifier, omitted from ordinary formatting.
        actual: FolderId,
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
            Self::CacheMiss => formatter.write_str("no complete program is available in the offline cache"),
            Self::CacheCorrupt { reason } => write!(formatter, "program cache is corrupt: {reason}"),
            Self::CacheRejected { reason } => write!(formatter, "program cache rejected: {reason}"),
            Self::DownloadRejected { reason } => write!(formatter, "program preparation rejected: {reason}"),
            Self::DownloadHttp { status } => write!(formatter, "program source returned HTTP {status}"),
            Self::EventSubscriptionFailure => formatter.write_str("event subscription task failed"),
            Self::EventGenerationChanged => formatter.write_str("engine generation changed during event observation"),
            Self::ScanNotIdle => formatter.write_str("next-scan observation requires an idle folder"),
            Self::UnlistedProgramVersion => formatter.write_str("requested program version is not in the fixed catalog"),
            Self::UnsupportedProgramTarget { .. } => formatter.write_str("requested program target is not in the fixed catalog"),
            Self::ShareKeyRejected { .. } => formatter.write_str("engine rejected the sharing key"),
            Self::LicenseRequired { code, .. } => write!(formatter, "engine requires a feature license (code {code})"),
            Self::IgnorePatternsRejected { .. } => formatter.write_str("engine reported invalid stored ignore patterns; inspect or explicitly restore the rules"),
            Self::ShareAlreadyConfigured { .. } => formatter.write_str("sharing group is already configured locally"),
            Self::ScanObservationLost => formatter.write_str("scan observation lost continuity; query state explicitly"),
            Self::ProgramRejected { reason } => write!(formatter, "selected program rejected: {reason}"),
            Self::ManagedProcessExited { operation, code, .. } => write!(formatter, "owned program exited while attempting to {operation} (code {code:?})"),
            Self::ManagedFailure { reason } => write!(formatter, "managed operation failed: {reason}"),
            Self::ManagedStateInUse => formatter.write_str("managed state already has an exclusive owner"),
            Self::UnmanagedState => formatter.write_str("state is not an admissible private library-owned directory"),
            Self::LocalIo { operation, .. } => write!(formatter, "native operation failed while attempting to {operation}"),
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
            Self::FolderPaused {..}=>formatter.write_str("operation requires an unpaused folder"),
            Self::FolderIdentityMismatch {..}=>formatter.write_str("response folder identity did not match the requested folder"),
            Self::DeviceNotFound {..}=>formatter.write_str("device is not configured"),
            Self::DeviceAlreadyExists {..}=>formatter.write_str("device ID is already configured; creation did not start"),
            Self::LocalDeviceProtected=>formatter.write_str("remote-device mutation cannot target the local identity"),
            Self::PendingOfferNotFound=>formatter.write_str("pending offer is not present"),
            Self::FolderNotIgnored=>formatter.write_str("folder is not ignored for this device"),
            Self::DeviceNotIgnored=>formatter.write_str("device is not ignored"),
            Self::ConfiguredDeviceCannotBeIgnored {..}=>formatter.write_str("configured device must be explicitly removed before it is ignored"),
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
            Self::LocalIo { source, .. } => Some(source),
            Self::Transport { source, .. } => Some(source),
            Self::MutationOutcomeUnknown { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// A result returned by the control library.
pub type Result<T> = std::result::Result<T, Error>;
