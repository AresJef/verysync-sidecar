//! Matchable errors for control inputs and operations.

use std::fmt;

pub(crate) const GRACEFUL_SHUTDOWN_OPERATION: &str = "request graceful owned shutdown";

use crate::{DeviceId, FolderId};

/// The independent state-admission lock that refused an owned operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedStateLock {
    /// Another operation holds the sidecar's private state lease.
    LibraryLease,
    /// The native `verysync.lock` is held independently of the sidecar lease.
    EngineLock,
}

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
/// Default messages omit management credentials. Match typed variants and
/// inspect their causes when your application needs to decide what to do.
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
    /// The native official-account endpoint explicitly returned a nested error.
    /// Code 5000 also describes upstream service/network failures; it is not
    /// automatically an incorrect-password or management-authentication error.
    OfficialAccountRejected {
        /// Exact native signed error code, including future codes.
        code: i64,
        /// Bounded private native envelope, excluded from ordinary formatting.
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
    /// The fixed kernel's provider has no matching downloadable release for
    /// this target. This is a known refusal, separate from SDK artifact listing.
    UpgradeReleaseUnavailable {
        /// Actual bounded provider refusal; private bytes require explicit inspection.
        response: ResponseDiagnostic,
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
    /// An offline snapshot, its limits or restoration input is not admissible.
    StateBackupRejected {
        /// A description without private paths, credentials or manifest data.
        reason: &'static str,
    },
    /// A dedicated-state admission lock is busy. This does not authorize killing
    /// its owner or deleting the lock file; inspect the specific lock scope.
    ManagedStateInUse {
        /// Which independently checked lock refused admission.
        lock: ManagedStateLock,
    },
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
    /// A full-save preflight observed a change since the snapshot was read.
    /// No PUT was sent. Independent writers must still coordinate: this check
    /// is not an atomic server-side compare-and-swap.
    ConfigurationChanged,
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
        ///
        /// Default formatting shows only a short numeric release number.
        /// Inspect this field directly if a custom build label is needed.
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
        /// Actual engine rejection code: 3000 for Pro or 3001 for Local-API.
        code: i64,
        /// Original bounded response, hidden from ordinary formatting.
        response: ResponseDiagnostic,
    },
    /// A bounded management request did not finish before its deadline.
    Timeout {
        /// The operation that timed out.
        operation: &'static str,
    },
    /// The caller explicitly cancelled the wait for a business operation.
    OperationWaitCancelled {
        /// The operation the caller stopped waiting for.
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
    /// A file transfer input or response violates its explicit safety contract.
    ResourceTransferRejected {
        /// A description excluding file paths, URLs and upstream response bytes.
        reason: &'static str,
    },
    /// An explicit resource mutation fails a path, kind or observation contract.
    ResourceMutationRejected {
        /// A description excluding native paths and upstream private data.
        reason: &'static str,
    },
    /// The requested resource is absent during a mutation preflight.
    ResourceNotFound,
    /// A non-overwriting mutation found an existing destination before writing.
    ResourceAlreadyExists,
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
    /// The requested remote peer has no association with this folder.
    FolderPeerNotAssociated,
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
    /// Native restore timestamp safety could not be established. No restoring
    /// POST was sent. Inspect target state before making another explicit call.
    ArchiveRestorePrecondition {
        /// Static reason, without private paths or native timestamp values.
        reason: &'static str,
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
    /// VerySync may have applied the request. Check the affected files,
    /// settings or session before deciding whether to try again.
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
    /// HTTPS certificate verification rejected the selected recovery endpoint.
    TlsCertificateRejected {
        /// The original URL-redacted management transport error.
        source: Box<Error>,
    },
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
        let message = match self {
            Self::ResourceTransferRejected { reason } => {
                let summary = match *reason {
                    "resource exceeded the explicit transfer byte bound"
                    | "resource body length differs from the announced interval" =>
                        "The download stopped after opening the new file. Check it for incomplete data.",
                    _ => "The file transfer could not be completed.",
                };
                return explain(formatter, summary, reason);
            }
            Self::ResourceMutationRejected { reason } =>
                return explain(formatter, "The file operation could not be completed.", reason),
            Self::ResourceNotFound => "VerySync could not find the selected file or folder. Check the selected device, storage location and path.",
            Self::ResourceAlreadyExists => "The destination already exists. VerySync received no request to replace it. Choose another destination or review the existing file.",
            Self::CacheMiss => "The selected VerySync version is missing from the offline cache. Prepare that version before running offline.",
            Self::CacheCorrupt { reason } =>
                return explain(formatter, "The cached VerySync program failed verification. Prepare a verified copy of the same version and keep its separate data directory.", reason),
            Self::CacheRejected { reason } =>
                return explain(formatter, "The program cache could not be used.", reason),
            Self::DownloadRejected { reason } =>
                return explain(formatter, "The VerySync program could not be prepared.", reason),
            Self::DownloadHttp { status } =>
                return write!(formatter, "The program download source returned HTTP {status}. Check the source for the selected version."),
            Self::EventSubscriptionFailure => "Reading events stopped. Read the current state before starting another subscription.",
            Self::EventGenerationChanged => "VerySync's reported start time changed while reading events. Read the current state before using the event history.",
            Self::ScanNotIdle => "The folder is not ready for a new scan. Check its status on the selected device. If it is paused, resume it only when you want scanning to continue. If it is busy, wait for the current activity to finish.",
            Self::UnlistedProgramVersion => "The selected program version has no verified download in the catalog. Select a listed version or verify a local program explicitly.",
            Self::UnsupportedProgramTarget { .. } => "The catalog has no verified download for the selected system, processor and build. Review the supported targets.",
            Self::ShareKeyRejected { .. } => "VerySync declined the sharing key. Check the key and the permissions it grants on the selected instance.",
            Self::OfficialAccountRejected { code, .. } =>
                return write!(formatter, "VerySync reported a problem with the account request (code {code}). Check the account service before trying again."),
            Self::LicenseRequired { code, .. } => {
                let access = match code {
                    3000 => "VerySync Pro",
                    3001 => "permission to use this VerySync Local-API feature",
                    _ => "a VerySync feature license",
                };
                return write!(formatter, "This operation requires {access} (code {code}). Check the license on the selected instance.");
            }
            Self::IgnorePatternsRejected { .. } => "VerySync rejected one or more ignore rules. Some rules may already be stored. Read the current rules before editing or restoring them.",
            Self::ShareAlreadyConfigured { .. } => "This share is already registered on the selected device. No new registration was requested.",
            Self::ScanObservationLost => "The scan can no longer be tracked from these updates. Read the current folder status to find out whether the scan is still running.",
            Self::ProgramRejected { reason } =>
                return write!(formatter, "selected program rejected: {reason}. Check the selected VerySync program and its verification details."),
            Self::UpgradeReleaseUnavailable { .. } => "The upgrade source has no program that matches the requested version and target. Check the version and platform in the upgrade source.",
            Self::ManagedProcessExited { operation, code, .. } => {
                write!(formatter, "The managed VerySync program exited while trying to {operation}")?;
                if let Some(code) = code {
                    write!(formatter, " (exit code {code})")?;
                }
                return formatter.write_str(".");
            }
            Self::ManagedFailure { reason } =>
                return explain(formatter, "The managed VerySync operation could not be completed.", reason),
            Self::StateBackupRejected { reason } =>
                return explain(formatter, "The saved VerySync state could not be copied or restored. Keep the existing copy while you check the problem.", reason),
            Self::ManagedStateInUse { lock } => match lock {
                ManagedStateLock::LibraryLease => "Another library operation is using the selected state directory. Wait for that operation to finish or choose a separate directory.",
                ManagedStateLock::EngineLock => "A VerySync process is using the selected state directory. Verify which instance owns it before taking any action.",
            },
            Self::UnmanagedState => "The selected state directory is not recognized as belonging to this library. Use the original managed directory or a separate directory for a new instance.",
            Self::LocalIo { operation, .. } => {
                if matches!(*operation, "write resource output" | "flush resource output") {
                    return formatter.write_str("The local download stopped while writing the output. Check the new file for incomplete data before trying again.");
                }
                return write!(formatter, "A local file or system operation failed while trying to {operation}. Check access to the selected path or resource.");
            }
            Self::InvalidConfiguration { reason } =>
                return explain(formatter, "The configuration value could not be used.", reason),
            Self::ConfigurationChanged => "The configuration changed after it was read. No replacement was sent. Read the current configuration before deciding whether to apply the change.",
            Self::InvalidCredential { reason } =>
                return explain(formatter, "The supplied credential cannot be used.", reason),
            Self::InvalidIdentity { reason } =>
                return explain(formatter, "The supplied device ID cannot be used.", reason),
            Self::IdentityMismatch { .. } => "The connected device did not match the expected device. Verify the endpoint and device ID before making changes.",
            Self::IncompatibleVersion { actual } => {
                if is_version_number(actual) {
                    return write!(formatter, "The current version policy has not verified VerySync version {actual}. Check which version is running on the selected instance.");
                }
                return formatter.write_str("The selected VerySync version is outside the verified range. Check which version is running before continuing.");
            }
            Self::UnsupportedTransport { transport } => match *transport {
                "Unix-domain sockets on this platform" | "managed Unix socket" =>
                    "This build cannot connect to a Unix socket on this system. Choose an HTTP or HTTPS management address.",
                "HTTPS requires the tls feature" | "managed HTTPS requires the tls feature" =>
                    "This build cannot open an HTTPS connection. Enable the tls feature to use HTTPS.",
                "HTTPS proxy requires the tls feature" =>
                    "This build cannot connect to an HTTPS proxy. Enable the tls feature to use the selected proxy.",
                "trusted certificates require the tls feature" =>
                    "This build cannot use your trusted certificates. Enable the tls feature to verify HTTPS connections.",
                "native browser requires an explicit HTTP(S) management URL" =>
                    "The VerySync browser helper needs an HTTP or HTTPS management address. Supply the address for the selected instance.",
                _ => return explain(formatter, "This connection method is unavailable.", transport),
            },
            Self::Authentication { status } =>
                return write!(formatter, "VerySync declined authentication (HTTP {status}). Verify the credentials for the selected instance."),
            Self::AccessDenied { response } =>
                return write!(formatter, "VerySync declined access (HTTP {}). Check the credentials and permissions for this request.", response.status()),
            Self::Timeout { operation } => {
                if is_download(operation) {
                    return formatter.write_str("The download did not finish in time. If a new output file exists, check it for incomplete data.");
                }
                return write!(formatter, "The time limit expired while trying to {operation}.");
            }
            Self::OperationWaitCancelled { operation } =>
                return write!(formatter, "You stopped waiting for VerySync to {operation}. Check the operation report for its last confirmed state."),
            Self::ResponseTooLarge { limit } =>
                return write!(formatter, "The reply exceeded the configured limit of {limit} bytes."),
            Self::Http { response } =>
                return write!(formatter, "The request failed with HTTP {}. Check the service that received the request.", response.status()),
            Self::Api { operation, .. } =>
                return write!(formatter, "VerySync reported a problem while trying to {operation}."),
            Self::InvalidResponse { operation, .. } =>
                return write!(formatter, "The library could not read the reply while trying to {operation}."),
            Self::Transport { operation, .. } => {
                if is_download(operation) {
                    return formatter.write_str("The download connection was interrupted. If a new output file exists, check it for incomplete data.");
                }
                return write!(formatter, "The connection did not complete the request to {operation}. Check the selected connection.");
            }
            Self::TlsCertificateRejected { .. } =>
                "The selected endpoint's HTTPS certificate could not be verified. Check the address and trust settings before trying again.",
            Self::InvalidFolderId { reason } =>
                return explain(formatter, "The supplied folder ID cannot be used.", reason),
            Self::FolderNotFound { .. } => "The selected folder is not registered on this device. Check the device and folder ID.",
            Self::FolderPaused { .. } => "This operation needs a running folder. The selected folder is paused.",
            Self::ArchiveRestorePrecondition { reason } =>
                return explain(formatter, "The restore did not start. Review the selected archive and the destination before trying again.", reason),
            Self::FolderIdentityMismatch { .. } => "VerySync returned a different folder from the one requested. Verify the selected folder and device.",
            Self::DeviceNotFound { .. } => "The selected device is not registered on this instance. Check the device ID.",
            Self::DeviceAlreadyExists { .. } => "This device is already registered. No new registration was requested.",
            Self::LocalDeviceProtected => "This operation changes a remote device. The selected ID belongs to the local device.",
            Self::PendingOfferNotFound => "The selected offer is no longer available. Refresh the list of pending offers.",
            Self::FolderPeerNotAssociated => "The selected folder is not shared with this device. Check the folder's sharing settings.",
            Self::FolderNotIgnored => "This folder is not on the ignore list for the selected device.",
            Self::DeviceNotIgnored => "This device is not on the ignore list.",
            Self::ConfiguredDeviceCannotBeIgnored { .. } => "The device is already registered. Review its shares and existing registration before deciding whether to remove it and ignore future offers.",
            Self::FolderAlreadyExists { .. } => "This folder ID is already registered. No new registration was requested.",
            Self::FolderPathAlreadyConfigured { .. } => "The selected path is already registered. No new registration was requested.",
            Self::MutationOutcomeUnknown { operation, .. } =>
                return explain_unknown_outcome(formatter, operation),
            Self::InvalidEndpoint { reason } =>
                return explain(formatter, "The supplied connection address cannot be used.", reason),
            Self::InvalidPath { reason } =>
                return explain(formatter, "The selected path cannot be used on the target system.", reason),
            Self::PathEncoding => "The target protocol cannot represent this path without changing its name. Choose a path that the target can represent.",
        };
        formatter.write_str(message)
    }
}

fn is_version_number(label: &str) -> bool {
    if label.len() > 24 {
        return false;
    }
    let mut parts = label.strip_prefix('v').unwrap_or(label).split('.');
    let numbers = [parts.next(), parts.next(), parts.next()];
    parts.next().is_none()
        && numbers.into_iter().all(|part| {
            part.is_some_and(|part| {
                !part.is_empty()
                    && part.bytes().all(|byte| byte.is_ascii_digit())
                    && (part.len() == 1 || !part.starts_with('0'))
            })
        })
}

fn explain(formatter: &mut fmt::Formatter<'_>, summary: &str, reason: &str) -> fmt::Result {
    formatter.write_str(summary)?;
    let mut chars = reason.chars();
    if let Some(first) = chars.next() {
        write!(formatter, " {}{}", first.to_uppercase(), chars.as_str())?;
        if !reason.ends_with(['.', '!', '?']) {
            formatter.write_str(".")?;
        }
    }
    Ok(())
}

fn is_download(operation: &str) -> bool {
    matches!(
        operation,
        "download file resource" | "download resource archive" | "download selected resources"
    )
}

fn explain_unknown_outcome(formatter: &mut fmt::Formatter<'_>, operation: &str) -> fmt::Result {
    let message = match operation {
        "log in to native GUI" | "reconcile native GUI authentication" =>
            "VerySync may have signed you in. Check for an existing session on the selected instance before trying again.",
        "log out native GUI session" =>
            "VerySync may have ended the session. Check whether the session still works before trying again.",
        "set local GUI credentials" =>
            "VerySync may have changed the sign-in settings. Check the selected instance before trying again.",
        "rotate management API key" | "reconcile management API key rotation" =>
            "VerySync may have replaced the API key. Check which key works on the selected instance before requesting another change.",
        "upload file resource" | "write existing resource text" =>
            "The destination file may have changed. Compare its contents with your source on the selected device before trying again.",
        "move resource" | "copy resource" =>
            "Some files may have changed. Check the source and destination on the selected device before trying again.",
        "delete resource" =>
            "Some or all of the selected files may have been removed. Check what remains on the selected device before requesting another deletion.",
        "create resource directory" =>
            "The folder may already exist. Check the selected destination on the device before trying again.",
        "read back unregistered folder" =>
            "The original device acknowledged the request to unregister the folder. We could not confirm whether the folder is still registered. Check the folder list on that device before sending another removal request.",
        "restore archived directory versions" | "restore explicit file versions" =>
            "The restore may have written some files. Check the destination on the selected device and preserve any files you still need before trying again.",
        GRACEFUL_SHUTDOWN_OPERATION =>
            "VerySync may have stopped. Check whether the selected instance is still running before sending another shutdown request.",
        "request native shutdown" | "request native restart" | "validate native restart acknowledgement" =>
            "VerySync may have stopped or restarted. Check whether the selected instance is running before sending another request.",
        "request server-selected upgrade" | "upload fixed kernel upgrade" | "run kernel CLI upgrade" =>
            "The upgrade may have started. Check the installed version and running program before trying again.",
        _ => return write!(formatter, "Could not confirm the result of the request to {operation}. Check the affected state before trying again."),
    };
    formatter.write_str(message)
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LocalIo { source, .. } => Some(source),
            Self::Transport { source, .. } => Some(source),
            Self::MutationOutcomeUnknown { source, .. }
            | Self::TlsCertificateRejected { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// A result returned by the control library.
pub type Result<T> = std::result::Result<T, Error>;
