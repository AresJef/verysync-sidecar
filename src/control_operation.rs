//! Durable, read-only descriptions of explicitly selected control mutations.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    DeviceId, Error, GuiListenAddress, GuiListenerPatch, GuiSocketPermissions, ManagementEndpoint,
    PathStyle, Result, TargetPath,
};

const SCHEMA_VERSION: u16 = 1;
const MAX_RECEIPT_BYTES: usize = 8192;

/// What the initiating application could establish about a write.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ControlSubmission {
    /// The intent was created before the transport checkpoint.
    Prepared,
    /// The initiating call finished before handing a write to its transport.
    NotSubmitted,
    /// The write could have been sent. Check the target with a fresh read.
    ///
    /// This also represents the conservative checkpoint saved just before a
    /// write, if the initiating process exited or could not save its outcome.
    PossiblySubmitted,
    /// A complete native acknowledgement was received for the request.
    Acknowledged {
        /// The actual HTTP status of the completed acknowledgement.
        status: u16,
    },
}

/// The named control action recorded by a receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ControlOperationKind {
    /// Change one or more native GUI listener fields.
    GuiListenerChange,
}

/// A redacted event that can be sent to the caller's own logging facility.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlOperationEvent {
    /// Local correlation ID. It is not a native task ID or deduplication key.
    pub operation_id: String,
    /// The selected action.
    pub kind: ControlOperationKind,
    /// Submission evidence at this point in the operation.
    pub submission: ControlSubmission,
    /// Time when the intent was prepared, in Unix epoch milliseconds.
    pub started_at_unix_millis: u64,
    /// Elapsed time observed by the initiating call.
    pub elapsed_millis: u64,
    /// Actual status if HTTP response headers were seen.
    pub response_status: Option<u16>,
}

/// A single-use prepared action. It can be executed only with its original
/// management endpoint and matching device identity and engine version.
///
/// A reopened receipt cannot be converted into this type.
pub struct PreparedControlOperation {
    pub(crate) endpoint: ManagementEndpoint,
    pub(crate) receipt: ControlOperationReceipt,
}

impl PreparedControlOperation {
    /// Borrow the intent for private storage or a redacted log event.
    pub fn receipt(&self) -> &ControlOperationReceipt {
        &self.receipt
    }
}

impl fmt::Debug for PreparedControlOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedControlOperation")
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

/// The original result and the durable evidence from the same initiating call.
#[derive(Debug)]
pub struct ControlOperationResult<T> {
    /// Receipt for this attempt. Keep it if the result is uncertain.
    pub receipt: ControlOperationReceipt,
    /// The same operation result and error contract as the original write API.
    pub result: Result<T>,
}

/// A bounded, versioned private receipt for an explicitly initiated mutation.
///
/// It contains the selected settings and device identity needed for a later
/// observation. Store it privately. It carries no management credentials,
/// trusted endpoint, process handle or permission to send a write.
#[derive(Clone)]
pub struct ControlOperationReceipt(ReceiptData);

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReceiptData {
    schema_version: u16,
    operation_id: String,
    device_id: DeviceId,
    version_fingerprint: [u8; 32],
    started_at_unix_millis: u64,
    elapsed_millis: u64,
    submission: ControlSubmission,
    response_status: Option<u16>,
    intent: ControlIntent,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ControlIntent {
    GuiListenerChange { unix: bool, fields: ListenerFields },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListenerFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(rename = "useTLS", skip_serializing_if = "Option::is_none")]
    use_tls: Option<bool>,
    #[serde(
        rename = "unixSocketPermissions",
        skip_serializing_if = "Option::is_none"
    )]
    socket_permissions: Option<String>,
}

impl ListenerFields {
    fn patch(&self, style: PathStyle) -> Result<GuiListenerPatch> {
        let mut patch = GuiListenerPatch::default();
        if let Some(value) = self.enabled {
            patch = patch.enabled(value);
        }
        if let Some(value) = &self.address {
            let address = if style == PathStyle::Unix && value.starts_with('/') {
                GuiListenAddress::unix_socket(TargetPath::remote(style, value.clone())?)?
            } else {
                GuiListenAddress::tcp(value)?
            };
            patch = patch.address(address);
        }
        if let Some(value) = self.use_tls {
            patch = patch.use_tls(value);
        }
        if let Some(value) = &self.socket_permissions {
            let mode = if value.is_empty() {
                GuiSocketPermissions::NativeDefault
            } else {
                let number = u16::from_str_radix(value, 8).map_err(|_| invalid_receipt())?;
                if value != &format!("{number:04o}") {
                    return Err(invalid_receipt());
                }
                GuiSocketPermissions::Mode(number)
            };
            patch = patch.unix_socket_permissions(mode);
        }
        // Use the existing typed validation for empty patches, permissions,
        // and target-specific paths in both the write and recovery directions.
        patch.body(style)?;
        Ok(patch)
    }
}

impl ControlOperationReceipt {
    /// Local operation ID for matching caller logs and private evidence.
    pub fn id(&self) -> &str {
        &self.0.operation_id
    }

    /// Device identity selected while this intent was prepared.
    pub fn target_device_id(&self) -> &DeviceId {
        &self.0.device_id
    }

    /// Original submission evidence. A subsequent read does not change it.
    pub fn submission(&self) -> ControlSubmission {
        self.0.submission
    }

    /// HTTP response status, available even if the response body was incomplete.
    pub fn response_status(&self) -> Option<u16> {
        self.0.response_status
    }

    /// Prepare a redacted log record without taking over the caller's logging.
    pub fn log_event(&self) -> ControlOperationEvent {
        ControlOperationEvent {
            operation_id: self.id().to_owned(),
            kind: match self.0.intent {
                ControlIntent::GuiListenerChange { .. } => ControlOperationKind::GuiListenerChange,
            },
            submission: self.submission(),
            started_at_unix_millis: self.0.started_at_unix_millis,
            elapsed_millis: self.0.elapsed_millis,
            response_status: self.response_status(),
        }
    }

    /// Encode a versioned receipt for the caller's private storage.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(&self.0).map_err(|_| invalid_receipt())?;
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(invalid_receipt());
        }
        Ok(bytes)
    }

    /// Reopen a receipt after enforcing the version, size and field contracts.
    /// This does not open an endpoint or authorize a control request.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RECEIPT_BYTES
            || bytes
                .iter()
                .copied()
                .find(|byte| !byte.is_ascii_whitespace())
                != Some(b'{')
        {
            return Err(invalid_receipt());
        }
        let data: ReceiptData = serde_json::from_slice(bytes).map_err(|_| invalid_receipt())?;
        if data.schema_version != SCHEMA_VERSION {
            return Err(Error::InvalidConfiguration {
                reason: "control operation receipt uses an unsupported version",
            });
        }
        let id_is_valid = data.operation_id.len() == 32
            && data
                .operation_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        let status_is_valid = data
            .response_status
            .is_none_or(|status| (100..=599).contains(&status))
            && match data.submission {
                ControlSubmission::Prepared | ControlSubmission::NotSubmitted => {
                    data.response_status.is_none()
                }
                ControlSubmission::Acknowledged { status } => {
                    (200..300).contains(&status) && data.response_status == Some(status)
                }
                ControlSubmission::PossiblySubmitted => true,
            };
        if !id_is_valid || !status_is_valid {
            return Err(invalid_receipt());
        }
        let receipt = Self(data);
        match &receipt.0.intent {
            ControlIntent::GuiListenerChange { .. } => {
                receipt.gui_listener_patch()?;
            }
        }
        Ok(receipt)
    }

    pub(crate) fn for_gui_listener(
        device_id: DeviceId,
        version: &str,
        patch: &GuiListenerPatch,
        style: PathStyle,
    ) -> Result<Self> {
        let fields = serde_json::from_value(patch.body(style)?).map_err(|_| invalid_receipt())?;
        Self::new(
            device_id,
            version,
            ControlIntent::GuiListenerChange {
                unix: style == PathStyle::Unix,
                fields,
            },
        )
    }

    fn new(device_id: DeviceId, version: &str, intent: ControlIntent) -> Result<Self> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| Error::InvalidConfiguration {
            reason: "the control operation ID could not be generated",
        })?;
        let receipt = Self(ReceiptData {
            schema_version: SCHEMA_VERSION,
            operation_id: bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
            device_id,
            version_fingerprint: version_fingerprint(version),
            started_at_unix_millis: milliseconds(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default(),
            ),
            elapsed_millis: 0,
            submission: ControlSubmission::Prepared,
            response_status: None,
            intent,
        });
        receipt.encode()?;
        Ok(receipt)
    }

    pub(crate) fn version_fingerprint(&self) -> &[u8; 32] {
        &self.0.version_fingerprint
    }

    pub(crate) fn gui_listener_patch(&self) -> Result<GuiListenerPatch> {
        match &self.0.intent {
            ControlIntent::GuiListenerChange { unix, fields } => fields.patch(if *unix {
                PathStyle::Unix
            } else {
                PathStyle::Windows
            }),
        }
    }

    pub(crate) fn note_submission(
        &mut self,
        submission: ControlSubmission,
        response_status: Option<u16>,
        elapsed: Duration,
    ) {
        self.0.elapsed_millis = milliseconds(elapsed);
        self.0.submission = submission;
        self.0.response_status = response_status;
    }
}

impl fmt::Debug for ControlOperationReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlOperationReceipt")
            .field("schema_version", &self.0.schema_version)
            .field("event", &self.log_event())
            .finish_non_exhaustive()
    }
}

pub(crate) fn version_fingerprint(version: &str) -> [u8; 32] {
    Sha256::digest(version.as_bytes()).into()
}

fn milliseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn invalid_receipt() -> Error {
    Error::InvalidConfiguration {
        reason: "the control operation receipt is damaged or contains unsupported fields",
    }
}
