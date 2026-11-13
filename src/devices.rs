//! Explicit peer configuration, independent of connection and transfer state.
use crate::{DeviceId, DeviceTransport, Error, FolderId, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// Compression setting reported by the selected engine.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceCompression {
    /// Compress all eligible data.
    Always,
    /// Compress protocol metadata.
    Metadata,
    /// Do not request compression.
    Never,
    /// An unrecognized readback value, retained for explicit inspection.
    /// Typed mutations reject this variant rather than guessing its semantics.
    #[serde(untagged)]
    Unknown(String),
}
impl fmt::Debug for DeviceCompression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Always => "DeviceCompression::Always",
            Self::Metadata => "DeviceCompression::Metadata",
            Self::Never => "DeviceCompression::Never",
            Self::Unknown(_) => "DeviceCompression::Unknown([REDACTED])",
        })
    }
}

/// A device configuration snapshot. This is not proof of a live peer connection.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceConfig {
    /// Actual configured certificate identity.
    #[serde(rename = "deviceID")]
    pub device_id: DeviceId,
    /// Configured display name, which the engine may later update on connection.
    pub name: String,
    /// Engine-interpreted peer addresses, such as `dynamic` or `tcp://host:port`.
    /// These are protocol addresses, not local filesystem paths.
    pub addresses: Vec<String>,
    /// Current compression setting, retaining future unknown values.
    pub compression: DeviceCompression,
    /// Device-level pause setting, independent of folder or instance pauses.
    pub paused: bool,
    /// Actual transport selectors, if reported. An empty list means engine policy,
    /// not proof that every transport is disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_transports: Option<Vec<DeviceTransport>>,
    /// Other actual fields. Values can be sensitive; Debug omits them.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for DeviceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceConfig")
            .field("paused", &self.paused)
            .field("address_count", &self.addresses.len())
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// Actual device defaults. The template's identity may be empty, unlike a peer ID.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceDefaults {
    /// Default display name.
    pub name: String,
    /// Default peer address policy.
    pub addresses: Vec<String>,
    /// Default compression policy.
    pub compression: DeviceCompression,
    /// Default device-level pause.
    pub paused: bool,
    /// Actual default selectors, if supplied. Empty follows the engine policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_transports: Option<Vec<DeviceTransport>>,
    /// Unmodeled defaults, preserved verbatim when creating a peer.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for DeviceDefaults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceDefaults")
            .field("paused", &self.paused)
            .field("address_count", &self.addresses.len())
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// Explicit peer changes. Unspecified fields are not sent by PATCH.
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) addresses: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) compression: Option<DeviceCompression>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) paused: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) allowed_transports: Option<Vec<DeviceTransport>>,
}
impl DevicePatch {
    /// Set the display name, including an explicitly empty name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
    /// Replace this peer's explicit protocol address list.
    /// The library does not resolve, connect to, or infer reachability of them.
    pub fn addresses(mut self, addresses: Vec<String>) -> Self {
        self.addresses = Some(addresses);
        self
    }
    /// Select one of the known compression values.
    pub fn compression(mut self, compression: DeviceCompression) -> Self {
        self.compression = Some(compression);
        self
    }
    /// Set only this device's pause layer.
    pub fn paused(mut self, paused: bool) -> Self {
        self.paused = Some(paused);
        self
    }
    /// Replace explicit protocol selectors; an empty list asks for engine policy.
    /// A matching readback does not prove a UDP/relay path has been exercised.
    pub fn allowed_transports(mut self, values: Vec<DeviceTransport>) -> Self {
        self.allowed_transports = Some(values);
        self
    }
    pub(crate) fn validate(&self, require_fields: bool) -> Result<()> {
        if require_fields
            && self.name.is_none()
            && self.addresses.is_none()
            && self.compression.is_none()
            && self.paused.is_none()
            && self.allowed_transports.is_none()
        {
            return Err(Error::InvalidConfiguration {
                reason: "device patch must contain at least one field",
            });
        }
        if matches!(self.compression, Some(DeviceCompression::Unknown(_))) {
            return Err(Error::InvalidConfiguration {
                reason: "unknown device compression cannot be submitted by a typed mutation",
            });
        }
        if self
            .allowed_transports
            .as_ref()
            .is_some_and(|v| v.iter().any(|t| matches!(t, DeviceTransport::Unknown(_))))
        {
            return Err(Error::InvalidConfiguration {
                reason: "unknown device transport cannot be submitted by a typed mutation",
            });
        }
        if self.addresses.as_ref().is_some_and(|values| {
            values
                .iter()
                .any(|v| v.is_empty() || v.chars().any(char::is_control))
        }) {
            return Err(Error::InvalidConfiguration {
                reason: "device addresses must be nonempty values without control characters",
            });
        }
        Ok(())
    }
    pub(crate) fn matches(&self, value: &DeviceConfig) -> bool {
        self.name.as_ref().is_none_or(|v| *v == value.name)
            && self
                .addresses
                .as_ref()
                .is_none_or(|v| *v == value.addresses)
            && self
                .compression
                .as_ref()
                .is_none_or(|v| *v == value.compression)
            && self.paused.is_none_or(|v| v == value.paused)
            && self
                .allowed_transports
                .as_ref()
                .is_none_or(|v| value.allowed_transports.as_ref() == Some(v))
    }
}
impl fmt::Debug for DevicePatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DevicePatch")
            .field("changes_name", &self.name.is_some())
            .field("changes_addresses", &self.addresses.is_some())
            .field("changes_compression", &self.compression.is_some())
            .field("changes_transports", &self.allowed_transports.is_some())
            .field("paused", &self.paused)
            .finish()
    }
}

/// A new exact peer identity plus explicit overrides of this instance's defaults.
#[derive(Clone)]
pub struct CreateDeviceOptions {
    pub(crate) id: DeviceId,
    pub(crate) patch: DevicePatch,
}
impl CreateDeviceOptions {
    /// Create a new peer with upstream defaults; do not replace an existing ID.
    pub fn new(id: DeviceId) -> Self {
        Self {
            id,
            patch: DevicePatch::default(),
        }
    }
    /// Supply explicit overrides, preserving all other engine defaults.
    pub fn settings(mut self, patch: DevicePatch) -> Self {
        self.patch = patch;
        self
    }
    /// The requested identity, useful for reconciling cancellation or lost replies.
    pub fn device_id(&self) -> &DeviceId {
        &self.id
    }
}
impl fmt::Debug for CreateDeviceOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateDeviceOptions")
            .field("settings", &self.patch)
            .finish_non_exhaustive()
    }
}

/// Configuration readback following one creation or patch, not transfer evidence.
#[derive(Clone, Debug)]
pub struct DeviceUpdate {
    /// The current engine-reported device configuration.
    pub configuration: DeviceConfig,
    /// Whether every explicit requested field matches this readback.
    pub requested_fields_match: bool,
}

/// Observations following one device DELETE. No local file deletion is requested.
#[derive(Clone, Debug)]
pub struct DeviceRemoval {
    /// Configuration observed immediately before the modifying request.
    pub previous_configuration: DeviceConfig,
    /// Whether the exact ID is absent from the following device snapshot.
    pub configuration_absent: bool,
    /// Folder IDs still referring to the peer in the following folder snapshot.
    /// An empty list observes detachment, not synchronization or file deletion.
    pub remaining_folder_associations: Vec<FolderId>,
}
