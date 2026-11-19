//! Explicit native remote-management observations, separate from permission.
use crate::DeviceId;
use serde::Deserialize;
use std::{collections::BTreeMap, fmt};

/// One native tunnel probe result. An unavailable tunnel is a valid negative
/// observation, not success of a remote GUI session or proof of license status.
#[derive(Clone, Deserialize)]
pub struct DeviceTunnelProbe {
    #[serde(rename = "device")]
    pub(crate) device: DeviceId,
    #[serde(rename = "tunnel")]
    available: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}
impl DeviceTunnelProbe {
    /// Exact peer identity reported by the probe and matched to the request.
    pub fn device_id(&self) -> &DeviceId {
        &self.device
    }
    /// Whether this particular native probe reported a usable tunnel. This is
    /// a point-in-time observation and does not authenticate a management client.
    pub fn tunnel_available(&self) -> bool {
        self.available
    }
    /// Native diagnostic text, possibly containing private target information.
    /// The library does not classify licenses from human-readable error strings.
    pub fn native_error(&self) -> Option<&str> {
        self.error.as_deref()
    }
    /// Unmodeled native fields, retained for explicit inspection only.
    pub fn extra(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.extra
    }
}
impl fmt::Debug for DeviceTunnelProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceTunnelProbe")
            .field("tunnel_available", &self.available)
            .field(
                "has_native_error",
                &self.error.as_ref().is_some_and(|v| !v.is_empty()),
            )
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}
