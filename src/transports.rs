//! Explicit transport settings and separately reported tracker/NAT state.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// Actual fixed-version transport settings, without a connectivity guarantee.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportConfig {
    /// Whether the built-in tracker is enabled.
    pub tracker_enabled: bool,
    /// Whether UDP transport is enabled.
    pub udp_enabled: bool,
    /// Configured UDP port.
    pub udp_port: u16,
    /// Whether automatic NAT mapping is enabled.
    pub nat_enabled: bool,
    /// Whether relay client transport is enabled.
    pub relays_enabled: bool,
    /// Whether TCP punching is enabled; distinct from NAT mapping.
    pub tcp_punch_enabled: bool,
    /// Explicit STUN server selectors. Empty is retained as returned.
    pub stun_servers: Vec<String>,
    /// Explicit relay client addresses. This does not enable a relay server.
    pub custom_relay_addresses: Vec<String>,
    /// Configured NAT lease in whole minutes.
    pub nat_lease_minutes: u32,
    /// Configured NAT renewal in whole minutes.
    pub nat_renewal_minutes: u32,
    /// Configured NAT operation timeout in whole seconds.
    pub nat_timeout_seconds: u32,
    /// Other actual settings; values may contain private data.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for TransportConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportConfig")
            .field("tracker_enabled", &self.tracker_enabled)
            .field("udp_enabled", &self.udp_enabled)
            .field("nat_enabled", &self.nat_enabled)
            .field("relays_enabled", &self.relays_enabled)
            .finish_non_exhaustive()
    }
}

/// Send only explicitly selected transport settings. Network traffic can result.
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    tracker_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nat_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relays_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_punch_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stun_servers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    custom_relay_addresses: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nat_lease_minutes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nat_renewal_minutes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nat_timeout_seconds: Option<u32>,
}
impl TransportPatch {
    /// Explicitly enable or disable the built-in tracker.
    pub fn tracker(mut self, enabled: bool) -> Self {
        self.tracker_enabled = Some(enabled);
        self
    }
    /// Explicitly enable or disable UDP transport.
    pub fn udp(mut self, enabled: bool) -> Self {
        self.udp_enabled = Some(enabled);
        self
    }
    /// Select a nonzero UDP port independently of listener and management ports.
    pub fn udp_port(mut self, port: u16) -> Self {
        self.udp_port = Some(port);
        self
    }
    /// Explicitly enable or disable NAT mapping.
    pub fn nat_mapping(mut self, enabled: bool) -> Self {
        self.nat_enabled = Some(enabled);
        self
    }
    /// Explicitly enable or disable relay client transport.
    pub fn relay_client(mut self, enabled: bool) -> Self {
        self.relays_enabled = Some(enabled);
        self
    }
    /// Explicitly enable or disable TCP punching.
    pub fn tcp_punching(mut self, enabled: bool) -> Self {
        self.tcp_punch_enabled = Some(enabled);
        self
    }
    /// Replace STUN server selectors without enabling NAT mapping or UDP.
    pub fn stun_servers(mut self, values: Vec<String>) -> Self {
        self.stun_servers = Some(values);
        self
    }
    /// Replace relay addresses without enabling relay client transport.
    pub fn relay_addresses(mut self, values: Vec<String>) -> Self {
        self.custom_relay_addresses = Some(values);
        self
    }
    /// Select the NAT lease duration in whole minutes.
    pub fn nat_lease_minutes(mut self, value: u32) -> Self {
        self.nat_lease_minutes = Some(value);
        self
    }
    /// Select the NAT renewal duration in whole minutes.
    pub fn nat_renewal_minutes(mut self, value: u32) -> Self {
        self.nat_renewal_minutes = Some(value);
        self
    }
    /// Select the NAT request timeout in whole seconds.
    pub fn nat_timeout_seconds(mut self, value: u32) -> Self {
        self.nat_timeout_seconds = Some(value);
        self
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.tracker_enabled.is_none()
            && self.udp_enabled.is_none()
            && self.udp_port.is_none()
            && self.nat_enabled.is_none()
            && self.relays_enabled.is_none()
            && self.tcp_punch_enabled.is_none()
            && self.stun_servers.is_none()
            && self.custom_relay_addresses.is_none()
            && self.nat_lease_minutes.is_none()
            && self.nat_renewal_minutes.is_none()
            && self.nat_timeout_seconds.is_none()
        {
            return Err(Error::InvalidConfiguration {
                reason: "transport patch must contain at least one field",
            });
        }
        if self.udp_port == Some(0) {
            return Err(Error::InvalidConfiguration {
                reason: "UDP port must be nonzero",
            });
        }
        for value in self
            .stun_servers
            .iter()
            .chain(self.custom_relay_addresses.iter())
            .flatten()
        {
            if value.is_empty() || value.chars().any(char::is_control) {
                return Err(Error::InvalidConfiguration {
                    reason: "transport addresses must be nonempty without controls",
                });
            }
        }
        Ok(())
    }
    pub(crate) fn matches(&self, v: &TransportConfig) -> bool {
        self.tracker_enabled.is_none_or(|x| x == v.tracker_enabled)
            && self.udp_enabled.is_none_or(|x| x == v.udp_enabled)
            && self.udp_port.is_none_or(|x| x == v.udp_port)
            && self.nat_enabled.is_none_or(|x| x == v.nat_enabled)
            && self.relays_enabled.is_none_or(|x| x == v.relays_enabled)
            && self
                .tcp_punch_enabled
                .is_none_or(|x| x == v.tcp_punch_enabled)
            && self
                .stun_servers
                .as_ref()
                .is_none_or(|x| *x == v.stun_servers)
            && self
                .custom_relay_addresses
                .as_ref()
                .is_none_or(|x| *x == v.custom_relay_addresses)
            && self
                .nat_lease_minutes
                .is_none_or(|x| x == v.nat_lease_minutes)
            && self
                .nat_renewal_minutes
                .is_none_or(|x| x == v.nat_renewal_minutes)
            && self
                .nat_timeout_seconds
                .is_none_or(|x| x == v.nat_timeout_seconds)
    }
}
impl fmt::Debug for TransportPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportPatch")
            .field("tracker", &self.tracker_enabled)
            .field("udp", &self.udp_enabled)
            .field("nat", &self.nat_enabled)
            .field("relay_client", &self.relays_enabled)
            .finish_non_exhaustive()
    }
}
/// Configuration receipt; does not assert any selected protocol is connected.
#[derive(Clone, Debug)]
pub struct TransportUpdate {
    /// Actual configuration after one mutation.
    pub configuration: TransportConfig,
    /// Whether every explicitly requested field matches readback.
    pub requested_fields_match: bool,
}
/// Current tracker observations, with unknown states and metadata retained.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrackerStatus {
    /// Actual state label; an unfamiliar value is not guessed as connected.
    #[serde(rename = "connectStatus")]
    pub connection_state: String,
    /// Actual reason when provided. It may contain private network information.
    pub disconnect_reason: Option<String>,
    /// Other actual fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for TrackerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrackerStatus")
            .field("has_disconnect_reason", &self.disconnect_reason.is_some())
            .finish_non_exhaustive()
    }
}
/// Engine-reported tracker and NAT state, not an independent traversal test.
#[derive(Clone, Deserialize)]
pub struct TransportStatus {
    /// Reported NAT classification; unknown remains the upstream unknown label.
    #[serde(rename = "natType")]
    pub nat_type: String,
    /// Actual tracker state.
    #[serde(rename = "trackerStatus")]
    pub tracker: TrackerStatus,
}
impl fmt::Debug for TransportStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportStatus")
            .field("tracker", &self.tracker)
            .finish_non_exhaustive()
    }
}
