//! Network configuration and live observations have separate result types.
use crate::{DeviceId, Error, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// A transport selector accepted in the fixed GUI's device configuration.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceTransport {
    /// The TCP protocol selector.
    Tcp,
    /// The UDP protocol selector; runtime validation is separate.
    Udp,
    /// The relay selector; runtime validation is separate.
    Relay,
    /// Unrecognized readback, retained but refused by typed writes.
    #[serde(untagged)]
    Unknown(String),
}
impl fmt::Debug for DeviceTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "DeviceTransport::Tcp",
            Self::Udp => "DeviceTransport::Udp",
            Self::Relay => "DeviceTransport::Relay",
            Self::Unknown(_) => "DeviceTransport::Unknown([REDACTED])",
        })
    }
}

/// Current listener and discovery options, independent of actual reachability.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConfig {
    /// Engine-interpreted listening URLs. Empty means no configured listeners.
    pub listen_addresses: Vec<String>,
    /// Stored discovery server selectors. The fixed kernel was observed using
    /// built-in providers even after custom selectors were saved and restarted.
    /// This field does not establish which server is actually contacted.
    pub global_announce_servers: Vec<String>,
    /// Whether global discovery is enabled in configuration.
    pub global_announce_enabled: bool,
    /// Whether local discovery is enabled in configuration.
    pub local_announce_enabled: bool,
    /// Configured local discovery port.
    pub local_announce_port: u16,
    /// Engine-interpreted local multicast address.
    #[serde(rename = "localAnnounceMCAddr")]
    pub local_announce_mc_addr: String,
    /// Actual reconnection interval in seconds, including engine normalization.
    #[serde(rename = "reconnectionIntervalS")]
    pub reconnection_interval_seconds: u64,
    /// Other actual options. Values may contain secrets; Debug omits them.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for NetworkConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkConfig")
            .field("listener_count", &self.listen_addresses.len())
            .field("global_discovery", &self.global_announce_enabled)
            .field("local_discovery", &self.local_announce_enabled)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// Partial network settings. Unspecified fields are never sent by PATCH.
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) listen_addresses: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) global_announce_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) local_announce_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) local_announce_port: Option<u16>,
    #[serde(
        rename = "localAnnounceMCAddr",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) local_announce_mc_addr: Option<String>,
    #[serde(
        rename = "reconnectionIntervalS",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) reconnection_interval_seconds: Option<u64>,
}
impl NetworkPatch {
    /// Replace the listening URL list; this does not change the management URL.
    pub fn listen_addresses(mut self, values: Vec<String>) -> Self {
        self.listen_addresses = Some(values);
        self
    }
    /// Set global discovery explicitly. Observe actual results separately.
    pub fn global_discovery(mut self, value: bool) -> Self {
        self.global_announce_enabled = Some(value);
        self
    }
    /// Set local discovery explicitly. This can emit local-network traffic.
    pub fn local_discovery(mut self, value: bool) -> Self {
        self.local_announce_enabled = Some(value);
        self
    }
    /// Choose the local discovery port.
    pub fn local_discovery_port(mut self, value: u16) -> Self {
        self.local_announce_port = Some(value);
        self
    }
    /// Choose the engine-interpreted local multicast address.
    pub fn local_discovery_multicast(mut self, value: impl Into<String>) -> Self {
        self.local_announce_mc_addr = Some(value.into());
        self
    }
    /// Choose whole seconds; the engine can normalize it. Zero is rejected.
    pub fn reconnection_interval_seconds(mut self, value: u64) -> Self {
        self.reconnection_interval_seconds = Some(value);
        self
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.listen_addresses.is_none()
            && self.global_announce_enabled.is_none()
            && self.local_announce_enabled.is_none()
            && self.local_announce_port.is_none()
            && self.local_announce_mc_addr.is_none()
            && self.reconnection_interval_seconds.is_none()
        {
            return Err(Error::InvalidConfiguration {
                reason: "network patch must contain at least one field",
            });
        }
        if self.reconnection_interval_seconds == Some(0) {
            return Err(Error::InvalidConfiguration {
                reason: "reconnection interval must be nonzero",
            });
        }
        for value in self
            .listen_addresses
            .iter()
            .flatten()
            .map(String::as_str)
            .chain(self.local_announce_mc_addr.as_deref())
        {
            if value.is_empty() || value.chars().any(char::is_control) {
                return Err(Error::InvalidConfiguration {
                    reason: "network addresses must be nonempty without control characters",
                });
            }
        }
        Ok(())
    }
    pub(crate) fn matches(&self, v: &NetworkConfig) -> bool {
        self.listen_addresses
            .as_ref()
            .is_none_or(|x| *x == v.listen_addresses)
            && self
                .global_announce_enabled
                .is_none_or(|x| x == v.global_announce_enabled)
            && self
                .local_announce_enabled
                .is_none_or(|x| x == v.local_announce_enabled)
            && self
                .local_announce_port
                .is_none_or(|x| x == v.local_announce_port)
            && self
                .local_announce_mc_addr
                .as_ref()
                .is_none_or(|x| *x == v.local_announce_mc_addr)
            && self
                .reconnection_interval_seconds
                .is_none_or(|x| x == v.reconnection_interval_seconds)
    }
}
impl fmt::Debug for NetworkPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkPatch")
            .field("changes_listeners", &self.listen_addresses.is_some())
            .field("global_discovery", &self.global_announce_enabled)
            .field("local_discovery", &self.local_announce_enabled)
            .finish_non_exhaustive()
    }
}
/// Actual configuration readback following one partial network change.
#[derive(Clone, Debug)]
pub struct NetworkUpdate {
    /// The current engine configuration.
    pub configuration: NetworkConfig,
    /// Whether every explicit setting matches; not a listener/connection verdict.
    pub requested_fields_match: bool,
}

/// Observed connection kind, retaining unrecognized future types.
#[derive(Clone, Eq, PartialEq, Deserialize)]
pub enum PeerConnectionType {
    /// A TCP client-side connection.
    #[serde(rename = "tcp-client")]
    TcpClient,
    /// A TCP server-side connection.
    #[serde(rename = "tcp-server")]
    TcpServer,
    /// A QUIC client connection, observed with UDP-only device selectors.
    #[serde(rename = "quic-client")]
    QuicClient,
    /// A QUIC server connection, observed with UDP-only device selectors.
    #[serde(rename = "quic-server")]
    QuicServer,
    /// A relay session initiated by this peer.
    #[serde(rename = "relay-client")]
    RelayClient,
    /// A relay session accepted by this peer.
    #[serde(rename = "relay-server")]
    RelayServer,
    /// An unrecognized upstream type, not guessed as direct or relayed.
    #[serde(untagged)]
    Unknown(String),
}
impl fmt::Debug for PeerConnectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TcpClient => "PeerConnectionType::TcpClient",
            Self::TcpServer => "PeerConnectionType::TcpServer",
            Self::QuicClient => "PeerConnectionType::QuicClient",
            Self::QuicServer => "PeerConnectionType::QuicServer",
            Self::RelayClient => "PeerConnectionType::RelayClient",
            Self::RelayServer => "PeerConnectionType::RelayServer",
            Self::Unknown(_) => "PeerConnectionType::Unknown([REDACTED])",
        })
    }
}
/// Fresh peer connection data; absent metrics remain unknown, not zero.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerConnection {
    /// The engine's actual connected flag.
    pub connected: bool,
    /// Reported device-level pause, when present.
    pub paused: Option<bool>,
    /// Reported connection address; does not grant access or verify a peer itself.
    pub address: Option<String>,
    /// Reported transport kind.
    #[serde(rename = "type")]
    pub connection_type: Option<PeerConnectionType>,
    /// Cumulative incoming bytes, when reported.
    pub in_bytes_total: Option<u64>,
    /// Cumulative outgoing bytes, when reported.
    pub out_bytes_total: Option<u64>,
    /// Upstream local-network classification, when reported.
    pub is_local: Option<bool>,
    /// Upstream connection timestamp, without timezone conversion.
    pub started_at: Option<String>,
    /// Other actual fields, including unmodeled primary-connection metadata.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for PeerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerConnection")
            .field("connected", &self.connected)
            .field("paused", &self.paused)
            .field("connection_type", &self.connection_type)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}
/// Engine-reported aggregate connection counters.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionTotals {
    /// Reported incoming bytes; missing remains unknown.
    pub in_bytes_total: Option<u64>,
    /// Reported outgoing bytes; missing remains unknown.
    pub out_bytes_total: Option<u64>,
    /// Other actual fields, hidden from Debug.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for ConnectionTotals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionTotals")
            .field("in_bytes_total", &self.in_bytes_total)
            .field("out_bytes_total", &self.out_bytes_total)
            .finish_non_exhaustive()
    }
}
/// One engine response, not a transfer-completion or durable-presence receipt.
#[derive(Clone, Deserialize)]
pub struct ConnectionSnapshot {
    /// Actual peer entries. An absent ID is not a fabricated disconnected record.
    pub connections: BTreeMap<DeviceId, PeerConnection>,
    /// Aggregate counters, when the engine supplies them.
    pub total: Option<ConnectionTotals>,
    /// Other response fields, omitted from ordinary formatting.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for ConnectionSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionSnapshot")
            .field("peer_count", &self.connections.len())
            .field("total", &self.total)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// Actual status for one configured listener/service key.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListenerStatus {
    /// Current engine error, if reported; not inferred from empty addresses.
    pub error: Option<String>,
    /// Actual engine-reported local addresses.
    pub lan_addresses: Vec<String>,
    /// Actual engine-reported external addresses, not independent WAN proof.
    pub wan_addresses: Vec<String>,
    /// Other actual fields, omitted from ordinary formatting.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for ListenerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerStatus")
            .field("error_present", &self.error.is_some())
            .field("lan_address_count", &self.lan_addresses.len())
            .field("wan_address_count", &self.wan_addresses.len())
            .finish_non_exhaustive()
    }
}

/// One actual discovery-cache record. An entry does not establish connectivity.
#[derive(Clone, Deserialize)]
pub struct DiscoveryRecord {
    /// Engine-reported candidate addresses, retained exactly as received.
    pub addresses: Vec<String>,
    /// Other actual metadata; absent information is not invented.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for DiscoveryRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscoveryRecord")
            .field("address_count", &self.addresses.len())
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}
