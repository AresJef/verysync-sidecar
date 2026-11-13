//! Private/public relay server configuration and independently observed runtime.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// Current relay server configuration. Debug omits addresses and the token.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayServerConfig {
    /// Stored enable flag; inspect runtime separately.
    pub enabled: bool,
    /// Engine-interpreted listener address.
    pub listen: String,
    /// Engine-interpreted status listener address.
    pub status_addr: String,
    /// Whether this relay is configured for public operation.
    pub public: bool,
    /// Pool addresses as accepted by this fixed engine, including an empty string.
    pub pool_addrs: String,
    /// Whether relay-specific NAT mapping is enabled.
    pub nat_enabled: bool,
    /// Actual authentication flag, which can differ from a requested value.
    pub auth_enabled: bool,
    /// Actual sensitive token. Explicit inspection is allowed; Debug omits it.
    pub token: String,
    /// Provider description, distinct from authorization or identity.
    pub provided_by: String,
    /// Per-session limit in bytes per second; zero is the upstream unlimited value.
    pub session_limit_bps: u64,
    /// Aggregate limit in bytes per second; zero is the upstream unlimited value.
    pub global_limit_bps: u64,
    /// Network timeout in seconds; stored zero selects an engine default.
    #[serde(rename = "networkTimeout")]
    pub network_timeout_seconds: u64,
    /// Ping interval in seconds; stored zero selects an engine default.
    #[serde(rename = "pingInterval")]
    pub ping_interval_seconds: u64,
    /// Message timeout in seconds; stored zero selects an engine default.
    #[serde(rename = "messageTimeout")]
    pub message_timeout_seconds: u64,
    /// Other actual options, including fields whose runtime units remain unverified.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for RelayServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayServerConfig")
            .field("enabled", &self.enabled)
            .field("public", &self.public)
            .field("nat_enabled", &self.nat_enabled)
            .field("auth_enabled", &self.auth_enabled)
            .finish_non_exhaustive()
    }
}
/// Explicit partial relay changes. Enabling can open listeners and contact pools.
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayServerPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    listen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pool_addrs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nat_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provided_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_limit_bps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    global_limit_bps: Option<u64>,
    #[serde(rename = "networkTimeout", skip_serializing_if = "Option::is_none")]
    network_timeout_seconds: Option<u64>,
    #[serde(rename = "pingInterval", skip_serializing_if = "Option::is_none")]
    ping_interval_seconds: Option<u64>,
    #[serde(rename = "messageTimeout", skip_serializing_if = "Option::is_none")]
    message_timeout_seconds: Option<u64>,
}
impl RelayServerPatch {
    /// Choose the server's enabled configuration explicitly.
    pub fn enabled(mut self, value: bool) -> Self {
        self.enabled = Some(value);
        self
    }
    /// Choose the server listener. The library does not substitute an address.
    pub fn listen(mut self, value: impl Into<String>) -> Self {
        self.listen = Some(value.into());
        self
    }
    /// Choose the server status listener.
    pub fn status_address(mut self, value: impl Into<String>) -> Self {
        self.status_addr = Some(value.into());
        self
    }
    /// Choose public operation explicitly; this is not an authorization grant.
    pub fn public(mut self, value: bool) -> Self {
        self.public = Some(value);
        self
    }
    /// Choose pool addresses explicitly; an empty string is retained.
    pub fn pool_addresses(mut self, value: impl Into<String>) -> Self {
        self.pool_addrs = Some(value.into());
        self
    }
    /// Choose relay-specific NAT mapping, independent of client NAT options.
    pub fn nat_mapping(mut self, value: bool) -> Self {
        self.nat_enabled = Some(value);
        self
    }
    /// Request authentication; matching readback and actual enforcement are separate.
    pub fn authentication(mut self, value: bool) -> Self {
        self.auth_enabled = Some(value);
        self
    }
    /// Set or clear a sensitive token without logging it.
    pub fn token(mut self, value: impl Into<String>) -> Self {
        self.token = Some(value.into());
        self
    }
    /// Choose the provider description.
    pub fn provided_by(mut self, value: impl Into<String>) -> Self {
        self.provided_by = Some(value.into());
        self
    }
    /// Set the session limit in bytes per second. Zero requests unlimited.
    pub fn session_limit_bytes_per_second(mut self, value: u64) -> Self {
        self.session_limit_bps = Some(value);
        self
    }
    /// Set the aggregate limit in bytes per second. Zero requests unlimited.
    pub fn global_limit_bytes_per_second(mut self, value: u64) -> Self {
        self.global_limit_bps = Some(value);
        self
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.enabled.is_none()
            && self.listen.is_none()
            && self.status_addr.is_none()
            && self.public.is_none()
            && self.pool_addrs.is_none()
            && self.nat_enabled.is_none()
            && self.auth_enabled.is_none()
            && self.token.is_none()
            && self.provided_by.is_none()
            && self.session_limit_bps.is_none()
            && self.global_limit_bps.is_none()
            && self.network_timeout_seconds.is_none()
            && self.ping_interval_seconds.is_none()
            && self.message_timeout_seconds.is_none()
        {
            return Err(Error::InvalidConfiguration {
                reason: "relay patch must contain at least one field",
            });
        }
        if self
            .listen
            .as_ref()
            .into_iter()
            .chain(self.status_addr.as_ref())
            .any(String::is_empty)
            || self
                .listen
                .as_ref()
                .into_iter()
                .chain(self.status_addr.as_ref())
                .chain(self.pool_addrs.as_ref())
                .chain(self.token.as_ref())
                .chain(self.provided_by.as_ref())
                .any(|s| s.chars().any(char::is_control))
        {
            return Err(Error::InvalidConfiguration {
                reason:
                    "relay addresses must be nonempty and relay strings must not contain controls",
            });
        }
        Ok(())
    }
    pub(crate) fn matches(&self, v: &RelayServerConfig) -> bool {
        self.enabled.is_none_or(|x| x == v.enabled)
            && self.listen.as_ref().is_none_or(|x| *x == v.listen)
            && self
                .status_addr
                .as_ref()
                .is_none_or(|x| *x == v.status_addr)
            && self.public.is_none_or(|x| x == v.public)
            && self.pool_addrs.as_ref().is_none_or(|x| *x == v.pool_addrs)
            && self.nat_enabled.is_none_or(|x| x == v.nat_enabled)
            && self.auth_enabled.is_none_or(|x| x == v.auth_enabled)
            && self.token.as_ref().is_none_or(|x| *x == v.token)
            && self
                .provided_by
                .as_ref()
                .is_none_or(|x| *x == v.provided_by)
            && self
                .session_limit_bps
                .is_none_or(|x| x == v.session_limit_bps)
            && self
                .global_limit_bps
                .is_none_or(|x| x == v.global_limit_bps)
            && self
                .network_timeout_seconds
                .is_none_or(|x| x == v.network_timeout_seconds)
            && self
                .ping_interval_seconds
                .is_none_or(|x| x == v.ping_interval_seconds)
            && self
                .message_timeout_seconds
                .is_none_or(|x| x == v.message_timeout_seconds)
    }
    /// Choose a whole-second network timeout. Zero selects the engine default.
    pub fn network_timeout_seconds(mut self, value: u64) -> Self {
        self.network_timeout_seconds = Some(value);
        self
    }
    /// Choose a whole-second ping interval. Zero selects the engine default.
    pub fn ping_interval_seconds(mut self, value: u64) -> Self {
        self.ping_interval_seconds = Some(value);
        self
    }
    /// Choose a whole-second message timeout. Zero selects the engine default.
    pub fn message_timeout_seconds(mut self, value: u64) -> Self {
        self.message_timeout_seconds = Some(value);
        self
    }
}
impl fmt::Debug for RelayServerPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayServerPatch")
            .field("enabled", &self.enabled)
            .field("public", &self.public)
            .field("authentication", &self.auth_enabled)
            .finish_non_exhaustive()
    }
}
/// Actual relay configuration readback after one partial write.
#[derive(Clone, Debug)]
pub struct RelayServerUpdate {
    /// Actual configuration; sensitive values are omitted by Debug.
    pub configuration: RelayServerConfig,
    /// Whether all requested fields match, without inferring their runtime effect.
    pub requested_fields_match: bool,
}
/// Engine-reported relay runtime. Disabled responses omit runtime statistics.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayServerStatus {
    /// Actual runtime enable flag.
    pub enabled: bool,
    /// Actual relay URL, which can contain credentials; omitted by Debug.
    #[serde(rename = "relayURL")]
    pub relay_url: Option<String>,
    /// Actual cumulative proxied byte count, when reported.
    pub bytes_proxied: Option<u64>,
    /// Current connection count, when reported.
    pub num_connections: Option<u64>,
    /// Current active-session count, when reported.
    pub num_active_sessions: Option<u64>,
    /// Actual uptime in seconds, when reported.
    pub uptime_seconds: Option<u64>,
    /// Actual runtime options, which can differ from stored default selectors.
    pub options: Option<RelayRuntimeOptions>,
    /// Other actual statistics/options. Debug omits values.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for RelayServerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayServerStatus")
            .field("enabled", &self.enabled)
            .field("bytes_proxied", &self.bytes_proxied)
            .field("num_connections", &self.num_connections)
            .field("num_active_sessions", &self.num_active_sessions)
            .finish_non_exhaustive()
    }
}

/// Reported relay-probe result. HTTP success alone never selects `Success`.
#[derive(Clone, Eq, PartialEq, Deserialize)]
pub enum RelayProbeResult {
    /// The fixed engine explicitly reported a successful probe.
    #[serde(rename = "success")]
    Success,
    /// The fixed engine explicitly reported a failed probe.
    #[serde(rename = "failed")]
    Failed,
    /// Other actual result labels, retained without a success interpretation.
    #[serde(untagged)]
    Unknown(String),
}
impl fmt::Debug for RelayProbeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Success => "RelayProbeResult::Success",
            Self::Failed => "RelayProbeResult::Failed",
            Self::Unknown(_) => "RelayProbeResult::Unknown([REDACTED])",
        })
    }
}
/// Actual result from one explicitly requested upstream relay probe.
#[derive(Clone, Deserialize)]
pub struct RelayProbe {
    /// Actual result; unknown labels are never treated as success.
    pub result: RelayProbeResult,
    /// Actual engine error text, including an empty string; may contain URLs.
    pub error: Option<String>,
    /// Unmodeled actual fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for RelayProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayProbe")
            .field("result", &self.result)
            .field(
                "has_error_text",
                &self.error.as_ref().is_some_and(|s| !s.is_empty()),
            )
            .finish_non_exhaustive()
    }
}

/// Effective runtime values reported by the running relay, not a throughput test.
#[derive(Clone, Deserialize)]
pub struct RelayRuntimeOptions {
    /// Effective network timeout in seconds, when reported.
    #[serde(rename = "network-timeout")]
    pub network_timeout_seconds: Option<u64>,
    /// Effective message timeout in seconds, when reported.
    #[serde(rename = "message-timeout")]
    pub message_timeout_seconds: Option<u64>,
    /// Effective ping interval in seconds, when reported.
    #[serde(rename = "ping-interval")]
    pub ping_interval_seconds: Option<u64>,
    /// Effective per-session bytes-per-second limit, when reported.
    #[serde(rename = "per-session-rate")]
    pub session_limit_bytes_per_second: Option<u64>,
    /// Effective aggregate bytes-per-second limit, when reported.
    #[serde(rename = "global-rate")]
    pub global_limit_bytes_per_second: Option<u64>,
    /// Other actual options. Values can contain private addresses or descriptions.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for RelayRuntimeOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayRuntimeOptions")
            .field("network_timeout_seconds", &self.network_timeout_seconds)
            .field("ping_interval_seconds", &self.ping_interval_seconds)
            .finish_non_exhaustive()
    }
}
