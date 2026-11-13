//! Explicit folder pull order and byte-based transfer limits.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// The fixed engine's file pull-order values. This does not change block order.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FolderPullOrder {
    /// Random file order.
    Random,
    /// Alphabetic file order.
    Alphabetic,
    /// Smallest files first.
    SmallestFirst,
    /// Largest files first.
    LargestFirst,
    /// Oldest files first.
    OldestFirst,
    /// Newest files first.
    NewestFirst,
    /// Unknown readback; typed writes reject it.
    #[serde(untagged)]
    Unknown(String),
}
impl fmt::Debug for FolderPullOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Random => "FolderPullOrder::Random",
            Self::Alphabetic => "FolderPullOrder::Alphabetic",
            Self::SmallestFirst => "FolderPullOrder::SmallestFirst",
            Self::LargestFirst => "FolderPullOrder::LargestFirst",
            Self::OldestFirst => "FolderPullOrder::OldestFirst",
            Self::NewestFirst => "FolderPullOrder::NewestFirst",
            Self::Unknown(_) => "FolderPullOrder::Unknown([REDACTED])",
        })
    }
}
/// Actual folder scheduling fields; other advanced settings remain unmodeled.
#[derive(Clone, Deserialize)]
pub struct FolderSchedulingConfig {
    /// Actual file order, independently of currently active files.
    #[serde(rename = "order")]
    pub pull_order: FolderPullOrder,
    /// Other folder settings, potentially including private keys and paths.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for FolderSchedulingConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderSchedulingConfig")
            .field("pull_order", &self.pull_order)
            .finish_non_exhaustive()
    }
}
/// Actual readback after setting one folder's file order.
#[derive(Clone, Debug)]
pub struct FolderSchedulingUpdate {
    /// Actual current scheduling snapshot.
    pub configuration: FolderSchedulingConfig,
    /// Whether the explicitly requested order matches current readback.
    pub requested_order_match: bool,
}
/// Actual global byte-rate settings. Zero means unlimited for this limiter.
#[derive(Clone, Deserialize)]
pub struct GlobalBandwidthConfig {
    /// Upload limit in KiB/s (1024 bytes per second per unit).
    #[serde(rename = "maxSendKbps")]
    pub max_send_kib_per_second: u32,
    /// Download limit in KiB/s (1024 bytes per second per unit).
    #[serde(rename = "maxRecvKbps")]
    pub max_receive_kib_per_second: u32,
    /// Whether the global limit also applies to connections classified as local.
    #[serde(rename = "limitBandwidthInLan")]
    pub limit_in_lan: bool,
    /// Additional settings, potentially private.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for GlobalBandwidthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GlobalBandwidthConfig")
            .field("max_send_kib_per_second", &self.max_send_kib_per_second)
            .field(
                "max_receive_kib_per_second",
                &self.max_receive_kib_per_second,
            )
            .field("limit_in_lan", &self.limit_in_lan)
            .finish_non_exhaustive()
    }
}
/// Partial global bandwidth settings; omitted fields are never submitted.
#[derive(Clone, Debug, Default, Serialize)]
pub struct BandwidthPatch {
    #[serde(rename = "maxSendKbps", skip_serializing_if = "Option::is_none")]
    send: Option<u32>,
    #[serde(rename = "maxRecvKbps", skip_serializing_if = "Option::is_none")]
    receive: Option<u32>,
    #[serde(
        rename = "limitBandwidthInLan",
        skip_serializing_if = "Option::is_none"
    )]
    lan: Option<bool>,
}
impl BandwidthPatch {
    /// Set upload KiB/s; zero explicitly removes this global rate limit.
    pub fn max_send_kib_per_second(mut self, value: u32) -> Self {
        self.send = Some(value);
        self
    }
    /// Set download KiB/s; zero explicitly removes this global rate limit.
    pub fn max_receive_kib_per_second(mut self, value: u32) -> Self {
        self.receive = Some(value);
        self
    }
    /// Include or exempt connections classified by the engine as local.
    pub fn limit_in_lan(mut self, value: bool) -> Self {
        self.lan = Some(value);
        self
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.send.is_none() && self.receive.is_none() && self.lan.is_none() {
            return Err(Error::InvalidConfiguration {
                reason: "bandwidth patch must contain at least one field",
            });
        }
        for value in [self.send, self.receive].into_iter().flatten() {
            validate_rate(value)?;
        }
        Ok(())
    }
    pub(crate) fn matches(&self, v: &GlobalBandwidthConfig) -> bool {
        self.send.is_none_or(|x| x == v.max_send_kib_per_second)
            && self
                .receive
                .is_none_or(|x| x == v.max_receive_kib_per_second)
            && self.lan.is_none_or(|x| x == v.limit_in_lan)
    }
}
pub(crate) fn validate_rate(value: u32) -> Result<()> {
    if value > i32::MAX as u32 {
        return Err(Error::InvalidConfiguration {
            reason: "bandwidth limit exceeds the supported signed 32-bit range",
        });
    }
    Ok(())
}
/// Settings readback, separate from observed enforcement or transfer completion.
#[derive(Clone, Debug)]
pub struct BandwidthUpdate {
    /// Actual current global settings.
    pub configuration: GlobalBandwidthConfig,
    /// Whether all explicitly requested fields match readback.
    pub requested_fields_match: bool,
}
