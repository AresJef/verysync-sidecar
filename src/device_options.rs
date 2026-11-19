//! Additional native peer and creation-template selections.
use crate::{DeviceId, Error, IgnoredFolder, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// The native introduction-source field. Missing fields are represented by an
/// outer Option, distinct from the explicit empty no-source value.
#[derive(Clone, Eq, PartialEq)]
pub enum IntroductionSource {
    /// Explicit native empty identity.
    None,
    /// Exact parsed native source identity.
    Device(DeviceId),
    /// Unknown readback retained privately; typed setters cannot submit it.
    Unknown(String),
}
impl Serialize for IntroductionSource {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            Self::None => "",
            Self::Device(id) => id.as_str(),
            Self::Unknown(v) => v,
        })
    }
}
impl<'de> Deserialize<'de> for IntroductionSource {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Ok(if text.is_empty() {
            Self::None
        } else {
            match DeviceId::parse(&text) {
                Ok(id) => Self::Device(id),
                Err(_) => Self::Unknown(text),
            }
        })
    }
}
impl fmt::Debug for IntroductionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "IntroductionSource::None",
            Self::Device(_) => "IntroductionSource::Device([REDACTED])",
            Self::Unknown(_) => "IntroductionSource::Unknown([REDACTED])",
        })
    }
}

/// Actual additional device selections. Missing fields remain absent. These
/// values do not prove introductions, encryption, connections or accepted data.
#[derive(Clone, Deserialize)]
pub struct DeviceAdvancedConfig {
    /// Expected native certificate-name selection; empty retains native policy.
    #[serde(rename = "certName")]
    pub certificate_name: Option<String>,
    /// Trust this peer as a native introducer; actual introductions are separate.
    #[serde(rename = "introducer")]
    pub introducer: Option<bool>,
    /// Select native introduction-removal behavior.
    #[serde(rename = "skipIntroductionRemovals")]
    pub skip_introduction_removals: Option<bool>,
    /// Actual source identity or the native empty no-source selection.
    #[serde(rename = "introducedBy")]
    pub introduced_by: Option<IntroductionSource>,
    /// Native peer network rules; not controller routes or firewall rules.
    #[serde(rename = "allowedNetworks")]
    pub allowed_networks: Option<Vec<String>>,
    /// Select native automatic folder acceptance; enabling may register future offers.
    #[serde(rename = "autoAcceptFolders")]
    pub auto_accept_folders: Option<bool>,
    /// Native outstanding request budget in KiB; zero retains native policy.
    #[serde(rename = "maxRequestKiB")]
    pub max_request_kib: Option<u32>,
    /// Native untrusted-peer selection; does not establish encryption.
    #[serde(rename = "untrusted")]
    pub untrusted: Option<bool>,
    /// Native desired connection count; zero retains native policy.
    #[serde(rename = "numConnections")]
    pub num_connections: Option<u32>,
    /// Native peer-specific remote-name adoption selection.
    #[serde(rename = "overwriteRemoteDeviceNamesOnConnect")]
    pub overwrite_remote_device_names_on_connect: Option<bool>,
    /// Explicit complete ignored-folder list for this peer or template.
    #[serde(rename = "ignoredFolders")]
    pub ignored_folders: Option<Vec<IgnoredFolder>>,
    /// Native `selfed` classification flag; not proof of account ownership.
    #[serde(rename = "selfed")]
    pub self_classification: Option<bool>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}
impl DeviceAdvancedConfig {
    pub(crate) fn from_fields(fields: &BTreeMap<String, serde_json::Value>) -> Result<Self> {
        serde_json::from_value(
            serde_json::to_value(fields)
                .map_err(|_| invalid("device options cannot be encoded"))?,
        )
        .map_err(|_| invalid("device options do not match their native schema"))
    }
}
impl fmt::Debug for DeviceAdvancedConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAdvancedConfig")
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// Explicit additional peer selections, shared by the existing DevicePatch and
/// creation-default APIs. Selecting an ignored list replaces that entire list.
#[derive(Clone, Default, Serialize)]
pub struct DeviceAdvancedPatch {
    #[serde(rename = "selfed", skip_serializing_if = "Option::is_none")]
    self_classification: Option<bool>,
    #[serde(rename = "certName", skip_serializing_if = "Option::is_none")]
    certificate_name: Option<String>,
    #[serde(rename = "introducer", skip_serializing_if = "Option::is_none")]
    introducer: Option<bool>,
    #[serde(
        rename = "skipIntroductionRemovals",
        skip_serializing_if = "Option::is_none"
    )]
    skip_introduction_removals: Option<bool>,
    #[serde(rename = "introducedBy", skip_serializing_if = "Option::is_none")]
    introduced_by: Option<IntroductionSource>,
    #[serde(rename = "allowedNetworks", skip_serializing_if = "Option::is_none")]
    allowed_networks: Option<Vec<String>>,
    #[serde(rename = "autoAcceptFolders", skip_serializing_if = "Option::is_none")]
    auto_accept_folders: Option<bool>,
    #[serde(rename = "maxRequestKiB", skip_serializing_if = "Option::is_none")]
    max_request_kib: Option<u32>,
    #[serde(rename = "untrusted", skip_serializing_if = "Option::is_none")]
    untrusted: Option<bool>,
    #[serde(rename = "numConnections", skip_serializing_if = "Option::is_none")]
    num_connections: Option<u32>,
    #[serde(
        rename = "overwriteRemoteDeviceNamesOnConnect",
        skip_serializing_if = "Option::is_none"
    )]
    overwrite_remote_device_names_on_connect: Option<bool>,
    #[serde(rename = "ignoredFolders", skip_serializing_if = "Option::is_none")]
    ignored_folders: Option<Vec<IgnoredFolder>>,
}
impl DeviceAdvancedPatch {
    /// Select the native `selfed` flag without changing the device certificate
    /// identity or proving ownership of an official account.
    pub fn self_classification(mut self, value: bool) -> Self {
        self.self_classification = Some(value);
        self
    }
    /// Expected native certificate-name selection; empty retains native policy.
    pub fn certificate_name(mut self, value: impl Into<String>) -> Self {
        self.certificate_name = Some(value.into());
        self
    }
    /// Trust this peer as a native introducer; actual introductions are separate.
    pub fn introducer(mut self, value: bool) -> Self {
        self.introducer = Some(value);
        self
    }
    /// Select native introduction-removal behavior.
    pub fn skip_introduction_removals(mut self, value: bool) -> Self {
        self.skip_introduction_removals = Some(value);
        self
    }
    /// Actual source identity or the native empty no-source selection.
    pub fn introduced_by(mut self, value: Option<DeviceId>) -> Self {
        self.introduced_by =
            Some(value.map_or(IntroductionSource::None, IntroductionSource::Device));
        self
    }
    /// Native peer network rules; not controller routes or firewall rules.
    pub fn allowed_networks(mut self, value: Vec<String>) -> Self {
        self.allowed_networks = Some(value);
        self
    }
    /// Select native automatic folder acceptance; enabling may register future offers.
    pub fn auto_accept_folders(mut self, value: bool) -> Self {
        self.auto_accept_folders = Some(value);
        self
    }
    /// Native outstanding request budget in KiB; zero retains native policy.
    pub fn max_request_kib(mut self, value: u32) -> Self {
        self.max_request_kib = Some(value);
        self
    }
    /// Native untrusted-peer selection; does not establish encryption.
    pub fn untrusted(mut self, value: bool) -> Self {
        self.untrusted = Some(value);
        self
    }
    /// Native desired connection count; zero retains native policy.
    pub fn num_connections(mut self, value: u32) -> Self {
        self.num_connections = Some(value);
        self
    }
    /// Native peer-specific remote-name adoption selection.
    pub fn overwrite_remote_device_names_on_connect(mut self, value: bool) -> Self {
        self.overwrite_remote_device_names_on_connect = Some(value);
        self
    }
    /// Explicit complete ignored-folder list for this peer or template.
    pub fn ignored_folders(mut self, value: Vec<IgnoredFolder>) -> Self {
        self.ignored_folders = Some(value);
        self
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if [self.max_request_kib, self.num_connections]
            .into_iter()
            .flatten()
            .any(|v| v > i32::MAX as u32)
            || self
                .certificate_name
                .as_ref()
                .is_some_and(|v| v.len() > 4096 || v.chars().any(char::is_control))
            || self.allowed_networks.as_ref().is_some_and(|v| {
                v.len() > 256
                    || v.iter().any(|s| {
                        s.trim().is_empty() || s.len() > 4096 || s.chars().any(char::is_control)
                    })
            })
            || self.ignored_folders.as_ref().is_some_and(|v| {
                v.len() > 4096
                    || v.iter().any(|f| {
                        f.label.len() > 4096
                            || f.time.len() > 128
                            || f.label.chars().any(char::is_control)
                            || f.time.chars().any(char::is_control)
                    })
            })
            || matches!(self.introduced_by, Some(IntroductionSource::Unknown(_)))
        {
            return Err(invalid(
                "additional device selection exceeds its explicit bounds",
            ));
        }
        let body =
            serde_json::to_value(self).map_err(|_| invalid("device options cannot be encoded"))?;
        if body.as_object().is_none_or(|v| v.is_empty()) {
            return Err(invalid(
                "additional device patch must contain at least one field",
            ));
        }
        Ok(())
    }
    pub(crate) fn matches(&self, fields: &BTreeMap<String, serde_json::Value>) -> bool {
        serde_json::to_value(self).is_ok_and(|body| {
            body.as_object()
                .is_some_and(|v| v.iter().all(|(key, value)| fields.get(key) == Some(value)))
        })
    }
}
impl fmt::Debug for DeviceAdvancedPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAdvancedPatch")
            .finish_non_exhaustive()
    }
}
fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfiguration { reason }
}
