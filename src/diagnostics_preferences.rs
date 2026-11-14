//! Native diagnostic preferences, separate from actual report transmission.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// Actual native diagnostic settings. The fixed program normalizes its legacy
/// usage fields to fixed values; reading them does not establish report transmission.
#[derive(Clone, Deserialize)]
pub struct DiagnosticsOptions {
    /// Reported legacy accepted schema version, not an SDK consent record.
    #[serde(rename = "urAccepted")]
    pub usage_accepted_version: i64,
    /// Reported legacy seen schema version; not a verified configurable setting.
    #[serde(rename = "urSeen")]
    pub usage_seen_version: i64,
    #[serde(rename = "urUniqueId")]
    usage_identifier: String,
    #[serde(rename = "urURL")]
    usage_report_url: String,
    /// Reported legacy plaintext policy; a read does not establish transmission.
    #[serde(rename = "urPostInsecurely")]
    pub usage_post_insecurely: bool,
    /// Reported legacy initial delay; the fixed program ignored changes to it.
    #[serde(rename = "urInitialDelayS")]
    pub usage_initial_delay_seconds: u32,
    /// Current crash-reporting selection, independent of an actual upload.
    #[serde(rename = "crashReportingEnabled")]
    pub crash_reporting_enabled: bool,
    #[serde(rename = "crURL")]
    crash_report_url: String,
    /// Other actual options, potentially including private endpoint values.
    /// Ordinary Debug omits their values.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl DiagnosticsOptions {
    /// Explicitly inspect the native legacy usage identifier. Redact before logging.
    pub fn usage_identifier(&self) -> &str {
        &self.usage_identifier
    }
    /// Inspect the actual legacy URL, without contacting it or claiming it is used.
    pub fn usage_report_url(&self) -> &str {
        &self.usage_report_url
    }
    /// Inspect the selected crash destination; values can contain private tokens.
    pub fn crash_report_url(&self) -> &str {
        &self.crash_report_url
    }
}
impl fmt::Debug for DiagnosticsOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiagnosticsOptions")
            .field("usage_accepted_version", &self.usage_accepted_version)
            .field("usage_seen_version", &self.usage_seen_version)
            .field("crash_reporting_enabled", &self.crash_reporting_enabled)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// Explicit crash configuration changes. This does not generate a crash, upload
/// a report, alter legacy usage fields or accept terms on the caller's behalf.
#[derive(Clone, Default, Serialize)]
pub struct CrashReportingPatch {
    #[serde(
        rename = "crashReportingEnabled",
        skip_serializing_if = "Option::is_none"
    )]
    enabled: Option<bool>,
    #[serde(rename = "crURL", skip_serializing_if = "Option::is_none")]
    url: Option<String>,
}
impl CrashReportingPatch {
    /// Explicitly enable or disable native future crash reporting.
    pub fn enabled(mut self, value: bool) -> Self {
        self.enabled = Some(value);
        self
    }
    /// Select an HTTP(S) destination for a separately occurring native report.
    /// Query tokens remain private. Userinfo, fragments and control text are rejected.
    pub fn url(mut self, value: impl Into<String>) -> Self {
        self.url = Some(value.into());
        self
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let invalid = || Error::InvalidConfiguration {
            reason:
                "crash report URL must be bounded HTTP(S) without userinfo, fragments or controls",
        };
        if let Some(value) = &self.url {
            if value.len() > 32768 || value.chars().any(char::is_control) {
                return Err(invalid());
            }
            let url = url::Url::parse(value).map_err(|_| invalid())?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || url.port() == Some(0)
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
impl fmt::Debug for CrashReportingPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrashReportingPatch")
            .field("enabled", &self.enabled)
            .field("changes_url", &self.url.is_some())
            .finish()
    }
}
