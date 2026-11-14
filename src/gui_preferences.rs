//! Native GUI preferences, independent of listener and credential replacement.
use crate::{Client, Error, GuiAuthenticationConfig, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// Actual GUI preferences. Debug omits theme, cookie path and extra values.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuiPreferences {
    /// Whether native metrics can be requested without management authentication.
    pub metrics_without_auth: bool,
    theme: String,
    /// Native debugging selection, separate from its available debug resources.
    pub debugging: bool,
    /// Explicit native HTTP administrative-access policy.
    pub insecure_admin_access: bool,
    /// Native host-header checking bypass selection.
    #[serde(rename = "insecureSkipHostcheck")]
    pub insecure_skip_hostcheck: bool,
    /// Whether the native GUI permits frame loading.
    pub insecure_allow_frame_loading: bool,
    /// Whether native unauthenticated requests should prompt for Basic authentication.
    pub send_basic_auth_prompt: bool,
    /// Actual reported cookie lifetime, with native zero/negative policy retained.
    #[serde(rename = "sessionCookieDurationS")]
    pub session_cookie_duration_seconds: i64,
    session_cookie_path: String,
    /// Other native preferences, including potentially private listener settings.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl GuiPreferences {
    /// Actual stored theme selector. This does not establish rendered appearance.
    pub fn theme(&self) -> &str {
        &self.theme
    }
    /// Actual HTTP cookie path, not a local filesystem path.
    pub fn session_cookie_path(&self) -> &str {
        &self.session_cookie_path
    }
    pub(crate) fn from_auth(value: &GuiAuthenticationConfig) -> Result<Self> {
        serde_json::from_value(serde_json::Value::Object(
            value.extra.clone().into_iter().collect(),
        ))
        .map_err(|_| Error::InvalidConfiguration {
            reason: "native GUI preferences do not match the required schema",
        })
    }
}
impl fmt::Debug for GuiPreferences {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuiPreferences")
            .field("metrics_without_auth", &self.metrics_without_auth)
            .field("debugging", &self.debugging)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// Explicit partial GUI preferences. A change can reload the native GUI handler.
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuiPreferencesPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics_without_auth: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    theme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    debugging: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    insecure_admin_access: Option<bool>,
    #[serde(
        rename = "insecureSkipHostcheck",
        skip_serializing_if = "Option::is_none"
    )]
    insecure_skip_hostcheck: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    insecure_allow_frame_loading: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    send_basic_auth_prompt: Option<bool>,
    #[serde(
        rename = "sessionCookieDurationS",
        skip_serializing_if = "Option::is_none"
    )]
    session_cookie_duration_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_cookie_path: Option<String>,
}
impl GuiPreferencesPatch {
    /// Explicitly change unauthenticated metrics access.
    pub fn metrics_without_auth(mut self, value: bool) -> Self {
        self.metrics_without_auth = Some(value);
        self
    }
    /// Set a stored theme selector without claiming a rendered UI result.
    pub fn theme(mut self, value: impl Into<String>) -> Self {
        self.theme = Some(value.into());
        self
    }
    /// Explicitly select native debugging.
    pub fn debugging(mut self, value: bool) -> Self {
        self.debugging = Some(value);
        self
    }
    /// Explicitly select the native insecure administrative-access policy.
    pub fn insecure_admin_access(mut self, value: bool) -> Self {
        self.insecure_admin_access = Some(value);
        self
    }
    /// Explicitly bypass native host-header checks.
    pub fn insecure_skip_hostcheck(mut self, value: bool) -> Self {
        self.insecure_skip_hostcheck = Some(value);
        self
    }
    /// Explicitly select native frame loading.
    pub fn allow_frame_loading(mut self, value: bool) -> Self {
        self.insecure_allow_frame_loading = Some(value);
        self
    }
    /// Select the native Basic authentication prompt.
    pub fn send_basic_auth_prompt(mut self, value: bool) -> Self {
        self.send_basic_auth_prompt = Some(value);
        self
    }
    /// Select a nonnegative native cookie lifetime; zero retains native policy.
    pub fn session_cookie_duration_seconds(mut self, value: u32) -> Self {
        self.session_cookie_duration_seconds = Some(value);
        self
    }
    /// Select an absolute HTTP cookie path, without changing the management URL.
    pub fn session_cookie_path(mut self, value: impl Into<String>) -> Self {
        self.session_cookie_path = Some(value.into());
        self
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self
            .theme
            .as_ref()
            .is_some_and(|s| s.len() > 128 || s.chars().any(char::is_control))
            || self.session_cookie_path.as_ref().is_some_and(|s| {
                !s.starts_with('/')
                    || s.len() > 4096
                    || s.chars().any(char::is_control)
                    || s.contains([';', '\\', '?', '#'])
            })
        {
            return Err(Error::InvalidConfiguration {
                reason:
                    "GUI preference text is oversized or has an invalid theme or HTTP cookie path",
            });
        }
        Ok(())
    }
}
impl fmt::Debug for GuiPreferencesPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuiPreferencesPatch")
            .field("changes_theme", &self.theme.is_some())
            .field("changes_cookie_path", &self.session_cookie_path.is_some())
            .finish_non_exhaustive()
    }
}
/// Actual GUI readback after one PATCH and bounded fresh reauthentication.
#[derive(Clone, Debug)]
pub struct GuiPreferencesUpdate {
    /// Fresh same-endpoint connection with the original key and exact identity.
    pub client: Client,
    /// Actual native preference values, separate from observed HTTP/UI effects.
    pub configuration: GuiPreferences,
    /// Every explicitly submitted field matches native readback.
    pub requested_fields_match: bool,
    /// Whether the write response was acknowledged before read-only reconciliation.
    pub write_acknowledged: bool,
}
