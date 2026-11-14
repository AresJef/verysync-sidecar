//! Management authentication, separate from official account sessions.
use crate::{ApiKey, Client, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// Native management GUI authentication selector.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GuiAuthMode {
    /// Locally configured GUI username/password.
    Static,
    /// The engine's LDAP authentication configuration.
    Ldap,
    /// An unknown readback selector, retained without inferring semantics.
    #[serde(untagged)]
    Unknown(String),
}
impl fmt::Debug for GuiAuthMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Static => "GuiAuthMode::Static",
            Self::Ldap => "GuiAuthMode::Ldap",
            Self::Unknown(_) => "GuiAuthMode::Unknown([REDACTED])",
        })
    }
}

/// Actual GUI authentication settings. Password/key values are private and Debug
/// omits them, the username and unmodeled native configuration values.
#[derive(Clone, Deserialize)]
pub struct GuiAuthenticationConfig {
    /// Whether the native GUI server is enabled.
    pub enabled: bool,
    /// Native authentication mode; this is independent of API-key authorization.
    #[serde(rename = "authMode")]
    pub mode: GuiAuthMode,
    /// Configured management username, separate from an official VerySync account.
    #[serde(rename = "user")]
    pub username: String,
    #[serde(rename = "apiKey")]
    key: String,
    password: String,
    /// Other actual settings, including management address and TLS policy.
    /// Values may be private; inspect them explicitly.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl GuiAuthenticationConfig {
    /// Explicitly obtain the reported management credential as a redacted value.
    pub fn api_key(&self) -> Result<ApiKey> {
        ApiKey::new(&self.key)
    }
    /// Whether the native configuration contains a password value.
    /// This does not verify a supplied password or an LDAP authentication result.
    pub fn password_is_set(&self) -> bool {
        !self.password.is_empty()
    }
    pub(crate) fn key_matches(&self, key: &ApiKey) -> bool {
        self.key.as_bytes() == key.header().as_bytes()
    }
}
impl fmt::Debug for GuiAuthenticationConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuiAuthenticationConfig")
            .field("enabled", &self.enabled)
            .field("mode", &self.mode)
            .field("password_is_set", &self.password_is_set())
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// Actual readback after one credential change and bounded read-only reconnects.
#[derive(Clone, Debug)]
pub struct ApiKeyRotation {
    /// New connection after fresh version and exact identity checks. Old clones
    /// retain their old credential. Mutations share the original clone lock.
    pub client: Client,
    /// The modifying HTTP response was a successful acknowledgment. False means
    /// its outcome was initially unknown and subsequent reads reconciled it.
    pub write_acknowledged: bool,
    /// The GUI reports the submitted key at this observation.
    pub requested_key_matches: bool,
    /// A fresh connection with the previous key received HTTP 401/403.
    /// False means that connection was accepted, for example by open GUI policy.
    pub previous_key_rejected: bool,
    /// Actual reported GUI authentication settings, independently of login state.
    pub configuration: GuiAuthenticationConfig,
}
