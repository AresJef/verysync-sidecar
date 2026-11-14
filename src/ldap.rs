//! Native LDAP configuration, independent of actual directory authentication.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// LDAP transport selector reported by the fixed native program.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub enum LdapTransport {
    /// Plain LDAP, selected explicitly for private loopback fixtures.
    #[serde(rename = "plain")]
    Plain,
    /// Native TLS selector; actual trust and login need separate evidence.
    #[serde(rename = "tls")]
    Tls,
    /// Native StartTLS selector; actual trust and login need separate evidence.
    #[serde(rename = "starttls")]
    StartTls,
    /// Unrecognized readback. Typed changes reject this value.
    #[serde(untagged)]
    Unknown(String),
}
impl fmt::Debug for LdapTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Plain => "LdapTransport::Plain",
            Self::Tls => "LdapTransport::Tls",
            Self::StartTls => "LdapTransport::StartTls",
            Self::Unknown(_) => "LdapTransport::Unknown([REDACTED])",
        })
    }
}
/// Actual native LDAP settings. Debug omits server/DN/filter and extra values.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LdapConfiguration {
    /// Native server:port, possibly empty when LDAP is not configured.
    pub address: String,
    /// Native user-bind template; `%s` inserts the supplied GUI username.
    #[serde(rename = "bindDN")]
    pub bind_dn: String,
    /// Selected native transport, separate from an observed TLS handshake.
    pub transport: LdapTransport,
    /// Actual certificate-verification bypass setting; false retains verification.
    pub insecure_skip_verify: bool,
    /// Optional native search base, empty for direct bind.
    #[serde(rename = "searchBaseDN")]
    pub search_base_dn: String,
    /// Optional native search filter; configuration does not prove membership.
    pub search_filter: String,
    /// Future native fields, retained for explicit inspection.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for LdapConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LdapConfiguration")
            .field("transport", &self.transport)
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// Explicit partial settings; this does not activate LDAP GUI authentication.
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LdapPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(rename = "bindDN", skip_serializing_if = "Option::is_none")]
    bind_dn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<LdapTransport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    insecure_skip_verify: Option<bool>,
    #[serde(rename = "searchBaseDN", skip_serializing_if = "Option::is_none")]
    search_base_dn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    search_filter: Option<String>,
}
impl LdapPatch {
    /// Set or explicitly clear the native server:port string. No DNS is resolved.
    pub fn address(mut self, value: impl Into<String>) -> Self {
        self.address = Some(value.into());
        self
    }
    /// Set the native DN template. The library does not interpret directory DNs.
    pub fn bind_dn(mut self, value: impl Into<String>) -> Self {
        self.bind_dn = Some(value.into());
        self
    }
    /// Select the native transport; this does not install a trusted certificate.
    pub fn transport(mut self, value: LdapTransport) -> Self {
        self.transport = Some(value);
        self
    }
    /// Explicitly select certificate bypass. The default patch sends no change.
    pub fn insecure_skip_verify(mut self, value: bool) -> Self {
        self.insecure_skip_verify = Some(value);
        self
    }
    /// Set or clear the native optional search base.
    pub fn search_base_dn(mut self, value: impl Into<String>) -> Self {
        self.search_base_dn = Some(value.into());
        self
    }
    /// Set or clear the native optional search filter.
    pub fn search_filter(mut self, value: impl Into<String>) -> Self {
        self.search_filter = Some(value.into());
        self
    }
    pub(crate) fn validate(&self) -> crate::Result<()> {
        let invalid = || crate::Error::InvalidConfiguration {
            reason: "LDAP patch is empty, oversized or has invalid native fields",
        };
        if self.address.is_none()
            && self.bind_dn.is_none()
            && self.transport.is_none()
            && self.insecure_skip_verify.is_none()
            && self.search_base_dn.is_none()
            && self.search_filter.is_none()
        {
            return Err(invalid());
        }
        for text in [
            &self.address,
            &self.bind_dn,
            &self.search_base_dn,
            &self.search_filter,
        ]
        .into_iter()
        .flatten()
        {
            if text.len() > 32768 || text.contains('\0') {
                return Err(invalid());
            }
        }
        if matches!(self.transport, Some(LdapTransport::Unknown(_))) {
            return Err(invalid());
        }
        if let Some(address) = self.address.as_ref().filter(|s| !s.is_empty()) {
            let url = url::Url::parse(&format!("ldap://{address}")).map_err(|_| invalid())?;
            if address.chars().any(char::is_control)
                || url.host_str().is_none()
                || url.port().is_none_or(|p| p == 0)
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || !matches!(url.path(), "" | "/")
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
impl fmt::Debug for LdapPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LdapPatch")
            .field("changes_address", &self.address.is_some())
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

/// Actual native authentication-mode readback after a single GUI PATCH.
#[derive(Clone, Debug)]
pub struct GuiAuthModeUpdate {
    /// API-key connection authenticated after the native GUI reload.
    pub client: crate::Client,
    /// Actual settings, independent of a successful directory login.
    pub configuration: crate::GuiAuthenticationConfig,
    /// The native selector equals the explicitly requested mode.
    pub requested_mode_matches: bool,
    /// The modifying request was acknowledged before read-only reconciliation.
    pub write_acknowledged: bool,
}
