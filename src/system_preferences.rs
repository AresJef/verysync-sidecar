//! Native event-audit, thumbnail and proxy configuration with target-side paths.
use crate::{Error, PathStyle, Result, TargetPath};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::{collections::BTreeMap, fmt};

/// A native default location or an explicitly scoped target path.
#[derive(Clone)]
pub enum NativePathSelection {
    /// The native empty/default selector; no host path is resolved.
    Default,
    /// A target-interpreted path, without controller filesystem access.
    Path(TargetPath),
}
impl NativePathSelection {
    fn from_native(style: PathStyle, value: String) -> Result<Self> {
        if value.is_empty() {
            Ok(Self::Default)
        } else {
            Ok(Self::Path(TargetPath::remote(style, value)?))
        }
    }
    fn protocol(&self, style: PathStyle) -> Result<&str> {
        match self {
            Self::Default => Ok(""),
            Self::Path(path) => {
                if path.style() != style {
                    return Err(Error::InvalidPath {
                        reason: "preference path syntax differs from target",
                    });
                }
                let value = path.to_protocol()?;
                if value.len() > 32768 {
                    return Err(Error::InvalidPath {
                        reason: "preference path exceeds its text bound",
                    });
                }
                Ok(value)
            }
        }
    }
}
impl fmt::Debug for NativePathSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Default => "NativePathSelection::Default",
            Self::Path(_) => "NativePathSelection::Path([REDACTED])",
        })
    }
}

/// Actual selections, separate from log records, cache artifacts or a verified
/// proxy connection. Engine event audit is distinct from licensed folder history.
#[derive(Clone)]
pub struct SystemPreferences {
    /// Native engine event logging selection.
    pub event_audit_enabled: bool,
    /// Native log output selection, independent of any caller-global logger.
    pub event_audit_file: NativePathSelection,
    /// Stored thumbnail selection; preview/cache effects are separate.
    pub thumbnail_enabled: bool,
    /// Native cache location; the SDK does not open or move this directory.
    pub thumbnail_cache_directory: NativePathSelection,
    /// Native proxy selection, independent of the SDK's management transport.
    pub proxy_enabled: bool,
    proxy_address: String,
    /// Other actual options, potentially including private endpoints/identities.
    pub extra: BTreeMap<String, Value>,
}
impl SystemPreferences {
    /// Explicitly inspect the native URI, which can contain proxy credentials.
    pub fn proxy_address(&self) -> &str {
        &self.proxy_address
    }
}
impl fmt::Debug for SystemPreferences {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemPreferences")
            .field("event_audit_enabled", &self.event_audit_enabled)
            .field("thumbnail_enabled", &self.thumbnail_enabled)
            .field("proxy_enabled", &self.proxy_enabled)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}
#[derive(Deserialize)]
pub(crate) struct WireSystemPreferences {
    #[serde(rename = "auditEnabled")]
    audit_enabled: bool,
    #[serde(rename = "auditFile")]
    audit_file: String,
    #[serde(rename = "thumnailEnabled")]
    thumbnail_enabled: bool,
    #[serde(rename = "thumnailCacheDir")]
    thumbnail_cache_directory: String,
    #[serde(rename = "userProxyEnabled")]
    proxy_enabled: bool,
    #[serde(rename = "userProxyAddress")]
    proxy_address: String,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}
impl WireSystemPreferences {
    pub(crate) fn into_public(self, style: PathStyle) -> Result<SystemPreferences> {
        Ok(SystemPreferences {
            event_audit_enabled: self.audit_enabled,
            event_audit_file: NativePathSelection::from_native(style, self.audit_file)?,
            thumbnail_enabled: self.thumbnail_enabled,
            thumbnail_cache_directory: NativePathSelection::from_native(
                style,
                self.thumbnail_cache_directory,
            )?,
            proxy_enabled: self.proxy_enabled,
            proxy_address: self.proxy_address,
            extra: self.extra,
        })
    }
}

/// Explicit partial preferences. Paths are converted only at the protocol boundary.
#[derive(Clone, Default)]
pub struct SystemPreferencesPatch {
    audit_enabled: Option<bool>,
    audit_file: Option<NativePathSelection>,
    thumbnail_enabled: Option<bool>,
    thumbnail_cache_directory: Option<NativePathSelection>,
    proxy_enabled: Option<bool>,
    proxy_address: Option<String>,
}
impl SystemPreferencesPatch {
    /// Select native event logging, separately from folder-history licensing.
    pub fn event_audit_enabled(mut self, value: bool) -> Self {
        self.audit_enabled = Some(value);
        self
    }
    /// Select a target log path or the native default.
    pub fn event_audit_file(mut self, value: NativePathSelection) -> Self {
        self.audit_file = Some(value);
        self
    }
    /// Select the stored native thumbnail preference.
    pub fn thumbnail_enabled(mut self, value: bool) -> Self {
        self.thumbnail_enabled = Some(value);
        self
    }
    /// Select a target cache directory or native default, without moving old data.
    pub fn thumbnail_cache_directory(mut self, value: NativePathSelection) -> Self {
        self.thumbnail_cache_directory = Some(value);
        self
    }
    /// Explicitly select the official program's proxy preference.
    pub fn proxy_enabled(mut self, value: bool) -> Self {
        self.proxy_enabled = Some(value);
        self
    }
    /// Set or explicitly clear a native HTTP(S)/SOCKS5 URI. No connection is tested.
    pub fn proxy_address(mut self, value: impl Into<String>) -> Self {
        self.proxy_address = Some(value.into());
        self
    }
    pub(crate) fn body(&self, style: PathStyle) -> Result<Value> {
        let mut fields = Map::new();
        for (key, value) in [
            ("auditEnabled", self.audit_enabled),
            ("thumnailEnabled", self.thumbnail_enabled),
            ("userProxyEnabled", self.proxy_enabled),
        ] {
            if let Some(value) = value {
                fields.insert(key.into(), value.into());
            }
        }
        for (key, value) in [
            ("auditFile", &self.audit_file),
            ("thumnailCacheDir", &self.thumbnail_cache_directory),
        ] {
            if let Some(value) = value {
                fields.insert(key.into(), value.protocol(style)?.into());
            }
        }
        if let Some(value) = &self.proxy_address {
            let invalid = || {
                Error::InvalidConfiguration { reason:"native proxy URI must be bounded HTTP(S)/SOCKS5 authority without controls, query or fragment" }
            };
            if value.len() > 32768 || value.chars().any(char::is_control) {
                return Err(invalid());
            }
            if !value.is_empty() {
                let url = url::Url::parse(value).map_err(|_| invalid())?;
                if !matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h")
                    || url.host_str().is_none()
                    || url.port() == Some(0)
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || !matches!(url.path(), "" | "/")
                {
                    return Err(invalid());
                }
            }
            fields.insert("userProxyAddress".into(), value.clone().into());
        }
        Ok(Value::Object(fields))
    }
}
impl fmt::Debug for SystemPreferencesPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemPreferencesPatch")
            .field("changes_audit_path", &self.audit_file.is_some())
            .field(
                "changes_thumbnail_path",
                &self.thumbnail_cache_directory.is_some(),
            )
            .field("changes_proxy_address", &self.proxy_address.is_some())
            .finish_non_exhaustive()
    }
}
