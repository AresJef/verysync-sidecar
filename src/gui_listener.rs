//! Native GUI listener selections, separate from connection and process ownership.
use crate::{Error, GuiAuthenticationConfig, PathStyle, ResponseDiagnostic, Result, TargetPath};
use std::{collections::BTreeMap, fmt};

/// A native bind authority or target Unix socket path. Debug omits its value.
#[derive(Clone, Eq, PartialEq)]
pub struct GuiListenAddress(Address);
#[derive(Clone, Eq, PartialEq)]
enum Address {
    Tcp(String),
    Socket(TargetPath),
    Unknown(String),
}
impl GuiListenAddress {
    /// Select a native TCP bind authority, including a hostname, bracketed IPv6
    /// address or empty host. Port zero is explicit native ephemeral binding;
    /// callers must obtain a reachable connection address separately.
    pub fn tcp(authority: &str) -> Result<Self> {
        if authority.is_empty()
            || authority.len() > 1024
            || authority.chars().any(char::is_control)
            || authority.parse::<std::net::SocketAddr>().is_err()
                && !authority.rsplit_once(':').is_some_and(|(host, port)| {
                    port.parse::<u16>().is_ok()
                        && (host.is_empty() || url::Host::parse(host).is_ok())
                })
        {
            return Err(Error::InvalidConfiguration {
                reason: "GUI TCP binding requires a host and numeric port authority",
            });
        }
        Ok(Self(Address::Tcp(authority.into())))
    }
    /// Select an absolute Unix socket path using the target's syntax. Native
    /// local paths retain PathBuf through TargetPath; no filesystem access occurs.
    pub fn unix_socket(path: TargetPath) -> Result<Self> {
        if path.style() != PathStyle::Unix || !path.to_protocol()?.starts_with('/') {
            return Err(Error::InvalidPath {
                reason: "GUI Unix socket requires an absolute Unix target path",
            });
        }
        Ok(Self(Address::Socket(path)))
    }
    /// Borrow a TCP bind authority. It is not a reachable management URL.
    pub fn tcp_authority(&self) -> Option<&str> {
        if let Address::Tcp(v) = &self.0 {
            Some(v)
        } else {
            None
        }
    }
    /// Borrow the native or explicitly described target Unix socket path.
    pub fn socket_path(&self) -> Option<&TargetPath> {
        if let Address::Socket(v) = &self.0 {
            Some(v)
        } else {
            None
        }
    }
    /// Explicitly inspect an unrecognized native address. Typed writes refuse it.
    pub fn unknown_native(&self) -> Option<&str> {
        if let Address::Unknown(v) = &self.0 {
            Some(v)
        } else {
            None
        }
    }
    pub(crate) fn from_native(value: String, style: PathStyle) -> Self {
        if style == PathStyle::Unix && value.starts_with('/') {
            if let Ok(path) = TargetPath::remote(style, value.clone()) {
                return Self(Address::Socket(path));
            }
        }
        Self::tcp(&value).unwrap_or(Self(Address::Unknown(value)))
    }
    fn wire(&self, style: PathStyle) -> Result<&str> {
        match &self.0 {
            Address::Tcp(v) => Ok(v),
            Address::Socket(path) if style == PathStyle::Unix => path.to_protocol(),
            Address::Socket(_) => Err(Error::InvalidConfiguration {
                reason: "Unix GUI sockets require a Unix target",
            }),
            Address::Unknown(_) => Err(Error::InvalidConfiguration {
                reason: "unknown native GUI bind address cannot be submitted",
            }),
        }
    }
    fn same_native(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Address::Socket(a), Address::Socket(b)) => {
                a.style() == b.style() && a.to_protocol().ok() == b.to_protocol().ok()
            }
            _ => self == other,
        }
    }
}
impl fmt::Debug for GuiListenAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            Address::Tcp(_) => "GuiListenAddress::Tcp([REDACTED])",
            Address::Socket(_) => "GuiListenAddress::UnixSocket([REDACTED])",
            Address::Unknown(_) => "GuiListenAddress::Unknown([REDACTED])",
        })
    }
}

/// Native Unix socket mode selection, independent of HTTP cookie paths.
#[derive(Clone, Eq, PartialEq)]
pub enum GuiSocketPermissions {
    /// The native empty-string default; no explicit permission override.
    NativeDefault,
    /// Explicit Unix mode bits, validated as at most 0o7777 before submission.
    Mode(u16),
    /// An unrecognized native readback, retained but refused by typed writes.
    Unknown(String),
}
impl GuiSocketPermissions {
    fn from_native(v: &str) -> Self {
        if v.is_empty() {
            Self::NativeDefault
        } else {
            u16::from_str_radix(v, 8)
                .ok()
                .filter(|m| *m <= 0o7777)
                .map_or_else(|| Self::Unknown(v.into()), Self::Mode)
        }
    }
    fn wire(&self) -> Result<String> {
        match self {
            Self::NativeDefault => Ok(String::new()),
            Self::Mode(v) if *v <= 0o7777 => Ok(format!("{v:04o}")),
            _ => Err(Error::InvalidConfiguration {
                reason: "GUI socket permissions must be a known default or mode up to 0o7777",
            }),
        }
    }
}
impl fmt::Debug for GuiSocketPermissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativeDefault => f.write_str("GuiSocketPermissions::NativeDefault"),
            Self::Mode(v) => f
                .debug_tuple("GuiSocketPermissions::Mode")
                .field(v)
                .finish(),
            Self::Unknown(_) => f.write_str("GuiSocketPermissions::Unknown([REDACTED])"),
        }
    }
}

/// Actual stored listener settings. This does not prove a bind, TLS handshake,
/// socket mode, reachable endpoint or a running process. Credentials are excluded.
#[derive(Clone)]
pub struct GuiListenerConfig {
    /// Native management GUI server enabled selection, separate from desktop UI.
    pub enabled: bool,
    /// Actual native bind selection; not an automatically chosen connection URL.
    pub address: GuiListenAddress,
    /// Native TLS selection; certificate and hostname trust are separate.
    pub use_tls: bool,
    /// Native Unix socket mode override or preserved unknown selector.
    pub unix_socket_permissions: GuiSocketPermissions,
    extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for GuiListenerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuiListenerConfig")
            .field("enabled", &self.enabled)
            .field("address", &self.address)
            .field("use_tls", &self.use_tls)
            .field("unix_socket_permissions", &self.unix_socket_permissions)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}
impl GuiListenerConfig {
    /// Unmodeled preferences, excluding known GUI username/password/API key.
    /// These values can still be private; inspect them explicitly.
    pub fn extra(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.extra
    }
    pub(crate) fn from_auth(auth: GuiAuthenticationConfig, style: PathStyle) -> Result<Self> {
        let mut extra = auth.extra;
        let address = extra
            .remove("address")
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or_else(shape)?;
        let use_tls = extra
            .remove("useTLS")
            .and_then(|v| v.as_bool())
            .ok_or_else(shape)?;
        let mode = extra
            .remove("unixSocketPermissions")
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or_else(shape)?;
        Ok(Self {
            enabled: auth.enabled,
            address: GuiListenAddress::from_native(address, style),
            use_tls,
            unix_socket_permissions: GuiSocketPermissions::from_native(&mode),
            extra,
        })
    }
}
fn shape() -> Error {
    Error::InvalidConfiguration {
        reason: "native GUI listener does not match the required schema",
    }
}

/// Explicit listener changes. Unspecified fields and credentials are preserved.
#[derive(Clone, Default)]
pub struct GuiListenerPatch {
    enabled: Option<bool>,
    address: Option<GuiListenAddress>,
    use_tls: Option<bool>,
    permissions: Option<GuiSocketPermissions>,
}
impl GuiListenerPatch {
    /// Enable or disable the native server. Disabling can remove management
    /// access while synchronization and the process remain active.
    pub fn enabled(mut self, value: bool) -> Self {
        self.enabled = Some(value);
        self
    }
    /// Select an explicit native bind authority or target Unix socket path.
    pub fn address(mut self, value: GuiListenAddress) -> Self {
        self.address = Some(value);
        self
    }
    /// Enable or disable native TLS. Prepare matching server certificate/key
    /// material separately; the library does not install or bypass certificates.
    pub fn use_tls(mut self, value: bool) -> Self {
        self.use_tls = Some(value);
        self
    }
    /// Select native Unix socket permission bits. Rejects Windows targets.
    pub fn unix_socket_permissions(mut self, value: GuiSocketPermissions) -> Self {
        self.permissions = Some(value);
        self
    }
    pub(crate) fn body(&self, style: PathStyle) -> Result<serde_json::Value> {
        let mut body = serde_json::Map::new();
        if let Some(v) = self.enabled {
            body.insert("enabled".into(), v.into());
        }
        if let Some(v) = self.use_tls {
            body.insert("useTLS".into(), v.into());
        }
        if let Some(v) = &self.address {
            body.insert("address".into(), v.wire(style)?.into());
        }
        if let Some(v) = &self.permissions {
            if style != PathStyle::Unix {
                return Err(Error::InvalidConfiguration {
                    reason: "GUI socket permissions require a Unix target",
                });
            }
            body.insert("unixSocketPermissions".into(), v.wire()?.into());
        }
        if body.is_empty() {
            return Err(Error::InvalidConfiguration {
                reason: "GUI listener patch must contain at least one field",
            });
        }
        Ok(body.into())
    }
    fn matches(&self, actual: &GuiListenerConfig) -> bool {
        self.enabled.is_none_or(|v| v == actual.enabled)
            && self.use_tls.is_none_or(|v| v == actual.use_tls)
            && self
                .address
                .as_ref()
                .is_none_or(|v| v.same_native(&actual.address))
            && self
                .permissions
                .as_ref()
                .is_none_or(|v| v == &actual.unix_socket_permissions)
    }
}
impl fmt::Debug for GuiListenerPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuiListenerPatch")
            .field("enabled", &self.enabled)
            .field("use_tls", &self.use_tls)
            .field("changes_address", &self.address.is_some())
            .field("changes_permissions", &self.permissions.is_some())
            .finish()
    }
}

/// One acknowledged listener PATCH and its prior snapshot. No automatic reconnect
/// or process action follows. Acknowledgement does not prove the new listener works.
#[derive(Debug)]
pub struct GuiListenerUpdate {
    /// Previous stored listener selection, excluding known management credentials.
    pub previous_configuration: GuiListenerConfig,
    /// Exact private native acknowledgement, omitted by ordinary Debug.
    pub acknowledgement: ResponseDiagnostic,
    pub(crate) requested: GuiListenerPatch,
}
impl GuiListenerUpdate {
    /// Compare only requested fields with a fresh snapshot read after the caller
    /// explicitly reconnects. Another writer can subsequently change settings.
    pub fn requested_fields_match(&self, actual: &GuiListenerConfig) -> bool {
        self.requested.matches(actual)
    }
}
