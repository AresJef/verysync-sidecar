//! Per-connection trust and explicit proxy policy, without global state changes.
use crate::{Error, ManagementEndpoint, Result};
use std::fmt;

/// One explicitly selected HTTP(S) proxy. Ordinary Debug omits its address and
/// credentials. The library does not read proxy environment variables or PAC.
#[derive(Clone)]
pub struct ManagementProxy {
    wire: reqwest::Proxy,
    https: bool,
    authenticated: bool,
}
impl ManagementProxy {
    /// Select an HTTP(S) proxy authority with no user information, query,
    /// fragment, path prefix or zero port. Constructing this does not connect.
    /// HTTPS proxies require `tls`. Supply credentials separately.
    pub fn new(address: &str) -> Result<Self> {
        let endpoint = ManagementEndpoint::http(address)?;
        let url = endpoint.http_url().ok_or(Error::InvalidEndpoint {
            reason: "management proxy requires HTTP(S)",
        })?;
        if url.path() != "/" {
            return Err(Error::InvalidEndpoint {
                reason: "management proxy must not have a path prefix",
            });
        }
        let https = url.scheme() == "https";
        #[cfg(not(feature = "tls"))]
        if https {
            return Err(Error::UnsupportedTransport {
                transport: "HTTPS proxy requires the tls feature",
            });
        }
        let wire = reqwest::Proxy::all(url.as_str()).map_err(|_| Error::InvalidEndpoint {
            reason: "invalid management proxy authority",
        })?;
        Ok(Self {
            wire,
            https,
            authenticated: false,
        })
    }
    /// Supply Basic proxy authentication. Values are at most 4096 bytes without
    /// controls; a username cannot contain a colon. Credentials are not added
    /// to the target URL or target Authorization header. An HTTP proxy does not
    /// encrypt credentials on the proxy hop.
    pub fn basic_auth(mut self, username: &str, password: &str) -> Result<Self> {
        if username.len() > 4096
            || password.len() > 4096
            || username.contains(':')
            || username.chars().any(char::is_control)
            || password.chars().any(char::is_control)
        {
            return Err(Error::InvalidCredential {
                reason: "invalid or oversized proxy credentials",
            });
        }
        self.wire = self.wire.basic_auth(username, password);
        self.authenticated = true;
        Ok(self)
    }
}
impl fmt::Debug for ManagementProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagementProxy")
            .field("https", &self.https)
            .field("authenticated", &self.authenticated)
            .finish_non_exhaustive()
    }
}

/// Per-connection management trust and proxy policy. Default policy uses normal
/// TLS verification and no proxy. Clones retain policy without changing the
/// environment, operating-system trust store or a process-wide client.
#[derive(Clone, Default)]
pub struct ManagementTransport {
    proxy: Option<ManagementProxy>,
    #[cfg(feature = "tls")]
    roots: Vec<reqwest::tls::Certificate>,
}
impl ManagementTransport {
    /// Select one explicit proxy. HTTP uses forwarding and HTTPS uses CONNECT.
    /// The client does not fall back to a direct connection on proxy failure.
    pub fn proxy(mut self, proxy: ManagementProxy) -> Self {
        self.proxy = Some(proxy);
        self
    }
    /// Add a PEM bundle merged with normal platform roots. Each bundle must
    /// contain certificates and be at most one MiB; at most 64 additional roots
    /// are accepted across calls. PEM decoding and final TLS validation are
    /// separate; malformed DER can fail at connection construction. Certificate
    /// and hostname verification remain on. Requires `tls`; no system import.
    pub fn trusted_certificates_pem(self, bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 1024 * 1024 {
            return Err(Error::InvalidConfiguration {
                reason: "trusted PEM bundle must contain one byte to one MiB",
            });
        }
        #[cfg(feature = "tls")]
        {
            let certificates = reqwest::tls::Certificate::from_pem_bundle(bytes).map_err(|_| {
                Error::InvalidConfiguration {
                    reason: "trusted PEM certificate bundle cannot be decoded",
                }
            })?;
            self.with_roots(certificates)
        }
        #[cfg(not(feature = "tls"))]
        {
            Err(Error::UnsupportedTransport {
                transport: "trusted certificates require the tls feature",
            })
        }
    }
    /// Add one DER certificate, at most one MiB, to normal roots. Full trust-store
    /// validation occurs when the client is built. Hostname verification remains
    /// enabled. Requires `tls` and does not import into the operating system.
    pub fn trusted_certificate_der(self, bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 1024 * 1024 {
            return Err(Error::InvalidConfiguration {
                reason: "trusted DER certificate must contain one byte to one MiB",
            });
        }
        #[cfg(feature = "tls")]
        {
            let certificate = reqwest::tls::Certificate::from_der(bytes).map_err(|_| {
                Error::InvalidConfiguration {
                    reason: "trusted DER certificate cannot be decoded",
                }
            })?;
            self.with_roots(vec![certificate])
        }
        #[cfg(not(feature = "tls"))]
        {
            Err(Error::UnsupportedTransport {
                transport: "trusted certificates require the tls feature",
            })
        }
    }
    #[cfg(feature = "tls")]
    fn with_roots(mut self, certificates: Vec<reqwest::tls::Certificate>) -> Result<Self> {
        if certificates.is_empty() || certificates.len() > 64 - self.roots.len() {
            return Err(Error::InvalidConfiguration {
                reason: "management transport requires one to 64 additional roots",
            });
        }
        self.roots.extend(certificates);
        Ok(self)
    }
    fn root_count(&self) -> usize {
        #[cfg(feature = "tls")]
        {
            self.roots.len()
        }
        #[cfg(not(feature = "tls"))]
        {
            0
        }
    }
    pub(crate) fn version_diagnostic(&self, value: &str) -> String {
        // A credentialed proxy can reflect even the encoded authentication
        // header into a free-form version response. Ordinary errors/Debug do
        // not need that untrusted text; callers can inspect explicit metadata.
        if self.proxy.as_ref().is_some_and(|p| p.authenticated) {
            "[REDACTED proxy-authenticated version]".to_owned()
        } else {
            value.to_owned()
        }
    }
    pub(crate) fn apply(
        &self,
        mut builder: reqwest::ClientBuilder,
        endpoint: &ManagementEndpoint,
    ) -> Result<reqwest::ClientBuilder> {
        if endpoint.socket_path().is_some() && (self.proxy.is_some() || self.root_count() != 0) {
            return Err(Error::InvalidConfiguration {
                reason: "Unix management sockets do not use TCP proxy or TLS root settings",
            });
        }
        if let Some(proxy) = &self.proxy {
            builder = builder.proxy(proxy.wire.clone());
        }
        #[cfg(feature = "tls")]
        if !self.roots.is_empty() {
            builder = builder.tls_certs_merge(self.roots.clone());
        }
        Ok(builder)
    }
}
impl fmt::Debug for ManagementTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagementTransport")
            .field("proxy", &self.proxy)
            .field("additional_root_count", &self.root_count())
            .finish()
    }
}
