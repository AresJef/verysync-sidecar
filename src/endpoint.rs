//! Explicit management endpoints. Constructing one never contacts an instance.

use std::path::{Path, PathBuf};
use url::{Host, Url};

use crate::{Error, Result};

/// The transport and address category of an explicit management endpoint.
///
/// Classification is syntactic; it does not resolve DNS, probe a port, discover
/// a running program, or establish that an address is secure or reachable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointKind {
    /// A native Unix-domain socket path, supported by Unix client transports.
    UnixSocket,
    /// HTTP or HTTPS addressed to a literal loopback IP or `localhost`.
    LoopbackTcp,
    /// An explicitly supplied HTTP(S) address, including private LAN addresses.
    RemoteHttp,
}

/// An explicit target for a management connection.
///
/// There is no default address or automatic discovery. HTTP credentials belong
/// in connection authentication, not in the URL. A URL may include a reverse
/// proxy base path; a missing trailing slash is appended to that base path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementEndpoint(EndpointValue);

#[derive(Clone, Debug, Eq, PartialEq)]
enum EndpointValue {
    Socket(PathBuf),
    Http(Url),
}

impl ManagementEndpoint {
    /// Select an absolute native Unix socket path without opening it.
    ///
    /// The path is retained without conversion to a string. Whether the current
    /// platform can connect to Unix sockets is checked by the client transport.
    pub fn unix_socket(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if !path.is_absolute() || path.as_os_str().as_encoded_bytes().contains(&0) {
            return Err(Error::InvalidEndpoint {
                reason: "socket path must be absolute and contain no NUL",
            });
        }
        Ok(Self(EndpointValue::Socket(path)))
    }

    /// Select an explicit HTTP or HTTPS base URL without making a request.
    ///
    /// Private network addresses are accepted. User information, query strings,
    /// fragments, control characters, and destination port zero are rejected.
    /// Invalid input is never included in the returned error.
    pub fn http(value: &str) -> Result<Self> {
        if value.chars().any(char::is_control) {
            return Err(Error::InvalidEndpoint {
                reason: "URL contains control characters",
            });
        }
        let mut url = Url::parse(value).map_err(|_| Error::InvalidEndpoint {
            reason: "an absolute HTTP(S) URL is required",
        })?;
        if !matches!(url.scheme(), "http" | "https") || !url.has_host() {
            return Err(Error::InvalidEndpoint {
                reason: "an absolute HTTP(S) URL with a host is required",
            });
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::InvalidEndpoint {
                reason: "URL must not contain user information, a query, or a fragment",
            });
        }
        if url.port() == Some(0) {
            return Err(Error::InvalidEndpoint {
                reason: "destination port zero is not permitted",
            });
        }
        if !url.path().ends_with('/') {
            url.path_segments_mut()
                .map_err(|_| Error::InvalidEndpoint {
                    reason: "URL cannot be used as a base",
                })?
                .push("");
        }
        Ok(Self(EndpointValue::Http(url)))
    }

    /// Classify this explicit address without resolving or contacting it.
    pub fn kind(&self) -> EndpointKind {
        match &self.0 {
            EndpointValue::Socket(_) => EndpointKind::UnixSocket,
            EndpointValue::Http(url) => {
                let loopback = match url.host() {
                    Some(Host::Ipv4(ip)) => ip.is_loopback(),
                    Some(Host::Ipv6(ip)) => ip.is_loopback(),
                    Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
                    None => false,
                };
                if loopback {
                    EndpointKind::LoopbackTcp
                } else {
                    EndpointKind::RemoteHttp
                }
            }
        }
    }

    /// Borrow the exact native socket path, when this is a socket endpoint.
    pub fn socket_path(&self) -> Option<&Path> {
        match &self.0 {
            EndpointValue::Socket(path) => Some(path),
            EndpointValue::Http(_) => None,
        }
    }

    /// Borrow the validated HTTP(S) base URL, when this is an HTTP endpoint.
    pub fn http_url(&self) -> Option<&Url> {
        match &self.0 {
            EndpointValue::Http(url) => Some(url),
            EndpointValue::Socket(_) => None,
        }
    }
}
