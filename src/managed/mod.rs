//! Explicit ownership of a program and a library-owned private state directory.

mod bootstrap;
mod instance;
pub use instance::{ManagedExit, ManagedInstance};
mod native;
mod process;
mod state;

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use crate::{Error, LocalProgram, ManagementEndpoint, Result};

/// Settings for explicitly starting a caller-selected local program.
///
/// The state must be new/empty or already marked as owned by this library. The
/// library refuses an ordinary existing application state. Its exclusive state
/// lease is separate from any engine lock. Addresses are explicit: a socket must
/// be `gui.sock` directly inside the state, or HTTP must use a literal loopback
/// IP, a fixed port and no proxy prefix. No address discovery occurs.
#[derive(Clone, Debug)]
pub struct ManagedOptions {
    pub(crate) program: LocalProgram,
    pub(crate) state: PathBuf,
    pub(crate) endpoint: ManagementEndpoint,
    pub(crate) timeout: Duration,
    pub(crate) request_timeout: Duration,
}

impl ManagedOptions {
    /// Choose the local program, dedicated persistent state and management address.
    pub fn new(
        program: LocalProgram,
        state: impl Into<PathBuf>,
        endpoint: ManagementEndpoint,
    ) -> Result<Self> {
        let state = state.into();
        if !state.is_absolute()
            || state.as_os_str().as_encoded_bytes().contains(&0)
            || state
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(Error::InvalidConfiguration {
                reason: "managed state must be an absolute path without NUL or parent components",
            });
        }
        if let Some(socket) = endpoint.socket_path() {
            if socket != state.join("gui.sock") {
                return Err(Error::InvalidConfiguration {
                    reason: "managed socket must be gui.sock directly inside its dedicated state",
                });
            }
            #[cfg(unix)]
            if socket.as_os_str().as_encoded_bytes().len() >= 104 {
                return Err(Error::InvalidConfiguration {
                    reason: "managed socket path exceeds the portable Unix limit",
                });
            }
            #[cfg(not(unix))]
            return Err(Error::UnsupportedTransport {
                transport: "managed Unix socket",
            });
        } else if let Some(url) = endpoint.http_url() {
            let literal_loopback = match url.host() {
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                _ => false,
            };
            if url.scheme() != "http"
                || !literal_loopback
                || url.path() != "/"
                || url.port().is_none()
            {
                return Err(Error::InvalidConfiguration { reason: "managed HTTP requires a literal loopback IP, explicit nondefault port and no prefix" });
            }
        }
        // The fixed program's configuration protocol uses UTF-8 strings. Native
        // operations keep PathBuf; conversion fails rather than replacing bytes.
        state.to_str().ok_or(Error::PathEncoding)?;
        if let Some(path) = endpoint.socket_path() {
            path.to_str().ok_or(Error::PathEncoding)?;
        }
        Ok(Self {
            program,
            state,
            endpoint,
            timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(10),
        })
    }

    /// Set the total managed startup deadline, including preparation and readiness.
    pub fn startup_timeout(mut self, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            return Err(Error::InvalidConfiguration {
                reason: "managed startup deadline must be nonzero",
            });
        }
        self.timeout = timeout;
        Ok(self)
    }

    /// Set the retained management Client's per-request deadline (default 10s).
    /// The total startup deadline remains independently enforced.
    pub fn management_request_timeout(mut self, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            return Err(Error::InvalidConfiguration {
                reason: "management request deadline must be nonzero",
            });
        }
        self.request_timeout = timeout;
        Ok(self)
    }

    /// Borrow the explicit dedicated state path.
    pub fn state_directory(&self) -> &Path {
        &self.state
    }

    /// Borrow the selected local program without executing or inspecting it.
    pub fn program(&self) -> &LocalProgram {
        &self.program
    }

    /// Borrow the selected management address.
    pub fn management_endpoint(&self) -> &ManagementEndpoint {
        &self.endpoint
    }
}

fn io_error(operation: &'static str, source: std::io::Error) -> Error {
    Error::LocalIo { operation, source }
}
