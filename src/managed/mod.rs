//! Explicit ownership of a program and a library-owned private state directory.

#[cfg(feature = "download")]
mod archive;
mod bootstrap;
#[cfg(feature = "download")]
mod download;
#[cfg(feature = "download")]
pub use download::{DownloadOptions, PreparedProgram};
mod instance;
pub use instance::{ManagedExit, ManagedInstance};
mod native;
mod process;
mod restart;
mod shutdown;
mod state;

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use crate::{Error, LocalProgram, ManagementEndpoint, Result};

/// Lifetime selected before creating an owned core; never a system service.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ManagedLifetime {
    /// Dropping the owner or exiting the caller ends its private core.
    #[default]
    CallerOwned,
    /// Explicitly keep a successfully started core after owner/caller exit.
    /// External OS job/cgroup/console termination policies still apply.
    Persistent,
}

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
    pub(crate) lifetime: ManagedLifetime,
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
            lifetime: ManagedLifetime::CallerOwned,
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

    /// Explicitly select core persistence before startup (default CallerOwned).
    /// Helpers and cancelled/failed startup still request exact cleanup. An
    /// abrupt caller death after persistent core creation can leave that core
    /// running before authenticated startup returns. No service is installed.
    pub fn lifetime(mut self, lifetime: ManagedLifetime) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Inspect the explicitly selected core lifetime policy.
    pub fn lifetime_policy(&self) -> ManagedLifetime {
        self.lifetime
    }

    /// Reconnect read-only to an existing completed private state/endpoint.
    ///
    /// Reads protected persisted identity/credentials, then authenticates that
    /// identity. Does not acquire process ownership, run/check the selected
    /// executable, create state, change configuration, or stop an existing core.
    pub async fn connect_existing(&self) -> Result<crate::Client> {
        tokio::runtime::Handle::try_current().map_err(|_| Error::InvalidConfiguration {
            reason: "private-state connections require a Tokio runtime with I/O and timers",
        })?;
        let options = self.clone();
        let (key, identity) =
            tokio::task::spawn_blocking(move || bootstrap::existing_connection(&options))
                .await
                .map_err(|_| Error::ManagedFailure {
                    reason: "private state read task failed",
                })??;
        crate::Client::connect(
            crate::ConnectOptions::new(self.endpoint.clone(), key)
                .expected_device_id(identity)
                .request_timeout(self.request_timeout)?,
        )
        .await
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
