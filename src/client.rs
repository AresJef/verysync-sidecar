//! Authenticated management connections, separate from process ownership.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use url::Url;

use crate::{
    ApiKey, DeviceId, Error, ManagementEndpoint, ResponseDiagnostic, Result,
    BASELINE_ENGINE_VERSION,
};

/// The policy applied to an engine version during connection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum VersionPolicy {
    /// Accept only the fixed, validated baseline. This is the default.
    #[default]
    ValidatedOnly,
    /// Explicitly permit an unverified engine version for experimentation.
    ///
    /// This does not turn unverified operations or platforms into supported
    /// ones, and does not suppress authentication, identity, or schema errors.
    AllowUnverified,
}

/// Whether the connected engine matches the validated version baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionCompatibility {
    /// The version is exactly the selected baseline.
    ValidatedBaseline,
    /// The caller explicitly permitted a version without acceptance evidence.
    Unverified,
}

/// Build metadata returned by the official version endpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineVersion {
    /// The exact upstream version string, including its `v` prefix.
    #[serde(deserialize_with = "nonempty_metadata")]
    pub version: String,
    /// The upstream descriptive build string, if provided.
    pub long_version: Option<String>,
    /// The engine's own OS identifier, such as `darwin`, `windows`, or `linux`.
    #[serde(deserialize_with = "nonempty_metadata")]
    pub os: String,
    /// The engine's own architecture identifier, such as `amd64` or `arm64`.
    #[serde(deserialize_with = "nonempty_metadata")]
    pub arch: String,
    /// Other upstream fields, retained without inventing a schema for them.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Identity and version observed during the authenticated connection handshake.
///
/// This is a snapshot, not a live status or evidence that any transfer finished.
#[derive(Clone, Debug)]
pub struct InstanceInfo {
    /// The identity read from the authenticated status endpoint.
    pub device_id: DeviceId,
    /// The version read from the authenticated version endpoint.
    pub version: EngineVersion,
    /// The version policy outcome, independent of feature/platform acceptance.
    pub compatibility: VersionCompatibility,
}

/// Explicit inputs for connecting to an already running management endpoint.
///
/// Connection performs reads only. It never launches a process, writes engine
/// settings, discovers another endpoint, or takes process ownership.
#[derive(Clone, Debug)]
pub struct ConnectOptions {
    endpoint: ManagementEndpoint,
    api_key: ApiKey,
    expected_device_id: Option<DeviceId>,
    version_policy: VersionPolicy,
    timeout: Duration,
    response_limit: usize,
}

impl ConnectOptions {
    /// Use the validated version policy, a ten-second request deadline, and a
    /// one-MiB management response limit. No ambient proxy is used.
    pub fn new(endpoint: ManagementEndpoint, api_key: ApiKey) -> Self {
        Self {
            endpoint,
            api_key,
            expected_device_id: None,
            version_policy: VersionPolicy::default(),
            timeout: Duration::from_secs(10),
            response_limit: 1024 * 1024,
        }
    }

    /// Require an exact identity match in addition to management authentication.
    ///
    /// Without this option, the returned identity is parsed and exposed for the
    /// caller to inspect, but it has not been compared to an out-of-band ID.
    pub fn expected_device_id(mut self, identity: DeviceId) -> Self {
        self.expected_device_id = Some(identity);
        self
    }

    /// Select the explicit version policy for this connection.
    pub fn version_policy(mut self, policy: VersionPolicy) -> Self {
        self.version_policy = policy;
        self
    }

    /// Set a nonzero deadline covering each complete management response.
    pub fn request_timeout(mut self, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            return Err(Error::InvalidConfiguration {
                reason: "request timeout must be nonzero",
            });
        }
        self.timeout = timeout;
        Ok(self)
    }

    /// Set a nonzero maximum size for a buffered management response.
    pub fn response_limit(mut self, bytes: usize) -> Result<Self> {
        if bytes == 0 {
            return Err(Error::InvalidConfiguration {
                reason: "response limit must be nonzero",
            });
        }
        self.response_limit = bytes;
        Ok(self)
    }
}

#[derive(Clone)]
struct Connection {
    http: reqwest::Client,
    base: Url,
    key: ApiKey,
    response_limit: usize,
}

/// An authenticated connection that does not own the engine process.
///
/// Dropping or cloning this value never stops an engine. HTTP redirects and
/// automatic retries are disabled; credentials stay on the explicit endpoint.
/// The default `tls` feature validates HTTPS certificates normally.
#[derive(Clone)]
pub struct Client {
    connection: Connection,
    instance: InstanceInfo,
}

impl Client {
    /// Authenticate, apply the version policy, and read/optionally compare ID.
    ///
    /// Success means these management reads succeeded. It does not mean peers
    /// are connected, data has synchronized, or all optional features apply.
    /// Poll this future inside a Tokio runtime with I/O and timers enabled.
    /// A missing runtime is reported before any request is attempted.
    pub async fn connect(options: ConnectOptions) -> Result<Self> {
        tokio::runtime::Handle::try_current().map_err(|_| Error::InvalidConfiguration {
            reason: "a Tokio runtime with I/O and timers enabled is required",
        })?;
        let builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(options.timeout.min(Duration::from_secs(5)))
            .timeout(options.timeout)
            .user_agent(concat!("verysync-sidecar/", env!("CARGO_PKG_VERSION")));
        let (builder, base) = if let Some(socket) = options.endpoint.socket_path() {
            #[cfg(unix)]
            {
                (
                    builder.unix_socket(socket),
                    Url::parse("http://localhost/").map_err(|_| Error::InvalidEndpoint {
                        reason: "internal socket base URL",
                    })?,
                )
            }
            #[cfg(not(unix))]
            {
                let _ = socket;
                return Err(Error::UnsupportedTransport {
                    transport: "Unix-domain sockets on this platform",
                });
            }
        } else {
            let url = options
                .endpoint
                .http_url()
                .ok_or(Error::InvalidEndpoint {
                    reason: "missing HTTP base URL",
                })?
                .clone();
            #[cfg(not(feature = "tls"))]
            if url.scheme() == "https" {
                return Err(Error::UnsupportedTransport {
                    transport: "HTTPS requires the tls feature",
                });
            }
            (builder, url)
        };
        let http = builder
            .build()
            .map_err(|e| transport_error("build management client", e))?;
        let connection = Connection {
            http,
            base,
            key: options.api_key,
            response_limit: options.response_limit,
        };
        let version: EngineVersion = connection
            .get_json("read version", "rest/system/version")
            .await?;
        let compatibility = if version.version == BASELINE_ENGINE_VERSION {
            VersionCompatibility::ValidatedBaseline
        } else if options.version_policy == VersionPolicy::AllowUnverified {
            VersionCompatibility::Unverified
        } else {
            return Err(Error::IncompatibleVersion {
                actual: connection.key.redact(&version.version),
            });
        };
        #[derive(Deserialize)]
        struct StatusIdentity {
            #[serde(rename = "myID", deserialize_with = "device_identity")]
            my_id: DeviceId,
        }
        let status: StatusIdentity = connection
            .get_json("read identity", "rest/system/status")
            .await?;
        let device_id = status.my_id;
        if let Some(expected) = options.expected_device_id {
            if expected != device_id {
                return Err(Error::IdentityMismatch {
                    expected,
                    actual: device_id,
                });
            }
        }
        Ok(Self {
            connection,
            instance: InstanceInfo {
                device_id,
                version,
                compatibility,
            },
        })
    }

    /// Borrow the authenticated identity/version snapshot captured on connect.
    pub fn instance(&self) -> &InstanceInfo {
        &self.instance
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Client")
            .field(
                "base",
                &self.connection.key.redact(self.connection.base.as_str()),
            )
            .field(
                "device_id",
                &self.connection.key.redact(self.instance.device_id.as_str()),
            )
            .field(
                "version",
                &self.connection.key.redact(&self.instance.version.version),
            )
            .finish_non_exhaustive()
    }
}

impl Connection {
    async fn get_json<T: DeserializeOwned>(
        &self,
        operation: &'static str,
        route: &'static str,
    ) -> Result<T> {
        let url = self.base.join(route).map_err(|_| Error::InvalidEndpoint {
            reason: "management route cannot be joined to base URL",
        })?;
        let mut response = self
            .http
            .get(url)
            .header("X-API-Key", self.key.header())
            .send()
            .await
            .map_err(|e| transport_error(operation, e))?;
        let status = response.status().as_u16();
        if matches!(status, 401 | 403) {
            return Err(Error::Authentication { status });
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| transport_error(operation, e))?
        {
            if chunk.len() > self.response_limit.saturating_sub(bytes.len()) {
                return Err(Error::ResponseTooLarge {
                    limit: self.response_limit,
                });
            }
            bytes.extend_from_slice(&chunk);
        }
        if !(200..300).contains(&status) {
            return Err(Error::Http {
                response: ResponseDiagnostic::new(status, bytes),
            });
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse {
            operation,
            response: ResponseDiagnostic::new(status, bytes),
        })
    }
}

fn transport_error(operation: &'static str, error: reqwest::Error) -> Error {
    if error.is_timeout() {
        Error::Timeout { operation }
    } else {
        Error::Transport {
            operation,
            source: error.without_url(),
        }
    }
}

fn nonempty_metadata<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    if value.is_empty() {
        return Err(serde::de::Error::custom(
            "required engine metadata is empty",
        ));
    }
    Ok(value)
}

fn device_identity<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<DeviceId, D::Error> {
    let value = String::deserialize(deserializer)?;
    DeviceId::parse(&value).map_err(|_| serde::de::Error::custom("invalid engine identity layout"))
}
