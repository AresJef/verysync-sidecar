//! Explicit native Local-API connections; GUI API-key authentication is separate.
use super::{management_http, Connection, RequestAuthorization};
use crate::{
    DeviceId, EngineVersion, Error, InstanceInfo, ManagementEndpoint, ManagementTransport,
    RawRequest, RawResponse, RequestEffect, Result, SystemStatus, VersionCompatibility,
    VersionPolicy, BASELINE_ENGINE_VERSION,
};
use std::{fmt, sync::Arc, time::Duration};
mod common;
mod control;
pub use common::{
    LocalApiHardware, LocalApiHistoryFilter, LocalApiHistoryPage, LocalApiHistoryRecord,
};
pub use control::{LocalApiFolder, LocalApiPeer, LocalApiScanAcknowledgement};

#[derive(Clone)]
struct NativeLocalPolicy;
impl RequestAuthorization for NativeLocalPolicy {
    fn authorize(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request
    }
}

/// Explicit HTTP(S) endpoint and limits for an already enabled native Local-API.
///
/// The fixed core applies its own transport/enable/license conditions. GUI keys
/// are not required by the observed enabled loopback reads and are never sent
/// by this connection. Construction makes no request or configuration change.
#[derive(Clone, Debug)]
pub struct LocalApiConnectOptions {
    endpoint: ManagementEndpoint,
    expected_device_id: Option<DeviceId>,
    version_policy: VersionPolicy,
    timeout: Duration,
    response_limit: usize,
    transport: ManagementTransport,
}
impl LocalApiConnectOptions {
    /// Select an explicit HTTP(S) endpoint; the fixed core rejects Unix sockets
    /// before reading the Local-API enabled flag. No default address is chosen.
    pub fn new(endpoint: ManagementEndpoint) -> Result<Self> {
        if endpoint.http_url().is_none() {
            return Err(Error::InvalidEndpoint {
                reason: "native Local-API requires an explicit HTTP(S) endpoint",
            });
        }
        Ok(Self {
            endpoint,
            expected_device_id: None,
            version_policy: VersionPolicy::default(),
            timeout: Duration::from_secs(10),
            response_limit: 1024 * 1024,
            transport: ManagementTransport::default(),
        })
    }
    /// Require an out-of-band identity during the read-only connection handshake.
    pub fn expected_device_id(mut self, identity: DeviceId) -> Self {
        self.expected_device_id = Some(identity);
        self
    }
    /// Explicitly permit an unvalidated version, without promoting its features.
    pub fn version_policy(mut self, policy: VersionPolicy) -> Self {
        self.version_policy = policy;
        self
    }
    /// Bound each complete HTTP response with a nonzero deadline.
    pub fn request_timeout(mut self, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            return Err(Error::InvalidConfiguration {
                reason: "request timeout must be nonzero",
            });
        }
        self.timeout = timeout;
        Ok(self)
    }
    /// Bound buffered responses; zero is invalid rather than an unlimited mode.
    pub fn response_limit(mut self, bytes: usize) -> Result<Self> {
        if bytes == 0 {
            return Err(Error::InvalidConfiguration {
                reason: "response limit must be nonzero",
            });
        }
        self.response_limit = bytes;
        Ok(self)
    }
    /// Select explicit connection trust/proxy policy; ambient proxies are unused.
    pub fn transport(mut self, transport: ManagementTransport) -> Self {
        self.transport = transport;
        self
    }
}

/// Native Local-API connection, separate from GUI-key management and ownership.
///
/// It performs no activation, download, startup, discovery or license change.
/// Native enable, loopback and commercial conditions remain distinct. A reported
/// identity is compared out of band only when the caller supplies an expected ID.
#[derive(Clone)]
pub struct LocalApiClient {
    connection: Connection<NativeLocalPolicy>,
    instance: InstanceInfo,
}
impl fmt::Debug for LocalApiClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalApiClient")
            .field("endpoint_kind", &self.connection.endpoint_kind)
            .field("compatibility", &self.instance.compatibility)
            .finish_non_exhaustive()
    }
}
impl LocalApiClient {
    /// Read native version and identity without supplying a GUI key or changing
    /// settings. Disabled Local-API is not silently enabled or retried. A 404 is
    /// not automatically interpreted as a missing commercial entitlement.
    pub async fn connect(options: LocalApiConnectOptions) -> Result<Self> {
        tokio::runtime::Handle::try_current().map_err(|_| Error::InvalidConfiguration {
            reason: "a Tokio runtime with I/O and timers enabled is required",
        })?;
        let (http, base) = management_http(&options.endpoint, options.timeout, &options.transport)?;
        let connection = Connection {
            http,
            base,
            key: NativeLocalPolicy,
            response_limit: options.response_limit,
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            endpoint_kind: options.endpoint.kind(),
            endpoint: options.endpoint,
            timeout: options.timeout,
            version_policy: options.version_policy,
            transport: options.transport,
        };
        let version: EngineVersion = connection
            .get_json("read Local-API version", "rest/localapi/system/version")
            .await?;
        let compatibility = if version.version == BASELINE_ENGINE_VERSION {
            VersionCompatibility::ValidatedBaseline
        } else if options.version_policy == VersionPolicy::AllowUnverified {
            VersionCompatibility::Unverified
        } else {
            return Err(Error::IncompatibleVersion {
                actual: connection.transport.version_diagnostic(&version.version),
            });
        };
        let status: SystemStatus = connection
            .get_json("read Local-API identity", "rest/localapi/system/status")
            .await?;
        if let Some(expected) = options.expected_device_id {
            if expected != status.device_id {
                return Err(Error::IdentityMismatch {
                    expected,
                    actual: status.device_id,
                });
            }
        }
        Ok(Self {
            connection,
            instance: InstanceInfo {
                device_id: status.device_id,
                version,
                compatibility,
            },
        })
    }
    /// Borrow the exact endpoint; no endpoint discovery or fallback is performed.
    pub fn endpoint(&self) -> &ManagementEndpoint {
        &self.connection.endpoint
    }
    /// Identity/version snapshot from the connection's read-only handshake.
    pub fn instance(&self) -> &InstanceInfo {
        &self.instance
    }
    /// Read fresh version metadata without silently revising handshake policy.
    pub async fn version(&self) -> Result<EngineVersion> {
        self.connection
            .get_json("read Local-API version", "rest/localapi/system/version")
            .await
    }
    /// Read fresh native status and reject a changed instance identity.
    /// Missing metrics remain absent; this does not prove transfer completion.
    pub async fn system_status(&self) -> Result<SystemStatus> {
        let status: SystemStatus = self
            .connection
            .get_json("read Local-API status", "rest/localapi/system/status")
            .await?;
        if status.device_id != self.instance.device_id {
            return Err(Error::IdentityMismatch {
                expected: self.instance.device_id.clone(),
                actual: status.device_id,
            });
        }
        Ok(status)
    }
    /// Send bounded raw components beneath `rest/localapi/` on the selected
    /// endpoint. Components exclude that fixed prefix; native responses remain
    /// caller-interpreted. Potential writes serialize and recheck identity first.
    /// No request is retried, enabled, reversed or converted into a license grant.
    pub async fn raw(&self, request: RawRequest) -> Result<RawResponse> {
        let modifying = request.effect == RequestEffect::MayModify;
        let _guard = if modifying {
            Some(self.connection.mutation_lock.lock().await)
        } else {
            None
        };
        if modifying {
            self.system_status().await?;
        }
        let mut url = self.connection.base.clone();
        url.path_segments_mut()
            .map_err(|_| Error::InvalidEndpoint {
                reason: "Local-API URL cannot contain path segments",
            })?
            .pop_if_empty()
            .extend(["rest", "localapi"])
            .extend(&request.components);
        if !request.query.is_empty() {
            url.query_pairs_mut().extend_pairs(&request.query);
        }
        let mut prepared = self
            .connection
            .http
            .request(request.method.http(), url)
            .headers(request.headers);
        if let Some(body) = request.body {
            prepared = prepared.body(body);
        }
        self.connection
            .receive_response("execute raw Local-API request", prepared, modifying)
            .await
    }
}
