//! Authenticated management connections, separate from process ownership.

mod device_control;
mod device_ignore;
mod invitation_control;
mod network_control;
mod relay_control;
mod scan_control;
mod sync_observation;
mod transport_control;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use url::Url;

use crate::{
    ApiKey, CreateFolderOptions, DeviceId, Error, FolderConfig, FolderId, FolderPatch,
    FolderRemoval, FolderStatus, FolderUpdate, ManagementEndpoint, PathStyle, ResponseDiagnostic,
    Result, SystemStatus, BASELINE_ENGINE_VERSION,
};
use crate::{RawRequest, RawResponse, RequestEffect};

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
    mutation_lock: Arc<tokio::sync::Mutex<()>>,
    endpoint_kind: crate::EndpointKind,
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
    /// Explicitly ask this engine to generate a fresh read/write and read-only pair.
    /// Generation registers no folder; these credentials are not management keys.
    pub async fn generate_share(&self) -> Result<crate::GeneratedShare> {
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                "generate sharing keys",
                reqwest::Method::GET,
                self.connection
                    .management_url("rest/svc/folder/secret", &[])?,
                None,
                true,
            )
            .await?;
        crate::sharing::generated(status, bytes)
    }

    /// Validate a sharing key on this authenticated target and prepare its local ID.
    /// No key-format permission guess, cross-node ID equality or folder registration.
    pub async fn validate_share_key(&self, key: &crate::ShareKey) -> Result<crate::ValidatedShare> {
        self.system_status().await?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                "validate sharing key",
                reqwest::Method::GET,
                self.connection.management_url(
                    "rest/svc/folder/secret_validate",
                    &[("key", key.expose_secret())],
                )?,
                None,
                false,
            )
            .await?;
        crate::sharing::validated(self.instance.device_id.clone(), key.clone(), status, bytes)
    }

    /// Register an engine-validated sharing key, then read the actual local configuration.
    ///
    /// Use preparation from this same target. The key establishes group membership;
    /// no directory ID is manually copied from another node. Readback does not
    /// establish peer association, remote acceptance or file synchronization.
    /// Reconcile folder_id after cancellation/unknown outcome before retrying.
    pub async fn join_folder(
        &self,
        options: &crate::JoinFolderOptions,
    ) -> Result<crate::JoinFolderResult> {
        use crate::{JoinPeerObservation, SharePermission};
        let share = &options.share;
        if share.device_id != self.instance.device_id {
            return Err(Error::IdentityMismatch {
                expected: share.device_id.clone(),
                actual: self.instance.device_id.clone(),
            });
        }
        if matches!(share.permission, SharePermission::Unknown(_)) {
            return Err(Error::InvalidConfiguration {
                reason: "cannot register an unknown sharing permission",
            });
        }
        if options.path.style() != self.folder_path_style()? {
            return Err(Error::InvalidPath {
                reason: "path syntax differs from the connected engine",
            });
        }
        let path = options.path.to_protocol()?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let configured = self.folders().await?;
        for folder in &configured {
            if folder.id == share.registration_id {
                return Err(Error::FolderAlreadyExists {
                    id: folder.id.clone(),
                });
            }
            let known_key = ["secretKey", "readOnlySecret", "readWriteSecret"]
                .iter()
                .any(|field| {
                    folder
                        .extra
                        .get(*field)
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|value| {
                            value == share.submitted_key.expose_secret()
                                || value == share.read_only_key.expose_secret()
                                || share
                                    .read_write_key
                                    .as_ref()
                                    .is_some_and(|key| value == key.expose_secret())
                        })
                });
            if known_key {
                return Err(Error::ShareAlreadyConfigured {
                    id: folder.id.clone(),
                });
            }
            if !options.allow_shared_path && folder.path.to_protocol().is_ok_and(|p| p == path) {
                return Err(Error::FolderPathAlreadyConfigured {
                    id: folder.id.clone(),
                });
            }
        }
        let mut defaults: serde_json::Map<String, serde_json::Value> = self
            .connection
            .get_json("read folder defaults", "rest/config/defaults/folder")
            .await?;
        defaults.insert(
            "id".to_owned(),
            serde_json::json!(share.registration_id.as_str()),
        );
        defaults.insert("path".to_owned(), serde_json::json!(path));
        defaults.insert(
            "secretKey".to_owned(),
            serde_json::json!(share.submitted_key.expose_secret()),
        );
        // Match the actual join route: the engine derives these from the submitted key.
        defaults.insert("readOnlySecret".to_owned(), serde_json::json!(""));
        defaults.insert("readWriteSecret".to_owned(), serde_json::json!(""));
        if let Some(label) = &options.label {
            defaults.insert("label".to_owned(), serde_json::json!(label));
        }
        if let Some(paused) = options.paused {
            defaults.insert("paused".to_owned(), serde_json::json!(paused));
        }
        self.connection
            .post_json(
                "register sharing key",
                "rest/config/folders",
                &serde_json::Value::Object(defaults),
            )
            .await?;
        let configuration = self
            .folder(&share.registration_id)
            .await
            .map_err(|source| Error::MutationOutcomeUnknown {
                operation: "read back sharing registration",
                source: Box::new(source),
            })?;
        let value = |field: &str| {
            configuration
                .extra
                .get(field)
                .and_then(serde_json::Value::as_str)
        };
        let submitted_key_matches = value("secretKey") == Some(share.submitted_key.expose_secret());
        let read_only_key_matches =
            value("readOnlySecret") == Some(share.read_only_key.expose_secret());
        let read_write_key_matches = value("readWriteSecret")
            == Some(
                share
                    .read_write_key
                    .as_ref()
                    .map_or("", |key| key.expose_secret()),
            );
        Ok(crate::JoinFolderResult {
            configuration,
            permission: share.permission.clone(),
            submitted_key_matches,
            read_only_key_matches,
            read_write_key_matches,
            peer_observation: JoinPeerObservation::Unobserved,
        })
    }

    /// Request one whole-folder scan, with fresh identity/existence checks.
    ///
    /// This response alone is not a scan-completion receipt. Establish
    /// observe_next_scan first to observe an actual cycle. A failed modifying
    /// response can be an unknown outcome and is never automatically retried.
    pub async fn request_scan(&self, folder: &FolderId) -> Result<()> {
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        if self.folder(folder).await?.paused {
            return Err(Error::ScanNotIdle);
        }
        let url = self
            .connection
            .management_url("rest/db/scan", &[("folder", folder.as_str())])?;
        self.connection
            .request_bytes(
                "request folder scan",
                reqwest::Method::POST,
                url,
                None,
                true,
            )
            .await
            .map(|_| ())
    }
    pub(crate) async fn event_wire(
        &self,
        since: u64,
        limit: usize,
    ) -> Result<Vec<crate::events::WireEvent>> {
        let since = since.to_string();
        let limit_text = limit.to_string();
        let url = self.connection.management_url(
            "rest/events",
            &[("since", &since), ("limit", &limit_text), ("timeout", "0")],
        )?;
        let (status, bytes) = self
            .connection
            .request_bytes("read engine events", reqwest::Method::GET, url, None, false)
            .await?;
        let invalid = || Error::InvalidResponse {
            operation: "read bounded ordered engine events",
            response: ResponseDiagnostic::new(status, bytes.clone()),
        };
        let events: Vec<crate::events::WireEvent> =
            serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if !crate::events::validate_wire(&events, limit) {
            return Err(invalid());
        }
        Ok(events)
    }
    /// Request normal engine shutdown once, after a fresh identity check.
    ///
    /// Success acknowledges the management command; this borrowed Client cannot
    /// observe OS process-tree exit. Transport uncertainty is not retried. Owned
    /// callers should use ManagedInstance::shutdown to observe actual exit.
    pub async fn request_shutdown(&self) -> Result<()> {
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.connection
            .request_bytes(
                "request graceful owned shutdown",
                reqwest::Method::POST,
                self.connection
                    .management_url("rest/system/shutdown", &[])?,
                None,
                true,
            )
            .await
            .map(|_| ())
    }

    /// Authenticate, apply the version policy, and read/optionally compare ID.
    ///
    /// Success means these management reads succeeded. It does not mean peers
    /// are connected, data has synchronized, or all optional features apply.
    /// Poll this future inside a Tokio runtime with I/O and timers enabled.
    /// A missing runtime is reported before any request is attempted.
    pub async fn connect(options: ConnectOptions) -> Result<Self> {
        let endpoint_kind = options.endpoint.kind();
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
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            endpoint_kind,
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

    /// Read current engine build metadata with a new authenticated request.
    ///
    /// This does not replace the handshake snapshot or reclassify its version
    /// policy result. Reconnect after an engine replacement or upgrade to apply
    /// connection version/identity policy to that new instance.
    pub async fn version(&self) -> Result<EngineVersion> {
        self.connection
            .get_json("read current version", "rest/system/version")
            .await
    }

    /// Read fresh system status and require the handshake identity to match.
    ///
    /// Missing metrics remain unknown. This read does not own the process or
    /// establish that any particular file batch finished synchronizing.
    pub async fn system_status(&self) -> Result<SystemStatus> {
        let status: SystemStatus = self
            .connection
            .get_json("read system status", "rest/system/status")
            .await?;
        if status.device_id != self.instance.device_id {
            return Err(Error::IdentityMismatch {
                expected: self.instance.device_id.clone(),
                actual: status.device_id,
            });
        }
        Ok(status)
    }

    /// Read current synchronization state for one configured folder.
    ///
    /// The opaque identifier is encoded as one query value. Activity and
    /// counters are a snapshot, not a transfer or business-batch guarantee.
    pub async fn folder_status(&self, folder: &FolderId) -> Result<FolderStatus> {
        self.connection
            .get_json_with_query(
                "read folder status",
                "rest/db/status",
                &[("folder", folder.as_str())],
            )
            .await
    }

    fn folder_path_style(&self) -> Result<PathStyle> {
        match self.instance.version.os.as_str() {
            "windows" => Ok(PathStyle::Windows),
            "linux" | "darwin" => Ok(PathStyle::Unix),
            _ => Err(Error::InvalidConfiguration {
                reason: "engine path syntax is unknown; no host-based guess is made",
            }),
        }
    }

    /// Read configured folders while retaining their target paths and extra fields.
    ///
    /// This reads the configuration snapshot and extracts its folders. It does
    /// not expose other configuration values or access the caller's filesystem.
    pub async fn folders(&self) -> Result<Vec<FolderConfig>> {
        let style = self.folder_path_style()?;
        let wire: crate::folders::WireFolderIndex = self
            .connection
            .get_json("read configured folders", "rest/config")
            .await?;
        wire.folders
            .into_iter()
            .map(|folder| folder.into_config(style))
            .collect()
    }

    /// Find one exact opaque ID in the current folder configuration snapshot.
    pub async fn folder(&self, id: &FolderId) -> Result<FolderConfig> {
        self.folders()
            .await?
            .into_iter()
            .find(|folder| folder.id == *id)
            .ok_or_else(|| Error::FolderNotFound { id: id.clone() })
    }

    /// Register a new folder from upstream defaults, then read its configuration.
    ///
    /// Existing IDs and, by default, identical path strings are rejected before
    /// POST. Clones of this Client serialize creation. The upstream POST is an
    /// upsert and ignores the tested If-Match condition: independent clients or
    /// other writers must coordinate; this is not an atomic create-if-absent.
    ///
    /// Success means configuration was accepted and read back. Directory setup,
    /// scanning and synchronization can continue afterward; inspect folder status.
    /// After cancellation or MutationOutcomeUnknown, read the ID before retrying.
    pub async fn create_folder(&self, options: &CreateFolderOptions) -> Result<FolderConfig> {
        let style = self.folder_path_style()?;
        if options.path.style() != style {
            return Err(Error::InvalidPath {
                reason: "path syntax differs from the connected engine",
            });
        }
        let path = options.path.to_protocol()?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let configured = self.folders().await?;
        if configured.iter().any(|folder| folder.id == options.id) {
            return Err(Error::FolderAlreadyExists {
                id: options.id.clone(),
            });
        }
        if !options.allow_shared_path {
            if let Some(folder) = configured.iter().find(|folder| {
                folder
                    .path
                    .to_protocol()
                    .is_ok_and(|configured| configured == path)
            }) {
                return Err(Error::FolderPathAlreadyConfigured {
                    id: folder.id.clone(),
                });
            }
        }
        let mut defaults: serde_json::Map<String, serde_json::Value> = self
            .connection
            .get_json("read folder defaults", "rest/config/defaults/folder")
            .await?;
        defaults.insert("id".to_owned(), serde_json::json!(options.id.as_str()));
        defaults.insert("path".to_owned(), serde_json::json!(path));
        if let Some(label) = &options.label {
            defaults.insert("label".to_owned(), serde_json::json!(label));
        }
        if let Some(paused) = options.paused {
            defaults.insert("paused".to_owned(), serde_json::json!(paused));
        }
        self.connection
            .post_json(
                "create folder",
                "rest/config/folders",
                &serde_json::Value::Object(defaults),
            )
            .await?;
        self.folder(&options.id)
            .await
            .map_err(|source| Error::MutationOutcomeUnknown {
                operation: "read back created folder",
                source: Box::new(source),
            })
    }

    /// Change only the requested fields, then return actual configuration readback.
    ///
    /// Check `requested_fields_match`; a successful HTTP acknowledgment is not
    /// treated as proof that every requested value is already visible. Runtime
    /// activity remains a separate observation through [`Self::folder_status`].
    /// Clones serialize modifications and recheck identity before writing, but
    /// independent writers still need coordination. No mutation is retried.
    /// Empty patches and literal dot-segment IDs are rejected before requests;
    /// the latter cannot be addressed without URL path normalization.
    pub async fn update_folder(&self, id: &FolderId, patch: &FolderPatch) -> Result<FolderUpdate> {
        if patch.is_empty() {
            return Err(Error::InvalidConfiguration {
                reason: "folder patch must contain at least one field",
            });
        }
        let url = self.connection.folder_url(id)?;
        let body = serde_json::to_value(patch).map_err(|_| Error::InvalidConfiguration {
            reason: "folder patch cannot be encoded",
        })?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.folder(id).await?;
        self.connection
            .request_bytes(
                "update folder",
                reqwest::Method::PATCH,
                url,
                Some(&body),
                true,
            )
            .await?;
        let configuration =
            self.folder(id)
                .await
                .map_err(|source| Error::MutationOutcomeUnknown {
                    operation: "read back updated folder",
                    source: Box::new(source),
                })?;
        Ok(FolderUpdate {
            requested_fields_match: patch.matches(&configuration),
            configuration,
        })
    }

    /// Request folder-level pause and return configuration readback.
    ///
    /// This does not pause the instance or its devices. Runtime shutdown of
    /// folder activity can follow configuration application asynchronously.
    pub async fn pause_folder(&self, id: &FolderId) -> Result<FolderUpdate> {
        self.update_folder(id, &FolderPatch::default().paused(true))
            .await
    }

    /// Clear this folder's pause setting and return configuration readback.
    ///
    /// Other pause layers or errors may still prevent synchronization. Inspect
    /// the returned configuration and current activity rather than assuming it.
    pub async fn resume_folder(&self, id: &FolderId) -> Result<FolderUpdate> {
        self.update_folder(id, &FolderPatch::default().paused(false))
            .await
    }

    /// Unregister one exact folder ID without requesting deletion of its files.
    ///
    /// Only the configuration DELETE is sent, with no file-deletion parameter
    /// or body. The target and identity must still exist before the write.
    /// Inspect `configuration_absent` on the returned snapshot; another writer
    /// can change the ID again. The controller does not inspect or remove local
    /// paths. Unknown outcomes and cancellation require reconciliation before
    /// retrying; no modifying request is retried automatically.
    pub async fn remove_folder_keep_files(&self, id: &FolderId) -> Result<FolderRemoval> {
        let url = self.connection.folder_url(id)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let previous_configuration = self.folder(id).await?;
        self.connection
            .request_bytes(
                "unregister folder",
                reqwest::Method::DELETE,
                url,
                None,
                true,
            )
            .await?;
        let configured = self
            .folders()
            .await
            .map_err(|source| Error::MutationOutcomeUnknown {
                operation: "read back unregistered folder",
                source: Box::new(source),
            })?;
        Ok(FolderRemoval {
            previous_configuration,
            configuration_absent: !configured.iter().any(|folder| folder.id == *id),
        })
    }

    /// Send an explicit raw request only through this management connection.
    ///
    /// Components/queries are encoded under the configured base path. The
    /// connection's authentication, deadline, response bound and redirect/retry
    /// policy remain active. MayModify requests serialize with typed mutations
    /// and recheck instance identity first, even when their HTTP method is GET.
    /// The caller is responsible for declaring an unmodeled operation's effects.
    ///
    /// All HTTP statuses, headers and body bytes are retained. A returned raw
    /// response is not a typed business-success or capability-support claim.
    /// Transport/body failures after a possible write remain unknown outcomes.
    pub async fn raw_request(&self, request: &RawRequest) -> Result<RawResponse> {
        let mutation = request.effect == RequestEffect::MayModify;
        let _guard = if mutation {
            Some(self.connection.mutation_lock.lock().await)
        } else {
            None
        };
        if mutation {
            self.system_status().await?;
        }
        let mut url = self.connection.base.clone();
        if !request.components.is_empty() {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| Error::InvalidEndpoint {
                    reason: "management URL cannot contain path components",
                })?;
            path.pop_if_empty();
            for component in &request.components {
                path.push(component);
            }
        }
        if !request.query.is_empty() {
            url.query_pairs_mut().extend_pairs(
                request
                    .query
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
            );
        }
        let mut outgoing = self
            .connection
            .http
            .request(request.method.http(), url)
            .headers(request.headers.clone())
            .header("X-API-Key", self.connection.key.header());
        if let Some(body) = &request.body {
            outgoing = outgoing.body(body.clone());
        }
        self.connection
            .receive_response("raw management request", outgoing, mutation)
            .await
    }

    /// Inspect code/evidence, target-scope match and unprobed instance conditions.
    ///
    /// This uses the handshake snapshot and performs no I/O. Reconnect after
    /// changing the engine. Library implementation and historical validation
    /// do not establish this instance's optional authorization or license.
    pub fn capabilities(&self) -> crate::CapabilityReport {
        crate::CapabilityReport::build(
            &self.instance,
            self.connection.endpoint_kind,
            self.connection.base.scheme() == "https",
        )
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
        self.get_json_with_query(operation, route, &[]).await
    }

    async fn get_json_with_query<T: DeserializeOwned>(
        &self,
        operation: &'static str,
        route: &'static str,
        query: &[(&str, &str)],
    ) -> Result<T> {
        let url = self.management_url(route, query)?;
        let (status, bytes) = self
            .request_bytes(operation, reqwest::Method::GET, url, None, false)
            .await?;
        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse {
            operation,
            response: ResponseDiagnostic::new(status, bytes),
        })
    }
    async fn post_json(
        &self,
        operation: &'static str,
        route: &'static str,
        body: &serde_json::Value,
    ) -> Result<()> {
        self.request_bytes(
            operation,
            reqwest::Method::POST,
            self.management_url(route, &[])?,
            Some(body),
            true,
        )
        .await
        .map(|_| ())
    }
    fn management_url(&self, route: &str, query: &[(&str, &str)]) -> Result<Url> {
        let mut url = self.base.join(route).map_err(|_| Error::InvalidEndpoint {
            reason: "management route cannot be joined to base URL",
        })?;
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query.iter().copied());
        }
        Ok(url)
    }

    fn folder_url(&self, id: &FolderId) -> Result<Url> {
        if matches!(id.as_str(), "." | "..") {
            return Err(Error::InvalidConfiguration {
                reason: "dot-segment folder IDs cannot be addressed by an item URL",
            });
        }
        let mut url = self.management_url("rest/config/folders/", &[])?;
        url.path_segments_mut()
            .map_err(|_| Error::InvalidEndpoint {
                reason: "management URL cannot contain path segments",
            })?
            .pop_if_empty()
            .push(id.as_str());
        Ok(url)
    }

    async fn request_bytes(
        &self,
        operation: &'static str,
        method: reqwest::Method,
        url: Url,
        body: Option<&serde_json::Value>,
        mutation: bool,
    ) -> Result<(u16, Vec<u8>)> {
        let mut request = self
            .http
            .request(method, url)
            .header("X-API-Key", self.key.header());
        if let Some(body) = body {
            request = request.json(body);
        }
        let RawResponse {
            status,
            body: bytes,
            ..
        } = self.receive_response(operation, request, mutation).await?;
        if status == 401 {
            return Err(Error::Authentication { status });
        }
        let uncertain = |source| mutation_error(operation, mutation, source);
        if status == 403 {
            return Err(Error::AccessDenied {
                response: ResponseDiagnostic::new(status, bytes),
            });
        }
        if !(200..300).contains(&status) {
            return Err(uncertain(Error::Http {
                response: ResponseDiagnostic::new(status, bytes),
            }));
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ErrorEnvelope {
            error: String,
        }
        if serde_json::from_slice::<ErrorEnvelope>(&bytes)
            .is_ok_and(|envelope| !envelope.error.is_empty())
        {
            return Err(uncertain(Error::Api {
                operation,
                response: ResponseDiagnostic::new(status, bytes),
            }));
        }
        Ok((status, bytes))
    }

    async fn receive_response(
        &self,
        operation: &'static str,
        request: reqwest::RequestBuilder,
        mutation: bool,
    ) -> Result<RawResponse> {
        let uncertain = |source| mutation_error(operation, mutation, source);
        let mut response = request
            .send()
            .await
            .map_err(|e| uncertain(transport_error(operation, e)))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect();
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| uncertain(transport_error(operation, e)))?
        {
            if chunk.len() > self.response_limit.saturating_sub(body.len()) {
                return Err(uncertain(Error::ResponseTooLarge {
                    limit: self.response_limit,
                }));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(RawResponse {
            status,
            headers,
            body,
        })
    }
}

fn mutation_error(operation: &'static str, mutation: bool, source: Error) -> Error {
    if mutation {
        Error::MutationOutcomeUnknown {
            operation,
            source: Box::new(source),
        }
    } else {
        source
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
