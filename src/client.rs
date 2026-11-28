//! Authenticated management connections, separate from process ownership.

mod auxiliary_control;
mod auxiliary_maintenance;
mod configuration_control;
mod control_identity;
mod control_preflight;
mod control_preview;
mod control_recovery;
mod default_versioning;
mod device_control;
mod device_ignore;
mod device_recovery;
mod file_control;
mod file_mutation;
mod file_transfer;
mod folder_options;
mod gui_listener;
mod gui_preferences;
mod gui_resources;
mod hardware_control;
mod history_control;
mod ignore_control;
mod invitation_control;
mod ldap_control;
mod license_control;
mod local_api;
mod local_sync_control;
mod maintenance_control;
mod management_auth;
mod native_helpers;
mod network_control;
mod official_account_control;
mod recovery;
mod relay_control;
mod remote_management;
mod scan_control;
mod scheduling;
mod selective;
mod sync_observation;
mod transport_control;
mod upgrade_control;

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
pub use control_identity::ControlIdentityObservation;
pub use control_preview::{
    SettingsChange, SettingsCommit, SettingsField, SettingsFieldChange, SettingsFieldResult,
    SettingsFieldState, SettingsPreview, SettingsStep, SettingsStepResult, SettingsTarget,
    SettingsValue,
};
pub use control_recovery::GuiListenerRecovery;
pub use device_recovery::DeviceRemovalRecovery;
pub use local_api::{
    LocalApiClient, LocalApiConnectOptions, LocalApiExitAcknowledgement, LocalApiExitAction,
    LocalApiFolder, LocalApiFolderCollectionUpdate, LocalApiHardware, LocalApiHistoryFilter,
    LocalApiHistoryPage, LocalApiHistoryRecord, LocalApiPeer, LocalApiScanAcknowledgement,
    LocalApiUpgradeAcknowledgement,
};
pub(crate) use upgrade_control::{retry_delay, retryable_read};

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

/// Identity and version observed during a connection handshake.
///
/// This is a snapshot, not a live status or evidence that any transfer finished.
#[derive(Clone, Debug)]
pub struct InstanceInfo {
    /// The identity read from the selected channel's status endpoint.
    pub device_id: DeviceId,
    /// The version read from the selected channel's version endpoint.
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
    pub(crate) endpoint: ManagementEndpoint,
    api_key: ApiKey,
    pub(crate) expected_device_id: Option<DeviceId>,
    version_policy: VersionPolicy,
    timeout: Duration,
    response_limit: usize,
    pub(crate) transport: crate::ManagementTransport,
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
            transport: crate::ManagementTransport::default(),
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

    /// Select per-connection trust and an explicit HTTP(S) proxy. Default policy
    /// uses normal TLS verification and no ambient proxy. Credential reconnection
    /// and GUI reload reconciliation retain the selection.
    pub fn transport(mut self, transport: crate::ManagementTransport) -> Self {
        self.transport = transport;
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

trait RequestAuthorization: Clone {
    fn authorize(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder;
}

impl RequestAuthorization for ApiKey {
    fn authorize(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.header("X-API-Key", self.header())
    }
}

#[derive(Clone)]
struct Connection<Authorization = ApiKey> {
    http: reqwest::Client,
    base: Url,
    key: Authorization,
    response_limit: usize,
    mutation_lock: Arc<tokio::sync::Mutex<()>>,
    endpoint_kind: crate::EndpointKind,
    endpoint: ManagementEndpoint,
    timeout: Duration,
    version_policy: VersionPolicy,
    transport: crate::ManagementTransport,
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
    transient_read_retries: bool,
    #[cfg(all(test, feature = "engine-tests"))]
    shutdown_calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl Client {
    /// Enable bounded transient reads for eligible high-level operations on this
    /// handle and its clones. Legacy requests retain their single-attempt behavior.
    /// Use [crate::OperationOptions::without_read_retry] to disable it for one call.
    pub fn with_transient_read_retries(mut self) -> Self {
        self.transient_read_retries = true;
        self
    }

    /// Borrow the exact selected management endpoint; this performs no discovery.
    pub fn endpoint(&self) -> &ManagementEndpoint {
        &self.connection.endpoint
    }
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
    /// A proposed dot-segment ID is rejected before the registration POST.
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
        validate_folder_item_id(&share.registration_id)?;
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
        source: &crate::EventSource,
        since: u64,
        limit: usize,
    ) -> Result<Vec<crate::events::WireEvent>> {
        let since = since.to_string();
        let limit_text = limit.to_string();
        let mut query = vec![
            ("since", since.as_str()),
            ("limit", limit_text.as_str()),
            ("timeout", "0"),
        ];
        if let crate::EventSource::Filtered(filter) = source {
            query.push(("events", filter.query_value()));
        }
        let url = self.connection.management_url(
            match source {
                crate::EventSource::Standard | crate::EventSource::Filtered(_) => "rest/events",
                crate::EventSource::Disk => "rest/events/disk",
                crate::EventSource::LocalIndex(_) => {
                    return Err(Error::InvalidConfiguration {
                        reason: "Local-API event cursors require a LocalApiClient",
                    })
                }
            },
            &query,
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
    /// A successful reply acknowledges the request. Use
    /// [crate::ManagedInstance::shutdown] to observe exit for an owned process.
    /// If the outcome is unknown, check whether the selected instance is still
    /// running before sending another request. The client attempts shutdown once.
    pub async fn request_shutdown(&self) -> Result<()> {
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.send_shutdown().await
    }

    pub(crate) async fn request_owned_shutdown(
        &self,
        admission: std::sync::Arc<crate::managed::ShutdownAdmission>,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        let write = self.connection.mutation_lock.clone().lock_owned().await;
        let Some(dispatch) = admission.admit().await else {
            return Ok(());
        };
        self.system_status().await?;
        let client = self.clone();
        // After admission and identity read, keep both guards with the single
        // write until the transport is done, even if the caller stops waiting.
        tokio::spawn(async move {
            let (_write, _dispatch) = (write, dispatch);
            if admission.is_retired() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::Timeout {
                    operation: "gracefully stop owned program",
                });
            }
            tokio::time::timeout_at(deadline, client.send_shutdown())
                .await
                .map_err(|_| Error::Timeout {
                    operation: "gracefully stop owned program",
                })?
        })
        .await
        .map_err(|_| Error::ManagedFailure {
            reason: "owned shutdown request ended without a result",
        })?
    }

    #[cfg(all(test, feature = "engine-tests"))]
    pub(crate) async fn test_hold_write_gate(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.connection.mutation_lock.clone().lock_owned().await
    }

    #[cfg(all(test, feature = "engine-tests"))]
    pub(crate) fn test_shutdown_calls(&self) -> usize {
        self.shutdown_calls
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn send_shutdown(&self) -> Result<()> {
        #[cfg(all(test, feature = "engine-tests"))]
        self.shutdown_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.connection
            .request_bytes(
                crate::error::GRACEFUL_SHUTDOWN_OPERATION,
                reqwest::Method::POST,
                self.connection
                    .management_url("rest/system/shutdown", &[])?,
                None,
                true,
            )
            .await
            .map(|_| ())
    }

    /// Request the native restart action once after checking the current identity.
    ///
    /// Success acknowledges the command, without waiting for another program
    /// generation. A monitor may relaunch an externally managed program. The
    /// library's owned inner program instead exits with the native restart code;
    /// use [`crate::ManagedInstance::restart`] for explicit owned stop/start.
    /// An uncertain write or invalid acknowledgement is never retried. Observe
    /// a fresh identity and changed start time separately when reconciling it.
    pub async fn request_restart(&self) -> Result<()> {
        #[derive(Deserialize)]
        struct Acknowledgement {
            ok: String,
        }
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                "request native restart",
                reqwest::Method::POST,
                self.connection.management_url("rest/system/restart", &[])?,
                None,
                true,
            )
            .await?;
        let uncertain = || Error::MutationOutcomeUnknown {
            operation: "validate native restart acknowledgement",
            source: Box::new(Error::InvalidResponse {
                operation: "request native restart",
                response: ResponseDiagnostic::new(status, bytes.clone()),
            }),
        };
        let acknowledgement: Acknowledgement =
            serde_json::from_slice(&bytes).map_err(|_| uncertain())?;
        if acknowledgement.ok != "restarting" {
            return Err(uncertain());
        }
        Ok(())
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
        let (http, base) = management_http(&options.endpoint, options.timeout, &options.transport)?;
        let connection = Connection {
            http,
            base,
            key: options.api_key,
            response_limit: options.response_limit,
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            endpoint_kind,
            endpoint: options.endpoint,
            timeout: options.timeout,
            version_policy: options.version_policy,
            transport: options.transport,
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
                actual: connection
                    .transport
                    .version_diagnostic(&connection.key.redact(&version.version)),
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
            transient_read_retries: false,
            #[cfg(all(test, feature = "engine-tests"))]
            shutdown_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
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
    /// POST. Dot-segment IDs cannot be registered through this method.
    /// Clones of this Client serialize creation. The upstream POST is an
    /// upsert and ignores the tested If-Match condition: independent clients or
    /// other writers must coordinate; this is not an atomic create-if-absent.
    ///
    /// Success means configuration was accepted and read back. Directory setup,
    /// scanning and synchronization can continue afterward; inspect folder status.
    /// After cancellation or MutationOutcomeUnknown, read the ID before retrying.
    pub async fn create_folder(&self, options: &CreateFolderOptions) -> Result<FolderConfig> {
        validate_folder_item_id(&options.id)?;
        let advanced = options
            .advanced
            .as_ref()
            .map(crate::FolderAdvancedPatch::body)
            .transpose()?;
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
        if let Some(body) = advanced {
            defaults.extend(
                body.as_object()
                    .ok_or(Error::InvalidConfiguration {
                        reason: "initial folder settings must be an object",
                    })?
                    .clone(),
            );
        }
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
        let configuration =
            self.folder(&options.id)
                .await
                .map_err(|source| Error::MutationOutcomeUnknown {
                    operation: "read back created folder",
                    source: Box::new(source),
                })?;
        if options.advanced.is_some() {
            configuration.advanced_configuration().map_err(|source| {
                Error::MutationOutcomeUnknown {
                    operation: "read back created folder",
                    source: Box::new(source),
                }
            })?;
        }
        Ok(configuration)
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
        let body = Self::folder_patch_body(patch)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.folder(id).await?;
        self.submit_folder_patch(url, &body).await?;
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

    fn folder_patch_body(patch: &FolderPatch) -> Result<serde_json::Value> {
        serde_json::to_value(patch).map_err(|_| Error::InvalidConfiguration {
            reason: "folder patch cannot be encoded",
        })
    }

    async fn submit_folder_patch(&self, url: Url, body: &serde_json::Value) -> Result<u16> {
        let (status, _) = self
            .connection
            .request_bytes(
                "update folder",
                reqwest::Method::PATCH,
                url,
                Some(body),
                true,
            )
            .await?;
        Ok(status)
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
    /// Inspect `configuration_absent` on the returned snapshot. Identity checks
    /// on each side of the read can detect a changed endpoint. Each check uses
    /// a separate request, so deployments that replace instances must coordinate
    /// the change with callers. The controller leaves local paths untouched.
    /// If readback fails, check the folder list on the intended instance before
    /// removing another registration. The client sends DELETE once.
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
        let readback = async {
            self.system_status().await?;
            let configured = self.folders().await?;
            self.system_status().await?;
            Ok::<_, Error>(configured)
        };
        let configured = readback
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
                &self.connection.transport.version_diagnostic(
                    &self.connection.key.redact(&self.instance.version.version),
                ),
            )
            .finish_non_exhaustive()
    }
}

fn validate_folder_item_id(id: &FolderId) -> Result<()> {
    if matches!(id.as_str(), "." | "..") {
        return Err(Error::InvalidConfiguration {
            reason: "dot-segment folder IDs cannot be addressed by an item URL",
        });
    }
    Ok(())
}

pub(crate) fn management_http(
    endpoint: &ManagementEndpoint,
    timeout: Duration,
    transport: &crate::ManagementTransport,
) -> Result<(reqwest::Client, Url)> {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(timeout.min(Duration::from_secs(5)))
        .timeout(timeout)
        .user_agent(concat!("verysync-sidecar/", env!("CARGO_PKG_VERSION")));
    let builder = transport.apply(builder, endpoint)?;
    let (builder, base) = if let Some(socket) = endpoint.socket_path() {
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
        let url = endpoint
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
    Ok((http, base))
}

impl<Authorization: RequestAuthorization> Connection<Authorization> {
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
        validate_folder_item_id(id)?;
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
        let request = self.authorized_request(method, url, body);
        self.request_prepared(operation, request, mutation).await
    }

    fn authorized_request(
        &self,
        method: reqwest::Method,
        url: Url,
        body: Option<&serde_json::Value>,
    ) -> reqwest::RequestBuilder {
        let request = self.key.authorize(self.http.request(method, url));
        if let Some(body) = body {
            request.json(body)
        } else {
            request
        }
    }

    async fn request_prepared(
        &self,
        operation: &'static str,
        request: reqwest::RequestBuilder,
        mutation: bool,
    ) -> Result<(u16, Vec<u8>)> {
        let response = self
            .request_prepared_response(operation, request, mutation)
            .await?;
        Ok((response.status, response.body))
    }

    async fn request_prepared_response(
        &self,
        operation: &'static str,
        request: reqwest::RequestBuilder,
        mutation: bool,
    ) -> Result<RawResponse> {
        send_checked(operation, request, mutation, self.response_limit).await
    }

    async fn receive_response(
        &self,
        operation: &'static str,
        request: reqwest::RequestBuilder,
        mutation: bool,
    ) -> Result<RawResponse> {
        send_bounded(operation, request, mutation, self.response_limit).await
    }
}

pub(crate) async fn send_bounded(
    operation: &'static str,
    request: reqwest::RequestBuilder,
    mutation: bool,
    response_limit: usize,
) -> Result<RawResponse> {
    send_bounded_with_status(operation, request, mutation, response_limit)
        .await
        .map_err(|failure| failure.error)
}

pub(crate) struct BoundedResponseFailure {
    pub(crate) status: Option<u16>,
    pub(crate) error: Error,
}

pub(crate) async fn send_bounded_with_status(
    operation: &'static str,
    request: reqwest::RequestBuilder,
    mutation: bool,
    response_limit: usize,
) -> std::result::Result<RawResponse, BoundedResponseFailure> {
    let mut status = None;
    send_bounded_reporting_headers(operation, request, mutation, response_limit, &mut status)
        .await
        .map_err(|error| BoundedResponseFailure { status, error })
}

pub(super) async fn send_bounded_reporting_headers(
    operation: &'static str,
    request: reqwest::RequestBuilder,
    mutation: bool,
    response_limit: usize,
    response_status: &mut Option<u16>,
) -> Result<RawResponse> {
    send_bounded_observing_headers(operation, request, mutation, response_limit, |status| {
        *response_status = Some(status);
    })
    .await
}

async fn send_bounded_observing_headers(
    operation: &'static str,
    request: reqwest::RequestBuilder,
    mutation: bool,
    response_limit: usize,
    observe_headers: impl FnOnce(u16),
) -> Result<RawResponse> {
    let uncertain = |source| mutation_error(operation, mutation, source);
    let mut response = request
        .send()
        .await
        .map_err(|error| uncertain(transport_error(operation, error)))?;
    let status = response.status().as_u16();
    observe_headers(status);
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect();
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| uncertain(transport_error(operation, error)))?
    {
        if chunk.len() > response_limit.saturating_sub(body.len()) {
            return Err(uncertain(Error::ResponseTooLarge {
                limit: response_limit,
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

pub(crate) async fn send_checked(
    operation: &'static str,
    request: reqwest::RequestBuilder,
    mutation: bool,
    response_limit: usize,
) -> Result<RawResponse> {
    let response = send_bounded(operation, request, mutation, response_limit).await?;
    checked_response(operation, response, mutation)
}

pub(crate) fn checked_response(
    operation: &'static str,
    response: RawResponse,
    mutation: bool,
) -> Result<RawResponse> {
    let RawResponse {
        status,
        body: bytes,
        headers,
    } = response;
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
        #[serde(default)]
        code: Option<i64>,
    }
    // Serde can deserialize structs from JSON sequences. Only an actual JSON
    // object can be a native error envelope; a one/two-element data array must
    // never become Api or LicenseRequired because it fits those struct fields.
    if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'{')
    {
        if let Ok(envelope) = serde_json::from_slice::<ErrorEnvelope>(&bytes) {
            if !envelope.error.is_empty() {
                if envelope.code == Some(3000) {
                    return Err(Error::LicenseRequired {
                        code: 3000,
                        response: ResponseDiagnostic::new(status, bytes),
                    });
                }
                return Err(uncertain(Error::Api {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                }));
            }
        }
    }
    Ok(RawResponse {
        status,
        headers,
        body: bytes,
    })
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
