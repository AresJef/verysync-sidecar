//! Native registered folder controls, separate from GUI route contracts.
use super::LocalApiClient;
use crate::{
    Capability, Error, FolderId, InstanceObservation, ListPage, NeedPage, OperationPreflightReport,
    PathStyle, PreflightObservation, PreflightReads, RawMethod, RawRequest, RawResponse,
    RequestEffect, ResponseDiagnostic, Result, SelectiveAcknowledgement, SelectiveAction,
    SelectiveScope, SelectiveTree, TargetPath,
};
use serde::{de::DeserializeOwned, Deserialize};
use std::{collections::BTreeMap, fmt};

/// Actual Local-API folder projection, distinct from GUI configuration.
/// The native projection omits GUI labels and includes private sharing fields.
#[derive(Clone)]
pub struct LocalApiFolder {
    /// Exact configured folder identifier.
    pub id: FolderId,
    /// Target-native path; no controller filesystem lookup is performed.
    pub path: TargetPath,
    /// Reported pause setting.
    pub paused: bool,
    /// Reported peers in the Local-API projection; this is not connectivity.
    pub peers: Option<Vec<LocalApiPeer>>,
    /// Reported whole-second rescan interval; zero remains an explicit zero.
    pub rescan_interval_seconds: Option<u32>,
    /// Reported scan progress interval; minus one retains its native meaning.
    pub scan_progress_interval_seconds: Option<i32>,
    /// Reported selective-mode flag; this grants no selection entitlement.
    pub selective_enabled: Option<bool>,
    /// Native optional ignore-permissions flag; omission is preserved.
    pub ignore_permissions: Option<bool>,
    /// Other actual fields, including private sharing material and peers.
    pub extra: BTreeMap<String, serde_json::Value>,
}
/// A peer projection containing the two fields emitted by native Local-API.
#[derive(Clone, Deserialize)]
pub struct LocalApiPeer {
    /// Exact native device identity, without a presence or connection claim.
    #[serde(rename = "deviceID")]
    pub device_id: crate::DeviceId,
    /// Private display name, retained without controller-side normalization.
    pub name: String,
}
impl fmt::Debug for LocalApiPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalApiPeer")
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for LocalApiFolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalApiFolder")
            .field("id", &self.id)
            .field("paused", &self.paused)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}
#[derive(Deserialize)]
struct WireFolder {
    id: FolderId,
    path: String,
    paused: bool,
    peers: Option<Vec<LocalApiPeer>>,
    #[serde(rename = "rescanIntervalS")]
    rescan_interval_seconds: Option<u32>,
    #[serde(rename = "scanProgressIntervalS")]
    scan_progress_interval_seconds: Option<i32>,
    #[serde(rename = "selectiveEnabled")]
    selective_enabled: Option<bool>,
    #[serde(rename = "ignorePerms")]
    ignore_permissions: Option<bool>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

/// Exact native acknowledgement, distinct from an observed scan completion.
#[derive(Debug)]
pub struct LocalApiScanAcknowledgement {
    /// Bounded native response containing the verified `ok: scanning` marker.
    pub response: ResponseDiagnostic,
}

impl LocalApiClient {
    /// Read native device identity/name projections. These records do not
    /// contain full GUI device configuration or establish live peer presence.
    pub async fn devices(&self) -> Result<Vec<LocalApiPeer>> {
        self.control_json(
            RawRequest::new(
                RawMethod::Get,
                ["config", "devices"],
                RequestEffect::ReadOnly,
            )?,
            "read Local-API devices",
        )
        .await
    }
    pub(super) fn path_style(&self) -> Result<PathStyle> {
        match self.instance.version.os.as_str() {
            "windows" => Ok(PathStyle::Windows),
            "linux" | "darwin" => Ok(PathStyle::Unix),
            _ => Err(Error::InvalidConfiguration {
                reason: "engine path syntax is unknown; no host-based guess is made",
            }),
        }
    }

    pub(super) async fn control_response(
        &self,
        request: RawRequest,
        operation: &'static str,
    ) -> Result<RawResponse> {
        let modifying = request.effect == RequestEffect::MayModify;
        if !modifying {
            self.system_status().await?;
        }
        let response = self.raw(request).await?;
        checked_control_response(operation, response, modifying)
    }

    pub(super) async fn control_json<T: DeserializeOwned>(
        &self,
        request: RawRequest,
        operation: &'static str,
    ) -> Result<T> {
        let modifying = request.effect == RequestEffect::MayModify;
        let response = self.control_response(request, operation).await?;
        serde_json::from_slice(&response.body).map_err(|_| {
            crate::client::mutation_error(
                operation,
                modifying,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(response.status, response.body),
                },
            )
        })
    }

    pub(super) async fn control_response_locked(
        &self,
        request: RawRequest,
        operation: &'static str,
        _guard: &tokio::sync::MutexGuard<'_, ()>,
    ) -> Result<RawResponse> {
        self.system_status().await?;
        let modifying = request.effect == RequestEffect::MayModify;
        checked_control_response(operation, self.send_raw(request).await?, modifying)
    }
}

pub(super) fn checked_control_response(
    operation: &'static str,
    response: RawResponse,
    modifying: bool,
) -> Result<RawResponse> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LicenseEnvelope {
        code: i64,
        error: String,
    }
    // HTTP200 is the actual native Local-API rejection. Do not classify
    // ordinary 403 responses or JSON arrays as commercial rejections.
    if (200..300).contains(&response.status)
        && response
            .body
            .iter()
            .copied()
            .find(|v| !v.is_ascii_whitespace())
            == Some(b'{')
    {
        if let Ok(envelope) = serde_json::from_slice::<LicenseEnvelope>(&response.body) {
            if envelope.code == 3001 && !envelope.error.is_empty() {
                return Err(Error::LicenseRequired {
                    code: 3001,
                    response: ResponseDiagnostic::new(response.status, response.body),
                });
            }
        }
    }
    crate::client::checked_response(operation, response, modifying)
}

impl LocalApiClient {
    fn scope_request(
        &self,
        method: RawMethod,
        route: &str,
        folder: &FolderId,
        scope: &SelectiveScope,
        effect: RequestEffect,
    ) -> Result<RawRequest> {
        let path = scope.protocol(self.path_style()?)?;
        let mut request = RawRequest::new(method, ["folders", route, folder.as_str()], effect)?;
        // The native wildcard requires a trailing slash for the root. Nonempty
        // target subpaths are encoded as data; no local filesystem is consulted.
        request.components.push(path.to_owned());
        Ok(request)
    }

    /// Read native Local-API folder configurations. Returned target paths and
    /// unmodeled fields stay private in ordinary diagnostics.
    pub async fn folders(&self) -> Result<Vec<LocalApiFolder>> {
        let style = self.path_style()?;
        let folders: Vec<WireFolder> = self
            .control_json(
                RawRequest::new(
                    RawMethod::Get,
                    ["config", "folders"],
                    RequestEffect::ReadOnly,
                )?,
                "read Local-API folders",
            )
            .await?;
        folders
            .into_iter()
            .map(|folder| {
                Ok(LocalApiFolder {
                    id: folder.id,
                    path: TargetPath::remote(style, folder.path)?,
                    paused: folder.paused,
                    peers: folder.peers,
                    rescan_interval_seconds: folder.rescan_interval_seconds,
                    scan_progress_interval_seconds: folder.scan_progress_interval_seconds,
                    selective_enabled: folder.selective_enabled,
                    ignore_permissions: folder.ignore_permissions,
                    extra: folder.extra,
                })
            })
            .collect()
    }

    /// Find an exact ID in the fresh Local-API folder snapshot.
    pub async fn folder(&self, folder: &FolderId) -> Result<LocalApiFolder> {
        self.folders()
            .await?
            .into_iter()
            .find(|entry| entry.id == *folder)
            .ok_or_else(|| Error::FolderNotFound { id: folder.clone() })
    }

    /// Read the native selective tree at its fixed level-zero Local-API depth.
    /// This has a separate Local-API entitlement check; no traversal, selection
    /// or file transfer is initiated. Licensed success requires separate proof.
    pub async fn browse_folder(
        &self,
        folder: &FolderId,
        scope: &SelectiveScope,
    ) -> Result<SelectiveTree> {
        let request = self.scope_request(
            RawMethod::Get,
            "browser",
            folder,
            scope,
            RequestEffect::ReadOnly,
        )?;
        self.folder(folder).await?;
        self.control_json(request, "browse Local-API folder").await
    }

    /// Read exactly one bounded need page. The native wrapper defaults an empty
    /// limit to 100; this API always sends the caller's explicit validated page.
    pub async fn folder_need(&self, folder: &FolderId, page: ListPage) -> Result<NeedPage> {
        let request = Self::need_page_request(folder, page)?;
        self.folder(folder).await?;
        self.control_json(request, "read Local-API folder need")
            .await
    }

    /// Inspect readiness for one Local-API folder-need operation.
    ///
    /// With selected reads, the client checks version and device before and
    /// after requesting page 1 with an item limit of 1 for the exact folder.
    /// If the response reports a page number or limit, it must match the
    /// request. The page contents stay out of the report. A successful read
    /// describes only that page at the observed time. Other Local-API, Pro
    /// and enterprise permissions remain unverified.
    pub async fn preflight_folder_need(
        &self,
        folder: &FolderId,
        reads: PreflightReads,
    ) -> OperationPreflightReport {
        let mut report = OperationPreflightReport::new(
            Capability::LocalApiConnection,
            self.instance(),
            self.connection.endpoint_kind,
            self.connection.base.scheme() == "https",
        );
        // The credential-free Local-API handshake identifies the peer. It
        // does not establish GUI authentication or any commercial entitlement.
        report.static_evidence.instance.authentication = InstanceObservation::Unknown;
        if reads == PreflightReads::SelectedOperation {
            report.observation = Some(match self.preflight_local_identity().await {
                Ok(()) => {
                    let page = ListPage {
                        number: 1,
                        per_page: 1,
                    };
                    let read = self.preflight_need_page(folder, page).await;
                    match self.preflight_local_identity().await {
                        Ok(()) => PreflightObservation::from_read(read, true, true),
                        Err(error) => PreflightObservation::from_read(Err(error), false, true),
                    }
                }
                Err(error) => PreflightObservation::from_read(Err(error), false, true),
            });
        }
        report
    }

    fn need_page_request(folder: &FolderId, page: ListPage) -> Result<RawRequest> {
        let request = RawRequest::new(
            RawMethod::Get,
            ["folders", "need", folder.as_str()],
            RequestEffect::ReadOnly,
        )?
        .query("page", page.number().to_string())
        .query("perpage", page.per_page().to_string());
        Ok(request)
    }

    async fn preflight_need_page(&self, folder: &FolderId, page: ListPage) -> Result<()> {
        let operation = "preflight Local-API folder need";
        let request = Self::need_page_request(folder, page)?;
        // This dedicated read is paced by its own identity checks. It does not
        // enumerate the unrelated folder configurations used by the old call.
        let response = checked_control_response(operation, self.send_raw(request).await?, false)?;
        let page_matches = serde_json::from_slice::<NeedPage>(&response.body).is_ok_and(|actual| {
            actual.page.is_none_or(|number| number == page.number())
                && actual
                    .per_page
                    .is_none_or(|limit| limit == u32::from(page.per_page()))
        });
        if page_matches {
            Ok(())
        } else {
            Err(Error::InvalidResponse {
                operation,
                response: ResponseDiagnostic::new(response.status, response.body),
            })
        }
    }

    async fn preflight_local_identity(&self) -> Result<()> {
        let expected = &self.instance().version;
        let observed = self.version().await?;
        if observed.version != expected.version {
            return Err(Error::IncompatibleVersion {
                actual: self
                    .connection
                    .transport
                    .version_diagnostic(&observed.version),
            });
        }
        super::super::control_preflight::compare_preflight_platform(&observed, expected)?;
        self.system_status().await?;
        Ok(())
    }

    /// Request one root/subpath scan through the registered native wrapper.
    /// A `scanning` acknowledgement is not a correlated completion event. The
    /// request is never retried, and paused folders are refused before posting.
    /// Clones of this client share the lock from the folder check through the request.
    ///
    /// ```no_run
    /// # async fn example(client: &verysync_sidecar::LocalApiClient,
    /// # folder: &verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
    /// let receipt = client.request_scan(folder,
    ///     &verysync_sidecar::SelectiveScope::FolderRoot).await?;
    /// assert_eq!(receipt.response.status(), 200);
    /// // Observe actual index/events separately; this is an acknowledgement.
    /// # Ok(())
    /// # }
    /// ```
    pub async fn request_scan(
        &self,
        folder: &FolderId,
        scope: &SelectiveScope,
    ) -> Result<LocalApiScanAcknowledgement> {
        let request = self.scope_request(
            RawMethod::Post,
            "scan",
            folder,
            scope,
            RequestEffect::MayModify,
        )?;
        let guard = self.connection.mutation_lock.lock().await;
        if self.folder(folder).await?.paused {
            return Err(Error::ScanNotIdle);
        }
        let response = self
            .control_response_locked(request, "request Local-API scan", &guard)
            .await?;
        let acknowledgement: serde_json::Value =
            serde_json::from_slice(&response.body).map_err(|_| invalid_scan(&response))?;
        if acknowledgement
            .get("ok")
            .and_then(serde_json::Value::as_str)
            != Some("scanning")
        {
            return Err(invalid_scan(&response));
        }
        Ok(LocalApiScanAcknowledgement {
            response: ResponseDiagnostic::new(response.status, response.body),
        })
    }

    /// Submit one explicit Local-API selection request. Commercial rejection
    /// code3001 is distinct from GUI-key rejection and the separate Pro code3000.
    /// Observe file retention and transfer separately. Clones of this client
    /// share the lock from the folder check through the request.
    pub async fn request_selection(
        &self,
        folder: &FolderId,
        scope: &SelectiveScope,
        action: SelectiveAction,
    ) -> Result<SelectiveAcknowledgement> {
        let request = self
            .scope_request(
                RawMethod::Post,
                "selective",
                folder,
                scope,
                RequestEffect::MayModify,
            )?
            .query(
                "selected",
                if action == SelectiveAction::Select {
                    "true"
                } else {
                    "false"
                },
            )
            .query(
                "removefromall",
                if action == SelectiveAction::RemoveFromAll {
                    "true"
                } else {
                    "false"
                },
            );
        let guard = self.connection.mutation_lock.lock().await;
        self.folder(folder).await?;
        let response = self
            .control_response_locked(request, "request Local-API selection", &guard)
            .await?;
        Ok(SelectiveAcknowledgement {
            response: ResponseDiagnostic::new(response.status, response.body),
        })
    }
}

fn invalid_scan(response: &RawResponse) -> Error {
    crate::client::mutation_error(
        "decode Local-API scan acknowledgement",
        true,
        Error::InvalidResponse {
            operation: "decode Local-API scan acknowledgement",
            response: ResponseDiagnostic::new(response.status, response.body.clone()),
        },
    )
}
