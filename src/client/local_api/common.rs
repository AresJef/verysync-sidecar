//! Shared native Local-API handlers, with their actual per-route gates.
use super::LocalApiClient;
use crate::{
    Error, FolderId, FolderStatus, GeneratedShare, ListPage, NativeCpuHardware,
    NativeMemoryHardware, NativeNetworkHardware, RawMethod, RawRequest, RequestEffect,
    ResponseDiagnostic, Result, ShareKey, ValidatedShare,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// Explicit native history filters. Timestamp strings must be RFC3339; the SDK
/// preserves their spelling and does not supply the controller's current time.
/// Leap seconds and precision finer than nanoseconds are rejected.
#[derive(Clone, Default, Serialize)]
pub struct LocalApiHistoryFilter {
    /// Optional native name filter; matching semantics remain the target's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Restrict the native query to one folder identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<FolderId>,
    /// Native action label; future labels are not rewritten or guessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Optional RFC3339 native start boundary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    /// Optional RFC3339 native end boundary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
}
impl fmt::Debug for LocalApiHistoryFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalApiHistoryFilter")
            .finish_non_exhaustive()
    }
}
impl LocalApiHistoryFilter {
    fn query(&self) -> Result<String> {
        if [&self.name, &self.action]
            .iter()
            .filter_map(|v| v.as_ref())
            .any(|v| v.len() > 4096 || v.chars().any(char::is_control))
        {
            return Err(Error::InvalidConfiguration {
                reason: "history text filters must be bounded and free of controls",
            });
        }
        let timestamp = |value: &Option<String>| {
            value
                .as_ref()
                .map(|v| {
                    if v.len() > 128 {
                        return Err(Error::InvalidConfiguration {
                            reason: "history timestamps must be bounded RFC3339 values",
                        });
                    }
                    crate::timestamps::parse_rfc3339(v).ok_or_else(|| Error::InvalidConfiguration {
                        reason: "history timestamps must use RFC3339",
                    })
                })
                .transpose()
        };
        let (start, end) = (timestamp(&self.start)?, timestamp(&self.end)?);
        if start.zip(end).is_some_and(|(start, end)| start > end) {
            return Err(Error::InvalidConfiguration {
                reason: "history start must not follow its end",
            });
        }
        serde_json::to_string(self).map_err(|_| Error::InvalidConfiguration {
            reason: "history filters cannot be encoded",
        })
    }
}

/// One actual native audit record. All known fields use native omitempty, so
/// absence is retained. Integer timestamp units are not assumed or converted.
#[derive(Clone, Deserialize)]
pub struct LocalApiHistoryRecord {
    /// Native signed record index, when emitted.
    pub idx: Option<i64>,
    /// Native integer modified timestamp, when emitted.
    pub modified: Option<i64>,
    /// Native integer event timestamp, when emitted.
    pub event_time: Option<i64>,
    /// Native action label, including unrecognized future values.
    pub action: Option<String>,
    /// Native item type label.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    /// Private native display label.
    pub label: Option<String>,
    /// Private native item name.
    pub name: Option<String>,
    /// Native opaque folder identifier, without a cross-node equality claim.
    pub folder_id: Option<String>,
    /// Native device identifier text, without guessing its representation.
    pub device_id: Option<String>,
    /// Private native device name.
    pub device_name: Option<String>,
    /// Additional native fields, omitted from ordinary Debug.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for LocalApiHistoryRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalApiHistoryRecord")
            .finish_non_exhaustive()
    }
}
/// One bounded native history page; a null record collection remains absent.
#[derive(Clone, Deserialize)]
pub struct LocalApiHistoryPage {
    /// Native signed total; it is not replaced by the returned record count.
    pub total: i64,
    /// Native records, preserving null separately from an empty array.
    #[serde(rename = "data")]
    pub records: Option<Vec<LocalApiHistoryRecord>>,
    /// Additional actual page fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for LocalApiHistoryPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalApiHistoryPage")
            .field("total", &self.total)
            .field("record_count", &self.records.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

/// The native Local-API hardware object's three typed sections. Partial native
/// hardware failures remain bounded errors; no zero inventory is fabricated.
#[derive(Clone, Deserialize)]
pub struct LocalApiHardware {
    /// Native CPU inventory; no controller hardware is substituted.
    pub cpu: NativeCpuHardware,
    /// Native memory inventory, preserving negative unknown markers.
    pub memory: NativeMemoryHardware,
    /// Native network interface inventory.
    pub network: NativeNetworkHardware,
    /// Other private native fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for LocalApiHardware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalApiHardware").finish_non_exhaustive()
    }
}

impl LocalApiClient {
    /// Read native current peer connections. This does not initiate discovery,
    /// dial a peer or establish WAN reachability; Local-API entitlement applies.
    pub async fn connections(&self) -> Result<crate::ConnectionSnapshot> {
        self.control_json(
            RawRequest::new(
                RawMethod::Get,
                ["system", "connections"],
                RequestEffect::ReadOnly,
            )?,
            "read Local-API peer connections",
        )
        .await
    }

    /// Read native per-folder statistics, without inventing records for omitted
    /// IDs or turning these counters into a synchronization completion receipt.
    pub async fn folder_statistics(&self) -> Result<BTreeMap<FolderId, crate::FolderStatistics>> {
        self.control_json(
            RawRequest::new(RawMethod::Get, ["stats", "folder"], RequestEffect::ReadOnly)?,
            "read Local-API folder statistics",
        )
        .await
    }

    /// Read native per-file progress for one configured folder. Empty data is
    /// not completion; a missing native progress state remains an error.
    pub async fn folder_download_progress(
        &self,
        folder: &FolderId,
    ) -> Result<crate::FolderDownloadProgress> {
        self.folder(folder).await?;
        self.control_json(
            RawRequest::new(
                RawMethod::Get,
                ["folder", "downloadprogress"],
                RequestEffect::ReadOnly,
            )?
            .query("folder", folder.as_str()),
            "read Local-API download progress",
        )
        .await
    }

    /// Read completion records for configured peers of this folder. The native
    /// handler excludes this instance and can return a subset after peer errors.
    /// Reported completion does not prove connectivity, bytes or file durability.
    pub async fn folder_completions(
        &self,
        folder: &FolderId,
    ) -> Result<BTreeMap<crate::DeviceId, crate::CompletionSnapshot>> {
        self.folder(folder).await?;
        self.control_json(
            RawRequest::new(
                RawMethod::Get,
                ["folder", "completion"],
                RequestEffect::ReadOnly,
            )?
            .query("folder", folder.as_str()),
            "read Local-API folder completions",
        )
        .await
    }
    /// Read the native hardware object. An embedded section error fails the
    /// typed read with exact bounded diagnostics, preserving partial raw data.
    pub async fn hardware(&self) -> Result<LocalApiHardware> {
        let operation = "read Local-API hardware";
        let response = self
            .control_response(
                RawRequest::new(RawMethod::Get, ["hardware"], RequestEffect::ReadOnly)?,
                operation,
            )
            .await?;
        let value: serde_json::Value =
            serde_json::from_slice(&response.body).map_err(|_| invalid(operation, &response))?;
        if !value.is_object()
            || ["cpu", "memory", "network"]
                .iter()
                .any(|name| !value.get(name).is_some_and(serde_json::Value::is_object))
        {
            return Err(invalid(operation, &response));
        }
        if ["cpu", "memory", "network"].iter().any(|name| {
            value
                .get(name)
                .and_then(|v| v.get("error"))
                .is_some_and(|v| !v.is_null())
        }) {
            return Err(Error::Api {
                operation,
                response: ResponseDiagnostic::new(response.status, response.body),
            });
        }
        serde_json::from_value(value).map_err(|_| invalid(operation, &response))
    }

    /// Read the native map of folder summaries. The core omits individual
    /// folders whose summary failed; absence does not establish a zero result.
    pub async fn folder_summaries(&self) -> Result<BTreeMap<FolderId, FolderStatus>> {
        self.control_json(
            RawRequest::new(
                RawMethod::Get,
                ["folders", "summary"],
                RequestEffect::ReadOnly,
            )?,
            "read Local-API folder summaries",
        )
        .await
    }

    /// Read one explicit history page with validated native filters. A native
    /// backend error is an Api error, not an empty successful page. No recording
    /// preference, Pro entitlement, file, reset or pagination is changed.
    pub async fn folder_history(
        &self,
        page: ListPage,
        filter: &LocalApiHistoryFilter,
    ) -> Result<LocalApiHistoryPage> {
        let request = RawRequest::new(
            RawMethod::Get,
            ["folders", "history"],
            RequestEffect::ReadOnly,
        )?
        .query("page", page.number().to_string())
        .query("perpage", page.per_page().to_string())
        .query("filters", filter.query()?);
        let operation = "read Local-API folder history";
        let response = self.control_response(request, operation).await?;
        let value: serde_json::Value =
            serde_json::from_slice(&response.body).map_err(|_| invalid(operation, &response))?;
        if value.get("data").is_none() {
            return Err(invalid(operation, &response));
        }
        match value.get("error") {
            Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::String(error)) if error.is_empty() => {}
            Some(serde_json::Value::String(_)) => {
                return Err(Error::Api {
                    operation,
                    response: ResponseDiagnostic::new(response.status, response.body),
                })
            }
            _ => return Err(invalid(operation, &response)),
        }
        serde_json::from_value(value).map_err(|_| invalid(operation, &response))
    }

    /// Generate new share material through the native licensed GET. Generation
    /// consumes randomness and is treated as a mutation, but registers no folder.
    /// The returned local suggestion is not a stable key or cross-node ID.
    pub async fn generate_share(&self) -> Result<GeneratedShare> {
        let response = self
            .control_response(
                RawRequest::new(RawMethod::Get, ["secret"], RequestEffect::MayModify)?,
                "generate Local-API share",
            )
            .await?;
        crate::sharing::generated(response.status, response.body)
    }

    /// Validate an explicit sharing key through the native licensed GET. Native
    /// rejection preserves arbitrary error JSON; it is not constrained to text.
    /// Fresh random suggested IDs can differ across calls; no folder is joined.
    pub async fn validate_share_key(&self, key: &ShareKey) -> Result<ValidatedShare> {
        let request = RawRequest::new(
            RawMethod::Get,
            ["secret", "check"],
            RequestEffect::MayModify,
        )?
        .query("key", key.expose_secret());
        let response = self
            .control_response(request, "validate Local-API share")
            .await?;
        crate::sharing::validated(
            self.instance.device_id.clone(),
            key.clone(),
            response.status,
            response.body,
        )
    }
}

fn invalid(operation: &'static str, response: &crate::RawResponse) -> Error {
    Error::InvalidResponse {
        operation,
        response: ResponseDiagnostic::new(response.status, response.body.clone()),
    }
}
