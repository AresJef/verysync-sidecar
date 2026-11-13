//! Explicit versioning policies and native archive operations, without retries.
use super::{mutation_error, Client};
use crate::{AuditHistoryPage, AuditHistorySettings, AuditHistoryUpdate};
use crate::{DirectoryVersionOrder, VersionedDirectory};
use crate::{
    Error, FileVersionRestore, FileVersionRestoreReport, FolderId, FolderVersionHistory,
    FolderVersioningConfiguration, FolderVersioningPolicy, FolderVersioningUpdate,
    ResponseDiagnostic, Result, TargetPath,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

fn restore_precondition(reason: &'static str) -> Error {
    Error::ArchiveRestorePrecondition { reason }
}
fn archive_second(value: &str) -> Result<i64> {
    if value.len() > 128 {
        return Err(restore_precondition(
            "native clock or archive timestamp is not bounded RFC3339",
        ));
    }
    let time = chrono::DateTime::parse_from_rfc3339(value).map_err(|_| {
        restore_precondition("native clock or archive timestamp is not verified RFC3339")
    })?;
    if time.timestamp_subsec_nanos() >= 1_000_000_000 {
        return Err(restore_precondition(
            "native leap-second timestamps are not verified",
        ));
    }
    Ok(time.timestamp())
}
fn archive_components(value: &str, style: crate::PathStyle) -> Result<Vec<String>> {
    let path = TargetPath::remote(style, value)?;
    crate::scans::validate_subpath(&path, style)?;
    Ok(value
        .split(|c| c == '/' || (style == crate::PathStyle::Windows && c == '\\'))
        .map(str::to_owned)
        .collect())
}

impl Client {
    async fn require_past_archive_second(&self, latest: i64) -> Result<()> {
        // Use the target's fresh clock immediately before writing. Never use
        // controller wall time or rewrite the native token submitted in POST.
        let status = self.system_status().await?;
        let now = archive_second(
            status
                .now_time
                .as_deref()
                .ok_or_else(|| restore_precondition("target did not report its current clock"))?,
        )?;
        if latest >= now {
            return Err(restore_precondition(
                "selected archives must precede the target's current whole second",
            ));
        }
        Ok(())
    }
    async fn directory_archive_second(
        &self,
        folder: &FolderId,
        scope: &VersionedDirectory,
    ) -> Result<i64> {
        let style = self.folder_path_style()?;
        let selected = match scope {
            VersionedDirectory::FolderRoot => Vec::new(),
            VersionedDirectory::Path(path) => archive_components(path.to_protocol()?, style)?,
        };
        let mut stack = vec![(None, Vec::<String>::new())];
        let mut seen = BTreeSet::from([Vec::<String>::new()]);
        let mut scope_found = selected.is_empty();
        let mut latest = None::<i64>;
        let mut count = 0usize;
        let mut logical_bytes = 0usize;
        while let Some((prefix, parent)) = stack.pop() {
            let listing = self.folder_versions(folder, prefix.as_ref()).await?;
            for (name, versions) in listing.0 {
                let components = archive_components(&name, style)?;
                if !components.starts_with(&parent) || components.len() != parent.len() + 1 {
                    return Err(restore_precondition(
                        "archive browse returned an inconsistent directory level",
                    ));
                }
                if !components.starts_with(&selected) && !selected.starts_with(&components) {
                    continue;
                }
                count = count.saturating_add(1);
                logical_bytes = logical_bytes.saturating_add(name.len());
                if count > 1024 || logical_bytes > 65536 {
                    return Err(restore_precondition(
                        "directory preflight exceeds 1024 entries or 64 KiB",
                    ));
                }
                if versions.is_empty() {
                    if components == selected {
                        scope_found = true;
                    }
                    if !seen.insert(components.clone()) {
                        return Err(restore_precondition("archive browse repeated a directory"));
                    }
                    stack.push((Some(TargetPath::remote(style, name)?), components));
                } else {
                    if components == selected {
                        return Err(restore_precondition(
                            "explicit directory scope identifies an archived file",
                        ));
                    }
                    if components.starts_with(&selected) {
                        for version in versions {
                            count = count.saturating_add(1);
                            logical_bytes =
                                logical_bytes.saturating_add(version.version_time.len());
                            if count > 1024 || logical_bytes > 65536 {
                                return Err(restore_precondition(
                                    "directory preflight exceeds 1024 entries or 64 KiB",
                                ));
                            }
                            let second = archive_second(&version.version_time)?;
                            latest = Some(latest.map_or(second, |prior| prior.max(second)));
                        }
                    }
                }
            }
        }
        if !scope_found {
            return Err(restore_precondition(
                "explicit archive directory was not observed",
            ));
        }
        latest.ok_or_else(|| {
            restore_precondition("no archived file was observed in the explicit directory scope")
        })
    }
    /// Request the native directory version restore planner for one explicit
    /// root/directory scope. Current files can be overwritten and errors can be
    /// partial. The SDK does not traverse controller files, pause peers, retry,
    /// create backups or roll back. A successful error-free report remains an
    /// acknowledgement; observe actual restored content separately.
    ///
    /// Explicit FolderRoot uses the observed native dot-root representation.
    /// The fixed GUI's empty-root spelling did not reliably restore the isolated
    /// samples and is not silently accepted as a completed restore.
    /// Native second-resolution archive collisions can consume the selected old
    /// version while retaining current bytes with an empty report. Coordinate
    /// writers, preserve independent copies and verify actual target content.
    /// A bounded read-only archive preflight refuses same-second/future or
    /// unverified timestamps before POST. It permits at most 1024 relevant
    /// entries/records, 64 KiB and 30 seconds of inventory work. All observed
    /// archive records must precede the fresh target clock; no controller clock,
    /// implicit waiting, partial inventory or unsafe fallback is used.
    pub async fn restore_directory_versions(
        &self,
        folder: &FolderId,
        scope: &VersionedDirectory,
        order: DirectoryVersionOrder,
    ) -> Result<FileVersionRestoreReport> {
        let path = match scope {
            VersionedDirectory::FolderRoot => ".",
            VersionedDirectory::Path(path) => {
                crate::scans::validate_subpath(path, self.folder_path_style()?)?
            }
        };
        if path.len() > 65536 {
            return Err(Error::InvalidConfiguration {
                reason: "directory version selection exceeds 64 KiB",
            });
        }
        let action = match order {
            DirectoryVersionOrder::Newest => "latest",
            DirectoryVersionOrder::Oldest => "oldest",
        };
        let operation = "restore archived directory versions";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        if self.folder(folder).await?.paused {
            return Err(Error::FolderPaused { id: folder.clone() });
        }
        let latest = tokio::time::timeout(
            Duration::from_secs(30),
            self.directory_archive_second(folder, scope),
        )
        .await
        .map_err(|_| Error::Timeout { operation })??;
        self.require_past_archive_second(latest).await?;
        let url = self.connection.management_url(
            "rest/folder/versions/restore",
            &[("folder", folder.as_str())],
        )?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::POST,
                url,
                Some(&serde_json::json!({"items":[{"path":path,"action":action}]})),
                true,
            )
            .await?;
        serde_json::from_slice(&bytes).map_err(|_| {
            mutation_error(
                operation,
                true,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                },
            )
        })
    }
    /// Read native audit-log settings, without inferring actual entitlement or
    /// successful recording from an enabled flag alone.
    pub async fn audit_history_settings(&self) -> Result<AuditHistorySettings> {
        self.system_status().await?;
        self.connection
            .get_json("read global file audit settings", "rest/config/options")
            .await
    }
    /// Attempt explicit audit recording/retention settings once, then read back
    /// actual values. The SDK does not enable a license or bypass Pro checks.
    /// A zero maximum_records explicitly requests unlimited native retention.
    pub async fn set_audit_history_settings(
        &self,
        settings: AuditHistorySettings,
    ) -> Result<AuditHistoryUpdate> {
        if settings.maximum_records > i32::MAX as u32 {
            return Err(Error::InvalidConfiguration {
                reason: "audit retention exceeds the native signed integer bound",
            });
        }
        let operation = "set global file audit settings";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let url = self.connection.management_url("rest/config/options", &[])?;
        self.connection.request_bytes(operation,reqwest::Method::PATCH,url,Some(&serde_json::json!({"folderHistoryEnabled":settings.enabled,"folderHistoryMaxRecords":settings.maximum_records})),true).await?;
        let configuration: AuditHistorySettings = self
            .connection
            .get_json(operation, "rest/config/options")
            .await
            .map_err(|e| mutation_error(operation, true, e))?;
        Ok(AuditHistoryUpdate {
            requested_fields_match: settings == configuration,
            configuration,
        })
    }
    /// Read one explicit global audit-log page. Page numbers start at one and
    /// requested page sizes are bounded to 1..=1000. There is no automatic
    /// pagination, filtering, licensing inference or controller file access.
    pub async fn audit_history(&self, page: u32, per_page: u16) -> Result<AuditHistoryPage> {
        if page == 0 || !(1..=1000).contains(&per_page) {
            return Err(Error::InvalidConfiguration {
                reason: "audit page must be positive and page size between one and 1000",
            });
        }
        self.system_status().await?;
        self.connection
            .get_json_with_query(
                "read global file audit page",
                "rest/history/list",
                &[
                    ("page", &page.to_string()),
                    ("perpage", &per_page.to_string()),
                ],
            )
            .await
    }
    /// Request global audit-log reset once. The native GET modifies data and is
    /// deliberately treated as a mutation, with identity checking and no retry.
    /// Ok acknowledges the native error-free response. Verify reported totals
    /// separately; resetting an already empty free-instance log does not prove
    /// licensed recording or removal of real history records.
    pub async fn reset_audit_history(&self) -> Result<()> {
        #[derive(serde::Deserialize)]
        struct Reset {
            error: serde_json::Value,
        }
        let operation = "reset global file audit history";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let url = self.connection.management_url("rest/history/reset", &[])?;
        let (status, bytes) = self
            .connection
            .request_bytes(operation, reqwest::Method::GET, url, None, true)
            .await?;
        let response: Reset = serde_json::from_slice(&bytes).map_err(|_| {
            mutation_error(
                operation,
                true,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes.clone()),
                },
            )
        })?;
        if !response.error.is_null() && response.error.as_str() != Some("") {
            return Err(mutation_error(
                operation,
                true,
                Error::Api {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                },
            ));
        }
        Ok(())
    }
    /// Read the actual versioner policy and archive location. This is not proof
    /// that historical files exist or that a custom backend is usable.
    pub async fn folder_versioning(
        &self,
        folder: &FolderId,
    ) -> Result<FolderVersioningConfiguration> {
        self.system_status().await?;
        self.read_folder_versioning(folder).await
    }
    async fn read_folder_versioning(
        &self,
        folder: &FolderId,
    ) -> Result<FolderVersioningConfiguration> {
        let config = self.folder(folder).await?;
        let value = config
            .extra
            .get("versioning")
            .cloned()
            .ok_or(Error::InvalidConfiguration {
                reason: "native folder versioning configuration is absent",
            })?;
        serde_json::from_value(value).map_err(|_| Error::InvalidConfiguration {
            reason: "native folder versioning configuration has an unknown schema",
        })
    }
    /// Change only the built-in policy, preserving the actual archive location
    /// and unknown/inactive parameters. Native PATCH merges parameter maps;
    /// disabling a policy therefore retains its unused parameter values.
    /// No cleanup, restart, retry or rollback is
    /// implicit. Readback is separate from actual archival/retention effects.
    pub async fn set_folder_versioning(
        &self,
        folder: &FolderId,
        policy: FolderVersioningPolicy,
    ) -> Result<FolderVersioningUpdate> {
        policy.validate()?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let mut expected = self.read_folder_versioning(folder).await?;
        policy.apply(&mut expected)?;
        let operation = "set folder versioning policy";
        let url = self.connection.folder_url(folder)?;
        self.connection
            .request_bytes(
                operation,
                reqwest::Method::PATCH,
                url,
                Some(&serde_json::json!({"versioning":expected})),
                true,
            )
            .await?;
        let configuration = self
            .read_folder_versioning(folder)
            .await
            .map_err(|e| mutation_error(operation, true, e))?;
        Ok(FolderVersioningUpdate {
            requested_fields_match: configuration == expected,
            configuration,
        })
    }
    /// Browse archived versions at the root (None) or one explicit relative
    /// prefix. The management byte limit bounds the single response; there is
    /// no automatic recursive traversal or controller filesystem access. A
    /// native null denotes an observed empty prefix listing. Prefix browsing
    /// lists descendants; a file used as prefix can therefore return no entries.
    pub async fn folder_versions(
        &self,
        folder: &FolderId,
        prefix: Option<&TargetPath>,
    ) -> Result<FolderVersionHistory> {
        let prefix = prefix
            .map(|p| crate::scans::validate_subpath(p, self.folder_path_style()?))
            .transpose()?;
        self.system_status().await?;
        self.folder(folder).await?;
        let mut query = vec![("folder", folder.as_str())];
        if let Some(prefix) = prefix {
            query.push(("prefix", prefix));
        }
        self.connection
            .get_json_with_query(
                "browse folder versions",
                "rest/folder/versions/browse",
                &query,
            )
            .await
    }
    /// Restore 1..=1024 exact file versions through the verified native map
    /// endpoint. Current data can be overwritten. Peer activity can subsequently
    /// change it again; coordinate writers explicitly. The SDK does not pause
    /// peers, scan, retry, create a backup or roll back partial effects.
    ///
    /// A successful report with zero native errors is an acknowledgement only.
    /// Verify actual file content separately. Cancellation/transport failure
    /// after POST leaves a possible partial, unknown outcome.
    /// The baseline can replace a selected archive when current-content
    /// archiving collides with its one-second timestamp; preserve independent
    /// copies and coordinate archive generations before destructive restoration.
    /// Selected RFC3339 timestamps must precede the target's fresh reported
    /// whole second. Missing/unknown clocks and same-second/future selections
    /// return ArchiveRestorePrecondition before POST, without an implicit wait.
    pub async fn restore_file_versions(
        &self,
        folder: &FolderId,
        items: &[FileVersionRestore],
    ) -> Result<FileVersionRestoreReport> {
        if !(1..=1024).contains(&items.len()) {
            return Err(Error::InvalidConfiguration {
                reason: "restore requires between one and 1024 explicit file versions",
            });
        }
        let style = self.folder_path_style()?;
        let mut selected = BTreeMap::new();
        let mut latest = i64::MIN;
        let mut bytes = 0usize;
        for item in items {
            latest = latest.max(archive_second(&item.version_time)?);
            let path = crate::scans::validate_subpath(&item.path, style)?;
            bytes = bytes
                .saturating_add(path.len())
                .saturating_add(item.version_time.len());
            if selected.insert(path, item.version_time.as_str()).is_some() || bytes > 65536 {
                return Err(Error::InvalidConfiguration {
                    reason: "restore paths must be unique within a 64 KiB logical selection bound",
                });
            }
        }
        let operation = "restore explicit file versions";
        let body = serde_json::to_value(selected).map_err(|_| Error::InvalidConfiguration {
            reason: "restore selection cannot be encoded",
        })?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let config = self.folder(folder).await?;
        if config.paused {
            return Err(Error::FolderPaused { id: folder.clone() });
        }
        self.require_past_archive_second(latest).await?;
        let url = self
            .connection
            .management_url("rest/folder/versions", &[("folder", folder.as_str())])?;
        let (status, bytes) = self
            .connection
            .request_bytes(operation, reqwest::Method::POST, url, Some(&body), true)
            .await?;
        serde_json::from_slice(&bytes).map_err(|_| {
            mutation_error(
                operation,
                true,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                },
            )
        })
    }
}
