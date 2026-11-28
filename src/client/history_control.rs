//! Explicit versioning policies and native archive operations, without retries.
use super::{mutation_error, workflow_write_result, Client};
use crate::{
    AuditHistoryPage, AuditHistoryResetOutcome, AuditHistoryResetReport, AuditHistorySettings,
    AuditHistoryUpdate, OperationOptions, OperationPhase,
};
use crate::{DirectoryVersionOrder, VersionArchiveLocation, VersionedDirectory};
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

fn decode_audit_reset(operation: &'static str, status: u16, bytes: Vec<u8>) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct Reset {
        error: serde_json::Value,
    }
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
fn archive_second(value: &str) -> Result<i64> {
    if value.len() > 128 {
        return Err(restore_precondition(
            "native clock or archive timestamp is not bounded RFC3339",
        ));
    }
    if value.as_bytes().get(17..19) == Some(b"60") {
        return Err(restore_precondition(
            "native leap-second timestamps are not verified",
        ));
    }
    let time = crate::timestamps::parse_rfc3339(value).ok_or_else(|| {
        restore_precondition("native clock or archive timestamp is not verified RFC3339")
    })?;
    // Timestamp::as_second truncates negative fractions; native archive buckets
    // use floor seconds, including instants before the Unix epoch.
    i64::try_from(time.as_nanosecond().div_euclid(1_000_000_000))
        .map_err(|_| restore_precondition("native timestamp is outside verified seconds"))
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
    /// Read the versioner's whole-folder inventory once through the distinct
    /// native route. This differs from prefix archive browsing. Fresh identity
    /// and folder checks precede the read; paused/unavailable versioners retain
    /// native errors. Empty maps are valid; null/malformed maps are errors.
    /// Existing response/deadline bounds apply. No recursive requests, restore,
    /// scan, timestamp rewriting or controller filesystem access occurs.
    pub async fn folder_version_inventory(
        &self,
        folder: &FolderId,
    ) -> Result<FolderVersionHistory> {
        self.system_status().await?;
        self.folder(folder).await?;
        let records: std::collections::BTreeMap<String, Vec<crate::ArchivedFileVersion>> = self
            .connection
            .get_json_with_query(
                "read whole folder version inventory",
                "rest/folder/versions",
                &[("folder", folder.as_str())],
            )
            .await?;
        Ok(FolderVersionHistory(records))
    }
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
        let operation = "reset global file audit history";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let url = self.connection.management_url("rest/history/reset", &[])?;
        let (status, bytes) = self
            .connection
            .request_bytes(operation, reqwest::Method::GET, url, None, true)
            .await?;
        decode_audit_reset(operation, status, bytes)
    }

    /// Clear the selected device's global audit history once and check the
    /// current first page. If it already reports zero records, no reset is
    /// submitted. New records after the request can come from later activity.
    /// History recording and licensed data effects are separate observations.
    pub async fn reset_audit_history_and_verify(
        &self,
        options: OperationOptions,
    ) -> Result<AuditHistoryResetReport> {
        const RESET: &str = "reset the selected device's audit history";
        const READ: &str = "check the current file audit history";
        use AuditHistoryResetOutcome as Outcome;
        let context = options.start()?;
        let mut report = AuditHistoryResetReport {
            outcome: Outcome::NotSubmitted,
            write: Default::default(),
            original: None,
            before: None,
            observed: None,
            observation_error: None,
        };
        let dispatch = context.dispatch_deadline();
        let mut guard = None;
        let attempt = context
            .wait(dispatch, RESET, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                let before = self.read_audit_history_for_reset().await?;
                let empty = before.total == 0;
                report.before = Some(before);
                if empty {
                    return Ok(false);
                }
                self.system_status().await?;
                let url = self.connection.management_url("rest/history/reset", &[])?;
                if tokio::time::Instant::now() >= dispatch {
                    return Err(Error::Timeout { operation: RESET });
                }
                let request = self
                    .connection
                    .authorized_request(reqwest::Method::GET, url, None);
                let response = self
                    .connection
                    .send_workflow_write(RESET, request, &context, &mut report.write)
                    .await?;
                decode_audit_reset(RESET, response.status, response.body)?;
                Ok(true)
            })
            .await;
        if matches!(attempt, Ok(false)) {
            report.outcome = Outcome::AlreadyEmpty;
        } else {
            report.original = Some(workflow_write_result(
                RESET,
                report.write,
                attempt.map(|_| ()),
            ));
            if report.write.response_complete
                && matches!(
                    report.original,
                    Some(Err(Error::Authentication { .. }
                        | Error::AccessDenied { .. }
                        | Error::LicenseRequired { .. }))
                )
            {
                report.outcome = Outcome::Rejected;
            } else if report.write.dispatched {
                context.phase(OperationPhase::Verifying);
                match context
                    .wait(context.deadline, READ, self.read_audit_history_for_reset())
                    .await
                {
                    Ok(current) => {
                        report.outcome = if current.total == 0 {
                            Outcome::CurrentHistoryEmpty
                        } else {
                            Outcome::CurrentHistoryHasRecords
                        };
                        report.observed = Some(current);
                    }
                    Err(source) => {
                        report.outcome = Outcome::Unconfirmed;
                        report.observation_error = Some(source);
                    }
                }
            }
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn read_audit_history_for_reset(&self) -> Result<AuditHistoryPage> {
        const PAGE_SIZE: u16 = 20;
        let page = self.audit_history(1, PAGE_SIZE).await?;
        let count = page.records.as_ref().map_or(0, Vec::len) as u64;
        if page
            .error
            .as_deref()
            .is_some_and(|reason| !reason.is_empty())
            || count != page.total.min(u64::from(PAGE_SIZE))
        {
            return Err(Error::InvalidConfiguration {
                reason: "the selected audit history page did not account for the reported records",
            });
        }
        Ok(page)
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
    /// Change only the native policy, preserving the actual archive location
    /// and unknown/inactive parameters. Native PATCH merges parameter maps;
    /// disabling a policy therefore retains its unused parameter values.
    /// The SDK starts no cleanup task, restart, retry or rollback. Native
    /// retention can follow the explicit policy. Readback is separate from
    /// actual archival/retention effects.
    /// External explicitly selects a caller-supplied command for execution by
    /// the target core when archiving; it is not run by the controller SDK.
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
        self.write_folder_versioning(folder, expected, operation)
            .await
    }

    /// Select the native archive directory without SDK migration of existing
    /// archives. Native retention can clean the selected location. Target paths
    /// are not opened or expanded on the controller.
    /// The basic backend uses native target-relative/absolute/tilde semantics.
    /// RemoteUri selects the URI's native FTP/SFTP backend, not the controller's
    /// path syntax or Local Sync option format. Successful configuration readback
    /// is not an authentication, host-verification or archival success receipt.
    /// Changing location can make earlier archives absent from current browsing;
    /// it does not migrate them or change an external versioner's command.
    ///
    /// ```rust,no_run
    /// # async fn select(client: &verysync_sidecar::Client, folder: &verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
    /// use verysync_sidecar::VersionArchiveLocation;
    /// let update = client.set_version_archive_location(
    ///     folder, &VersionArchiveLocation::FolderDefault,
    /// ).await?;
    /// assert!(update.requested_fields_match);
    /// # Ok(()) }
    /// ```
    pub async fn set_version_archive_location(
        &self,
        folder: &FolderId,
        location: &VersionArchiveLocation,
    ) -> Result<FolderVersioningUpdate> {
        let path = location.protocol(self.folder_path_style()?)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let mut expected = self.read_folder_versioning(folder).await?;
        expected.filesystem_path = path.to_owned();
        expected.filesystem_type = location.filesystem_type().to_owned();
        self.write_folder_versioning(folder, expected, "set native version archive location")
            .await
    }

    async fn write_folder_versioning(
        &self,
        folder: &FolderId,
        expected: FolderVersioningConfiguration,
        operation: &'static str,
    ) -> Result<FolderVersioningUpdate> {
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

#[cfg(test)]
mod timestamp_contracts {
    use super::archive_second;
    #[test]
    fn archive_seconds_preserve_negative_fraction_floor_and_offset_equivalence() {
        assert_eq!(archive_second("1969-12-31T23:59:59.500Z").unwrap(), -1);
        assert_eq!(archive_second("1970-01-01T07:59:59.500+08:00").unwrap(), -1);
        assert_eq!(archive_second("1970-01-01T00:00:00.999999999Z").unwrap(), 0);
    }
    #[test]
    fn archive_seconds_never_normalize_leaps_or_discard_unknown_precision() {
        for value in [
            "2016-12-31T23:59:60Z",
            "2026-11-17T03:00:00.1234567890Z",
            "2026-11-17T03:00:00Z[UTC]",
        ] {
            assert!(archive_second(value).is_err());
        }
    }
}
