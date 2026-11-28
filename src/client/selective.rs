//! Explicit selective browse/search and conditional feature requests.
use super::{workflow_write_result, Client};
use crate::{
    Error, FolderId, FolderSelectiveConfig, FolderSelectiveUpdate, OperationOptions,
    OperationPhase, PathStyle, ResponseDiagnostic, Result, SelectiveAcknowledgement,
    SelectiveAction, SelectiveBrowseOptions, SelectiveEntry, SelectivePathOutcome,
    SelectivePathReport, SelectiveScope, SelectiveSearchOptions, SelectiveSearchPage,
    SelectiveTree, TargetPath,
};
use serde::Deserialize;
impl Client {
    /// Read an actual index tree with bounded explicit depth.
    pub async fn browse_selective(
        &self,
        folder: &FolderId,
        options: &SelectiveBrowseOptions,
    ) -> Result<SelectiveTree> {
        options.validate()?;
        let prefix = options.scope.protocol(self.folder_path_style()?)?;
        self.system_status().await?;
        self.folder(folder).await?;
        let levels = options.levels.to_string();
        let mut query = vec![
            ("folder", folder.as_str()),
            ("prefix", prefix),
            ("levels", &levels),
        ];
        if options.directories_only {
            query.push(("dirsonly", "true"));
        }
        self.connection
            .get_json_with_query("browse selective index", "rest/db/browse/selective", &query)
            .await
    }
    /// Read exactly one search page; preserve its cursor and reported has_more.
    pub async fn search_selective(
        &self,
        folder: &FolderId,
        options: &SelectiveSearchOptions,
    ) -> Result<SelectiveSearchPage> {
        options.validate()?;
        let prefix = options.scope.protocol(self.folder_path_style()?)?;
        self.system_status().await?;
        self.folder(folder).await?;
        let limit = options.limit.to_string();
        let mut query = vec![
            ("folder", folder.as_str()),
            ("prefix", prefix),
            ("search", options.search.as_str()),
            ("limit", &limit),
        ];
        if options.directories_only {
            query.push(("dirsonly", "true"));
        }
        if let Some(cursor) = &options.cursor {
            query.push(("cursor", cursor));
        }
        let url = self
            .connection
            .management_url("rest/db/browse/selective", &query)?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                "search selective index",
                reqwest::Method::GET,
                url,
                None,
                false,
            )
            .await?;
        let page: SelectiveSearchPage =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse {
                operation: "decode selective search page",
                response: ResponseDiagnostic::new(status, bytes.clone()),
            })?;
        if !page.search {
            return Err(Error::InvalidResponse {
                operation: "validate selective search mode",
                response: ResponseDiagnostic::new(status, bytes),
            });
        }
        Ok(page)
    }
    /// Read actual selective-mode settings without changing selections.
    pub async fn folder_selective_configuration(
        &self,
        folder: &FolderId,
    ) -> Result<FolderSelectiveConfig> {
        #[derive(Deserialize)]
        struct Entry {
            id: FolderId,
            #[serde(flatten)]
            selective: FolderSelectiveConfig,
        }
        #[derive(Deserialize)]
        struct Config {
            folders: Vec<Entry>,
        }
        self.system_status().await?;
        let config: Config = self
            .connection
            .get_json("read folder selective configuration", "rest/config")
            .await?;
        config
            .folders
            .into_iter()
            .find(|x| x.id == *folder)
            .map(|x| x.selective)
            .ok_or_else(|| Error::FolderNotFound { id: folder.clone() })
    }
    /// Change only the mode flag. Readback does not establish feature entitlement
    /// or select any file; enabling it can leave files unselected.
    pub async fn set_folder_selective_enabled(
        &self,
        folder: &FolderId,
        enabled: bool,
    ) -> Result<FolderSelectiveUpdate> {
        let url = self.connection.folder_url(folder)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.folder(folder).await?;
        self.connection
            .request_bytes(
                "set folder selective mode",
                reqwest::Method::PATCH,
                url,
                Some(&serde_json::json!({"selectiveEnabled":enabled})),
                true,
            )
            .await?;
        let configuration =
            self.folder_selective_configuration(folder)
                .await
                .map_err(|source| Error::MutationOutcomeUnknown {
                    operation: "read back changed selective mode",
                    source: Box::new(source),
                })?;
        Ok(FolderSelectiveUpdate {
            requested_mode_match: configuration.enabled == enabled,
            configuration,
        })
    }
    /// Submit an explicit conditional selection request once. The fixed free
    /// engine returns LicenseRequired; licensed effects and root selection
    /// semantics have not yet passed native acceptance. Acknowledgement is not
    /// a receipt for file retention, removal, download or all-node completion.
    pub async fn request_selection(
        &self,
        folder: &FolderId,
        scope: &SelectiveScope,
        action: SelectiveAction,
    ) -> Result<SelectiveAcknowledgement> {
        let path = scope.protocol(self.folder_path_style()?)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.folder(folder).await?;
        let url = self.selection_url(folder, path, action)?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                "request selective selection",
                reqwest::Method::POST,
                url,
                None,
                true,
            )
            .await?;
        Ok(SelectiveAcknowledgement {
            response: ResponseDiagnostic::new(status, bytes),
        })
    }

    /// Request selection or deselection for one exact indexed path and verify
    /// the native flags on the selected device. The mode must already be
    /// enabled. The optional existence goal refers to the engine's index,
    /// and actual files or effects on other devices require independent proof.
    /// An explicit `RemoveFromAll` request is never skipped based on this
    /// device's selection flag. It can affect every participating device.
    pub async fn set_selective_path_and_verify(
        &self,
        folder: &FolderId,
        path: &TargetPath,
        action: SelectiveAction,
        expected_index_presence: Option<bool>,
        options: OperationOptions,
    ) -> Result<SelectivePathReport> {
        const APPLY: &str = "set selective state for the indexed path";
        const VERIFY: &str = "check the selected path in the engine index";
        let style = self.folder_path_style()?;
        let target = TargetPath::remote(style, crate::scans::validate_subpath(path, style)?)?;
        let path = crate::scans::validate_subpath(&target, style)?;
        let desired = action == SelectiveAction::Select;
        let (parent, name) =
            match path.rsplit_once(|c| c == '/' || (style == PathStyle::Windows && c == '\\')) {
                Some((parent, name)) => (
                    SelectiveScope::Path(TargetPath::remote(style, parent)?),
                    name,
                ),
                None => (SelectiveScope::FolderRoot, path),
            };
        let url = self.selection_url(folder, path, action)?;
        let context = options.start()?;
        let dispatch = context.dispatch_deadline();
        let mut report = SelectivePathReport {
            outcome: SelectivePathOutcome::NotSubmitted,
            configuration: None,
            write: Default::default(),
            original: None,
            observed: None,
            expected_index_presence_observed: None,
            observation_error: None,
        };
        let mut before = None;
        let mut guard = None;
        let scope = SelectiveBrowseOptions::new(parent);
        let attempt = context
            .wait(dispatch, APPLY, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                before = Some(self.folder(folder).await?);
                let config = self.folder_selective_configuration(folder).await?;
                let enabled = config.enabled;
                report.configuration = Some(config);
                if !enabled {
                    return Err(Error::InvalidConfiguration {
                        reason: "selective sync is disabled for the selected folder",
                    });
                }
                let selected = self.observe_selective_child(folder, &scope, name).await?;
                let current = self.folder(folder).await?;
                if before
                    .as_ref()
                    .is_none_or(|original| original.path != current.path)
                {
                    return Err(Error::ConfigurationChanged);
                }
                let no_change =
                    action != SelectiveAction::RemoveFromAll && desired == selected.selected;
                if no_change {
                    report.observed = Some(selected);
                    return Ok(None);
                }
                self.system_status().await?;
                if tokio::time::Instant::now() >= dispatch {
                    return Err(Error::Timeout { operation: APPLY });
                }
                let request = self
                    .connection
                    .authorized_request(reqwest::Method::POST, url, None);
                let response = self
                    .connection
                    .send_workflow_write(APPLY, request, &context, &mut report.write)
                    .await?;
                Ok(Some(SelectiveAcknowledgement {
                    response: ResponseDiagnostic::new(response.status, response.body),
                }))
            })
            .await;
        match workflow_write_result(APPLY, report.write, attempt) {
            Ok(None) => report.outcome = SelectivePathOutcome::AlreadyMatched,
            attempted => {
                report.original = Some(attempted.and_then(|ack| {
                    ack.ok_or(Error::ManagedFailure {
                        reason: "the selection acknowledgement was not retained",
                    })
                }));
                if report.write.response_complete
                    && matches!(
                        report.original,
                        Some(Err(Error::Authentication { .. }
                            | Error::AccessDenied { .. }
                            | Error::LicenseRequired { .. }))
                    )
                {
                    report.outcome = SelectivePathOutcome::Rejected;
                } else if report.write.dispatched {
                    report.outcome = SelectivePathOutcome::Unconfirmed;
                }
            }
        }
        if matches!(
            report.outcome,
            SelectivePathOutcome::AlreadyMatched | SelectivePathOutcome::Unconfirmed
        ) {
            context.phase(OperationPhase::Verifying);
            let checked = context
                .wait(context.deadline, VERIFY, async {
                    loop {
                        if let (Some(expected), Some(observed)) =
                            (expected_index_presence, &report.observed)
                        {
                            report.expected_index_presence_observed =
                                Some(observed.exists_locally == expected);
                        }
                        if report
                            .observed
                            .as_ref()
                            .is_some_and(|entry| entry.selected == desired)
                            && report.expected_index_presence_observed != Some(false)
                        {
                            break Ok(());
                        }
                        let current = self.folder(folder).await?;
                        if before
                            .as_ref()
                            .is_none_or(|original| original.path != current.path)
                            || !self.folder_selective_configuration(folder).await?.enabled
                        {
                            report.outcome = SelectivePathOutcome::Unconfirmed;
                            return Err(Error::ConfigurationChanged);
                        }
                        let snapshot = self.observe_selective_child(folder, &scope, name).await?;
                        let matches = snapshot.selected == desired;
                        report.observed = Some(snapshot);
                        report.outcome = if matches {
                            if report.write.dispatched {
                                SelectivePathOutcome::CurrentMatches
                            } else {
                                SelectivePathOutcome::AlreadyMatched
                            }
                        } else {
                            SelectivePathOutcome::Unconfirmed
                        };
                        if !matches
                            || expected_index_presence.is_some_and(|expected| {
                                report
                                    .observed
                                    .as_ref()
                                    .is_some_and(|current| current.exists_locally != expected)
                            })
                        {
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                })
                .await;
            report.observation_error = checked.err();
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn observe_selective_child(
        &self,
        folder: &FolderId,
        parent: &SelectiveBrowseOptions,
        name: &str,
    ) -> Result<SelectiveEntry> {
        let mut tree = self.browse_selective(folder, parent).await?;
        self.system_status().await?;
        tree.entries
            .remove(name)
            .filter(|entry| entry.name == name)
            .ok_or(Error::InvalidConfiguration {
                reason: "the engine index did not return the exact selected path",
            })
    }

    fn selection_url(
        &self,
        folder: &FolderId,
        path: &str,
        action: SelectiveAction,
    ) -> Result<url::Url> {
        let selected = if action == SelectiveAction::Select {
            "true"
        } else {
            "false"
        };
        let remove = if action == SelectiveAction::RemoveFromAll {
            "true"
        } else {
            "false"
        };
        self.connection.management_url(
            "rest/folder/selector",
            &[
                ("folder", folder.as_str()),
                ("path", path),
                ("selected", selected),
                ("removefromall", remove),
            ],
        )
    }
}
