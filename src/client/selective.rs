//! Explicit selective browse/search and conditional feature requests.
use super::Client;
use crate::{
    Error, FolderId, FolderSelectiveConfig, FolderSelectiveUpdate, ResponseDiagnostic, Result,
    SelectiveAcknowledgement, SelectiveAction, SelectiveBrowseOptions, SelectiveScope,
    SelectiveSearchOptions, SelectiveSearchPage, SelectiveTree,
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
        let url = self.connection.management_url(
            "rest/folder/selector",
            &[
                ("folder", folder.as_str()),
                ("path", path),
                ("selected", selected),
                ("removefromall", remove),
            ],
        )?;
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
}
