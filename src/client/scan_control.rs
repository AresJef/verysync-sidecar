//! Explicit scan scopes and partial per-folder scheduling settings.
use super::Client;
use crate::{
    Error, FolderId, FolderScanConfig, FolderScanPatch, FolderScanUpdate, Result, TargetPath,
};
use serde::Deserialize;

impl Client {
    /// Read actual scan scheduling settings for an existing folder.
    pub async fn folder_scan_configuration(&self, folder: &FolderId) -> Result<FolderScanConfig> {
        #[derive(Deserialize)]
        struct Entry {
            id: FolderId,
            #[serde(flatten)]
            scan: FolderScanConfig,
        }
        #[derive(Deserialize)]
        struct Config {
            folders: Vec<Entry>,
        }
        self.system_status().await?;
        let config: Config = self
            .connection
            .get_json("read folder scan configuration", "rest/config")
            .await?;
        config
            .folders
            .into_iter()
            .find(|x| x.id == *folder)
            .map(|x| x.scan)
            .ok_or_else(|| Error::FolderNotFound { id: folder.clone() })
    }
    /// Patch selected scan settings once, without retry or automatic restart.
    /// Readback is distinct from a watcher readiness or scan completion receipt.
    pub async fn update_folder_scan_configuration(
        &self,
        folder: &FolderId,
        patch: &FolderScanPatch,
    ) -> Result<FolderScanUpdate> {
        patch.validate()?;
        let url = self.connection.folder_url(folder)?;
        let body = serde_json::to_value(patch).map_err(|_| Error::InvalidConfiguration {
            reason: "scan settings cannot be encoded",
        })?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.folder(folder).await?;
        self.connection
            .request_bytes(
                "update folder scan configuration",
                reqwest::Method::PATCH,
                url,
                Some(&body),
                true,
            )
            .await?;
        let configuration = self
            .folder_scan_configuration(folder)
            .await
            .map_err(|source| Error::MutationOutcomeUnknown {
                operation: "read back changed folder scan configuration",
                source: Box::new(source),
            })?;
        Ok(FolderScanUpdate {
            requested_fields_match: patch.matches(&configuration),
            configuration,
        })
    }
    /// Request a scan of 1..=256 relative target subpaths. This acknowledgement
    /// does not correlate an observed cycle with this particular request.
    pub async fn request_scan_subpaths(
        &self,
        folder: &FolderId,
        subpaths: &[TargetPath],
    ) -> Result<()> {
        if subpaths.is_empty() || subpaths.len() > 256 {
            return Err(Error::InvalidPath {
                reason: "subpath scan requires 1 through 256 explicit subpaths",
            });
        }
        let mut query = vec![("folder", folder.as_str())];
        for path in subpaths {
            query.push((
                "sub",
                crate::scans::validate_subpath(path, self.folder_path_style()?)?,
            ));
        }
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        if self.folder(folder).await?.paused {
            return Err(Error::ScanNotIdle);
        }
        let url = self.connection.management_url("rest/db/scan", &query)?;
        self.connection
            .request_bytes(
                "request subpath scan",
                reqwest::Method::POST,
                url,
                None,
                true,
            )
            .await
            .map(|_| ())
    }
    /// Request scans for all folders handled by the engine. Paused folders are
    /// governed by the engine. This does not resume folders or await completion.
    pub async fn request_all_scans(&self) -> Result<()> {
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let url = self.connection.management_url("rest/db/scan", &[])?;
        self.connection
            .request_bytes(
                "request all folder scans",
                reqwest::Method::POST,
                url,
                None,
                true,
            )
            .await
            .map(|_| ())
    }
}
