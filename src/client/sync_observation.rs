//! Fresh typed observations. Multiple calls are not one atomic snapshot.
use super::Client;
use crate::{
    CompletionSnapshot, DeviceId, DeviceStatistics, Error, FolderErrorPage, FolderId,
    FolderStatistics, FolderStatus, ListPage, NeedPage, Result, SyncFilePage,
};
use std::collections::BTreeMap;
impl Client {
    /// Read one full native index FileInfo observation for a strictly relative
    /// target path. Fresh identity and configured-folder checks precede one GET.
    /// Missing index objects remain native HTTP errors, not zero-file successes.
    /// Native zero local records and advertised availability do not establish
    /// filesystem existence, peer reachability or a completed transfer. No scan,
    /// retry, filesystem I/O or peer contact is performed by this method.
    pub async fn index_file_info(
        &self,
        folder: &FolderId,
        path: &crate::TargetPath,
    ) -> Result<crate::IndexFileInfo> {
        let file = crate::scans::validate_subpath(path, self.folder_path_style()?)?;
        self.system_status().await?;
        self.folder(folder).await?;
        self.connection
            .get_json_with_query(
                "read native indexed file metadata",
                "rest/db/file",
                &[("folder", folder.as_str()), ("file", file)],
            )
            .await
    }
    /// Read the independent native debug-file index observation once.
    ///
    /// Reuses the complete native [`crate::IndexFileInfo`] schema, but the
    /// endpoint differs from [`Self::index_file_info`]: an absent file can return
    /// HTTP success with both global/local zero records (empty names and version
    /// vectors). These are not existing empty files or completed downloads.
    /// Identity, configured folder and strict target-relative path checks apply.
    /// No scan, filesystem read, transfer, normalization or retry is implicit.
    ///
    /// ```rust,no_run
    /// # async fn example(client: &verysync_sidecar::Client, folder: &verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
    /// let path = verysync_sidecar::TargetPath::local("sample.bin");
    /// let native = client.index_file_diagnostics(folder, &path).await?;
    /// // Inspect records explicitly; an empty name is a native zero placeholder.
    /// let _local_name = native.local.name;
    /// # Ok(()) }
    /// ```
    pub async fn index_file_diagnostics(
        &self,
        folder: &FolderId,
        path: &crate::TargetPath,
    ) -> Result<crate::IndexFileInfo> {
        let file = crate::scans::validate_subpath(path, self.folder_path_style()?)?;
        self.system_status().await?;
        self.folder(folder).await?;
        self.connection
            .get_json_with_query(
                "read native index file diagnostics",
                "rest/debug/file",
                &[("folder", folder.as_str()), ("file", file)],
            )
            .await
    }

    /// Read the selected folder's native index tree once. This differs from
    /// selective-mode browsing and file-manager resources. The default returns
    /// root entries at level zero; explicit None depth retains native unlimited
    /// depth subject to response/deadline/JSON bounds. Paths use target syntax.
    /// Fresh identity and folder checks precede the read. No scan, transfer,
    /// retry, cursor traversal, local filesystem access or mutation occurs.
    pub async fn browse_index(
        &self,
        folder: &FolderId,
        options: &crate::IndexBrowseOptions,
    ) -> Result<crate::IndexTree> {
        let style = self.folder_path_style()?;
        let prefix = options
            .prefix
            .as_ref()
            .map(|path| crate::scans::validate_subpath(path, style))
            .transpose()?;
        self.system_status().await?;
        self.folder(folder).await?;
        let levels = options.levels.map(|value| value.to_string());
        let mut query = vec![("folder", folder.as_str())];
        if let Some(prefix) = prefix {
            query.push(("prefix", prefix));
        }
        if let Some(levels) = levels.as_deref() {
            query.push(("levels", levels));
        }
        if options.directories_only {
            query.push(("dirsonly", "true"));
        }
        self.connection
            .get_json_with_query("browse native index", "rest/db/browse", &query)
            .await
    }
    /// Read one reported folder/peer completion value. Even 100 with unknown
    /// remote state does not certify peer presence or a caller's file batch.
    pub async fn folder_completion(
        &self,
        folder: &FolderId,
        device: &DeviceId,
    ) -> Result<CompletionSnapshot> {
        self.system_status().await?;
        self.folder(folder).await?;
        self.connection
            .get_json_with_query(
                "read folder peer completion",
                "rest/db/completion",
                &[("folder", folder.as_str()), ("device", device.as_str())],
            )
            .await
    }
    /// Read all completion records returned for this exact folder. An omitted
    /// peer is not given a fabricated record or completion percentage.
    pub async fn folder_completions(
        &self,
        folder: &FolderId,
    ) -> Result<BTreeMap<DeviceId, CompletionSnapshot>> {
        self.system_status().await?;
        self.folder(folder).await?;
        self.connection
            .get_json_with_query(
                "read folder completion batch",
                "rest/batch/db/completion",
                &[("folder", folder.as_str())],
            )
            .await
    }
    /// Read the engine's current batch folder-status map, without inventing a
    /// coherent snapshot across subsequent requests or a batch transaction ID.
    pub async fn batch_folder_status(&self) -> Result<BTreeMap<FolderId, FolderStatus>> {
        self.system_status().await?;
        self.connection
            .get_json("read batch folder status", "rest/batch/db/status")
            .await
    }
    /// Read one explicit page of local need. This does not launch a transfer.
    pub async fn folder_need(&self, folder: &FolderId, page: ListPage) -> Result<NeedPage> {
        self.system_status().await?;
        self.folder(folder).await?;
        let number = page.number.to_string();
        let limit = page.per_page.to_string();
        self.connection
            .get_json_with_query(
                "read folder need",
                "rest/db/need",
                &[
                    ("folder", folder.as_str()),
                    ("page", &number),
                    ("perpage", &limit),
                ],
            )
            .await
    }
    /// Read one actual remote-need page. Index knowledge and live peer presence
    /// are distinct; this call does not start discovery or send files.
    pub async fn remote_need(
        &self,
        folder: &FolderId,
        device: &DeviceId,
        page: ListPage,
    ) -> Result<SyncFilePage> {
        self.system_status().await?;
        self.folder(folder).await?;
        let number = page.number.to_string();
        let limit = page.per_page.to_string();
        self.connection
            .get_json_with_query(
                "read remote need",
                "rest/db/remoteneed",
                &[
                    ("folder", folder.as_str()),
                    ("device", device.as_str()),
                    ("page", &number),
                    ("perpage", &limit),
                ],
            )
            .await
    }
    /// Read one actual local-change page. No scan or filesystem mutation occurs.
    pub async fn local_changes(&self, folder: &FolderId, page: ListPage) -> Result<SyncFilePage> {
        self.system_status().await?;
        self.folder(folder).await?;
        let number = page.number.to_string();
        let limit = page.per_page.to_string();
        self.connection
            .get_json_with_query(
                "read local changes",
                "rest/db/localchanged",
                &[
                    ("folder", folder.as_str()),
                    ("page", &number),
                    ("perpage", &limit),
                ],
            )
            .await
    }
    /// Read a folder error page, retaining null rather than inventing an empty
    /// list. The exact folder in the response is checked against the request.
    pub async fn folder_errors(
        &self,
        folder: &FolderId,
        page: ListPage,
    ) -> Result<FolderErrorPage> {
        self.system_status().await?;
        self.folder(folder).await?;
        let number = page.number.to_string();
        let limit = page.per_page.to_string();
        let actual: FolderErrorPage = self
            .connection
            .get_json_with_query(
                "read folder errors",
                "rest/folder/errors",
                &[
                    ("folder", folder.as_str()),
                    ("page", &number),
                    ("perpage", &limit),
                ],
            )
            .await?;
        if actual.folder != *folder {
            return Err(Error::FolderIdentityMismatch {
                expected: folder.clone(),
                actual: actual.folder,
            });
        }
        Ok(actual)
    }
    /// Read actual per-device statistics without probing those peers.
    pub async fn device_statistics(&self) -> Result<BTreeMap<DeviceId, DeviceStatistics>> {
        self.system_status().await?;
        self.connection
            .get_json("read device statistics", "rest/stats/device")
            .await
    }
    /// Read actual folder statistics without starting scans or transfers.
    pub async fn folder_statistics(&self) -> Result<BTreeMap<FolderId, FolderStatistics>> {
        self.system_status().await?;
        self.connection
            .get_json("read folder statistics", "rest/stats/folder")
            .await
    }
}
