//! Fresh typed observations. Multiple calls are not one atomic snapshot.
use super::Client;
use crate::{
    CompletionSnapshot, DeviceId, DeviceStatistics, Error, FolderErrorPage, FolderId,
    FolderStatistics, FolderStatus, ListPage, NeedPage, Result, SyncFilePage,
};
use std::collections::BTreeMap;
impl Client {
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
