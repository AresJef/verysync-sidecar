//! Explicit scheduling mutations and independent rate-setting readback.
use super::Client;
use crate::{
    BandwidthPatch, BandwidthUpdate, Error, FolderId, FolderPullOrder, FolderSchedulingConfig,
    FolderSchedulingUpdate, GlobalBandwidthConfig, ListPage, NeedPage, ResponseDiagnostic, Result,
    TargetPath,
};
use serde::Deserialize;
impl Client {
    /// Read actual global byte-rate settings, without starting a transfer.
    pub async fn bandwidth_configuration(&self) -> Result<GlobalBandwidthConfig> {
        #[derive(Deserialize)]
        struct Config {
            options: GlobalBandwidthConfig,
        }
        self.system_status().await?;
        let config: Config = self
            .connection
            .get_json("read global bandwidth configuration", "rest/config")
            .await?;
        Ok(config.options)
    }
    /// Partially update global limits once; zero removes only the selected
    /// limiter. Device limits and other bottlenecks remain independent.
    pub async fn update_bandwidth_configuration(
        &self,
        patch: &BandwidthPatch,
    ) -> Result<BandwidthUpdate> {
        patch.validate()?;
        let body = serde_json::to_value(patch).map_err(|_| Error::InvalidConfiguration {
            reason: "bandwidth settings cannot be encoded",
        })?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let url = self.connection.management_url("rest/config/options", &[])?;
        self.connection
            .request_bytes(
                "update global bandwidth configuration",
                reqwest::Method::PATCH,
                url,
                Some(&body),
                true,
            )
            .await?;
        let configuration = self.bandwidth_configuration().await.map_err(|source| {
            Error::MutationOutcomeUnknown {
                operation: "read back changed global bandwidth configuration",
                source: Box::new(source),
            }
        })?;
        Ok(BandwidthUpdate {
            requested_fields_match: patch.matches(&configuration),
            configuration,
        })
    }
    /// Read the configured file pull order for an exact existing folder.
    pub async fn folder_scheduling_configuration(
        &self,
        folder: &FolderId,
    ) -> Result<FolderSchedulingConfig> {
        #[derive(Deserialize)]
        struct Entry {
            id: FolderId,
            #[serde(flatten)]
            scheduling: FolderSchedulingConfig,
        }
        #[derive(Deserialize)]
        struct Config {
            folders: Vec<Entry>,
        }
        self.system_status().await?;
        let config: Config = self
            .connection
            .get_json("read folder scheduling configuration", "rest/config")
            .await?;
        config
            .folders
            .into_iter()
            .find(|x| x.id == *folder)
            .map(|x| x.scheduling)
            .ok_or_else(|| Error::FolderNotFound { id: folder.clone() })
    }
    /// Change one known file-order value without altering block order or
    /// cancelling an already active file. Readback is not queue execution.
    pub async fn set_folder_pull_order(
        &self,
        folder: &FolderId,
        order: &FolderPullOrder,
    ) -> Result<FolderSchedulingUpdate> {
        if matches!(order, FolderPullOrder::Unknown(_)) {
            return Err(Error::InvalidConfiguration {
                reason: "unknown folder pull order cannot be submitted",
            });
        }
        let url = self.connection.folder_url(folder)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.folder(folder).await?;
        self.connection
            .request_bytes(
                "set folder file pull order",
                reqwest::Method::PATCH,
                url,
                Some(&serde_json::json!({"order":order})),
                true,
            )
            .await?;
        let configuration =
            self.folder_scheduling_configuration(folder)
                .await
                .map_err(|source| Error::MutationOutcomeUnknown {
                    operation: "read back changed folder pull order",
                    source: Box::new(source),
                })?;
        Ok(FolderSchedulingUpdate {
            requested_order_match: configuration.pull_order == *order,
            configuration,
        })
    }
    /// Ask the engine to prioritize a relative file and return its actual need
    /// page. An active file is not preempted; absence from this page is unknown.
    pub async fn prioritize_file(
        &self,
        folder: &FolderId,
        file: &TargetPath,
        page: ListPage,
    ) -> Result<NeedPage> {
        let file = crate::scans::validate_subpath(file, self.folder_path_style()?)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        if self.folder(folder).await?.paused {
            return Err(Error::FolderPaused { id: folder.clone() });
        }
        let number = page.number().to_string();
        let limit = page.per_page().to_string();
        let url = self.connection.management_url(
            "rest/db/prio",
            &[
                ("folder", folder.as_str()),
                ("file", file),
                ("page", &number),
                ("perpage", &limit),
            ],
        )?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                "prioritize folder file",
                reqwest::Method::POST,
                url,
                None,
                true,
            )
            .await?;
        serde_json::from_slice(&bytes).map_err(|_| Error::MutationOutcomeUnknown {
            operation: "decode prioritized need page",
            source: Box::new(Error::InvalidResponse {
                operation: "decode prioritized need page",
                response: ResponseDiagnostic::new(status, bytes),
            }),
        })
    }
}
