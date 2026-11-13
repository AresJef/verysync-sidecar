//! Explicit potentially destructive recovery requests without write retries.
use super::Client;
use crate::{Error, FolderId, MarkerRepairResult, ResponseDiagnostic, Result};
impl Client {
    /// Request receive-only local-change reversion once. This can overwrite
    /// edits. Unindexed local additions have a separate engine policy; this
    /// is not a filesystem reset. The fixed engine can restore RO-key
    /// deletions before this request. Ok acknowledges
    /// the request, not completion; observe actual files and local changes.
    pub async fn request_revert_local_changes(&self, folder: &FolderId) -> Result<()> {
        self.request_recovery_action(
            folder,
            "receiveonly",
            "rest/db/revert",
            "request receive-only revert",
        )
        .await
    }
    /// Request send-only authority override once. This can replace other peers'
    /// versions with the current local version. Ok is not peer completion.
    pub async fn request_override_remote_changes(&self, folder: &FolderId) -> Result<()> {
        self.request_recovery_action(
            folder,
            "sendonly",
            "rest/db/override",
            "request send-only override",
        )
        .await
    }
    async fn request_recovery_action(
        &self,
        folder: &FolderId,
        mode: &'static str,
        route: &'static str,
        operation: &'static str,
    ) -> Result<()> {
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let config = self.folder(folder).await?;
        if config.paused {
            return Err(Error::FolderPaused { id: folder.clone() });
        }
        if config.extra.get("type").and_then(serde_json::Value::as_str) != Some(mode) {
            return Err(Error::InvalidConfiguration {
                reason: "recovery request requires the corresponding verified folder mode",
            });
        }
        let url = self
            .connection
            .management_url(route, &[("folder", folder.as_str())])?;
        let (status, bytes) = self
            .connection
            .request_bytes(operation, reqwest::Method::POST, url, None, true)
            .await?;
        if !bytes.is_empty() {
            return Err(Error::MutationOutcomeUnknown {
                operation,
                source: Box::new(Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                }),
            });
        }
        Ok(())
    }
    /// Ask the engine to repair this configured folder's marker. The SDK never
    /// inspects, removes or creates paths itself. Inspect actual folder state
    /// afterward; a reported success is distinct from restored data/identity.
    pub async fn request_marker_repair(&self, folder: &FolderId) -> Result<MarkerRepairResult> {
        let operation = "request folder marker repair";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.folder(folder).await?;
        let url = self
            .connection
            .management_url("rest/folder/marker/repair", &[("folder", folder.as_str())])?;
        let (status, bytes) = self
            .connection
            .request_bytes(operation, reqwest::Method::POST, url, None, true)
            .await?;
        let result: MarkerRepairResult =
            serde_json::from_slice(&bytes).map_err(|_| Error::MutationOutcomeUnknown {
                operation,
                source: Box::new(Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes.clone()),
                }),
            })?;
        if !result.success || !result.error.is_empty() {
            return Err(Error::MutationOutcomeUnknown {
                operation,
                source: Box::new(Error::Api {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                }),
            });
        }
        Ok(result)
    }
}
