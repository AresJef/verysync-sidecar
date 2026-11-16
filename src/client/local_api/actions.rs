//! Explicit native actions; flush acknowledgements do not prove process exit.
use super::LocalApiClient;
use crate::{
    Error, FolderId, FolderTemporaryCleanup, RawMethod, RawRequest, RawResponse, RequestEffect,
    ResponseDiagnostic, Result,
};
use serde::Deserialize;
use std::collections::BTreeMap;

/// Native requested lifecycle action, separate from process ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalApiExitAction {
    /// Native acknowledgement precedes a nonblocking request for exit status0.
    Shutdown,
    /// Native acknowledgement precedes a nonblocking request for exit status3.
    Restart,
}
/// Bounded native acknowledgement, not a receipt for actual exit or relaunch.
#[derive(Debug)]
pub struct LocalApiExitAcknowledgement {
    /// Explicit action whose native text marker was checked.
    pub action: LocalApiExitAction,
    /// Exact native status/body, including private future fields.
    pub response: ResponseDiagnostic,
}
/// Result of the core's explicitly requested server-selected upgrade handler.
#[derive(Debug)]
pub struct LocalApiUpgradeAcknowledgement {
    /// Whether the native response contained its restarting acknowledgement.
    /// False denotes its empty successful response; installation/tree exit
    /// and fresh version/hash must always be observed separately.
    pub restart_acknowledged: bool,
    /// Exact native response, without a fabricated installed-version receipt.
    pub response: ResponseDiagnostic,
}

impl LocalApiClient {
    /// Request shutdown once, checking the native marker. The core flushes
    /// before its nonblocking exit request; await owned tree exit separately.
    pub async fn request_shutdown(&self) -> Result<LocalApiExitAcknowledgement> {
        self.request_exit(LocalApiExitAction::Shutdown).await
    }
    /// Request native restart once; this does not launch another generation.
    /// An owned inner core normally exits3. Use explicit ManagedInstance
    /// lifecycle operations to observe exit and choose any subsequent startup.
    pub async fn request_restart(&self) -> Result<LocalApiExitAcknowledgement> {
        self.request_exit(LocalApiExitAction::Restart).await
    }
    async fn request_exit(
        &self,
        action: LocalApiExitAction,
    ) -> Result<LocalApiExitAcknowledgement> {
        let (route, marker) = match action {
            LocalApiExitAction::Shutdown => ("shutdown", "shutting down"),
            LocalApiExitAction::Restart => ("restart", "restarting"),
        };
        let operation = "request Local-API lifecycle action";
        let response = self
            .control_response(
                RawRequest::new(RawMethod::Post, ["system", route], RequestEffect::MayModify)?,
                operation,
            )
            .await?;
        require_marker(operation, &response, marker)?;
        Ok(LocalApiExitAcknowledgement {
            action,
            response: ResponseDiagnostic::new(response.status, response.body),
        })
    }

    /// Explicitly invoke the core's selected release provider/installer. This
    /// can replace its executable; use a dedicated mutable program and backups.
    /// The SDK selects/downloads nothing, does not retry, restart or roll back.
    /// Native empty200 and restarting acknowledgements remain distinguishable;
    /// real installed-version/hash/tree outcomes require separate observation.
    pub async fn request_server_selected_upgrade(&self) -> Result<LocalApiUpgradeAcknowledgement> {
        let operation = "request Local-API server-selected upgrade";
        let response = self
            .control_response(
                RawRequest::new(
                    RawMethod::Post,
                    ["system", "upgrade"],
                    RequestEffect::MayModify,
                )?,
                operation,
            )
            .await
            .map_err(crate::client::upgrade_control::classify_release_unavailable)?;
        let restart_acknowledged = !response.body.is_empty();
        if restart_acknowledged {
            require_marker(operation, &response, "restarting")?;
        }
        Ok(LocalApiUpgradeAcknowledgement {
            restart_acknowledged,
            response: ResponseDiagnostic::new(response.status, response.body),
        })
    }

    /// Explicitly request native cleanup of this configured folder's
    /// `.verysync/*.tmp` and `*.sess` entries, including matching directories.
    /// The core can log individual removal failures yet acknowledge success;
    /// verify required effects independently. No retry or automatic scan occurs.
    pub async fn request_folder_temporary_cleanup(
        &self,
        folder: &FolderId,
    ) -> Result<FolderTemporaryCleanup> {
        #[derive(Deserialize)]
        struct Receipt {
            error: String,
            #[serde(flatten)]
            extra: BTreeMap<String, serde_json::Value>,
        }
        let operation = "request Local-API folder temporary cleanup";
        let guard = self.connection.mutation_lock.lock().await;
        self.folder(folder).await?;
        let response = self
            .control_response_locked(
                RawRequest::new(
                    RawMethod::Get,
                    ["tools", "cleantempfiles"],
                    RequestEffect::MayModify,
                )?
                .query("folder", folder.as_str()),
                operation,
                &guard,
            )
            .await?;
        let receipt: Receipt =
            serde_json::from_slice(&response.body).map_err(|_| invalid(operation, &response))?;
        if !receipt.error.is_empty() {
            return Err(crate::client::mutation_error(
                operation,
                true,
                Error::Api {
                    operation,
                    response: ResponseDiagnostic::new(response.status, response.body),
                },
            ));
        }
        Ok(FolderTemporaryCleanup {
            folder: folder.clone(),
            extra: receipt.extra,
        })
    }
}
fn require_marker(operation: &'static str, response: &RawResponse, marker: &str) -> Result<()> {
    let value: serde_json::Value =
        serde_json::from_slice(&response.body).map_err(|_| invalid(operation, response))?;
    if value.get("ok").and_then(serde_json::Value::as_str) != Some(marker) {
        return Err(invalid(operation, response));
    }
    Ok(())
}
fn invalid(operation: &'static str, response: &RawResponse) -> Error {
    crate::client::mutation_error(
        operation,
        true,
        Error::InvalidResponse {
            operation,
            response: ResponseDiagnostic::new(response.status, response.body.clone()),
        },
    )
}
