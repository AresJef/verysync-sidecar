//! Explicit target-side paths and native temporary-file maintenance.
use super::{mutation_error, Client};
use crate::{
    Error, FolderId, FolderTemporaryCleanup, NativeSystemPaths, ResponseDiagnostic, Result,
    TargetPath,
};
use std::collections::BTreeMap;

impl Client {
    /// Read the target program's actual configuration/data locations. Known
    /// filesystem locations use target path syntax without controller I/O.
    /// Other native values retain special markers and filename templates.
    pub async fn native_system_paths(&self) -> Result<NativeSystemPaths> {
        let operation = "read native system paths";
        self.system_status().await?;
        let style = self.folder_path_style()?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::GET,
                self.connection.management_url("rest/system/paths", &[])?,
                None,
                false,
            )
            .await?;
        let invalid = || Error::InvalidResponse {
            operation,
            response: ResponseDiagnostic::new(status, bytes.clone()),
        };
        let mut values: BTreeMap<String, String> =
            serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        let mut location = |name| {
            let value = values.remove(name).ok_or_else(invalid)?;
            if value == "-" || value.contains("%{") {
                return Err(invalid());
            }
            TargetPath::remote(style, value).map_err(|_| invalid())
        };
        Ok(NativeSystemPaths {
            configuration_directory: location("baseDir-config")?,
            data_directory: location("baseDir-data")?,
            user_home_directory: location("baseDir-userHome")?,
            configuration_file: location("config")?,
            database_directory: location("database")?,
            extra: values,
        })
    }

    /// Explicitly ask the native folder runner to remove its temporary/session
    /// files. The fixed core targets `.verysync/*.tmp` and `.verysync/*.sess`;
    /// matching directories and their contents can be removed recursively.
    /// Other directories and controller paths are outside this request's scope.
    ///
    /// This state-changing GET is serialized and never retried. A configured
    /// folder must exist, but that read is not an atomic guard against other
    /// controllers. A native empty-error receipt is only an acknowledgement:
    /// native per-file failures can be logged without reaching this response.
    /// Verify required file effects independently. Cancellation/uncertain
    /// responses remain unknown outcomes, with no implicit rollback or rescan.
    pub async fn request_folder_temporary_cleanup(
        &self,
        folder: &FolderId,
    ) -> Result<FolderTemporaryCleanup> {
        #[derive(serde::Deserialize)]
        struct Receipt {
            error: String,
            #[serde(flatten)]
            extra: BTreeMap<String, serde_json::Value>,
        }
        let operation = "request native folder temporary cleanup";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.folder(folder).await?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::GET,
                self.connection.management_url(
                    "rest/svc/folder/cleantempfiles",
                    &[("folder", folder.as_str())],
                )?,
                None,
                true,
            )
            .await?;
        let receipt: Receipt = serde_json::from_slice(&bytes).map_err(|_| {
            mutation_error(
                operation,
                true,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes.clone()),
                },
            )
        })?;
        if !receipt.error.is_empty() {
            return Err(mutation_error(
                operation,
                true,
                Error::Api {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                },
            ));
        }
        Ok(FolderTemporaryCleanup {
            folder: folder.clone(),
            extra: receipt.extra,
        })
    }
}
