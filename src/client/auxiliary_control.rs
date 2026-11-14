//! Native directory-picker contracts verified against the selected engine.
use super::{mutation_error, Client};
use crate::{
    Error, ResponseDiagnostic, Result, TargetDirectoryCreation, TargetDirectoryEntry,
    TargetDirectoryLocation, TargetPath,
};
use serde::Deserialize;
use std::collections::BTreeMap;

impl Client {
    /// Read native directory-picker starting locations (`system/storeages`,
    /// retaining the engine's spelling). This reads no controller directories.
    /// Titles can be localized; paths use the connected target's syntax.
    pub async fn target_directory_locations(&self) -> Result<Vec<TargetDirectoryLocation>> {
        #[derive(Deserialize)]
        struct Location {
            path: String,
            title: String,
            #[serde(flatten)]
            extra: BTreeMap<String, serde_json::Value>,
        }
        let operation = "read target directory locations";
        self.system_status().await?;
        let style = self.folder_path_style()?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::GET,
                self.connection
                    .management_url("rest/system/storeages", &[])?,
                None,
                false,
            )
            .await?;
        let invalid = || Error::InvalidResponse {
            operation,
            response: ResponseDiagnostic::new(status, bytes.clone()),
        };
        let locations: Vec<Location> = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        locations
            .into_iter()
            .map(|l| {
                Ok(TargetDirectoryLocation {
                    path: TargetPath::remote(style, l.path).map_err(|_| invalid())?,
                    title: l.title,
                    extra: l.extra,
                })
            })
            .collect()
    }

    /// List native child directories using the verified `d` picker filter.
    /// File-manager resources are a separate namespace. A missing/unreadable
    /// path or native error status is an error, never a successful empty list.
    /// The engine interprets target paths; the SDK does no local filesystem I/O.
    pub async fn target_directories(&self, path: &TargetPath) -> Result<Vec<TargetDirectoryEntry>> {
        let value = self.auxiliary_path(path)?;
        let operation = "list target directories";
        self.system_status().await?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::GET,
                self.connection
                    .management_url("rest/system/getdir", &[("current", value), ("filter", "d")])?,
                None,
                false,
            )
            .await?;
        #[derive(Deserialize)]
        struct Listing {
            status: String,
            #[serde(default)]
            data: Option<Vec<TargetDirectoryEntry>>,
        }
        let invalid = || Error::InvalidResponse {
            operation,
            response: ResponseDiagnostic::new(status, bytes.clone()),
        };
        let listing: Listing = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if listing.status == "error" {
            return Err(Error::Api {
                operation,
                response: ResponseDiagnostic::new(status, bytes),
            });
        }
        if listing.status != "ok" {
            return Err(invalid());
        }
        listing.data.ok_or_else(invalid)
    }

    /// Explicitly create a native target directory and read the requested path
    /// back as a directory. Existing directories are accepted by the native
    /// handler. Existing files are not overwritten. This neither registers a
    /// sync folder nor opens an OS window. Native path canonicalization is
    /// retained in the result, without applying the controller's path rules.
    ///
    /// Identity is checked and one POST is sent under the mutation lock. There
    /// is no retry or rollback. Any uncertain receipt, native error or failed
    /// readback after the POST is an unknown outcome: inspect the target before
    /// retrying, since native directory creation can have partial effects.
    pub async fn create_target_directory(
        &self,
        path: &TargetPath,
    ) -> Result<TargetDirectoryCreation> {
        let value = self.auxiliary_path(path)?;
        let operation = "create target directory";
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::POST,
                self.connection.management_url("rest/system/adddir", &[])?,
                Some(&serde_json::json!({"path": value})),
                true,
            )
            .await?;
        #[derive(Deserialize)]
        struct Receipt {
            error: String,
            success: String,
            path: String,
            #[serde(flatten)]
            extra: BTreeMap<String, serde_json::Value>,
        }
        let invalid = || {
            mutation_error(
                operation,
                true,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes.clone()),
                },
            )
        };
        let receipt: Receipt = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
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
        if receipt.success.is_empty() {
            return Err(invalid());
        }
        let returned =
            TargetPath::remote(self.folder_path_style()?, receipt.path).map_err(|_| invalid())?;
        self.target_directories(path)
            .await
            .map_err(|e| mutation_error(operation, true, e))?;
        Ok(TargetDirectoryCreation {
            path: returned,
            native_message: receipt.success,
            extra: receipt.extra,
        })
    }
    fn auxiliary_path<'a>(&self, path: &'a TargetPath) -> Result<&'a str> {
        if path.style() != self.folder_path_style()? {
            return Err(Error::InvalidPath {
                reason: "path syntax differs from the connected engine",
            });
        }
        path.to_protocol()
    }
}
