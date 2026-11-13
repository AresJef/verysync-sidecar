//! Explicit ignore-file reads, replacements and restoration of engine defaults.
use super::Client;
use crate::{
    Error, FolderId, IgnorePatterns, IgnoreSnapshot, IgnoreUpdate, ResponseDiagnostic, Result,
};

impl Client {
    /// Read current rules and parser diagnostics without changing the file.
    /// A malformed stored file is an observable snapshot with parse_error set.
    pub async fn ignore_patterns(&self, folder: &FolderId) -> Result<IgnoreSnapshot> {
        self.system_status().await?;
        self.folder(folder).await?;
        self.connection
            .get_json_with_query(
                "read folder ignore patterns",
                "rest/db/ignores",
                &[("folder", folder.as_str())],
            )
            .await
    }
    /// Replace exact ordered rules once. The engine may store invalid syntax
    /// while returning HTTP 200; this is IgnorePatternsRejected, never success.
    pub async fn set_ignore_patterns(
        &self,
        folder: &FolderId,
        patterns: &IgnorePatterns,
    ) -> Result<IgnoreUpdate> {
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.folder(folder).await?;
        self.change_ignore_file(
            folder,
            "rest/db/ignores",
            Some(&serde_json::json!({"ignore":patterns.patterns()})),
        )
        .await?;
        let snapshot =
            self.ignore_patterns(folder)
                .await
                .map_err(|source| Error::MutationOutcomeUnknown {
                    operation: "read back replaced ignore patterns",
                    source: Box::new(source),
                })?;
        reject_parse_error(snapshot).map(|snapshot| IgnoreUpdate {
            requested_patterns_match: snapshot.patterns.as_deref().unwrap_or_default()
                == patterns.patterns(),
            snapshot,
        })
    }
    /// Restore this engine's built-in default ignore list, rather than clearing
    /// it. The library does not embed or reconstruct the vendor's default text.
    pub async fn reset_ignore_patterns(&self, folder: &FolderId) -> Result<IgnoreSnapshot> {
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.folder(folder).await?;
        self.change_ignore_file(folder, "rest/db/resetIgnores", None)
            .await?;
        let snapshot =
            self.ignore_patterns(folder)
                .await
                .map_err(|source| Error::MutationOutcomeUnknown {
                    operation: "read back restored ignore defaults",
                    source: Box::new(source),
                })?;
        reject_parse_error(snapshot)
    }
    async fn change_ignore_file(
        &self,
        folder: &FolderId,
        route: &'static str,
        body: Option<&serde_json::Value>,
    ) -> Result<()> {
        let url = self
            .connection
            .management_url(route, &[("folder", folder.as_str())])?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                "change folder ignore patterns",
                reqwest::Method::POST,
                url,
                body,
                true,
            )
            .await?;
        let snapshot: IgnoreSnapshot =
            serde_json::from_slice(&bytes).map_err(|_| Error::MutationOutcomeUnknown {
                operation: "decode changed ignore patterns",
                source: Box::new(Error::InvalidResponse {
                    operation: "decode changed ignore patterns",
                    response: ResponseDiagnostic::new(status, bytes),
                }),
            })?;
        reject_parse_error(snapshot).map(|_| ())
    }
}
fn reject_parse_error(snapshot: IgnoreSnapshot) -> Result<IgnoreSnapshot> {
    if snapshot.parse_error.as_ref().is_some_and(|s| !s.is_empty()) {
        return Err(Error::IgnorePatternsRejected {
            snapshot: Box::new(snapshot),
        });
    }
    Ok(snapshot)
}
