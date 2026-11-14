//! Scoped advanced folder configuration, separate from filesystem effects.
use super::Client;
use crate::{
    ConfigurationSectionUpdate, Error, FolderAdvancedConfig, FolderAdvancedPatch, FolderId, Result,
};

impl Client {
    /// Read actual advanced selections after rechecking the authenticated identity.
    /// Missing fields remain absent; the SDK does not inspect local files.
    pub async fn folder_advanced_configuration(
        &self,
        folder: &FolderId,
    ) -> Result<FolderAdvancedConfig> {
        self.system_status().await?;
        self.folder(folder).await?.advanced_configuration()
    }

    /// PATCH explicit advanced settings for one existing folder, once.
    /// A matching readback establishes configuration only. Native changes may
    /// affect subsequent writes, deletes, metadata and durability. No restart,
    /// rollback, file operation or mutation retry is performed implicitly.
    pub async fn update_folder_advanced_configuration(
        &self,
        folder: &FolderId,
        patch: &FolderAdvancedPatch,
    ) -> Result<ConfigurationSectionUpdate<FolderAdvancedConfig>> {
        let body = patch.body()?;
        let url = self.connection.folder_url(folder)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.folder(folder).await?;
        self.connection
            .request_bytes(
                "update advanced folder configuration",
                reqwest::Method::PATCH,
                url,
                Some(&body),
                true,
            )
            .await?;
        let observed = async {
            let configuration = self.folder(folder).await?;
            let requested_fields_match = body.as_object().is_some_and(|fields| {
                fields
                    .iter()
                    .all(|(key, value)| configuration.extra.get(key) == Some(value))
            });
            Ok::<_, Error>(ConfigurationSectionUpdate {
                configuration: configuration.advanced_configuration()?,
                requested_fields_match,
            })
        }
        .await;
        observed.map_err(|source| Error::MutationOutcomeUnknown {
            operation: "read back advanced folder configuration",
            source: Box::new(source),
        })
    }
}
