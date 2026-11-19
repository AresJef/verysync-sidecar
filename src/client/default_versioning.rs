//! Default versioner selections, reusing native policies and archive paths.
use super::Client;
use crate::{
    Error, FolderVersioningConfiguration, FolderVersioningPolicy, FolderVersioningUpdate, Result,
    VersionArchiveLocation,
};

impl Client {
    /// Read the versioner inherited by future folders after checking identity.
    /// Existing folders and archived bytes are not changed.
    pub async fn folder_default_versioning(&self) -> Result<FolderVersioningConfiguration> {
        self.system_status().await?;
        self.read_default_versioning().await
    }
    async fn read_default_versioning(&self) -> Result<FolderVersioningConfiguration> {
        self.folder_defaults().await?.versioning_configuration()
    }
    /// Select a future-folder version policy, retaining archive location and
    /// unknown/inactive parameters. Existing folders remain independent. No
    /// cleanup, command, migration, restart, rollback or retry is run by the SDK.
    /// An external policy can execute its explicit command on future native archives.
    pub async fn set_folder_default_versioning(
        &self,
        policy: FolderVersioningPolicy,
    ) -> Result<FolderVersioningUpdate> {
        policy.validate()?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let mut expected = self.read_default_versioning().await?;
        policy.apply(&mut expected)?;
        self.write_default_versioning(expected).await
    }
    /// Select a target archive location inherited by future folders. Existing
    /// archives are not moved or deleted. The SDK does not open target paths.
    pub async fn set_folder_default_archive_location(
        &self,
        location: &VersionArchiveLocation,
    ) -> Result<FolderVersioningUpdate> {
        let path = location.protocol(self.folder_path_style()?)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let mut expected = self.read_default_versioning().await?;
        expected.filesystem_path = path.to_owned();
        expected.filesystem_type = "basic".into();
        self.write_default_versioning(expected).await
    }
    async fn write_default_versioning(
        &self,
        expected: FolderVersioningConfiguration,
    ) -> Result<FolderVersioningUpdate> {
        let url = self
            .connection
            .management_url("rest/config/defaults/folder", &[])?;
        self.connection
            .request_bytes(
                "update default versioning",
                reqwest::Method::PATCH,
                url,
                Some(&serde_json::json!({"versioning":expected})),
                true,
            )
            .await?;
        let configuration = self.read_default_versioning().await.map_err(|source| {
            Error::MutationOutcomeUnknown {
                operation: "read back default versioning",
                source: Box::new(source),
            }
        })?;
        Ok(FolderVersioningUpdate {
            requested_fields_match: configuration == expected,
            configuration,
        })
    }
}
