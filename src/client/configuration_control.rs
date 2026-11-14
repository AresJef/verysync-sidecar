//! Explicit configuration reads and writes on the authenticated connection.
use super::Client;
use crate::{
    ConfigurationSectionUpdate, ConfigurationSyncState, DeviceDefaults, DevicePatch, Error,
    FolderDefaults, FolderDefaultsPatch, Result,
};
use serde::{de::DeserializeOwned, Serialize};

impl Client {
    /// Read the complete native configuration after checking authenticated identity.
    /// Unknown values and target paths are retained; Debug omits private values.
    pub async fn configuration(&self) -> Result<crate::ConfigurationSnapshot> {
        self.system_status().await?;
        let document = self
            .connection
            .get_json("read full configuration", "rest/config")
            .await?;
        crate::ConfigurationSnapshot::from_native(
            self.instance.device_id.clone(),
            self.folder_path_style()?,
            document,
        )
    }

    /// PUT a complete, identity-bound snapshot after explicit typed edits.
    ///
    /// A fresh read must equal the original document; otherwise
    /// `ConfigurationChanged` is returned before PUT. This is not server-side
    /// compare-and-swap: independent writers must coordinate throughout the
    /// operation. Client clones serialize mutations. No write is retried and
    /// no restart, rollback, or credential change is performed implicitly.
    ///
    /// Matching readback and the native application flag are separate. Neither
    /// proves stable-storage durability. After cancellation or an unknown
    /// outcome, read a new configuration before considering another save.
    pub async fn replace_configuration(
        &self,
        desired: &crate::ConfigurationSnapshot,
    ) -> Result<crate::ConfigurationUpdate> {
        if desired.identity != self.instance.device_id {
            return Err(Error::IdentityMismatch {
                expected: self.instance.device_id.clone(),
                actual: desired.identity.clone(),
            });
        }
        let _guard = self.connection.mutation_lock.lock().await;
        let fresh = self.configuration().await?;
        if fresh.document != desired.original {
            return Err(Error::ConfigurationChanged);
        }
        let url = self.connection.management_url("rest/config", &[])?;
        self.connection
            .request_bytes(
                "replace full configuration",
                reqwest::Method::PUT,
                url,
                Some(&desired.document),
                true,
            )
            .await?;
        let configuration = self.configuration().await.map_err(full_save_unknown)?;
        let requested_fields_match = configuration.document == desired.document;
        let application_state = self
            .configuration_sync_state()
            .await
            .map_err(full_save_unknown)?;
        Ok(crate::ConfigurationUpdate {
            configuration,
            requested_fields_match,
            application_state,
        })
    }

    /// Read general options without changing settings or resource policy.
    pub async fn general_options(&self) -> Result<crate::GeneralOptions> {
        self.connection
            .get_json("read general options", "rest/config/options")
            .await
    }

    /// PATCH only explicit general options, then return the actual section.
    /// Readback does not prove scheduling, throughput or power-management effects.
    /// No mutation is retried or implicitly restarted.
    pub async fn update_general_options(
        &self,
        patch: &crate::GeneralOptionsPatch,
    ) -> Result<ConfigurationSectionUpdate<crate::GeneralOptions>> {
        patch.validate()?;
        self.patch_configuration_section("rest/config/options", patch)
            .await
    }

    /// Read the actual folder creation template without interpreting an empty path.
    pub async fn folder_defaults(&self) -> Result<FolderDefaults> {
        self.connection
            .get_json("read folder defaults", "rest/config/defaults/folder")
            .await
    }

    /// PATCH explicit template fields. Existing folders are not updated.
    ///
    /// Clones serialize writes and identity is rechecked. External writers must
    /// coordinate. No mutation is retried; after an unknown outcome or
    /// cancellation, read the template before considering another write.
    pub async fn update_folder_defaults(
        &self,
        patch: &FolderDefaultsPatch,
    ) -> Result<ConfigurationSectionUpdate<FolderDefaults>> {
        self.patch_configuration_section("rest/config/defaults/folder", patch)
            .await
    }

    /// PATCH explicit device template fields. Existing devices are not updated.
    /// The validation and unknown-outcome rules match `update_device`.
    pub async fn update_device_defaults(
        &self,
        patch: &DevicePatch,
    ) -> Result<ConfigurationSectionUpdate<DeviceDefaults>> {
        patch.validate(true)?;
        self.patch_configuration_section("rest/config/defaults/device", patch)
            .await
    }

    /// Read the native application flag. This does not save, restart or prove
    /// persistence. Use explicit owned-instance shutdown/restart when required.
    pub async fn configuration_sync_state(&self) -> Result<ConfigurationSyncState> {
        self.connection
            .get_json(
                "read configuration application state",
                "rest/system/config/insync",
            )
            .await
    }

    pub(super) async fn patch_configuration_section<T: DeserializeOwned>(
        &self,
        route: &'static str,
        patch: &impl Serialize,
    ) -> Result<ConfigurationSectionUpdate<T>> {
        let body = serde_json::to_value(patch).map_err(|_| Error::InvalidConfiguration {
            reason: "configuration section patch cannot be encoded",
        })?;
        let fields =
            body.as_object()
                .filter(|m| !m.is_empty())
                .ok_or(Error::InvalidConfiguration {
                    reason: "configuration section patch must contain at least one field",
                })?;
        let url = self.connection.management_url(route, &[])?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.connection
            .request_bytes(
                "update configuration section",
                reqwest::Method::PATCH,
                url,
                Some(&body),
                true,
            )
            .await?;
        let value: serde_json::Value = self
            .connection
            .get_json("read back configuration section", route)
            .await
            .map_err(section_unknown)?;
        let requested_fields_match = fields
            .iter()
            .all(|(key, expected)| value.get(key) == Some(expected));
        let configuration = serde_json::from_value(value).map_err(|_| {
            section_unknown(Error::InvalidConfiguration {
                reason: "configuration section readback does not match its required schema",
            })
        })?;
        Ok(ConfigurationSectionUpdate {
            configuration,
            requested_fields_match,
        })
    }
}

fn section_unknown(source: Error) -> Error {
    Error::MutationOutcomeUnknown {
        operation: "read back configuration section",
        source: Box::new(source),
    }
}

fn full_save_unknown(source: Error) -> Error {
    Error::MutationOutcomeUnknown {
        operation: "read back full configuration save",
        source: Box::new(source),
    }
}
