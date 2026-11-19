//! GUI preferences share the existing single-write reload reconciliation.
use super::Client;
use crate::{Error, GuiPreferences, GuiPreferencesPatch, GuiPreferencesUpdate, Result};
use std::time::Duration;
impl Client {
    /// Read actual preferences, without exposing GUI credentials through this DTO.
    pub async fn gui_preferences(&self) -> Result<GuiPreferences> {
        GuiPreferences::from_auth(&self.gui_authentication().await?)
    }
    /// Submit explicit GUI preferences once and freshly authenticate after reload.
    /// The total timeout covers clone-lock acquisition, identity, write and reads.
    /// Cancellation/unknown outcomes never replay or roll back the write. Listener,
    /// key, password and authentication mode are retained.
    pub async fn update_gui_preferences(
        &self,
        patch: &GuiPreferencesPatch,
        timeout: Duration,
    ) -> Result<GuiPreferencesUpdate> {
        patch.validate()?;
        let body = serde_json::to_value(patch).map_err(|_| Error::InvalidConfiguration {
            reason: "GUI preferences cannot be encoded",
        })?;
        let fields = body
            .as_object()
            .filter(|m| !m.is_empty())
            .ok_or(Error::InvalidConfiguration {
                reason: "GUI preference patch must contain at least one field",
            })?
            .clone();
        let (client, actual, write_acknowledged) = self
            .patch_gui_configuration(body, timeout, "update native GUI preferences")
            .await?;
        let requested_fields_match = fields.iter().all(|(k, v)| actual.extra.get(k) == Some(v));
        let configuration =
            GuiPreferences::from_auth(&actual).map_err(|source| Error::MutationOutcomeUnknown {
                operation: "read GUI preferences after update",
                source: Box::new(source),
            })?;
        Ok(GuiPreferencesUpdate {
            client,
            configuration,
            requested_fields_match,
            write_acknowledged,
        })
    }
}
