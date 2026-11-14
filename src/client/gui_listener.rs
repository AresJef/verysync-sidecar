//! Explicit endpoint-changing GUI writes without implicit endpoint discovery.
use super::Client;
use crate::{GuiListenerConfig, GuiListenerPatch, GuiListenerUpdate, ResponseDiagnostic, Result};
impl Client {
    /// Read stored GUI listener settings after checking this connection's identity.
    /// This is configuration evidence, not a certificate, bind or reachability test.
    pub async fn gui_listener(&self) -> Result<GuiListenerConfig> {
        self.system_status().await?;
        GuiListenerConfig::from_auth(self.gui_authentication().await?, self.folder_path_style()?)
    }
    /// Submit one explicit GUI listener PATCH and retain the prior configuration.
    /// This can close this endpoint or disable management while the core keeps
    /// running. Prepare a new explicit connection and trust policy separately.
    /// No reconnect, rollback, write retry, certificate install or process stop
    /// follows. Transport uncertainty remains MutationOutcomeUnknown; reconcile
    /// through the intended endpoint rather than repeating the write blindly.
    pub async fn update_gui_listener(&self, patch: &GuiListenerPatch) -> Result<GuiListenerUpdate> {
        let body = patch.body(self.folder_path_style()?)?;
        let _guard = self.connection.mutation_lock.lock().await;
        let previous_configuration = self.gui_listener().await?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                "change native GUI listener",
                reqwest::Method::PATCH,
                self.connection.management_url("rest/config/gui", &[])?,
                Some(&body),
                true,
            )
            .await?;
        Ok(GuiListenerUpdate {
            previous_configuration,
            acknowledgement: ResponseDiagnostic::new(status, bytes),
            requested: patch.clone(),
        })
    }
}
