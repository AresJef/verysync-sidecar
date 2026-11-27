//! Read-only reconciliation with explicit per-call trust and credentials.

use super::{control_identity::ReadOnlyControl, ConnectOptions, ControlIdentityObservation};
use crate::{ControlOperationReceipt, GuiListenerConfig, Result};

/// An independently observed listener state for a private operation receipt.
#[derive(Debug)]
pub struct GuiListenerRecovery {
    /// Checked device, version, and observation time. Borrowed generation is unknown.
    pub identity: ControlIdentityObservation,
    /// Listener settings read through the caller's trusted management address.
    pub current_configuration: GuiListenerConfig,
    /// Whether the selected fields match. This does not identify their author.
    pub requested_fields_match: bool,
}

impl ControlOperationReceipt {
    /// Read the current listener on a caller-selected, trusted endpoint.
    ///
    /// Supply fresh credentials and verification settings. The receipt never
    /// supplies an endpoint or starts a process. A successful observation
    /// confirms the current fields, independent of the original submission.
    pub async fn observe_gui_listener(
        &self,
        options: ConnectOptions,
    ) -> Result<GuiListenerRecovery> {
        let patch = self.gui_listener_patch()?;
        let reader =
            ReadOnlyControl::connect(options, self.target_device_id(), self.version_fingerprint())
                .await?;
        let (identity, current_configuration) = reader.gui_listener().await?;
        Ok(GuiListenerRecovery {
            requested_fields_match: patch.matches(&current_configuration),
            identity,
            current_configuration,
        })
    }
}
