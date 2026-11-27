//! Explicit endpoint-changing GUI writes without implicit endpoint discovery.

use std::{future::Future, io, time::Instant};

use super::{checked_response, send_bounded_with_status, Client};
use crate::control_operation::version_fingerprint;
use crate::{
    ControlOperationReceipt, ControlOperationResult, ControlSubmission, Error, GuiListenerConfig,
    GuiListenerPatch, GuiListenerUpdate, ManagementEndpoint, PreparedControlOperation,
    ResponseDiagnostic, Result,
};

const CHANGE_LISTENER: &str = "change native GUI listener";

impl Client {
    /// Read stored GUI listener settings after checking this connection's identity.
    /// This is configuration evidence, not a certificate, bind or reachability test.
    pub async fn gui_listener(&self) -> Result<GuiListenerConfig> {
        self.system_status().await?;
        GuiListenerConfig::from_auth(self.gui_authentication().await?, self.folder_path_style()?)
    }

    /// Submit one explicit GUI listener PATCH and retain the prior configuration.
    /// Address/protocol changes can interrupt this endpoint while the core keeps
    /// running. The stored enabled flag does not establish listener absence;
    /// v2.33.2 does not support live hot-disable and can restart its listener
    /// after accepting `enabled=false`. This is a stored configuration request.
    /// Prepare a new explicit connection and trust policy separately.
    /// No reconnect, rollback, write retry, certificate install or process stop
    /// follows. Transport uncertainty remains MutationOutcomeUnknown; reconcile
    /// through the intended endpoint rather than repeating the write blindly.
    pub async fn update_gui_listener(&self, patch: &GuiListenerPatch) -> Result<GuiListenerUpdate> {
        let body = patch.body(self.folder_path_style()?)?;
        let _guard = self.connection.mutation_lock.lock().await;
        let previous = self.gui_listener().await?;
        self.submit_gui_listener_patch(patch, &body, previous, &mut None)
            .await
    }

    /// Prepare a single-use listener change and its private intent receipt.
    ///
    /// Preparation is local. Execution checks the selected device again before
    /// sending. The bind setting is separate from any address used to reconnect.
    pub fn prepare_gui_listener_change(
        &self,
        patch: &GuiListenerPatch,
    ) -> Result<PreparedControlOperation> {
        let receipt = ControlOperationReceipt::for_gui_listener(
            self.instance.device_id.clone(),
            &self.instance.version.version,
            patch,
            self.folder_path_style()?,
        )?;
        Ok(PreparedControlOperation {
            endpoint: self.endpoint().clone(),
            receipt,
        })
    }

    /// Execute a prepared listener change once and return its original result.
    ///
    /// This mode keeps the receipt in memory. Choose the persisted method if a
    /// separate process must be able to resolve an interruption.
    pub async fn execute_gui_listener_change(
        &self,
        operation: PreparedControlOperation,
    ) -> ControlOperationResult<GuiListenerUpdate> {
        self.execute_gui_listener_change_persisted(operation, |_| std::future::ready(Ok(())))
            .await
    }

    /// Execute a prepared listener change with caller-owned asynchronous storage.
    ///
    /// The callback saves the intent first and then a conservative checkpoint
    /// before dispatch. An error saving either checkpoint prevents the PATCH.
    /// Save only to application-owned storage. The write lock remains held
    /// during the second callback, so the callback should avoid starting an
    /// operation on this client or any of its clones. The caller saves the
    /// returned receipt separately. If the application exits during dispatch,
    /// reopen the checkpoint and observe the selected target.
    pub async fn execute_gui_listener_change_persisted<Save, Saved>(
        &self,
        operation: PreparedControlOperation,
        mut save: Save,
    ) -> ControlOperationResult<GuiListenerUpdate>
    where
        Save: FnMut(ControlOperationReceipt) -> Saved,
        Saved: Future<Output = io::Result<()>>,
    {
        let started = Instant::now();
        let PreparedControlOperation {
            endpoint,
            mut receipt,
        } = operation;
        let mut response_status = None;
        let result = self
            .execute_gui_listener_inner(
                &endpoint,
                &mut receipt,
                &mut save,
                started,
                &mut response_status,
            )
            .await;
        let submission = match &result {
            Ok(update) => ControlSubmission::Acknowledged {
                status: update.acknowledgement.status(),
            },
            Err(_) if receipt.submission() == ControlSubmission::PossiblySubmitted => {
                ControlSubmission::PossiblySubmitted
            }
            Err(_) => ControlSubmission::NotSubmitted,
        };
        receipt.note_submission(submission, response_status, started.elapsed());
        ControlOperationResult { receipt, result }
    }

    async fn execute_gui_listener_inner<Save, Saved>(
        &self,
        endpoint: &ManagementEndpoint,
        receipt: &mut ControlOperationReceipt,
        save: &mut Save,
        started: Instant,
        response_status: &mut Option<u16>,
    ) -> Result<GuiListenerUpdate>
    where
        Save: FnMut(ControlOperationReceipt) -> Saved,
        Saved: Future<Output = io::Result<()>>,
    {
        if endpoint != self.endpoint() {
            return Err(Error::InvalidConfiguration {
                reason: "the prepared listener change belongs to a different management address",
            });
        }
        if receipt.target_device_id() != &self.instance.device_id {
            return Err(Error::IdentityMismatch {
                expected: receipt.target_device_id().clone(),
                actual: self.instance.device_id.clone(),
            });
        }
        if receipt.version_fingerprint() != &version_fingerprint(&self.instance.version.version) {
            return Err(Error::InvalidConfiguration {
                reason: "the prepared listener change belongs to a different engine version",
            });
        }
        let patch = receipt.gui_listener_patch()?;
        let body = patch.body(self.folder_path_style()?)?;
        save(receipt.clone()).await.map_err(save_error)?;

        let _guard = self.connection.mutation_lock.lock().await;
        let previous = self.gui_listener().await?;
        let mut checkpoint = receipt.clone();
        checkpoint.note_submission(
            ControlSubmission::PossiblySubmitted,
            None,
            started.elapsed(),
        );
        save(checkpoint).await.map_err(save_error)?;
        let live_version = self.version().await?;
        if receipt.version_fingerprint() != &version_fingerprint(&live_version.version) {
            return Err(Error::InvalidConfiguration {
                reason: "the engine version changed before the listener change was submitted",
            });
        }
        self.system_status().await?;

        receipt.note_submission(
            ControlSubmission::PossiblySubmitted,
            None,
            started.elapsed(),
        );
        self.submit_gui_listener_patch(&patch, &body, previous, response_status)
            .await
    }

    pub(super) async fn submit_gui_listener_patch(
        &self,
        patch: &GuiListenerPatch,
        body: &serde_json::Value,
        previous_configuration: GuiListenerConfig,
        response_status: &mut Option<u16>,
    ) -> Result<GuiListenerUpdate> {
        let request = self.connection.authorized_request(
            reqwest::Method::PATCH,
            self.connection.management_url("rest/config/gui", &[])?,
            Some(body),
        );
        let response = send_bounded_with_status(
            CHANGE_LISTENER,
            request,
            true,
            self.connection.response_limit,
        )
        .await;
        let response = match response {
            Ok(response) => response,
            Err(failure) => {
                *response_status = failure.status;
                return Err(failure.error);
            }
        };
        *response_status = Some(response.status);
        let response = checked_response(CHANGE_LISTENER, response, true)?;
        Ok(GuiListenerUpdate {
            previous_configuration,
            acknowledgement: ResponseDiagnostic::new(response.status, response.body),
            requested: patch.clone(),
        })
    }
}

fn save_error(source: io::Error) -> Error {
    Error::LocalIo {
        operation: "save private control operation checkpoint",
        source,
    }
}
