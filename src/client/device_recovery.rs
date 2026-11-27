//! Durable device removal with separate read-only verification.
use std::{
    fmt,
    future::Future,
    io,
    time::{Duration, Instant},
};

use super::{
    control_identity::ReadOnlyControl, device_control::uncertain, Client, ConnectOptions,
    ControlIdentityObservation,
};
use crate::{
    ControlOperationReceipt, ControlOperationResult, ControlSubmission, DeviceId, DeviceRemoval,
    Error, FolderId, PreparedControlOperation, Result,
};

const EXPLICIT_REMOVAL: &str = "disconnect and remove device";

#[derive(Default)]
struct RemovalResponses {
    pause: Option<u16>,
    delete: Option<u16>,
}

/// Current registration state on the verified management device.
pub struct DeviceRemovalRecovery {
    /// Device identity and version observed when the read finished.
    pub identity: ControlIdentityObservation,
    /// Whether the exact remote ID was absent from the registration snapshot.
    pub configuration_absent: bool,
    /// Folder IDs still referring to the peer in that snapshot.
    pub remaining_folder_associations: Vec<FolderId>,
}

impl fmt::Debug for DeviceRemovalRecovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceRemovalRecovery")
            .field("identity", &self.identity)
            .field("configuration_absent", &self.configuration_absent)
            .field(
                "remaining_folder_count",
                &self.remaining_folder_associations.len(),
            )
            .finish_non_exhaustive()
    }
}

impl ControlOperationReceipt {
    /// Read the current registration and folder references on a trusted endpoint.
    ///
    /// Supply the endpoint and its credentials again. The original request
    /// status stays in the receipt. A peer with valid keys can register again.
    pub async fn observe_device_removal(
        &self,
        options: ConnectOptions,
    ) -> Result<DeviceRemovalRecovery> {
        let (peer, _) = self.device_removal_intent()?;
        let reader =
            ReadOnlyControl::connect(options, self.target_device_id(), self.version_fingerprint())
                .await?;
        let (identity, registration) = reader.device_registration(peer).await?;
        Ok(DeviceRemovalRecovery {
            identity,
            configuration_absent: registration.configuration_absent,
            remaining_folder_associations: registration.remaining_folder_associations,
        })
    }
}

impl Client {
    /// Prepare one removal of this exact remote registration, without sending a request.
    pub fn prepare_device_removal(&self, peer: &DeviceId) -> Result<PreparedControlOperation> {
        self.prepare_peer_removal(peer, None)
    }

    /// Prepare a removal that first observes a disconnected registration.
    ///
    /// A peer that is still configured to run may be paused once. The deadline
    /// covers the lock, caller-owned saves, reads and writes.
    pub fn prepare_device_disconnect_and_remove(
        &self,
        peer: &DeviceId,
        timeout: Duration,
    ) -> Result<PreparedControlOperation> {
        self.prepare_peer_removal(peer, Some(timeout))
    }

    fn prepare_peer_removal(
        &self,
        peer: &DeviceId,
        disconnect_timeout: Option<Duration>,
    ) -> Result<PreparedControlOperation> {
        let receipt = ControlOperationReceipt::for_device_removal(
            self.instance().device_id.clone(),
            &self.instance().version.version,
            peer.clone(),
            disconnect_timeout,
        )?;
        Ok(PreparedControlOperation {
            endpoint: self.endpoint().clone(),
            receipt,
        })
    }

    /// Execute a prepared removal and return its private in-memory receipt.
    pub async fn execute_device_removal(
        &self,
        operation: PreparedControlOperation,
    ) -> ControlOperationResult<DeviceRemoval> {
        self.execute_device_removal_persisted(operation, |_| std::future::ready(Ok(())))
            .await
    }

    /// Execute a prepared removal with a caller-owned durable checkpoint.
    ///
    /// Save the intent and then a conservative checkpoint before each write.
    /// An unsuccessful save prevents the next write. An earlier pause can
    /// still take effect. Save the returned receipt separately. The later
    /// saves hold the shared lock, so the callback must not start another
    /// mutation through this client or its clones.
    ///
    /// If the DELETE reply is lost, reopen the receipt and inspect the device
    /// before deciding whether any further action is needed.
    pub async fn execute_device_removal_persisted<Save, Saved>(
        &self,
        operation: PreparedControlOperation,
        mut save: Save,
    ) -> ControlOperationResult<DeviceRemoval>
    where
        Save: FnMut(ControlOperationReceipt) -> Saved,
        Saved: Future<Output = io::Result<()>>,
    {
        let started = Instant::now();
        let PreparedControlOperation {
            endpoint,
            mut receipt,
        } = operation;
        let staged = receipt
            .device_removal_intent()
            .is_ok_and(|(_, timeout)| timeout.is_some());
        let mut responses = RemovalResponses::default();
        let result = match self.require_prepared_control_target(&endpoint, &receipt) {
            Ok(()) => {
                self.run_device_removal(&mut receipt, &mut save, started, &mut responses)
                    .await
            }
            Err(error) => Err(error),
        };
        let delete = match receipt.submission() {
            ControlSubmission::Prepared => ControlSubmission::NotSubmitted,
            state => state,
        };
        receipt.note_submission(delete, responses.delete, started.elapsed());
        if let Some(mut progress) = receipt.device_removal_progress() {
            if progress.pause_request == Some(ControlSubmission::Prepared) {
                progress.pause_request = Some(ControlSubmission::NotSubmitted);
            }
            progress.pause_response_status = responses.pause;
            receipt.note_device_removal_progress(progress);
        }
        let pause_may_have_applied = receipt.device_removal_progress().is_some_and(|progress| {
            matches!(
                progress.pause_request,
                Some(ControlSubmission::PossiblySubmitted | ControlSubmission::Acknowledged { .. })
            )
        });
        let result = result.map_err(|error| {
            if staged
                && (delete != ControlSubmission::NotSubmitted || pause_may_have_applied)
                && !matches!(error, Error::MutationOutcomeUnknown { .. })
            {
                uncertain("complete device removal", error)
            } else {
                error
            }
        });
        ControlOperationResult { receipt, result }
    }

    async fn run_device_removal<Save, Saved>(
        &self,
        receipt: &mut ControlOperationReceipt,
        save: &mut Save,
        started: Instant,
        responses: &mut RemovalResponses,
    ) -> Result<DeviceRemoval>
    where
        Save: FnMut(ControlOperationReceipt) -> Saved,
        Saved: Future<Output = io::Result<()>>,
    {
        let (peer, timeout) = receipt.device_removal_intent()?;
        let peer = peer.clone();
        let deadline = timeout.map(removal_deadline).transpose()?;
        let run = async {
            save(receipt.clone()).await.map_err(save_error)?;
            let _guard = self.connection.mutation_lock.lock().await;
            require_removal_time(deadline)?;
            self.observe_control_identity().await?;
            let previous = self.device(&peer).await?;
            if let Some(deadline) = deadline {
                self.pause_for_recorded_removal(
                    &peer,
                    previous.paused,
                    receipt,
                    save,
                    deadline,
                    &mut responses.pause,
                )
                .await?;
            }

            let mut checkpoint = receipt.clone();
            checkpoint.note_submission(
                ControlSubmission::PossiblySubmitted,
                None,
                started.elapsed(),
            );
            save(checkpoint).await.map_err(save_error)?;
            self.observe_control_identity().await?;
            if deadline.is_some() && !self.peer_disconnected(&peer).await? {
                return Err(Error::ConfigurationChanged);
            }
            require_removal_time(deadline)?;
            receipt.note_submission(
                ControlSubmission::PossiblySubmitted,
                None,
                started.elapsed(),
            );
            let status = self
                .submit_device_delete(&peer, &mut responses.delete)
                .await?;
            receipt.note_submission(
                ControlSubmission::Acknowledged { status },
                responses.delete,
                started.elapsed(),
            );
            let readback = async {
                self.system_status().await?;
                let state = self.device_registration_state(&peer).await?;
                self.observe_control_identity().await?;
                Ok(state.removal(previous))
            };
            readback
                .await
                .map_err(|source| uncertain("read back removed device", source))
        };
        if let Some(deadline) = deadline {
            tokio::time::timeout_at(deadline, run)
                .await
                .unwrap_or_else(|_| Err(removal_timeout()))
        } else {
            run.await
        }
    }

    async fn pause_for_recorded_removal<Save, Saved>(
        &self,
        peer: &DeviceId,
        already_paused: bool,
        receipt: &mut ControlOperationReceipt,
        save: &mut Save,
        deadline: tokio::time::Instant,
        pause_status: &mut Option<u16>,
    ) -> Result<()>
    where
        Save: FnMut(ControlOperationReceipt) -> Saved,
        Saved: Future<Output = io::Result<()>>,
    {
        let mut progress =
            receipt
                .device_removal_progress()
                .ok_or(Error::InvalidConfiguration {
                    reason: "the operation receipt does not describe device removal",
                })?;
        if already_paused {
            progress.pause_request = None;
        } else {
            let mut checkpoint = receipt.clone();
            progress.pause_request = Some(ControlSubmission::PossiblySubmitted);
            checkpoint.note_device_removal_progress(progress);
            save(checkpoint).await.map_err(save_error)?;
            self.observe_control_identity().await?;
            require_removal_time(Some(deadline))?;
            receipt.note_device_removal_progress(progress);
            let status = self.submit_peer_pause(peer, pause_status).await?;
            progress.pause_request = Some(ControlSubmission::Acknowledged { status });
            progress.pause_response_status = *pause_status;
            receipt.note_device_removal_progress(progress);
            if !self.device(peer).await?.paused {
                return Err(Error::ManagedFailure {
                    reason: "peer pause was not observed before removal",
                });
            }
        }
        receipt.note_device_removal_progress(progress);
        loop {
            if self.peer_disconnected(peer).await? {
                progress.disconnection_observed = true;
                receipt.note_device_removal_progress(progress);
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn peer_disconnected(&self, peer: &DeviceId) -> Result<bool> {
        Ok(self
            .connections()
            .await?
            .connections
            .get(peer)
            .is_some_and(|entry| !entry.connected))
    }
}

fn removal_deadline(timeout: Duration) -> Result<tokio::time::Instant> {
    tokio::runtime::Handle::try_current().map_err(|_| Error::InvalidConfiguration {
        reason: "explicit device disconnect/removal requires Tokio",
    })?;
    tokio::time::Instant::now()
        .checked_add(timeout)
        .filter(|_| !timeout.is_zero())
        .ok_or(Error::InvalidConfiguration {
            reason: "device disconnect/removal deadline must be positive and representable",
        })
}

fn require_removal_time(deadline: Option<tokio::time::Instant>) -> Result<()> {
    if deadline.is_some_and(|entry| tokio::time::Instant::now() >= entry) {
        return Err(removal_timeout());
    }
    Ok(())
}

fn removal_timeout() -> Error {
    Error::Timeout {
        operation: EXPLICIT_REMOVAL,
    }
}

fn save_error(source: io::Error) -> Error {
    Error::LocalIo {
        operation: "save private control operation checkpoint",
        source,
    }
}
