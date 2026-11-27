//! Peer operations on the same authenticated, bounded management connection.
use super::{checked_response, send_bounded_reporting_headers, Client};
use crate::{
    CreateDeviceOptions, DeviceConfig, DeviceDefaults, DeviceId, DevicePatch, DeviceRemoval,
    DeviceUpdate, Error, FolderId, Result,
};
use serde::Deserialize;

impl Client {
    /// Read configured devices, including this instance's own identity.
    /// Configuration does not establish that any device is connected.
    pub async fn devices(&self) -> Result<Vec<DeviceConfig>> {
        #[derive(Deserialize)]
        struct Index {
            devices: Vec<DeviceConfig>,
        }
        let index: Index = self
            .connection
            .get_json("read configured devices", "rest/config")
            .await?;
        Ok(index.devices)
    }

    /// Find one exact configured identity, without discovery or peer probing.
    pub async fn device(&self, id: &DeviceId) -> Result<DeviceConfig> {
        self.devices()
            .await?
            .into_iter()
            .find(|device| device.device_id == *id)
            .ok_or_else(|| Error::DeviceNotFound { id: id.clone() })
    }

    /// Read the current upstream creation defaults without changing them.
    pub async fn device_defaults(&self) -> Result<DeviceDefaults> {
        self.connection
            .get_json("read device defaults", "rest/config/defaults/device")
            .await
    }

    /// Register a new remote identity from actual defaults and explicit settings.
    ///
    /// Existing IDs and the connected instance's own ID are rejected before POST.
    /// Clones serialize mutations and recheck authenticated identity. Upstream
    /// creation is an upsert, so independent writers must still coordinate.
    /// No write is retried; reconcile the exact ID after cancellation or an
    /// unknown outcome. Success/readback does not prove a peer connection.
    pub async fn create_device(&self, options: &CreateDeviceOptions) -> Result<DeviceUpdate> {
        options.patch.validate(false)?;
        self.require_remote_device(&options.id)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        if self
            .devices()
            .await?
            .iter()
            .any(|v| v.device_id == options.id)
        {
            return Err(Error::DeviceAlreadyExists {
                id: options.id.clone(),
            });
        }
        let defaults = self.device_defaults().await?;
        let mut body = serde_json::to_value(defaults).map_err(|_| Error::InvalidConfiguration {
            reason: "device defaults cannot be encoded",
        })?;
        body["deviceID"] = serde_json::json!(options.id.as_str());
        let patch = patch_json(&options.patch)?;
        body.as_object_mut()
            .ok_or(Error::InvalidConfiguration {
                reason: "device defaults must be an object",
            })?
            .extend(
                patch
                    .as_object()
                    .ok_or(Error::InvalidConfiguration {
                        reason: "device settings must be an object",
                    })?
                    .clone(),
            );
        self.connection
            .post_json("create device", "rest/config/devices", &body)
            .await?;
        let configuration = self
            .device(&options.id)
            .await
            .map_err(|source| uncertain("read back created device", source))?;
        options
            .patch
            .validate_advanced_readback(&configuration.extra)
            .map_err(|source| uncertain("read back created device", source))?;
        Ok(DeviceUpdate {
            requested_fields_match: options.patch.matches(&configuration),
            configuration,
        })
    }

    /// Patch only explicit remote-device fields and return actual configuration.
    ///
    /// This method rejects the local identity, an absent ID, an empty patch and
    /// unknown compression inputs. Runtime disconnect or reconnection follows
    /// configuration asynchronously and requires independent observation.
    pub async fn update_device(&self, id: &DeviceId, patch: &DevicePatch) -> Result<DeviceUpdate> {
        patch.validate(true)?;
        self.require_remote_device(id)?;
        let body = patch_json(patch)?;
        let url = self.device_url(id)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.device(id).await?;
        self.connection
            .request_bytes(
                "update device",
                reqwest::Method::PATCH,
                url,
                Some(&body),
                true,
            )
            .await?;
        let configuration = self
            .device(id)
            .await
            .map_err(|source| uncertain("read back updated device", source))?;
        patch
            .validate_advanced_readback(&configuration.extra)
            .map_err(|source| uncertain("read back updated device", source))?;
        Ok(DeviceUpdate {
            requested_fields_match: patch.matches(&configuration),
            configuration,
        })
    }

    /// Set this remote device's pause layer; inspect live connections separately.
    pub async fn pause_device(&self, id: &DeviceId) -> Result<DeviceUpdate> {
        self.update_device(id, &DevicePatch::default().paused(true))
            .await
    }

    /// Clear this remote device's pause layer. Other layers may still stop work.
    pub async fn resume_device(&self, id: &DeviceId) -> Result<DeviceUpdate> {
        self.update_device(id, &DevicePatch::default().paused(false))
            .await
    }

    /// Delete one exact remote configuration, with no file-deletion body or flag.
    ///
    /// The engine owns association changes. The result observes absence and any
    /// remaining folder references; the library never visits local data paths.
    /// Native key holders have been observed registering again after removal;
    /// this does not revoke folder keys or establish a durable rejection policy.
    /// Other writers can also change these snapshots. No modifying request is retried.
    pub async fn remove_device(&self, id: &DeviceId) -> Result<DeviceRemoval> {
        self.require_remote_device(id)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let previous_configuration = self.device(id).await?;
        self.delete_device_registration(id, previous_configuration)
            .await
    }

    /// Explicitly pause a peer, observe it disconnected, then delete its record.
    ///
    /// The one total positive deadline includes lock acquisition, authenticated
    /// observations and the single DELETE. A present native connection entry
    /// must report `connected=false`; absence is not fabricated as disconnection.
    /// Only this peer's pause field is patched. Local data is never accessed.
    ///
    /// The peer may register/connect again using still-valid shared keys after
    /// deletion. This operation is not a durable rejection or key revocation.
    /// Timeout, cancellation or failure can leave the peer paused or deleted;
    /// no modification is retried or rolled back. The returned previous
    /// configuration is the snapshot from before the explicit pause.
    pub async fn disconnect_and_remove_device(
        &self,
        id: &DeviceId,
        timeout: std::time::Duration,
    ) -> Result<DeviceRemoval> {
        self.require_remote_device(id)?;
        tokio::runtime::Handle::try_current().map_err(|_| Error::InvalidConfiguration {
            reason: "explicit device disconnect/removal requires Tokio",
        })?;
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .filter(|_| !timeout.is_zero())
            .ok_or(Error::InvalidConfiguration {
                reason: "device disconnect/removal deadline must be positive and representable",
            })?;
        let mut modified = false;
        let check_deadline = || {
            if tokio::time::Instant::now() >= deadline {
                Err(Error::Timeout {
                    operation: "disconnect and remove device",
                })
            } else {
                Ok(())
            }
        };
        let result = tokio::time::timeout_at(deadline, async {
            let _guard = self.connection.mutation_lock.lock().await;
            check_deadline()?;
            self.system_status().await?;
            let previous = self.device(id).await?;
            check_deadline()?;
            if !previous.paused {
                modified = true;
                self.submit_peer_pause(id, &mut None).await?;
                if !self.device(id).await?.paused {
                    return Err(Error::ManagedFailure {
                        reason: "peer pause was not observed before removal",
                    });
                }
            }
            loop {
                let snapshot = self.connections().await?;
                if snapshot
                    .connections
                    .get(id)
                    .is_some_and(|peer| !peer.connected)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            check_deadline()?;
            modified = true;
            self.delete_device_registration(id, previous).await
        })
        .await
        .unwrap_or(Err(Error::Timeout {
            operation: "disconnect and remove device",
        }));
        result.map_err(|error| {
            if modified && !matches!(&error, Error::MutationOutcomeUnknown { .. }) {
                uncertain("disconnect and remove device", error)
            } else {
                error
            }
        })
    }

    async fn delete_device_registration(
        &self,
        id: &DeviceId,
        previous_configuration: DeviceConfig,
    ) -> Result<DeviceRemoval> {
        self.submit_device_delete(id, &mut None).await?;
        let snapshot = self
            .device_registration_state(id)
            .await
            .map_err(|source| uncertain("read back removed device", source))?;
        Ok(snapshot.removal(previous_configuration))
    }

    pub(super) async fn submit_peer_pause(
        &self,
        id: &DeviceId,
        status: &mut Option<u16>,
    ) -> Result<u16> {
        self.send_device_mutation(
            "pause peer before explicit removal",
            reqwest::Method::PATCH,
            id,
            Some(&serde_json::json!({"paused":true})),
            status,
        )
        .await
    }

    pub(super) async fn submit_device_delete(
        &self,
        id: &DeviceId,
        status: &mut Option<u16>,
    ) -> Result<u16> {
        self.send_device_mutation("remove device", reqwest::Method::DELETE, id, None, status)
            .await
    }

    async fn send_device_mutation(
        &self,
        operation: &'static str,
        method: reqwest::Method,
        id: &DeviceId,
        body: Option<&serde_json::Value>,
        status: &mut Option<u16>,
    ) -> Result<u16> {
        let request = self
            .connection
            .authorized_request(method, self.device_url(id)?, body);
        let response = send_bounded_reporting_headers(
            operation,
            request,
            true,
            self.connection.response_limit,
            status,
        )
        .await?;
        Ok(checked_response(operation, response, true)?.status)
    }

    pub(super) async fn device_registration_state(
        &self,
        id: &DeviceId,
    ) -> Result<DeviceRegistrationState> {
        #[derive(Deserialize)]
        struct Snapshot {
            devices: Vec<DeviceConfig>,
            folders: Vec<Associations>,
        }
        #[derive(Deserialize)]
        struct Associations {
            id: FolderId,
            devices: Vec<Peer>,
        }
        #[derive(Deserialize)]
        struct Peer {
            #[serde(rename = "deviceID")]
            id: DeviceId,
        }
        let snapshot: Snapshot = self
            .connection
            .get_json("read device removal associations", "rest/config")
            .await?;
        let remaining_folder_associations = snapshot
            .folders
            .into_iter()
            .filter(|folder| folder.devices.iter().any(|peer| peer.id == *id))
            .map(|folder| folder.id)
            .collect();
        Ok(DeviceRegistrationState {
            configuration_absent: !snapshot.devices.iter().any(|v| v.device_id == *id),
            remaining_folder_associations,
        })
    }

    pub(super) fn require_remote_device(&self, id: &DeviceId) -> Result<()> {
        if *id == self.instance.device_id {
            Err(Error::LocalDeviceProtected)
        } else {
            Ok(())
        }
    }
    pub(super) fn device_url(&self, id: &DeviceId) -> Result<url::Url> {
        let mut url = self
            .connection
            .management_url("rest/config/devices/", &[])?;
        url.path_segments_mut()
            .map_err(|_| Error::InvalidEndpoint {
                reason: "management URL cannot contain device segments",
            })?
            .pop_if_empty()
            .push(id.as_str());
        Ok(url)
    }
}

pub(super) struct DeviceRegistrationState {
    pub(super) configuration_absent: bool,
    pub(super) remaining_folder_associations: Vec<FolderId>,
}

impl DeviceRegistrationState {
    pub(super) fn removal(self, previous_configuration: DeviceConfig) -> DeviceRemoval {
        DeviceRemoval {
            previous_configuration,
            configuration_absent: self.configuration_absent,
            remaining_folder_associations: self.remaining_folder_associations,
        }
    }
}

fn patch_json(patch: &DevicePatch) -> Result<serde_json::Value> {
    serde_json::to_value(patch).map_err(|_| Error::InvalidConfiguration {
        reason: "device settings cannot be encoded",
    })
}
pub(super) fn uncertain(operation: &'static str, source: Error) -> Error {
    Error::MutationOutcomeUnknown {
        operation,
        source: Box::new(source),
    }
}
