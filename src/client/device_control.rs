//! Peer operations on the same authenticated, bounded management connection.
use super::Client;
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
    /// Another writer can change these snapshots. No modifying request is retried.
    pub async fn remove_device(&self, id: &DeviceId) -> Result<DeviceRemoval> {
        self.require_remote_device(id)?;
        let url = self.device_url(id)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let previous_configuration = self.device(id).await?;
        self.connection
            .request_bytes("remove device", reqwest::Method::DELETE, url, None, true)
            .await?;
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
            .await
            .map_err(|source| uncertain("read back removed device", source))?;
        let remaining_folder_associations = snapshot
            .folders
            .into_iter()
            .filter(|folder| folder.devices.iter().any(|peer| peer.id == *id))
            .map(|folder| folder.id)
            .collect();
        Ok(DeviceRemoval {
            previous_configuration,
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
fn patch_json(patch: &DevicePatch) -> Result<serde_json::Value> {
    serde_json::to_value(patch).map_err(|_| Error::InvalidConfiguration {
        reason: "device settings cannot be encoded",
    })
}
fn uncertain(operation: &'static str, source: Error) -> Error {
    Error::MutationOutcomeUnknown {
        operation,
        source: Box::new(source),
    }
}
