//! Fixed-version full-config PUT, preserving every unrelated field verbatim.
use super::Client;
use crate::{DeviceId, DeviceIgnoreUpdate, Error, IgnoredDevice, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Deserialize, Serialize)]
struct Configuration {
    devices: Vec<DeviceGuard>,
    #[serde(rename = "remoteIgnoredDevices")]
    ignored: Vec<IgnoredDevice>,
    #[serde(flatten)]
    other: BTreeMap<String, Value>,
}
#[derive(Deserialize, Serialize)]
struct DeviceGuard {
    #[serde(rename = "deviceID")]
    id: DeviceId,
    #[serde(flatten)]
    other: BTreeMap<String, Value>,
}
impl Client {
    /// Read persistent ignored-device records without inferring live rejection.
    pub async fn ignored_devices(&self) -> Result<Vec<IgnoredDevice>> {
        let config: Configuration = self
            .connection
            .get_json("read ignored devices", "rest/config")
            .await?;
        Ok(config.ignored)
    }

    /// Persistently ignore one unconfigured remote identity.
    ///
    /// The local identity is protected. An already configured peer must first
    /// be explicitly removed; this operation does not remove it or its folders.
    /// Baseline v2.33.2 requires a full configuration PUT. The library reads and
    /// preserves every other field, including credentials and unknown settings,
    /// under the shared clone mutation lock. Independent writers must coordinate:
    /// this is not an atomic field update against other clients.
    ///
    /// Metadata is left for the engine to supply rather than inventing a time.
    /// Readback alone is not proof that a connection attempt was blocked.
    pub async fn ignore_device(&self, device: &DeviceId) -> Result<DeviceIgnoreUpdate> {
        self.require_remote_device(device)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let mut config: Configuration = self
            .connection
            .get_json("read device ignore configuration", "rest/config")
            .await?;
        if config.devices.iter().any(|v| v.id == *device) {
            return Err(Error::ConfiguredDeviceCannotBeIgnored { id: device.clone() });
        }
        if config.ignored.iter().any(|v| v.device_id == *device) {
            return Ok(DeviceIgnoreUpdate { is_ignored: true });
        }
        config.ignored.push(IgnoredDevice {
            device_id: device.clone(),
            time: None,
            name: None,
            address: None,
            extra: BTreeMap::new(),
        });
        self.write_device_ignore_configuration(device, &config)
            .await
    }

    /// Remove only this exact ignored identity, preserving all other records.
    /// This does not register the peer, create a pending record, or connect it.
    /// It uses the same full-config preservation and external-writer contract.
    pub async fn unignore_device(&self, device: &DeviceId) -> Result<DeviceIgnoreUpdate> {
        self.require_remote_device(device)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let mut config: Configuration = self
            .connection
            .get_json("read device unignore configuration", "rest/config")
            .await?;
        if !config.ignored.iter().any(|v| v.device_id == *device) {
            return Err(Error::DeviceNotIgnored);
        }
        config.ignored.retain(|v| v.device_id != *device);
        self.write_device_ignore_configuration(device, &config)
            .await
    }

    async fn write_device_ignore_configuration(
        &self,
        device: &DeviceId,
        config: &Configuration,
    ) -> Result<DeviceIgnoreUpdate> {
        let body = serde_json::to_value(config).map_err(|_| Error::InvalidConfiguration {
            reason: "device ignore configuration cannot be encoded",
        })?;
        let url = self.connection.management_url("rest/config", &[])?;
        self.connection
            .request_bytes(
                "change ignored device",
                reqwest::Method::PUT,
                url,
                Some(&body),
                true,
            )
            .await?;
        let readback =
            self.ignored_devices()
                .await
                .map_err(|source| Error::MutationOutcomeUnknown {
                    operation: "read back ignored device",
                    source: Box::new(source),
                })?;
        Ok(DeviceIgnoreUpdate {
            is_ignored: readback.iter().any(|v| v.device_id == *device),
        })
    }
}
