//! Identity-bound complete documents with explicit typed edits.
use super::{FolderDefaults, FolderDefaultsPatch, GeneralOptions, GeneralOptionsPatch};
use crate::{DeviceConfig, DeviceId, DevicePatch, Error, FolderConfig, PathStyle, Result};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::fmt;

/// Complete native configuration, retaining unknown fields and private values.
/// Obtain it through [`crate::Client::configuration`]. Typed edits retain the
/// original document for a stale-snapshot check. It cannot be deserialized from
/// arbitrary JSON or rebound to another instance. Debug omits document values.
#[derive(Clone)]
pub struct ConfigurationSnapshot {
    pub(crate) identity: DeviceId,
    style: PathStyle,
    version: u64,
    pub(crate) original: Value,
    pub(crate) document: Value,
}
impl ConfigurationSnapshot {
    pub(crate) fn from_native(
        identity: DeviceId,
        style: PathStyle,
        document: Value,
    ) -> Result<Self> {
        let version = document
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(shape)?;
        for section in ["gui", "ldap", "relayServer"] {
            if !document.get(section).is_some_and(Value::is_object) {
                return Err(shape());
            }
        }
        if !document
            .get("remoteIgnoredDevices")
            .is_some_and(Value::is_array)
        {
            return Err(shape());
        }
        let snapshot = Self {
            identity,
            style,
            version,
            original: document.clone(),
            document,
        };
        snapshot.general_options()?;
        snapshot.folder_defaults()?;
        snapshot.device_defaults()?;
        snapshot.folders()?;
        if !snapshot
            .devices()?
            .iter()
            .any(|d| d.device_id == snapshot.identity)
        {
            return Err(shape());
        }
        Ok(snapshot)
    }
    /// Native configuration format version, independent of program version.
    pub fn version(&self) -> u64 {
        self.version
    }
    /// Inspect all native values explicitly, including credentials. Review and
    /// redact them before logging or publishing. Target paths keep native syntax.
    pub fn native_document(&self) -> &Value {
        &self.document
    }
    /// Read general options in this snapshot, without another request.
    pub fn general_options(&self) -> Result<GeneralOptions> {
        self.decode(&["options"])
    }
    /// Read the folder creation template, including possibly empty ID/path fields.
    pub fn folder_defaults(&self) -> Result<FolderDefaults> {
        self.decode(&["defaults", "folder"])
    }
    /// Read the device creation template, independent of live peers.
    pub fn device_defaults(&self) -> Result<crate::DeviceDefaults> {
        self.decode(&["defaults", "device"])
    }
    /// Read configured devices, including this snapshot's local identity.
    pub fn devices(&self) -> Result<Vec<DeviceConfig>> {
        self.decode(&["devices"])
    }
    /// Read configured folders with the target's path syntax, without local I/O.
    pub fn folders(&self) -> Result<Vec<FolderConfig>> {
        let folders: Vec<crate::folders::WireFolder> = self.decode(&["folders"])?;
        folders
            .into_iter()
            .map(|folder| folder.into_config(self.style))
            .collect()
    }
    /// Edit explicit general fields while retaining every other native value.
    pub fn set_general_options(&mut self, patch: &GeneralOptionsPatch) -> Result<()> {
        self.merge(&["options"], patch)
    }
    /// Edit future-folder defaults without changing existing registrations.
    pub fn set_folder_defaults(&mut self, patch: &FolderDefaultsPatch) -> Result<()> {
        self.merge(&["defaults", "folder"], patch)
    }
    /// Edit future-device defaults; unknown enum inputs are rejected.
    pub fn set_device_defaults(&mut self, patch: &DevicePatch) -> Result<()> {
        patch.validate(true)?;
        self.merge(&["defaults", "device"], patch)
    }
    fn decode<T: DeserializeOwned>(&self, path: &[&str]) -> Result<T> {
        let value = path
            .iter()
            .try_fold(&self.document, |value, key| value.get(*key))
            .ok_or_else(shape)?;
        serde_json::from_value(value.clone()).map_err(|_| shape())
    }
    fn merge(&mut self, path: &[&str], patch: &impl Serialize) -> Result<()> {
        let patch = serde_json::to_value(patch).map_err(|_| shape())?;
        let fields =
            patch
                .as_object()
                .filter(|m| !m.is_empty())
                .ok_or(Error::InvalidConfiguration {
                    reason: "configuration patch must contain at least one field",
                })?;
        let mut section = &mut self.document;
        for key in path {
            section = section.get_mut(*key).ok_or_else(shape)?;
        }
        section
            .as_object_mut()
            .ok_or_else(shape)?
            .extend(fields.clone());
        Ok(())
    }
}
impl fmt::Debug for ConfigurationSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigurationSnapshot")
            .field("version", &self.version)
            .field("has_changes", &(self.original != self.document))
            .finish_non_exhaustive()
    }
}
fn shape() -> Error {
    Error::InvalidConfiguration {
        reason: "native configuration does not match the required complete schema",
    }
}

/// Actual readback and native application flag after an explicit complete PUT.
#[derive(Clone, Debug)]
pub struct ConfigurationUpdate {
    /// Newly observed full configuration, retaining unmodeled native values.
    pub configuration: ConfigurationSnapshot,
    /// Whether the entire submitted document equals this actual readback.
    pub requested_fields_match: bool,
    /// Independent native application status; not a stable-storage receipt.
    pub application_state: super::ConfigurationSyncState,
}
