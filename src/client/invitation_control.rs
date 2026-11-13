//! Explicit invitation records, per-peer ignores and folder associations.
use super::Client;
use crate::{
    DeviceId, Error, FolderId, FolderPeerUpdate, IgnoredFolder, IgnoredFolderUpdate,
    PendingDeviceInfo, PendingDismissal, PendingFolderOffers, ResponseDiagnostic, Result,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

impl Client {
    /// Read pending device records. An empty object is distinct from an API error.
    /// Nonempty VerySync records and their dismissal need separate native evidence.
    pub async fn pending_devices(&self) -> Result<BTreeMap<DeviceId, PendingDeviceInfo>> {
        self.connection
            .get_json("read pending devices", "rest/cluster/pending/devices")
            .await
    }

    /// Read actual offered folder IDs, optionally restricted to one offering peer.
    /// The returned remote folder ID is not assumed to equal a key's local ID.
    pub async fn pending_folders(
        &self,
        device: Option<&DeviceId>,
    ) -> Result<BTreeMap<FolderId, PendingFolderOffers>> {
        let query = device
            .map(|id| vec![("device", id.as_str())])
            .unwrap_or_default();
        self.connection
            .get_json_with_query(
                "read pending folder offers",
                "rest/cluster/pending/folders",
                &query,
            )
            .await
    }

    /// Dismiss one existing device record. This does not persist an ignore rule.
    /// No mutation is retried; a new remote attempt may create another record.
    pub async fn dismiss_pending_device(&self, device: &DeviceId) -> Result<PendingDismissal> {
        self.require_remote_device(device)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        if !self.pending_devices().await?.contains_key(device) {
            return Err(Error::PendingOfferNotFound);
        }
        let url = self.connection.management_url(
            "rest/cluster/pending/devices",
            &[("device", device.as_str())],
        )?;
        self.connection
            .request_bytes(
                "dismiss pending device",
                reqwest::Method::DELETE,
                url,
                None,
                true,
            )
            .await?;
        let records = self
            .pending_devices()
            .await
            .map_err(|e| uncertain("read back dismissed device", e))?;
        Ok(PendingDismissal {
            record_absent: !records.contains_key(device),
        })
    }

    /// Dismiss only one exact folder/peer offer, without ignoring future offers.
    /// No all-peers default is inferred and no local path or registration is changed.
    pub async fn dismiss_folder_offer(
        &self,
        folder: &FolderId,
        device: &DeviceId,
    ) -> Result<PendingDismissal> {
        self.require_remote_device(device)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.require_folder_offer(folder, device).await?;
        let url = self.connection.management_url(
            "rest/cluster/pending/folders",
            &[("folder", folder.as_str()), ("device", device.as_str())],
        )?;
        self.connection
            .request_bytes(
                "dismiss pending folder offer",
                reqwest::Method::DELETE,
                url,
                None,
                true,
            )
            .await?;
        let records = self
            .pending_folders(Some(device))
            .await
            .map_err(|e| uncertain("read back dismissed folder offer", e))?;
        Ok(PendingDismissal {
            record_absent: !has_offer(&records, folder, device),
        })
    }

    /// Read one peer's actual persistent ignored-folder configuration.
    pub async fn ignored_folders(&self, device: &DeviceId) -> Result<Vec<IgnoredFolder>> {
        #[derive(Deserialize)]
        struct Index {
            devices: Vec<Peer>,
        }
        #[derive(Deserialize)]
        struct Peer {
            #[serde(rename = "deviceID")]
            id: DeviceId,
            #[serde(rename = "ignoredFolders")]
            folders: Vec<IgnoredFolder>,
        }
        let index: Index = self
            .connection
            .get_json("read ignored folders", "rest/config")
            .await?;
        index
            .devices
            .into_iter()
            .find(|v| v.id == *device)
            .map(|v| v.folders)
            .ok_or_else(|| Error::DeviceNotFound { id: device.clone() })
    }

    /// Persistently ignore this peer's currently observed folder offer.
    /// Its actual label/time are retained; unrelated ignored entries are preserved.
    /// Configuration and pending readback are separate observations, not a transfer receipt.
    pub async fn ignore_folder_offer(
        &self,
        folder: &FolderId,
        device: &DeviceId,
    ) -> Result<IgnoredFolderUpdate> {
        self.require_remote_device(device)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let records = self.require_folder_offer(folder, device).await?;
        let offer = &records[folder].offered_by[device];
        let mut ignored = self.ignored_folders(device).await?;
        if !ignored.iter().any(|v| v.id == *folder) {
            ignored.push(IgnoredFolder {
                id: folder.clone(),
                label: offer.label.clone(),
                time: offer.time.clone(),
                extra: BTreeMap::new(),
            });
        }
        self.write_ignored_folders(folder, device, &ignored).await
    }

    /// Remove this exact peer's persistent folder ignore, preserving other entries.
    /// A subsequent remote announcement is required before an offer can reappear.
    pub async fn unignore_folder(
        &self,
        folder: &FolderId,
        device: &DeviceId,
    ) -> Result<IgnoredFolderUpdate> {
        self.require_remote_device(device)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let mut ignored = self.ignored_folders(device).await?;
        if !ignored.iter().any(|v| v.id == *folder) {
            return Err(Error::FolderNotIgnored);
        }
        ignored.retain(|v| v.id != *folder);
        self.write_ignored_folders(folder, device, &ignored).await
    }

    /// Associate an existing local folder with an existing remote device.
    ///
    /// This adds no sharing key or implicit trust, changes no role, and preserves
    /// existing per-peer fields. Join a caller-chosen validated key separately;
    /// a remote offer's ID alone is not authority to grant access to a group.
    pub async fn share_folder_with(
        &self,
        folder: &FolderId,
        device: &DeviceId,
    ) -> Result<FolderPeerUpdate> {
        self.change_folder_peer(folder, device, true).await
    }

    /// Remove only this folder-to-peer association. Keep both registrations/files.
    /// Actual disconnect or transfer cessation requires independent observation.
    pub async fn unshare_folder_from(
        &self,
        folder: &FolderId,
        device: &DeviceId,
    ) -> Result<FolderPeerUpdate> {
        self.change_folder_peer(folder, device, false).await
    }

    async fn require_folder_offer(
        &self,
        folder: &FolderId,
        device: &DeviceId,
    ) -> Result<BTreeMap<FolderId, PendingFolderOffers>> {
        let records = self.pending_folders(Some(device)).await?;
        if !has_offer(&records, folder, device) {
            return Err(Error::PendingOfferNotFound);
        }
        Ok(records)
    }
    async fn write_ignored_folders(
        &self,
        folder: &FolderId,
        device: &DeviceId,
        ignored: &[IgnoredFolder],
    ) -> Result<IgnoredFolderUpdate> {
        let url = self.device_url(device)?;
        let body = json!({"ignoredFolders":ignored});
        self.connection
            .request_bytes(
                "change ignored folder",
                reqwest::Method::PATCH,
                url,
                Some(&body),
                true,
            )
            .await?;
        let readback = self
            .ignored_folders(device)
            .await
            .map_err(|e| uncertain("read back ignored folders", e))?;
        let pending = self
            .pending_folders(Some(device))
            .await
            .map_err(|e| uncertain("read back ignored folder offers", e))?;
        Ok(IgnoredFolderUpdate {
            is_ignored: readback.iter().any(|v| v.id == *folder),
            pending_offer_absent: !has_offer(&pending, folder, device),
        })
    }
    async fn change_folder_peer(
        &self,
        folder: &FolderId,
        device: &DeviceId,
        present: bool,
    ) -> Result<FolderPeerUpdate> {
        self.require_remote_device(device)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.device(device).await?;
        let previous = self.folder(folder).await?;
        let mut peers = folder_peers(&previous)?;
        if present {
            if !peers.iter().any(|v| v.device_id == *device) {
                peers.push(crate::invitations::FolderPeer {
                    device_id: device.clone(),
                    extra: BTreeMap::new(),
                });
            }
        } else {
            peers.retain(|v| v.device_id != *device);
        }
        let url = self.connection.folder_url(folder)?;
        self.connection
            .request_bytes(
                "change folder peer association",
                reqwest::Method::PATCH,
                url,
                Some(&json!({"devices":peers})),
                true,
            )
            .await?;
        let configuration = self
            .folder(folder)
            .await
            .map_err(|e| uncertain("read back folder peer association", e))?;
        let observed = folder_peers(&configuration)
            .map_err(|e| uncertain("decode changed folder peer association", e))?;
        Ok(FolderPeerUpdate {
            association_present: observed.iter().any(|v| v.device_id == *device),
            configuration,
        })
    }
}
fn has_offer(
    records: &BTreeMap<FolderId, PendingFolderOffers>,
    folder: &FolderId,
    device: &DeviceId,
) -> bool {
    records
        .get(folder)
        .is_some_and(|v| v.offered_by.contains_key(device))
}
fn folder_peers(folder: &crate::FolderConfig) -> Result<Vec<crate::invitations::FolderPeer>> {
    let value = folder.extra.get("devices").cloned().unwrap_or(Value::Null);
    serde_json::from_value(value).map_err(|_| Error::InvalidResponse {
        operation: "decode configured folder peers",
        response: ResponseDiagnostic::new(200, Vec::new()),
    })
}
fn uncertain(operation: &'static str, source: Error) -> Error {
    Error::MutationOutcomeUnknown {
        operation,
        source: Box::new(source),
    }
}
