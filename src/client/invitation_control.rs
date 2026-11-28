//! Explicit invitation records, per-peer ignores and folder associations.
use super::{workflow_write_result, Client};
use crate::invitations::FolderPeer;
use crate::{
    DeviceId, Error, FolderId, FolderPeerChange, FolderPeerEncryptionUpdate, FolderPeerUpdate,
    FolderPeerWorkflowReport, IgnoredFolder, IgnoredFolderUpdate, OperationOptions, OperationPhase,
    PendingDeviceInfo, PendingDismissal, PendingFolderOffers, ResponseDiagnostic, Result,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tokio::time::Instant;

impl Client {
    /// Change one existing folder's association with the exact selected peer.
    /// Read back that peer independently from the preserved associations.
    /// If the scoped state already matches, return without a PATCH.
    /// This reports configuration and leaves connection and data effects to
    /// the native engine. Coordinate other management writers.
    pub async fn change_folder_peer_and_verify(
        &self,
        folder: &FolderId,
        device: &DeviceId,
        change: FolderPeerChange<'_>,
        options: OperationOptions,
    ) -> Result<FolderPeerWorkflowReport> {
        const CHANGE: &str = "change the selected folder's peer association";
        const VERIFY: &str = "verify the selected folder's peer association";
        self.require_remote_device(device)?;
        if matches!(change, FolderPeerChange::EncryptionPassword(Some(""))) {
            return Err(Error::InvalidCredential {
                reason: "use the explicit clear option for an empty folder password",
            });
        }
        let url = self.connection.folder_url(folder)?;
        let context = options.start()?;
        let mut write = Default::default();
        let mut guard = None;
        let mut admission = None;
        let mut already = None;
        let result = context
            .wait(context.dispatch_deadline(), CHANGE, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                self.observe_control_identity().await?;
                let start =
                    self.system_status()
                        .await?
                        .start_time
                        .ok_or(Error::InvalidConfiguration {
                            reason: "the selected instance did not report its start time",
                        })?;
                self.device(device).await?;
                let current = self.folder(folder).await?;
                let mut peers = folder_peers(&current)?;
                let unchanged = other_associations(&peers, device)?;
                let facts = folder_peer_facts(&peers, device, change)?;
                self.check_folder_peer_generation(&start).await?;
                if facts.2 {
                    already = Some(facts);
                    return Ok(None);
                }
                match change {
                    FolderPeerChange::Share => peers.push(FolderPeer {
                        device_id: device.clone(),
                        extra: BTreeMap::new(),
                    }),
                    FolderPeerChange::Unshare => peers.retain(|peer| peer.device_id != *device),
                    FolderPeerChange::EncryptionPassword(password) => {
                        let index = folder_peer_index(&peers, device)?;
                        peers[index].extra.insert(
                            "encryptionPassword".into(),
                            Value::String(password.unwrap_or_default().into()),
                        );
                    }
                }
                if Instant::now() >= context.dispatch_deadline() {
                    return Err(Error::Timeout { operation: CHANGE });
                }
                admission = Some((start, current.path, unchanged));
                let body = json!({"devices":peers});
                let request =
                    self.connection
                        .authorized_request(reqwest::Method::PATCH, url, Some(&body));
                let reply = self
                    .connection
                    .send_workflow_write(CHANGE, request, &context, &mut write)
                    .await?;
                Ok(Some(ResponseDiagnostic::new(reply.status, reply.body)))
            })
            .await;
        let original = workflow_write_result(CHANGE, write, result);
        let refused = write.response_complete
            && matches!(
                original,
                Err(Error::Authentication { .. } | Error::AccessDenied { .. })
            );
        let mut report = FolderPeerWorkflowReport {
            write,
            original,
            association_present: already.map(|facts| facts.0),
            password_is_set: already.and_then(|facts| facts.1),
            requested_state_matches: already.map(|facts| facts.2),
            other_peers_preserved: already.map(|_| true),
            observation_error: None,
        };
        if let Some((start, path, expected)) = admission.filter(|_| write.dispatched && !refused) {
            context.phase(OperationPhase::Verifying);
            let observed = context
                .wait(context.deadline, VERIFY, async {
                    self.check_folder_peer_generation(&start).await?;
                    let current = self.folder(folder).await?;
                    if current.path != path {
                        return Err(Error::ConfigurationChanged);
                    }
                    let peers = folder_peers(&current)?;
                    let facts = folder_peer_facts(&peers, device, change)?;
                    let preserved = other_associations(&peers, device)? == expected;
                    self.check_folder_peer_generation(&start).await?;
                    Ok((facts, preserved))
                })
                .await;
            match observed {
                Ok(((associated, password, matched), preserved)) => {
                    report.association_present = Some(associated);
                    report.password_is_set = password;
                    report.requested_state_matches = Some(matched);
                    report.other_peers_preserved = Some(preserved);
                }
                Err(source) => report.observation_error = Some(source),
            }
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn check_folder_peer_generation(&self, expected: &str) -> Result<()> {
        if self.system_status().await?.start_time.as_deref() != Some(expected) {
            return Err(Error::ConfigurationChanged);
        }
        Ok(())
    }
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

    /// Read whether this exact folder association has an encryption password.
    ///
    /// An omitted native field remains absent. The password is used only to
    /// compute its presence and is never included in the returned value.
    pub async fn folder_peer_encryption_password_is_set(
        &self,
        folder: &FolderId,
        device: &DeviceId,
    ) -> Result<Option<bool>> {
        self.require_remote_device(device)?;
        self.system_status().await?;
        let peers = folder_peers(&self.folder(folder).await?)?;
        let peer = &peers[folder_peer_index(&peers, device)?];
        Ok(folder_peer_password(peer)?.map(|value| !value.is_empty()))
    }

    /// Set or clear the native encryption password for one existing folder association.
    ///
    /// Pass a nonempty password to set it, or `None` to clear it by sending the
    /// native empty value. The same association may be shared with other peers
    /// using different passwords. This call preserves all other peer fields,
    /// including unknown native fields, and submits one configuration PATCH.
    ///
    /// Clones of this client serialize edits. Independent configuration
    /// writers must coordinate with the caller. Keep the peer and directory
    /// paused while establishing an encrypted configuration. The receipt
    /// reports the native readback. Successful transfer and recovery require
    /// independent verification. After an uncertain outcome, read current
    /// configuration before considering another write.
    pub async fn set_folder_peer_encryption_password(
        &self,
        folder: &FolderId,
        device: &DeviceId,
        password: Option<&str>,
    ) -> Result<FolderPeerEncryptionUpdate> {
        self.require_remote_device(device)?;
        let requested = password.unwrap_or_default();
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.device(device).await?;
        let mut peers = folder_peers(&self.folder(folder).await?)?;
        let index = folder_peer_index(&peers, device)?;
        peers[index].extra.insert(
            "encryptionPassword".to_owned(),
            Value::String(requested.to_owned()),
        );
        self.write_folder_peers(folder, &peers, "set folder peer encryption password")
            .await?;

        let observed = async {
            let peers = folder_peers(&self.folder(folder).await?)?;
            let actual = folder_peer_password(&peers[folder_peer_index(&peers, device)?])?;
            Ok(FolderPeerEncryptionUpdate {
                password_is_set: actual.map(|value| !value.is_empty()),
                requested_password_matches: actual == Some(requested),
            })
        };
        observed
            .await
            .map_err(|error| uncertain("read back folder peer encryption password", error))
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
                peers.push(FolderPeer {
                    device_id: device.clone(),
                    extra: BTreeMap::new(),
                });
            }
        } else {
            peers.retain(|v| v.device_id != *device);
        }
        self.write_folder_peers(folder, &peers, "change folder peer association")
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

    async fn write_folder_peers(
        &self,
        folder: &FolderId,
        peers: &[FolderPeer],
        operation: &'static str,
    ) -> Result<()> {
        let url = self.connection.folder_url(folder)?;
        self.connection
            .request_bytes(
                operation,
                reqwest::Method::PATCH,
                url,
                Some(&json!({"devices":peers})),
                true,
            )
            .await
            .map(|_| ())
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
fn folder_peers(folder: &crate::FolderConfig) -> Result<Vec<FolderPeer>> {
    let value = folder.extra.get("devices").cloned().unwrap_or(Value::Null);
    serde_json::from_value(value).map_err(|_| Error::InvalidResponse {
        operation: "decode configured folder peers",
        response: ResponseDiagnostic::new(200, Vec::new()),
    })
}
fn folder_peer_index(peers: &[FolderPeer], device: &DeviceId) -> Result<usize> {
    let mut matches = peers
        .iter()
        .enumerate()
        .filter(|(_, peer)| peer.device_id == *device);
    let (index, _) = matches.next().ok_or(Error::FolderPeerNotAssociated)?;
    if matches.next().is_some() {
        return Err(Error::InvalidResponse {
            operation: "locate unique folder peer association",
            response: ResponseDiagnostic::new(200, Vec::new()),
        });
    }
    Ok(index)
}
fn folder_peer_password(peer: &FolderPeer) -> Result<Option<&str>> {
    peer.extra
        .get("encryptionPassword")
        .map(|value| {
            value.as_str().ok_or_else(|| Error::InvalidResponse {
                operation: "decode folder peer encryption password",
                response: ResponseDiagnostic::new(200, Vec::new()),
            })
        })
        .transpose()
}

fn folder_peer_facts(
    peers: &[FolderPeer],
    device: &DeviceId,
    change: FolderPeerChange<'_>,
) -> Result<(bool, Option<bool>, bool)> {
    let peer = match folder_peer_index(peers, device) {
        Ok(index) => Some(&peers[index]),
        Err(Error::FolderPeerNotAssociated) => None,
        Err(error) => return Err(error),
    };
    let password = peer.map(folder_peer_password).transpose()?.flatten();
    let matches = match change {
        FolderPeerChange::Share => peer.is_some(),
        FolderPeerChange::Unshare => peer.is_none(),
        FolderPeerChange::EncryptionPassword(value) => {
            peer.is_some() && password.unwrap_or_default() == value.unwrap_or_default()
        }
    };
    Ok((
        peer.is_some(),
        password.map(|value| !value.is_empty()),
        matches,
    ))
}

fn other_associations(
    peers: &[FolderPeer],
    selected: &DeviceId,
) -> Result<BTreeMap<DeviceId, FolderPeer>> {
    let mut others = BTreeMap::new();
    for peer in peers.iter().filter(|peer| peer.device_id != *selected) {
        if others
            .insert(peer.device_id.clone(), peer.clone())
            .is_some()
        {
            return Err(Error::InvalidResponse {
                operation: "verify unique folder peer associations",
                response: ResponseDiagnostic::new(200, Vec::new()),
            });
        }
    }
    Ok(others)
}
fn uncertain(operation: &'static str, source: Error) -> Error {
    Error::MutationOutcomeUnknown {
        operation,
        source: Box::new(source),
    }
}
