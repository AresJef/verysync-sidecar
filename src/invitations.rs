//! Pending offers and explicit folder-to-peer association readbacks.
use crate::{DeviceId, FolderConfig, FolderId};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// A pending-device record. Nonempty VerySync native records require validation.
/// Unknown fields are retained; timestamps remain upstream strings.
#[derive(Clone, Deserialize)]
pub struct PendingDeviceInfo {
    /// Upstream observation timestamp, without local timezone conversion.
    pub time: String,
    /// Name supplied by the remote peer.
    pub name: String,
    /// Remote-reported address; not a reachability verdict.
    pub address: String,
    /// Unmodeled response fields; omitted from Debug.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for PendingDeviceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingDeviceInfo")
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// One actual remote folder offer, independent of local registration or access.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingFolderOffer {
    /// Exact upstream observation timestamp.
    pub time: String,
    /// Remote-supplied display label.
    pub label: String,
    /// Upstream-reported receive-encrypted condition; not inferred key permission.
    pub receive_encrypted: bool,
    /// Upstream-reported remote-encrypted condition.
    pub remote_encrypted: bool,
    /// Unmodeled response fields, hidden from ordinary formatting.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for PendingFolderOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingFolderOffer")
            .field("receive_encrypted", &self.receive_encrypted)
            .field("remote_encrypted", &self.remote_encrypted)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// The remote identities currently offering one exact folder ID.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingFolderOffers {
    /// Actual offering peers, keyed by their parsed identity.
    pub offered_by: BTreeMap<DeviceId, PendingFolderOffer>,
    /// Unmodeled fields for this pending folder, hidden from Debug.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for PendingFolderOffers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingFolderOffers")
            .field("offering_peer_count", &self.offered_by.len())
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// A persistent per-device ignored-folder entry from actual configuration.
#[derive(Clone, Deserialize, Serialize)]
pub struct IgnoredFolder {
    /// Exact remote offered folder ID.
    pub id: FolderId,
    /// Label retained when the offer was ignored.
    pub label: String,
    /// Upstream timestamp retained verbatim.
    pub time: String,
    /// Unknown configuration fields, preserved during changes and hidden in Debug.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for IgnoredFolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IgnoredFolder")
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// Readback after dismissing one pending record, without registering or ignoring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingDismissal {
    /// Whether the exact record is absent at readback; a new offer can race it.
    pub record_absent: bool,
}

/// One persistent ignored-device configuration record, independent of live state.
#[derive(Clone, Deserialize, Serialize)]
pub struct IgnoredDevice {
    /// Exact remote identity.
    #[serde(rename = "deviceID")]
    pub device_id: DeviceId,
    /// Optional upstream observation timestamp; absent is not an invented time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    /// Optional retained peer name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional retained address, not a reachability verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Unknown fields, preserved during changes and omitted from Debug.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for IgnoredDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IgnoredDevice")
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// Configuration readback after explicitly changing one ignored identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceIgnoreUpdate {
    /// Whether that exact identity is currently in the ignored-device list.
    /// This alone does not prove a live attempt was blocked.
    pub is_ignored: bool,
}

/// Current configuration and pending state following an explicit ignore change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IgnoredFolderUpdate {
    /// Whether the remote folder is in this peer's current ignored-folder list.
    pub is_ignored: bool,
    /// Whether this peer's exact offer is absent from the pending snapshot.
    pub pending_offer_absent: bool,
}

/// Readback after explicitly sharing or unsharing a local folder with a peer.
#[derive(Clone, Debug)]
pub struct FolderPeerUpdate {
    /// Actual current local folder configuration.
    pub configuration: FolderConfig,
    /// Whether this exact remote peer is present in its device associations.
    pub association_present: bool,
}

/// Credential-free readback after changing one folder association's encryption password.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FolderPeerEncryptionUpdate {
    /// Whether the actual native password is nonempty, or absent if omitted.
    pub password_is_set: Option<bool>,
    /// Whether the native field contains exactly the requested string.
    /// Clearing matches an explicit empty string in the native readback.
    pub requested_password_matches: bool,
}

/// Explicit goal for one folder-to-device association.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum FolderPeerChange<'a> {
    /// Associate the already configured device with the folder.
    Share,
    /// Remove this folder association while retaining both registrations.
    Unshare,
    /// Set a nonempty password, or clear the existing password with `None`.
    EncryptionPassword(Option<&'a str>),
}

impl std::fmt::Debug for FolderPeerChange<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Share => "Share",
            Self::Unshare => "Unshare",
            Self::EncryptionPassword(Some(_)) => "SetEncryptionPassword",
            Self::EncryptionPassword(None) => "ClearEncryptionPassword",
        })
    }
}

/// Original association reply and a credential-free readback.
#[derive(Debug)]
#[non_exhaustive]
pub struct FolderPeerWorkflowReport {
    /// Dispatch and reply facts for the optional PATCH.
    pub write: crate::ManagementWriteEvidence,
    /// Initial result. An empty value means no configuration change was needed.
    pub original: crate::Result<Option<crate::ResponseDiagnostic>>,
    /// Whether this device remains in the selected folder, when readable.
    pub association_present: Option<bool>,
    /// Whether the current association reports a password set.
    pub password_is_set: Option<bool>,
    /// Whether the scoped goal matches current readback.
    pub requested_state_matches: Option<bool>,
    /// Whether other associations match their preflight fields.
    pub other_peers_preserved: Option<bool>,
    /// Why the authenticated result could not be read.
    pub observation_error: Option<crate::Error>,
}

impl FolderPeerWorkflowReport {
    /// Classify configuration evidence. Peer traffic requires separate proof.
    pub fn completion(&self) -> crate::OperationCompletion {
        use crate::OperationCompletion as Completion;
        match (self.requested_state_matches, self.other_peers_preserved) {
            (Some(true), Some(true)) => Completion::Completed,
            (Some(true), _) => Completion::PartiallyCompleted,
            (Some(false), _) => Completion::GoalNotMet,
            _ if !self.write.dispatched
                || (self.write.response_complete
                    && matches!(
                        self.original,
                        Err(crate::Error::Authentication { .. } | crate::Error::AccessDenied { .. })
                    )) =>
            {
                Completion::GoalNotMet
            }
            _ => Completion::Unconfirmed,
        }
    }
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
pub(crate) struct FolderPeer {
    #[serde(rename = "deviceID")]
    pub(crate) device_id: DeviceId,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, serde_json::Value>,
}

/// The current status of a selected peer and folder at one receiving instance.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FolderIntroductionReport {
    /// Whether the chosen introducer is currently trusted.
    pub introducer_trusted: Option<bool>,
    /// Whether this instance is configured to retain withdrawn introductions.
    pub keep_withdrawn_introductions: Option<bool>,
    /// Whether the selected third device is currently registered.
    pub device_registered: bool,
    /// Whether the registration identifies the chosen introducer as its source.
    pub device_origin_matches: Option<bool>,
    /// Whether the selected folder currently includes the third device.
    pub folder_associated: bool,
    /// Actual connection state for the introducer, if the engine lists it.
    pub introducer_connected: Option<bool>,
    /// Actual connection state for the introduced peer, if the engine lists it.
    pub peer_connected: Option<bool>,
}

impl FolderIntroductionReport {
    /// Confirm trusted introduction and a current folder association.
    pub fn has_selected_introduction(&self) -> bool {
        self.introducer_trusted == Some(true)
            && self.device_registered
            && self.device_origin_matches == Some(true)
            && self.folder_associated
    }

    /// Check whether both the registration and association are absent now.
    /// Compare with a prior report to establish that they were removed.
    pub fn both_absent(&self) -> bool {
        !self.device_registered && !self.folder_associated
    }
}
