//! Engine-generated sharing credentials, separate from management authentication.
use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde_json::Value;

use crate::{DeviceId, Error, FolderConfig, FolderId, ResponseDiagnostic, Result, TargetPath};

/// An opaque folder-sharing key, never a management API key.
#[derive(Clone, Eq, PartialEq)]
pub struct ShareKey(String);
impl ShareKey {
    /// Bound a credential without guessing its cryptographic format or permission.
    /// Actual validity is established by the selected engine's validation API.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 4096
            || value.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(Error::InvalidCredential {
                reason: "sharing key must be nonempty, bounded and free of whitespace/controls",
            });
        }
        Ok(Self(value))
    }
    /// Explicitly expose this sensitive credential, for storage or sharing.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for ShareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShareKey([REDACTED])")
    }
}

/// Permission reported by the engine, not inferred from a key prefix.
#[derive(Clone, Eq, PartialEq)]
pub enum SharePermission {
    /// Engine reported read/write permission.
    ReadWrite,
    /// Engine reported read-only permission.
    ReadOnly,
    /// Unrecognized permission; registration refuses to guess its meaning.
    Unknown(String),
}
impl fmt::Debug for SharePermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReadWrite => "ReadWrite",
            Self::ReadOnly => "ReadOnly",
            Self::Unknown(_) => "Unknown(..)",
        })
    }
}

/// A fresh engine-generated pair. Generation does not register a directory.
#[derive(Clone)]
pub struct GeneratedShare {
    /// Upstream suggested local registration ID, not a cross-node group ID.
    pub registration_id: FolderId,
    /// Read/write sharing credential.
    pub read_write_key: ShareKey,
    /// Read-only sharing credential.
    pub read_only_key: ShareKey,
    extra: BTreeMap<String, Value>,
}
impl GeneratedShare {
    /// Explicit access to unknown generation fields, which may contain secrets.
    pub fn extra(&self) -> &BTreeMap<String, Value> {
        &self.extra
    }
}
impl fmt::Debug for GeneratedShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedShare")
            .field("registration_id", &self.registration_id)
            .finish_non_exhaustive()
    }
}

/// A key validated by one authenticated target, including its proposed local ID.
/// Validation on another instance or another call may return a different ID.
#[derive(Clone)]
pub struct ValidatedShare {
    pub(crate) device_id: DeviceId,
    pub(crate) registration_id: FolderId,
    pub(crate) submitted_key: ShareKey,
    pub(crate) permission: SharePermission,
    pub(crate) read_only_key: ShareKey,
    pub(crate) read_write_key: Option<ShareKey>,
    extra: BTreeMap<String, Value>,
}
impl ValidatedShare {
    /// Identity of the engine that prepared this registration.
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }
    /// Engine-proposed local ID, retained for cancellation reconciliation.
    pub fn registration_id(&self) -> &FolderId {
        &self.registration_id
    }
    /// Permission actually reported by the validation response.
    pub fn permission(&self) -> &SharePermission {
        &self.permission
    }
    /// Submitted sensitive sharing credential.
    pub fn submitted_key(&self) -> &ShareKey {
        &self.submitted_key
    }
    /// Engine-reported read-only credential.
    pub fn read_only_key(&self) -> &ShareKey {
        &self.read_only_key
    }
    /// Engine-reported read/write credential, absent for read-only keys.
    pub fn read_write_key(&self) -> Option<&ShareKey> {
        self.read_write_key.as_ref()
    }
    /// Explicit access to unknown fields; these can contain credentials.
    pub fn extra(&self) -> &BTreeMap<String, Value> {
        &self.extra
    }
}
impl fmt::Debug for ValidatedShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedShare")
            .field("device_id", &self.device_id)
            .field("registration_id", &self.registration_id)
            .field("permission", &self.permission)
            .finish_non_exhaustive()
    }
}

/// Register a validated key at a target path, retaining the prepared local ID.
#[derive(Clone, Debug)]
pub struct JoinFolderOptions {
    pub(crate) share: ValidatedShare,
    pub(crate) path: TargetPath,
    pub(crate) label: Option<String>,
    pub(crate) paused: Option<bool>,
    pub(crate) allow_shared_path: bool,
}
impl JoinFolderOptions {
    /// Use preparation from this same engine; no caller-supplied shared ID.
    pub fn new(share: ValidatedShare, path: TargetPath) -> Self {
        Self {
            share,
            path,
            label: None,
            paused: None,
            allow_shared_path: false,
        }
    }
    /// Override the label while preserving other upstream defaults.
    pub fn label(mut self, value: impl Into<String>) -> Self {
        self.label = Some(value.into());
        self
    }
    /// Explicitly choose whether the newly registered folder starts paused.
    pub fn paused(mut self, value: bool) -> Self {
        self.paused = Some(value);
        self
    }
    /// Allow an identical configured path string; no alias/transaction guarantee.
    pub fn allow_shared_path(mut self, value: bool) -> Self {
        self.allow_shared_path = value;
        self
    }
    /// Exact proposed local ID for checking an uncertain modifying outcome.
    pub fn folder_id(&self) -> &FolderId {
        &self.share.registration_id
    }
}

/// Peer association has not been established by a configuration readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JoinPeerObservation {
    /// The registration result supplies no peer-connection or transfer verdict.
    Unobserved,
}

/// Actual local registration readback; not a peer acceptance/transfer receipt.
#[derive(Clone, Debug)]
pub struct JoinFolderResult {
    /// Fresh configuration for the prepared ID.
    pub configuration: FolderConfig,
    /// Permission reported during preparation.
    pub permission: SharePermission,
    /// Whether the submitted secret was retained in actual readback.
    pub submitted_key_matches: bool,
    /// Whether the engine readback retained the validated read-only material.
    pub read_only_key_matches: bool,
    /// Whether actual read/write material matches its expected presence/value.
    pub read_write_key_matches: bool,
    /// Configuration alone cannot establish remote peer association.
    pub peer_observation: JoinPeerObservation,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GeneratedWire {
    id: FolderId,
    read_only_secret: String,
    read_write_secret: String,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}
pub(crate) fn generated(status: u16, bytes: Vec<u8>) -> Result<GeneratedShare> {
    let wire: GeneratedWire = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("generate sharing keys", status, bytes.clone()))?;
    Ok(GeneratedShare {
        registration_id: wire.id,
        read_only_key: ShareKey::new(wire.read_only_secret)
            .map_err(|_| invalid("generate sharing keys", status, bytes.clone()))?,
        read_write_key: ShareKey::new(wire.read_write_secret)
            .map_err(|_| invalid("generate sharing keys", status, bytes))?,
        extra: wire.extra,
    })
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidationWire {
    validate: bool,
    id: Option<FolderId>,
    perm: Option<String>,
    read_only_secret: Option<String>,
    read_write_secret: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}
pub(crate) fn validated(
    device_id: DeviceId,
    key: ShareKey,
    status: u16,
    bytes: Vec<u8>,
) -> Result<ValidatedShare> {
    let wire: ValidationWire = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("validate sharing key", status, bytes.clone()))?;
    if !wire.validate {
        return Err(Error::ShareKeyRejected {
            response: ResponseDiagnostic::new(status, bytes),
        });
    }
    let registration_id = wire
        .id
        .ok_or_else(|| invalid("validate sharing key", status, bytes.clone()))?;
    let permission = match wire.perm.as_deref() {
        Some("rw") => SharePermission::ReadWrite,
        Some("ro") => SharePermission::ReadOnly,
        Some(other) => SharePermission::Unknown(other.to_owned()),
        None => return Err(invalid("validate sharing key", status, bytes)),
    };
    let read_only_key = ShareKey::new(
        wire.read_only_secret
            .ok_or_else(|| invalid("validate sharing key", status, bytes.clone()))?,
    )
    .map_err(|_| invalid("validate sharing key", status, bytes.clone()))?;
    let read_write_key = match wire.read_write_secret.filter(|s| !s.is_empty()) {
        Some(value) => Some(
            ShareKey::new(value)
                .map_err(|_| invalid("validate sharing key", status, bytes.clone()))?,
        ),
        None => None,
    };
    if (permission == SharePermission::ReadWrite && read_write_key.as_ref() != Some(&key))
        || (permission == SharePermission::ReadOnly
            && (read_only_key != key || read_write_key.is_some()))
    {
        return Err(invalid("validate sharing key", status, bytes));
    }
    Ok(ValidatedShare {
        device_id,
        registration_id,
        submitted_key: key,
        permission,
        read_only_key,
        read_write_key,
        extra: wire.extra,
    })
}
fn invalid(operation: &'static str, status: u16, bytes: Vec<u8>) -> Error {
    Error::InvalidResponse {
        operation,
        response: ResponseDiagnostic::new(status, bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const DEVICE: &str = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";

    #[test]
    fn share_keys_and_unknown_generation_values_are_retained_without_debug_disclosure() -> Result<()>
    {
        for key in ["", "two words", "secret\nvalue"] {
            assert!(ShareKey::new(key).is_err());
        }
        assert!(ShareKey::new("s".repeat(4097)).is_err());
        let source = json!({"id":"engine-local-id","readOnlySecret":"synthetic-ro-private","readWriteSecret":"synthetic-rw-private","future":"synthetic-future-private"});
        let share = generated(200, serde_json::to_vec(&source).unwrap())?;
        assert_eq!(share.extra()["future"], source["future"]);
        let debug = format!(
            "{share:?} {:?} {:?}",
            share.read_only_key, share.read_write_key
        );
        for secret in [
            "synthetic-ro-private",
            "synthetic-rw-private",
            "synthetic-future-private",
        ] {
            assert!(!debug.contains(secret));
        }
        Ok(())
    }

    #[test]
    fn inconsistent_validated_permissions_are_rejected_and_unknown_permissions_are_preserved(
    ) -> Result<()> {
        let key = ShareKey::new("synthetic-submitted-private")?;
        let id = DeviceId::parse(DEVICE)?;
        let mut response = json!({"validate":true,"id":"local-id","perm":"ro","readOnlySecret":key.expose_secret(),"readWriteSecret":"unexpected-write-private","future":"opaque-private"});
        assert!(matches!(
            validated(
                id.clone(),
                key.clone(),
                200,
                serde_json::to_vec(&response).unwrap()
            ),
            Err(Error::InvalidResponse { .. })
        ));
        response["readWriteSecret"] = json!("");
        response["perm"] = json!("future-permission-private");
        let share = validated(
            id.clone(),
            key.clone(),
            200,
            serde_json::to_vec(&response).unwrap(),
        )?;
        assert!(matches!(share.permission(), SharePermission::Unknown(_)));
        assert_eq!(share.extra()["future"], "opaque-private");
        for secret in [
            "future-permission-private",
            "synthetic-submitted-private",
            "opaque-private",
        ] {
            assert!(!format!("{share:?}").contains(secret));
        }
        response["perm"] = json!("rw");
        assert!(validated(id, key, 200, serde_json::to_vec(&response).unwrap()).is_err());
        Ok(())
    }
}
