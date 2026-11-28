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
    pub(crate) style: PathStyle,
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
    /// Read actual diagnostic settings, retaining fixed legacy usage information.
    pub fn diagnostics_options(&self) -> Result<crate::DiagnosticsOptions> {
        self.decode(&["options"])
    }
    /// Read event logging, thumbnail and proxy selections with target-side paths.
    pub fn system_preferences(&self) -> Result<crate::SystemPreferences> {
        let wire: crate::system_preferences::WireSystemPreferences = self.decode(&["options"])?;
        wire.into_public(self.style)
    }
    /// Edit explicit target selections without opening files or starting a proxy.
    pub fn set_system_preferences(&mut self, patch: &crate::SystemPreferencesPatch) -> Result<()> {
        self.merge(&["options"], &patch.body(self.style)?)
    }
    /// Edit only explicit native crash settings, without uploading or accepting terms.
    pub fn set_crash_reporting(&mut self, patch: &crate::CrashReportingPatch) -> Result<()> {
        patch.validate()?;
        self.merge(&["options"], patch)
    }
    /// Edit explicit discovery/listener options without establishing reachability.
    pub fn set_network_configuration(&mut self, patch: &crate::NetworkPatch) -> Result<()> {
        patch.validate()?;
        self.merge(&["options"], patch)
    }
    /// Edit explicit transport options without establishing NAT or peer effects.
    pub fn set_transport_configuration(&mut self, patch: &crate::TransportPatch) -> Result<()> {
        patch.validate()?;
        self.merge(&["options"], patch)
    }
    /// Edit only the selected GUI preferences, retaining credentials and listener.
    /// Saving this document can reload the native GUI handler.
    pub fn set_gui_preferences(&mut self, patch: &crate::GuiPreferencesPatch) -> Result<()> {
        patch.validate()?;
        self.merge(&["gui"], patch)
    }
    /// Edit explicit GUI listener selections using this snapshot's target syntax.
    /// A save can invalidate the current endpoint; prepare its replacement first.
    pub fn set_gui_listener(&mut self, patch: &crate::GuiListenerPatch) -> Result<()> {
        self.merge(&["gui"], &patch.body(self.style)?)
    }
    /// Select local GUI credentials in the document. Saving submits the password
    /// to native hashing; a stored password is not proof of a successful login.
    pub fn set_gui_credentials(&mut self, credentials: &crate::GuiCredentials) -> Result<()> {
        self.merge(
            &["gui"],
            &serde_json::json!({
                "user":credentials.username,"password":credentials.password,"authMode":"static"
            }),
        )
    }
    /// Select a known GUI authentication mode. LDAP configuration and actual
    /// login verification remain separate operations.
    pub fn set_gui_auth_mode(&mut self, mode: &crate::GuiAuthMode) -> Result<()> {
        if matches!(mode, crate::GuiAuthMode::Unknown(_)) {
            return Err(Error::InvalidConfiguration {
                reason: "unknown GUI authentication mode cannot be submitted",
            });
        }
        self.merge(&["gui"], &serde_json::json!({"authMode":mode}))
    }
    /// Select an explicit key with at least 20 ASCII bytes. Retain it before
    /// saving; existing clients keep their old key and do not reconnect implicitly.
    pub fn set_gui_api_key(&mut self, key: &crate::ApiKey) -> Result<()> {
        let header = key.header();
        if header.as_bytes().len() < 20 {
            return Err(Error::InvalidCredential {
                reason: "replacement API key must contain at least 20 ASCII bytes",
            });
        }
        let value = header.to_str().map_err(|_| Error::InvalidCredential {
            reason: "replacement key cannot be encoded",
        })?;
        self.merge(&["gui"], &serde_json::json!({"apiKey":value}))
    }
    /// Read the folder creation template, including possibly empty ID/path fields.
    pub fn folder_defaults(&self) -> Result<FolderDefaults> {
        self.decode(&["defaults", "folder"])
    }
    /// Read the global default-ignore template, separate from per-folder files.
    pub fn default_ignore_patterns(&self) -> Result<crate::IgnoreDefaults> {
        self.decode(&["defaults", "ignores"])
    }
    /// Edit only the ordered template lines, retaining unknown native values.
    /// Saving or parsing this template does not alter existing ignore files.
    pub fn set_default_ignore_patterns(&mut self, patterns: &crate::IgnorePatterns) -> Result<()> {
        self.default_ignore_patterns()?;
        self.merge(
            &["defaults", "ignores"],
            &serde_json::json!({"lines":patterns.patterns()}),
        )
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
        patch.validate()?;
        self.merge(&["options"], patch)
    }
    /// Edit future-folder defaults without changing existing registrations.
    pub fn set_folder_defaults(&mut self, patch: &FolderDefaultsPatch) -> Result<()> {
        patch.validate()?;
        self.merge(&["defaults", "folder"], patch)
    }
    /// Edit a future-folder versioning policy while retaining native location,
    /// inactive parameters and every unrelated complete-document field.
    pub fn set_folder_default_versioning(
        &mut self,
        policy: crate::FolderVersioningPolicy,
    ) -> Result<()> {
        policy.validate()?;
        let mut expected = self.folder_defaults()?.versioning_configuration()?;
        policy.apply(&mut expected)?;
        self.merge(
            &["defaults", "folder"],
            &serde_json::json!({"versioning":expected}),
        )
    }
    /// Edit only the future-folder basic archive location using target syntax.
    /// No archive migration or controller filesystem access is performed.
    pub fn set_folder_default_archive_location(
        &mut self,
        location: &crate::VersionArchiveLocation,
    ) -> Result<()> {
        let path = location.protocol(self.style)?;
        let mut expected = self.folder_defaults()?.versioning_configuration()?;
        expected.filesystem_path = path.into();
        expected.filesystem_type = "basic".into();
        self.merge(
            &["defaults", "folder"],
            &serde_json::json!({"versioning":expected}),
        )
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

/// Acknowledgement of one complete GUI PUT, without following a changed endpoint
/// or guessing replacement credentials. This does not establish stored readback,
/// listener state, GUI visibility or successful authentication.
#[derive(Debug)]
pub struct GuiConfigurationReplacement {
    /// Actual GUI configuration observed immediately before dispatch.
    pub previous_configuration: crate::GuiAuthenticationConfig,
    /// Native HTTP acknowledgement. Debug omits potentially private body values.
    pub acknowledgement: crate::ResponseDiagnostic,
}

/// Scope of one complete native configuration replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConfigurationScope {
    /// All sections, including untouched native fields.
    Complete,
    /// The complete options section.
    Options,
    /// The complete GUI section on the selected connection.
    Gui,
}

/// The request and separately observed document and application state.
#[derive(Debug)]
#[non_exhaustive]
pub struct ConfigurationSaveReport {
    /// Native scope selected by the caller.
    pub scope: ConfigurationScope,
    /// Dispatch and completion of the initial reply.
    pub write: crate::ManagementWriteEvidence,
    /// Original result. An empty value means the current scoped document
    /// already matched and no PUT was needed.
    pub original: Result<Option<crate::ResponseDiagnostic>>,
    /// Complete current authenticated snapshot when available.
    pub configuration: Option<ConfigurationSnapshot>,
    /// Whether the complete selected scope equals the requested document.
    pub scope_matches: Option<bool>,
    /// Independently reported application state, when readable.
    pub application_state: Option<super::ConfigurationSyncState>,
    /// Why the configuration could not safely be read after dispatch.
    pub observation_error: Option<Error>,
    /// Why the native application status could not be confirmed.
    pub application_error: Option<Error>,
}

impl ConfigurationSaveReport {
    /// Classify the configuration values. Inspect application state separately.
    pub fn completion(&self) -> crate::OperationCompletion {
        use crate::OperationCompletion as Completion;
        if self.write.response_complete
            && matches!(
                self.original,
                Err(Error::Authentication { .. } | Error::AccessDenied { .. })
            )
        {
            return Completion::GoalNotMet;
        }
        match self.scope_matches {
            Some(true) => Completion::Completed,
            Some(false) => Completion::GoalNotMet,
            None if !self.write.dispatched => Completion::GoalNotMet,
            None => Completion::Unconfirmed,
        }
    }
}
