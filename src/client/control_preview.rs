//! Scoped settings previews and explicit, checked writes.

use std::collections::HashSet;
use std::fmt;
use std::time::Instant;

use serde::Deserialize;
use serde_json::Value;

use super::{Client, ConnectOptions, ControlIdentityObservation};
use crate::{
    ControlOperationReceipt, ControlSubmission, Error, FolderId, FolderPatch, GuiListenAddress,
    GuiListenerConfig, GuiListenerPatch, GuiSocketPermissions, ManagementEndpoint, Result,
};

/// A supported change to preview, without submitting it.
#[non_exhaustive]
pub enum SettingsChange<'a> {
    /// Set a folder label, pause flag, or both.
    Folder {
        /// The exact existing registration ID.
        id: &'a FolderId,
        /// The fields the caller wants to change.
        patch: &'a FolderPatch,
    },
    /// Change settings for the native management listener.
    GuiListener {
        /// The listener fields the caller wants to change.
        patch: &'a GuiListenerPatch,
    },
}

/// A resource addressed by one step of a settings preview.
#[non_exhaustive]
#[derive(Clone, Eq, PartialEq)]
pub enum SettingsTarget {
    /// One existing folder registration.
    Folder(FolderId),
    /// The selected device's management listener.
    GuiListener,
}

impl fmt::Debug for SettingsTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Folder(_) => formatter.write_str("Folder([REDACTED])"),
            Self::GuiListener => formatter.write_str("GuiListener"),
        }
    }
}

/// A setting selected by the caller for preview and readback.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingsField {
    /// Folder display label.
    FolderLabel,
    /// Folder-level pause flag.
    FolderPaused,
    /// Management listener's stored enable flag.
    ListenerEnabled,
    /// Native management bind address or Unix socket path.
    ListenerAddress,
    /// Management listener's stored TLS selection.
    ListenerTls,
    /// Management listener's Unix socket permission override.
    ListenerSocketPermissions,
}

/// A projected setting. Inspect values explicitly in a trusted interface.
/// Ordinary Debug conceals private text, paths and addresses.
#[non_exhaustive]
#[derive(Clone)]
pub enum SettingsValue {
    /// A folder label.
    Text(String),
    /// An enabled, paused or TLS flag.
    Flag(bool),
    /// A native listener bind setting.
    Address(GuiListenAddress),
    /// A native Unix socket permission setting.
    SocketPermissions(GuiSocketPermissions),
}

impl SettingsValue {
    fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Text(a), Self::Text(b)) => a == b,
            (Self::Flag(a), Self::Flag(b)) => a == b,
            (Self::Address(a), Self::Address(b)) => a.same_native(b),
            (Self::SocketPermissions(a), Self::SocketPermissions(b)) => a == b,
            _ => false,
        }
    }
}

impl fmt::Debug for SettingsValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(_) => formatter.write_str("Text([REDACTED])"),
            Self::Flag(flag) => formatter.debug_tuple("Flag").field(flag).finish(),
            Self::Address(address) => formatter.debug_tuple("Address").field(address).finish(),
            Self::SocketPermissions(mode) => formatter
                .debug_tuple("SocketPermissions")
                .field(mode)
                .finish(),
        }
    }
}

/// The observed and requested values for one field of a preview.
#[derive(Debug)]
pub struct SettingsFieldChange {
    /// The field whose value is compared.
    pub field: SettingsField,
    /// Its value when the preview was created.
    pub previous: SettingsValue,
    /// The value the selected change would send.
    pub requested: SettingsValue,
}

impl SettingsFieldChange {
    /// Whether the requested value differs from the observed value.
    pub fn is_change(&self) -> bool {
        !self.previous.matches(&self.requested)
    }
}

enum Intent {
    Folder {
        id: FolderId,
        body: Value,
    },
    GuiListener {
        patch: GuiListenerPatch,
        body: Value,
    },
}

/// One resource and the selected fields a preview would change.
pub struct SettingsStep {
    intent: Intent,
    fields: Vec<SettingsFieldChange>,
}

impl SettingsStep {
    /// The exact resource to which this step applies.
    pub fn target(&self) -> SettingsTarget {
        match &self.intent {
            Intent::Folder { id, .. } => SettingsTarget::Folder(id.clone()),
            Intent::GuiListener { .. } => SettingsTarget::GuiListener,
        }
    }

    /// The values of only the fields the caller selected.
    pub fn fields(&self) -> &[SettingsFieldChange] {
        &self.fields
    }

    /// Whether submitting this step can interrupt management access.
    pub fn may_interrupt_management(&self) -> bool {
        matches!(self.intent, Intent::GuiListener { .. })
    }
}

impl fmt::Debug for SettingsStep {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SettingsStep")
            .field("target", &self.target())
            .field("fields", &self.fields)
            .field("may_interrupt_management", &self.may_interrupt_management())
            .finish()
    }
}

/// An observed preview that can be consumed by an explicit commit.
/// The original endpoint is private and cannot be changed on this preview.
pub struct SettingsPreview {
    endpoint: ManagementEndpoint,
    identity: ControlIdentityObservation,
    steps: Vec<SettingsStep>,
}

impl SettingsPreview {
    /// The authenticated device and engine observed during the preview.
    pub fn identity(&self) -> &ControlIdentityObservation {
        &self.identity
    }

    /// The ordered resources and fields to inspect before deciding to commit.
    pub fn steps(&self) -> &[SettingsStep] {
        &self.steps
    }
}

impl fmt::Debug for SettingsPreview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SettingsPreview")
            .field("identity", &self.identity)
            .field("steps", &self.steps)
            .finish_non_exhaustive()
    }
}

/// The latest evidence for an individual requested field.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingsFieldState {
    /// No write was attempted for this field.
    NotExecuted,
    /// Its current value differed from the preview before submission.
    Conflict,
    /// The checked resource currently reports the requested value.
    Confirmed,
    /// The checked resource currently reports a different value.
    Different,
    /// A write was attempted and trustworthy readback is still unavailable.
    Unknown,
}

/// The current evidence for one field. Readback does not identify its author.
#[derive(Debug)]
pub struct SettingsFieldResult {
    /// The field that was selected.
    pub field: SettingsField,
    /// The outcome of comparing current evidence to the preview or request.
    pub state: SettingsFieldState,
    /// Its last trusted value if reported during conflict detection or readback.
    pub observed: Option<SettingsValue>,
}

/// Submission and readback evidence for one resource.
pub struct SettingsStepResult {
    /// The resource selected for this step.
    pub target: SettingsTarget,
    /// Evidence from the write itself, independent of later readback.
    pub submission: ControlSubmission,
    /// Results in the same field order as the preview.
    pub fields: Vec<SettingsFieldResult>,
    /// If attempted, the original listener receipt for independent readback.
    pub listener_receipt: Option<ControlOperationReceipt>,
    /// The original identity, precondition, write or read failure, if any.
    /// Inspect explicitly. Ordinary Debug reports only whether an error exists.
    pub error: Option<Error>,
    /// The time and verified device of the last successful readback.
    pub observation: Option<ControlIdentityObservation>,
}

impl SettingsStepResult {
    fn new(step: &SettingsStep) -> Self {
        Self {
            target: step.target(),
            submission: ControlSubmission::NotSubmitted,
            fields: step
                .fields
                .iter()
                .map(|field| SettingsFieldResult {
                    field: field.field,
                    state: SettingsFieldState::NotExecuted,
                    observed: None,
                })
                .collect(),
            listener_receipt: None,
            error: None,
            observation: None,
        }
    }

    fn mark_attempted(&mut self) {
        self.submission = ControlSubmission::PossiblySubmitted;
        for field in &mut self.fields {
            field.state = SettingsFieldState::Unknown;
        }
    }

    fn record_fields(
        &mut self,
        expected: impl IntoIterator<Item = (SettingsField, SettingsValue)>,
        snapshot: &Snapshot,
        before_write: bool,
    ) {
        for (field, value) in expected {
            let (Some(result), Some(observed)) = (
                self.fields.iter_mut().find(|result| result.field == field),
                snapshot.value(field),
            ) else {
                continue;
            };
            if before_write && !value.matches(&observed) {
                result.state = SettingsFieldState::Conflict;
                result.observed = Some(observed);
            } else if !before_write {
                result.state = if value.matches(&observed) {
                    SettingsFieldState::Confirmed
                } else {
                    SettingsFieldState::Different
                };
                result.observed = Some(observed);
            }
        }
    }

    /// Read the current listener using an explicit trusted connection supplied
    /// by the caller. Keep the original submission and error evidence. An
    /// unavailable or untrusted endpoint leaves the previous evidence intact.
    pub async fn observe_listener(&mut self, options: ConnectOptions) -> Result<()> {
        let receipt = self
            .listener_receipt
            .as_ref()
            .ok_or(Error::InvalidConfiguration {
                reason: "this step does not have a submitted listener change to observe",
            })?;
        let expected = gui_fields(&receipt.gui_listener_patch()?);
        let observed = receipt.observe_gui_listener(options).await?;
        self.record_fields(
            expected,
            &Snapshot::Gui(observed.current_configuration),
            false,
        );
        self.observation = Some(observed.identity);
        Ok(())
    }
}

impl fmt::Debug for SettingsStepResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SettingsStepResult")
            .field("target", &self.target)
            .field("submission", &self.submission)
            .field("fields", &self.fields)
            .field("listener_receipt", &self.listener_receipt)
            .field("has_error", &self.error.is_some())
            .field("observation", &self.observation)
            .finish()
    }
}

/// Outcomes in preview order, including steps that were never executed.
#[derive(Debug)]
pub struct SettingsCommit {
    /// One outcome per previewed resource.
    pub steps: Vec<SettingsStepResult>,
}

#[derive(Deserialize)]
struct SelectedFolder {
    id: FolderId,
    label: String,
    paused: bool,
}

enum Snapshot {
    Folder(SelectedFolder),
    Gui(GuiListenerConfig),
}

impl Snapshot {
    fn value(&self, field: SettingsField) -> Option<SettingsValue> {
        use SettingsField as Field;
        use SettingsValue as Setting;
        Some(match (self, field) {
            (Self::Folder(config), Field::FolderLabel) => Setting::Text(config.label.clone()),
            (Self::Folder(config), Field::FolderPaused) => Setting::Flag(config.paused),
            (Self::Gui(config), Field::ListenerEnabled) => Setting::Flag(config.enabled),
            (Self::Gui(config), Field::ListenerAddress) => Setting::Address(config.address.clone()),
            (Self::Gui(config), Field::ListenerTls) => Setting::Flag(config.use_tls),
            (Self::Gui(config), Field::ListenerSocketPermissions) => {
                Setting::SocketPermissions(config.unix_socket_permissions.clone())
            }
            _ => return None,
        })
    }
}

fn gui_fields(patch: &GuiListenerPatch) -> Vec<(SettingsField, SettingsValue)> {
    let mut fields = Vec::new();
    if let Some(enabled) = patch.enabled {
        fields.push((SettingsField::ListenerEnabled, SettingsValue::Flag(enabled)));
    }
    if let Some(address) = &patch.address {
        fields.push((
            SettingsField::ListenerAddress,
            SettingsValue::Address(address.clone()),
        ));
    }
    if let Some(use_tls) = patch.use_tls {
        fields.push((SettingsField::ListenerTls, SettingsValue::Flag(use_tls)));
    }
    if let Some(permissions) = &patch.permissions {
        fields.push((
            SettingsField::ListenerSocketPermissions,
            SettingsValue::SocketPermissions(permissions.clone()),
        ));
    }
    fields
}

impl Client {
    /// Read the targeted resources and show the selected fields without
    /// changing settings. Include each target once. Place a listener change
    /// last because it can interrupt the management address.
    pub async fn preview_settings_changes(
        &self,
        changes: &[SettingsChange<'_>],
    ) -> Result<SettingsPreview> {
        if changes.is_empty() {
            return Err(Error::InvalidConfiguration {
                reason: "select at least one setting to preview",
            });
        }
        let mut seen_folders = HashSet::new();
        let mut intents = Vec::with_capacity(changes.len());
        for (index, change) in changes.iter().enumerate() {
            let (intent, requested) = match change {
                SettingsChange::Folder { id, patch } => {
                    let id = *id;
                    if !seen_folders.insert(id) {
                        return Err(Error::InvalidConfiguration {
                            reason: "include each folder in the preview once",
                        });
                    }
                    if patch.is_empty() {
                        return Err(Error::InvalidConfiguration {
                            reason: "folder patch must contain at least one field",
                        });
                    }
                    self.connection.folder_url(id)?;
                    let body = Self::folder_patch_body(patch)?;
                    let mut requested = Vec::new();
                    if let Some(label) = &patch.label {
                        requested.push((
                            SettingsField::FolderLabel,
                            SettingsValue::Text(label.clone()),
                        ));
                    }
                    if let Some(paused) = patch.paused {
                        requested.push((SettingsField::FolderPaused, SettingsValue::Flag(paused)));
                    }
                    (
                        Intent::Folder {
                            id: id.clone(),
                            body,
                        },
                        requested,
                    )
                }
                SettingsChange::GuiListener { patch } => {
                    if index + 1 != changes.len() {
                        return Err(Error::InvalidConfiguration {
                            reason: "place the GUI listener change last in the preview",
                        });
                    }
                    let body = patch.body(self.folder_path_style()?)?;
                    (
                        Intent::GuiListener {
                            patch: (*patch).clone(),
                            body,
                        },
                        gui_fields(patch),
                    )
                }
            };
            intents.push((intent, requested));
        }

        self.observe_control_identity().await?;
        let mut steps = Vec::with_capacity(intents.len());
        for (intent, requested) in intents {
            let snapshot = self.read_settings_target(&intent).await?;
            let fields = requested
                .into_iter()
                .map(|(field, requested)| {
                    Ok(SettingsFieldChange {
                        field,
                        previous: snapshot.value(field).ok_or(Error::InvalidConfiguration {
                            reason: "the resource did not report the selected setting",
                        })?,
                        requested,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            steps.push(SettingsStep { intent, fields });
        }
        Ok(SettingsPreview {
            endpoint: self.endpoint().clone(),
            identity: self.observe_control_identity().await?,
            steps,
        })
    }

    /// Explicitly submit the preview. Before the first write, check the
    /// selected device, engine version and every selected value. A later
    /// step is checked again before it writes. Clones share one write lock.
    ///
    /// The native service has independent writers, and changes can still
    /// occur between the final read and PATCH. A failed or differing step
    /// stops the remaining steps. Previously submitted writes are retained.
    /// The listener step requires a separate `SettingsStepResult::observe_listener`
    /// call for readback at the caller's chosen trusted endpoint.
    pub async fn commit_settings_preview(&self, preview: SettingsPreview) -> SettingsCommit {
        let mut steps: Vec<_> = preview.steps.iter().map(SettingsStepResult::new).collect();
        let _guard = self.connection.mutation_lock.lock().await;
        if let Err(error) = self.check_preview_binding(&preview) {
            steps[0].error = Some(error);
            return SettingsCommit { steps };
        }

        if steps.len() > 1 {
            for (step, result) in preview.steps.iter().zip(&mut steps) {
                if let Err(error) = self.check_settings_step(step, result).await {
                    result.error = Some(error);
                    return SettingsCommit { steps };
                }
            }
        }
        for (step, result) in preview.steps.iter().zip(&mut steps) {
            if let Err(error) = self.commit_settings_step(step, result).await {
                result.error = Some(error);
                break;
            }
            if result
                .fields
                .iter()
                .any(|field| field.state == SettingsFieldState::Different)
            {
                break;
            }
        }
        SettingsCommit { steps }
    }

    fn check_preview_binding(&self, preview: &SettingsPreview) -> Result<()> {
        if preview.endpoint != *self.endpoint() {
            return Err(Error::InvalidConfiguration {
                reason: "the settings preview belongs to a different management address",
            });
        }
        if preview.identity.device_id() != &self.instance().device_id {
            return Err(Error::IdentityMismatch {
                expected: preview.identity.device_id().clone(),
                actual: self.instance().device_id.clone(),
            });
        }
        if preview.identity.engine_version().version != self.instance().version.version {
            return Err(Error::InvalidConfiguration {
                reason: "the settings preview belongs to a different engine version",
            });
        }
        Ok(())
    }

    async fn read_settings_target(&self, intent: &Intent) -> Result<Snapshot> {
        match intent {
            Intent::Folder { id, .. } => {
                let url = self.connection.folder_url(id)?;
                let (_, bytes) = self
                    .connection
                    .request_bytes(
                        "read selected folder settings",
                        reqwest::Method::GET,
                        url,
                        None,
                        false,
                    )
                    .await?;
                let selected: SelectedFolder =
                    serde_json::from_slice(&bytes).map_err(|_| Error::InvalidConfiguration {
                        reason: "the selected folder settings did not match their native schema",
                    })?;
                if selected.id != *id {
                    return Err(Error::InvalidConfiguration {
                        reason: "the management service returned a different folder than the selected folder",
                    });
                }
                Ok(Snapshot::Folder(selected))
            }
            Intent::GuiListener { .. } => self.gui_listener().await.map(Snapshot::Gui),
        }
    }

    async fn check_settings_step(
        &self,
        step: &SettingsStep,
        result: &mut SettingsStepResult,
    ) -> Result<Snapshot> {
        self.observe_control_identity().await?;
        let current = self.read_settings_target(&step.intent).await?;
        let identity = self.observe_control_identity().await?;
        result.record_fields(
            step.fields
                .iter()
                .map(|field| (field.field, field.previous.clone())),
            &current,
            true,
        );
        if result
            .fields
            .iter()
            .any(|field| field.state == SettingsFieldState::Conflict)
        {
            result.observation = Some(identity);
            return Err(Error::ConfigurationChanged);
        }
        Ok(current)
    }

    async fn commit_settings_step(
        &self,
        step: &SettingsStep,
        result: &mut SettingsStepResult,
    ) -> Result<()> {
        let current = self.check_settings_step(step, result).await?;
        match (&step.intent, current) {
            (Intent::Folder { id, body }, Snapshot::Folder(_)) => {
                let url = self.connection.folder_url(id)?;
                result.mark_attempted();
                let status = self.submit_folder_patch(url, body).await?;
                result.submission = ControlSubmission::Acknowledged { status };
                let (observed, identity) = self
                    .read_back_settings_folder(&step.intent)
                    .await
                    .map_err(|source| Error::MutationOutcomeUnknown {
                        operation: "read back updated folder",
                        source: Box::new(source),
                    })?;
                result.record_fields(
                    step.fields
                        .iter()
                        .map(|field| (field.field, field.requested.clone())),
                    &observed,
                    false,
                );
                result.observation = Some(identity);
                Ok(())
            }
            (Intent::GuiListener { patch, body }, Snapshot::Gui(previous)) => {
                let mut receipt = self.prepare_gui_listener_change(patch)?.receipt;
                let started = Instant::now();
                let mut response_status = None;
                result.mark_attempted();
                let update = self
                    .submit_gui_listener_patch(patch, body, previous, &mut response_status)
                    .await;
                if let Ok(update) = &update {
                    result.submission = ControlSubmission::Acknowledged {
                        status: update.acknowledgement.status(),
                    };
                }
                receipt.note_submission(result.submission, response_status, started.elapsed());
                result.listener_receipt = Some(receipt);
                update.map(|_| ())
            }
            _ => Err(Error::InvalidConfiguration {
                reason: "the selected settings target did not match its readback",
            }),
        }
    }

    async fn read_back_settings_folder(
        &self,
        intent: &Intent,
    ) -> Result<(Snapshot, ControlIdentityObservation)> {
        let observed = self.read_settings_target(intent).await?;
        let identity = self.observe_control_identity().await?;
        Ok((observed, identity))
    }
}
