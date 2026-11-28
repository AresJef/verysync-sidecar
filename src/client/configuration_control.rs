//! Explicit configuration reads and writes on the authenticated connection.
use super::{workflow_write_result, Client};
use crate::{
    ConfigurationSaveReport, ConfigurationScope, ConfigurationSectionUpdate, ConfigurationSnapshot,
    ConfigurationSyncState, DeviceDefaults, DevicePatch, Error, FolderDefaults,
    FolderDefaultsPatch, OperationOptions, OperationPhase, ResponseDiagnostic, Result,
};
use serde::{de::DeserializeOwned, Serialize};
use tokio::time::Instant;

const SAVE: &str = "save selected VerySync configuration";
const READ: &str = "verify the selected configuration values";

impl Client {
    /// Read the native `ping` marker through this authenticated connection.
    /// No retries or identity/status query are implicit. Inspect `is_pong()`;
    /// this marker alone does not establish current identity or sync health.
    pub async fn ping(&self) -> Result<crate::SystemPing> {
        self.connection
            .get_json("read management ping", "rest/system/ping")
            .await
    }

    /// Read the dedicated configured-folder collection without fetching the
    /// complete configuration document and its unrelated credentials.
    ///
    /// This returns the same folder model as `folders()`, with target-side path
    /// syntax and retained unknown fields. It opens no controller files, retries
    /// no request, and does not establish sync readiness or current identity.
    pub async fn folder_configurations(&self) -> Result<Vec<crate::FolderConfig>> {
        let style = self.folder_path_style()?;
        let folders: Vec<crate::folders::WireFolder> = self
            .connection
            .get_json(
                "read folder configuration collection",
                "rest/config/folders",
            )
            .await?;
        folders
            .into_iter()
            .map(|folder| folder.into_config(style))
            .collect()
    }

    /// Read event-log, thumbnail and proxy selections using target path syntax.
    pub async fn system_preferences(&self) -> Result<crate::SystemPreferences> {
        let wire: crate::system_preferences::WireSystemPreferences = self
            .connection
            .get_json("read system preferences", "rest/config/options")
            .await?;
        wire.into_public(self.folder_path_style()?)
    }
    /// PATCH explicit selections and read actual values. The official program may
    /// create event logs/cache data or use a proxy; this is not a connection/preview
    /// receipt. The SDK does not open target paths, retry or restart the core.
    pub async fn update_system_preferences(
        &self,
        patch: &crate::SystemPreferencesPatch,
    ) -> Result<ConfigurationSectionUpdate<crate::SystemPreferences>> {
        let style = self.folder_path_style()?;
        let body = patch.body(style)?;
        let update: ConfigurationSectionUpdate<crate::system_preferences::WireSystemPreferences> =
            self.patch_configuration_section("rest/config/options", &body)
                .await?;
        let configuration = update
            .configuration
            .into_public(style)
            .map_err(section_unknown)?;
        Ok(ConfigurationSectionUpdate {
            configuration,
            requested_fields_match: update.requested_fields_match,
        })
    }

    /// Read native diagnostic preferences. Fixed legacy usage values do not
    /// establish consent, mutability or actual report transmission.
    pub async fn diagnostics_options(&self) -> Result<crate::DiagnosticsOptions> {
        self.connection
            .get_json("read diagnostic options", "rest/config/options")
            .await
    }

    /// PATCH only explicit crash-report settings and return actual readback.
    /// Does not crash, upload, retry, restart or accept terms. Enabling can affect
    /// future native network activity; URL validation does not authenticate a collector.
    pub async fn update_crash_reporting(
        &self,
        patch: &crate::CrashReportingPatch,
    ) -> Result<ConfigurationSectionUpdate<crate::DiagnosticsOptions>> {
        patch.validate()?;
        self.patch_configuration_section("rest/config/options", patch)
            .await
    }

    /// Read the complete native configuration after checking authenticated identity.
    /// Unknown values and target paths are retained; Debug omits private values.
    pub async fn configuration(&self) -> Result<crate::ConfigurationSnapshot> {
        self.system_status().await?;
        let document = self
            .connection
            .get_json("read full configuration", "rest/config")
            .await?;
        crate::ConfigurationSnapshot::from_native(
            self.instance.device_id.clone(),
            self.folder_path_style()?,
            document,
        )
    }

    /// Save one reviewed full configuration or complete section, with one
    /// deadline for checking, dispatch and readback. When fresh values already
    /// match the selected scope, return without a write. A changed stale scope
    /// refuses dispatch. Independent writers must coordinate because the
    /// native PUT does not conditionally apply the previous document.
    ///
    /// The client only reads the original trusted connection afterward.
    /// Listener or credential changes can make readback unavailable. Use
    /// the dedicated listener or API-key workflow when switching credentials
    /// or management addresses.
    pub async fn save_configuration_and_verify(
        &self,
        desired: &ConfigurationSnapshot,
        scope: ConfigurationScope,
        options: OperationOptions,
    ) -> Result<ConfigurationSaveReport> {
        self.require_snapshot_scope(desired)?;
        let context = options.start()?;
        let body = scoped_document(scope, &desired.document)?;
        let original_document = scoped_document(scope, &desired.original)?;
        if scope == ConfigurationScope::Gui
            && serde_json::from_value::<crate::GuiAuthenticationConfig>(body.clone()).is_err()
        {
            return Err(Error::InvalidConfiguration {
                reason: "complete GUI section does not match the required native schema",
            });
        }
        let route = match scope {
            ConfigurationScope::Complete => "rest/config",
            ConfigurationScope::Options => "rest/config/options",
            ConfigurationScope::Gui => "rest/config/gui",
        };
        let url = self.connection.management_url(route, &[])?;
        let mut write = Default::default();
        let mut guard = None;
        let mut original_generation = None;
        let mut configuration = None;
        let result =
            context
                .wait(context.dispatch_deadline(), SAVE, async {
                    context.phase(OperationPhase::Checking);
                    guard = Some(self.connection.mutation_lock.lock().await);
                    self.observe_control_identity().await?;
                    let generation = self.system_status().await?.start_time.ok_or(
                        Error::InvalidConfiguration {
                            reason: "the selected instance did not report its start time",
                        },
                    )?;
                    let fresh = self.configuration().await?;
                    let observed = scoped_document(scope, &fresh.document)?;
                    self.require_configuration_generation(&generation).await?;
                    if observed == body {
                        configuration = Some(fresh);
                        original_generation = Some(generation);
                        return Ok(None);
                    }
                    if observed != original_document {
                        return Err(Error::ConfigurationChanged);
                    }
                    if Instant::now() >= context.dispatch_deadline() {
                        return Err(Error::Timeout { operation: SAVE });
                    }
                    original_generation = Some(generation);
                    let request =
                        self.connection
                            .authorized_request(reqwest::Method::PUT, url, Some(body));
                    let response = self
                        .connection
                        .send_workflow_write(SAVE, request, &context, &mut write)
                        .await?;
                    Ok(Some(ResponseDiagnostic::new(
                        response.status,
                        response.body,
                    )))
                })
                .await;
        let original = workflow_write_result(SAVE, write, result);
        let refused = write.response_complete
            && matches!(
                original,
                Err(Error::Authentication { .. } | Error::AccessDenied { .. })
            );
        let mut report = ConfigurationSaveReport {
            scope,
            scope_matches: configuration.as_ref().map(|_| true),
            write,
            original,
            configuration,
            application_state: None,
            observation_error: None,
            application_error: None,
        };
        if let Some(generation) = original_generation.filter(|_| !refused) {
            context.phase(OperationPhase::Verifying);
            if write.dispatched {
                let observed = context
                    .wait(context.deadline, READ, async {
                        self.require_configuration_generation(&generation).await?;
                        let current = self.configuration().await?;
                        self.require_configuration_generation(&generation).await?;
                        let matches = scoped_document(scope, &current.document)? == body;
                        Ok((current, matches))
                    })
                    .await;
                match observed {
                    Ok((current, matches)) => {
                        report.configuration = Some(current);
                        report.scope_matches = Some(matches);
                    }
                    Err(error) => report.observation_error = Some(error),
                }
            }
            // Observe application status only for a verified current document.
            if report.configuration.is_some() {
                let application = context
                    .wait(
                        context.deadline,
                        "read the selected instance's configuration application state",
                        async {
                            let state = self.configuration_sync_state().await?;
                            self.require_configuration_generation(&generation).await?;
                            Ok(state)
                        },
                    )
                    .await;
                match application {
                    Ok(state) => report.application_state = Some(state),
                    Err(error) => report.application_error = Some(error),
                }
            }
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn require_configuration_generation(&self, generation: &str) -> Result<()> {
        if self.system_status().await?.start_time.as_deref() != Some(generation) {
            return Err(Error::ConfigurationChanged);
        }
        Ok(())
    }

    /// PUT a complete, identity-bound snapshot after explicit typed edits.
    ///
    /// A fresh read must equal the original document; otherwise
    /// `ConfigurationChanged` is returned before PUT. This is not server-side
    /// compare-and-swap: independent writers must coordinate throughout the
    /// operation. Client clones serialize mutations. No write is retried and
    /// no restart, rollback, or credential change is performed implicitly.
    ///
    /// Matching readback and the native application flag are separate. Neither
    /// proves stable-storage durability. After cancellation or an unknown
    /// outcome, read a new configuration before considering another save.
    pub async fn replace_configuration(
        &self,
        desired: &crate::ConfigurationSnapshot,
    ) -> Result<crate::ConfigurationUpdate> {
        self.require_snapshot_scope(desired)?;
        let _guard = self.connection.mutation_lock.lock().await;
        let fresh = self.configuration().await?;
        if fresh.document != desired.original {
            return Err(Error::ConfigurationChanged);
        }
        let url = self.connection.management_url("rest/config", &[])?;
        self.connection
            .request_bytes(
                "replace full configuration",
                reqwest::Method::PUT,
                url,
                Some(&desired.document),
                true,
            )
            .await?;
        let configuration = self.configuration().await.map_err(full_save_unknown)?;
        let requested_fields_match = configuration.document == desired.document;
        let application_state = self
            .configuration_sync_state()
            .await
            .map_err(full_save_unknown)?;
        Ok(crate::ConfigurationUpdate {
            configuration,
            requested_fields_match,
            application_state,
        })
    }

    /// PUT the complete options section from an identity-bound snapshot.
    ///
    /// A fresh options section must match the snapshot's original options;
    /// unrelated section changes do not cause an overwrite or stale refusal.
    /// Clones serialize mutations, but independent writers must coordinate:
    /// this is not server-side compare-and-swap. Only one PUT is sent. Actual
    /// complete readback is returned; application and durability remain separate.
    pub async fn replace_options_configuration(
        &self,
        desired: &crate::ConfigurationSnapshot,
    ) -> Result<ConfigurationSectionUpdate<crate::GeneralOptions>> {
        self.require_snapshot_scope(desired)?;
        let body = desired
            .document
            .get("options")
            .filter(|v| v.is_object())
            .ok_or(Error::InvalidConfiguration {
                reason: "complete options section is absent",
            })?;
        let _guard = self.connection.mutation_lock.lock().await;
        let fresh = self.configuration().await?;
        if fresh.document.get("options") != desired.original.get("options") {
            return Err(Error::ConfigurationChanged);
        }
        self.connection
            .request_bytes(
                "replace complete options configuration",
                reqwest::Method::PUT,
                self.connection.management_url("rest/config/options", &[])?,
                Some(body),
                true,
            )
            .await?;
        let actual = self.configuration().await.map_err(section_unknown)?;
        Ok(ConfigurationSectionUpdate {
            requested_fields_match: actual.document.get("options") == Some(body),
            configuration: actual.general_options().map_err(section_unknown)?,
        })
    }

    /// PUT the complete GUI section from an identity-bound snapshot once.
    ///
    /// The original GUI section must still match a fresh authenticated snapshot.
    /// This is a coordinated stale check, not server-side compare-and-swap.
    /// Listener, protocol, password, mode and key can change together, so no
    /// endpoint discovery, reconnect, readback, retry or rollback is implicit.
    /// Retain intended credentials/trust and explicitly connect to the selected
    /// endpoint to reconcile configuration and actual effects. An acknowledgement
    /// alone proves neither them nor a reliable GUI hot-disable.
    pub async fn replace_gui_configuration(
        &self,
        desired: &crate::ConfigurationSnapshot,
    ) -> Result<crate::GuiConfigurationReplacement> {
        self.require_snapshot_scope(desired)?;
        let body = desired
            .document
            .get("gui")
            .filter(|v| v.is_object())
            .ok_or(Error::InvalidConfiguration {
                reason: "complete GUI section is absent",
            })?;
        let _: crate::GuiAuthenticationConfig =
            serde_json::from_value(body.clone()).map_err(|_| Error::InvalidConfiguration {
                reason: "complete GUI section does not match the required native schema",
            })?;
        let _guard = self.connection.mutation_lock.lock().await;
        let fresh = self.configuration().await?;
        if fresh.document.get("gui") != desired.original.get("gui") {
            return Err(Error::ConfigurationChanged);
        }
        let previous_configuration = serde_json::from_value(fresh.document["gui"].clone())
            .map_err(|_| Error::InvalidConfiguration {
                reason: "current GUI section does not match the required native schema",
            })?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                "replace complete GUI configuration",
                reqwest::Method::PUT,
                self.connection.management_url("rest/config/gui", &[])?,
                Some(body),
                true,
            )
            .await?;
        Ok(crate::GuiConfigurationReplacement {
            previous_configuration,
            acknowledgement: crate::ResponseDiagnostic::new(status, bytes),
        })
    }

    fn require_snapshot_scope(&self, desired: &crate::ConfigurationSnapshot) -> Result<()> {
        if desired.identity != self.instance.device_id {
            return Err(Error::IdentityMismatch {
                expected: self.instance.device_id.clone(),
                actual: desired.identity.clone(),
            });
        }
        if desired.style != self.folder_path_style()? {
            return Err(Error::InvalidPath {
                reason: "configuration snapshot belongs to different target path syntax",
            });
        }
        Ok(())
    }

    /// Read general options without changing settings or resource policy.
    pub async fn general_options(&self) -> Result<crate::GeneralOptions> {
        self.connection
            .get_json("read general options", "rest/config/options")
            .await
    }

    /// PATCH only explicit general options, then return the actual section.
    /// Readback does not prove scheduling, throughput or power-management effects.
    /// No mutation is retried or implicitly restarted.
    pub async fn update_general_options(
        &self,
        patch: &crate::GeneralOptionsPatch,
    ) -> Result<ConfigurationSectionUpdate<crate::GeneralOptions>> {
        patch.validate()?;
        self.patch_configuration_section("rest/config/options", patch)
            .await
    }

    /// Read the actual folder creation template without interpreting an empty path.
    pub async fn folder_defaults(&self) -> Result<FolderDefaults> {
        self.connection
            .get_json("read folder defaults", "rest/config/defaults/folder")
            .await
    }

    /// PATCH explicit template fields. Existing folders are not updated.
    ///
    /// Clones serialize writes and identity is rechecked. External writers must
    /// coordinate. No mutation is retried; after an unknown outcome or
    /// cancellation, read the template before considering another write.
    pub async fn update_folder_defaults(
        &self,
        patch: &FolderDefaultsPatch,
    ) -> Result<ConfigurationSectionUpdate<FolderDefaults>> {
        patch.validate()?;
        self.patch_configuration_section("rest/config/defaults/folder", patch)
            .await
    }

    /// PATCH explicit device template fields. Existing devices are not updated.
    /// The validation and unknown-outcome rules match `update_device`.
    pub async fn update_device_defaults(
        &self,
        patch: &DevicePatch,
    ) -> Result<ConfigurationSectionUpdate<DeviceDefaults>> {
        patch.validate(true)?;
        let update: ConfigurationSectionUpdate<DeviceDefaults> = self
            .patch_configuration_section("rest/config/defaults/device", patch)
            .await?;
        patch
            .validate_advanced_readback(&update.configuration.extra)
            .map_err(section_unknown)?;
        Ok(update)
    }

    /// Read the native application flag. This does not save, restart or prove
    /// persistence. Use explicit owned-instance shutdown/restart when required.
    pub async fn configuration_sync_state(&self) -> Result<ConfigurationSyncState> {
        self.connection
            .get_json(
                "read configuration application state",
                "rest/system/config/insync",
            )
            .await
    }

    pub(super) async fn patch_configuration_section<T: DeserializeOwned>(
        &self,
        route: &'static str,
        patch: &impl Serialize,
    ) -> Result<ConfigurationSectionUpdate<T>> {
        let body = serde_json::to_value(patch).map_err(|_| Error::InvalidConfiguration {
            reason: "configuration section patch cannot be encoded",
        })?;
        let fields =
            body.as_object()
                .filter(|m| !m.is_empty())
                .ok_or(Error::InvalidConfiguration {
                    reason: "configuration section patch must contain at least one field",
                })?;
        let url = self.connection.management_url(route, &[])?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.connection
            .request_bytes(
                "update configuration section",
                reqwest::Method::PATCH,
                url,
                Some(&body),
                true,
            )
            .await?;
        let value: serde_json::Value = self
            .connection
            .get_json("read back configuration section", route)
            .await
            .map_err(section_unknown)?;
        let requested_fields_match = fields
            .iter()
            .all(|(key, expected)| value.get(key) == Some(expected));
        let configuration = serde_json::from_value(value).map_err(|_| {
            section_unknown(Error::InvalidConfiguration {
                reason: "configuration section readback does not match its required schema",
            })
        })?;
        Ok(ConfigurationSectionUpdate {
            configuration,
            requested_fields_match,
        })
    }
}

fn scoped_document(
    scope: ConfigurationScope,
    document: &serde_json::Value,
) -> Result<&serde_json::Value> {
    let selected = match scope {
        ConfigurationScope::Complete => Some(document),
        ConfigurationScope::Options => document.get("options"),
        ConfigurationScope::Gui => document.get("gui"),
    };
    selected
        .filter(|value| value.is_object())
        .ok_or(Error::InvalidConfiguration {
            reason: "the complete selected configuration document is absent",
        })
}

fn section_unknown(source: Error) -> Error {
    Error::MutationOutcomeUnknown {
        operation: "read back configuration section",
        source: Box::new(source),
    }
}

fn full_save_unknown(source: Error) -> Error {
    Error::MutationOutcomeUnknown {
        operation: "read back full configuration save",
        source: Box::new(source),
    }
}
