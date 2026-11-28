//! Scoped native preference PATCH with one original request and read-only verification.

use super::{workflow_write_result, Client};
use crate::{
    Error, OperationOptions, OperationPhase, PreferenceChange, PreferenceReadback,
    PreferenceReport, PreferenceRuntime, ResponseDiagnostic, Result,
};
use reqwest::Method;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use tokio::time::Instant;

#[derive(Clone, Copy)]
enum Section {
    General,
    System,
    Gui,
    CrashReporting,
    FolderDefaults,
    DeviceDefaults,
    Ldap,
    Network,
    Transport,
    Bandwidth,
    RelayServer,
}

impl Section {
    fn route(self) -> &'static str {
        match self {
            Self::Gui => "rest/config/gui",
            Self::Ldap => "rest/config/ldap",
            Self::FolderDefaults => "rest/config/defaults/folder",
            Self::DeviceDefaults => "rest/config/defaults/device",
            Self::RelayServer => "rest/config/relayserver",
            Self::General
            | Self::System
            | Self::CrashReporting
            | Self::Network
            | Self::Transport
            | Self::Bandwidth => "rest/config/options",
        }
    }

    fn decode(self, value: Value, style: crate::PathStyle) -> Result<PreferenceReadback> {
        use PreferenceReadback as Readback;
        Ok(match self {
            Self::General => Readback::General(decode(value)?),
            Self::System => {
                let wire: crate::system_preferences::WireSystemPreferences = decode(value)?;
                Readback::System(wire.into_public(style)?)
            }
            Self::Gui => Readback::Gui(crate::GuiPreferences::from_auth(&decode(value)?)?),
            Self::CrashReporting => Readback::CrashReporting(decode(value)?),
            Self::FolderDefaults => Readback::FolderDefaults(decode(value)?),
            Self::DeviceDefaults => Readback::DeviceDefaults(decode(value)?),
            Self::Ldap => Readback::Ldap(decode(value)?),
            Self::Network => Readback::Network(decode(value)?),
            Self::Transport => Readback::Transport(decode(value)?),
            Self::Bandwidth => Readback::Bandwidth(decode(value)?),
            Self::RelayServer => Readback::RelayServer(decode(value)?),
        })
    }
}

impl Client {
    /// Update one typed preference scope and read back its selected fields.
    /// If the fields already match, skip the PATCH. Keep the original reply,
    /// observed state and any live status separate. Requests never replay a
    /// preference edit, restart a service, probe a network or log in to LDAP.
    pub async fn change_preferences_and_verify(
        &self,
        change: PreferenceChange<'_>,
        options: OperationOptions,
    ) -> Result<PreferenceReport> {
        const WRITE: &str = "change selected native preferences";
        const READ: &str = "verify the selected preferences";
        let style = self.folder_path_style()?;
        let (section, body) = encode_change(change, style)?;
        let fields =
            body.as_object()
                .filter(|m| !m.is_empty())
                .ok_or(Error::InvalidConfiguration {
                    reason: "select at least one preference to change",
                })?;
        let route = section.route();
        let url = self.connection.management_url(route, &[])?;
        let matching = |value: &Value| {
            fields
                .iter()
                .filter(|(key, expected)| value.get(*key) == Some(*expected))
                .count()
        };
        let context = options.start()?;
        let mut guard = None;
        let mut write = Default::default();
        let mut chosen = None;
        let mut unchanged = None;
        let attempted =
            context
                .wait(context.dispatch_deadline(), WRITE, async {
                    context.phase(OperationPhase::Checking);
                    guard = Some(self.connection.mutation_lock.lock().await);
                    self.observe_control_identity().await?;
                    let generation = self.system_status().await?.start_time.ok_or(
                        Error::InvalidConfiguration {
                            reason: "the selected instance did not report its start time",
                        },
                    )?;
                    let current: Value = self.connection.get_json(READ, route).await?;
                    let matched = matching(&current);
                    let current = section.decode(current, style)?;
                    self.require_configuration_generation(&generation).await?;
                    if matched == fields.len() {
                        chosen = Some(generation);
                        unchanged = Some(current);
                        return Ok(None);
                    }
                    if Instant::now() >= context.dispatch_deadline() {
                        return Err(Error::Timeout { operation: WRITE });
                    }
                    chosen = Some(generation);
                    let request =
                        self.connection
                            .authorized_request(Method::PATCH, url, Some(&body));
                    let reply = self
                        .connection
                        .send_workflow_write(WRITE, request, &context, &mut write)
                        .await?;
                    Ok(Some(ResponseDiagnostic::new(reply.status, reply.body)))
                })
                .await;
        let original = workflow_write_result(WRITE, write, attempted);
        let refused = write.response_complete
            && matches!(
                original,
                Err(Error::Authentication { .. } | Error::AccessDenied { .. })
            );
        let mut report = PreferenceReport {
            write,
            original,
            selected_fields: fields.len(),
            matching_fields: unchanged.as_ref().map(|_| fields.len()),
            current: unchanged,
            observation_error: None,
            application: None,
            runtime: None,
        };
        if let Some(generation) = chosen.filter(|_| !refused) {
            context.phase(OperationPhase::Verifying);
            if write.dispatched {
                let verified = context
                    .wait(context.deadline, READ, async {
                        self.require_configuration_generation(&generation).await?;
                        let value: Value = self.connection.get_json(READ, route).await?;
                        let count = matching(&value);
                        let current = section.decode(value, style)?;
                        self.require_configuration_generation(&generation).await?;
                        Ok((current, count))
                    })
                    .await;
                match verified {
                    Ok((current, count)) => {
                        report.current = Some(current);
                        report.matching_fields = Some(count);
                    }
                    Err(error) => report.observation_error = Some(error),
                }
            }
            if report.current.is_some() {
                let verified = context
                    .wait(
                        context.deadline,
                        "observe current native preference effects",
                        async {
                            self.require_configuration_generation(&generation).await?;
                            let (application, runtime) = tokio::join!(
                                self.configuration_sync_state(),
                                self.read_preference_runtime(section),
                            );
                            self.require_configuration_generation(&generation).await?;
                            Ok((application, runtime))
                        },
                    )
                    .await;
                match verified {
                    Ok((application, runtime)) => {
                        report.application = Some(application);
                        report.runtime = runtime;
                    }
                    Err(error) => report.application = Some(Err(error)),
                }
            }
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn read_preference_runtime(&self, section: Section) -> Option<Result<PreferenceRuntime>> {
        match section {
            Section::Network => {
                let (listeners, discovery) =
                    tokio::join!(self.listener_status(), self.discovery_cache());
                Some(Ok(PreferenceRuntime::Network {
                    listeners,
                    discovery,
                }))
            }
            Section::Transport | Section::Bandwidth => {
                let (status, connections) =
                    tokio::join!(self.transport_status(), self.connections());
                Some(Ok(PreferenceRuntime::Transport {
                    status,
                    connections,
                }))
            }
            Section::RelayServer => Some(
                self.relay_server_status()
                    .await
                    .map(PreferenceRuntime::RelayServer),
            ),
            _ => None,
        }
    }
}

fn encode_change(
    change: PreferenceChange<'_>,
    style: crate::PathStyle,
) -> Result<(Section, Value)> {
    Ok(match change {
        PreferenceChange::General(patch) => (Section::General, encode(patch, patch.validate())?),
        PreferenceChange::System(patch) => (Section::System, patch.body(style)?),
        PreferenceChange::Gui(patch) => (Section::Gui, encode(patch, patch.validate())?),
        PreferenceChange::CrashReporting(patch) => {
            (Section::CrashReporting, encode(patch, patch.validate())?)
        }
        PreferenceChange::FolderDefaults(patch) => {
            (Section::FolderDefaults, encode(patch, patch.validate())?)
        }
        PreferenceChange::DeviceDefaults(patch) => (
            Section::DeviceDefaults,
            encode(patch, patch.validate(true))?,
        ),
        PreferenceChange::Ldap(patch) => (Section::Ldap, encode(patch, patch.validate())?),
        PreferenceChange::Network(patch) => (Section::Network, encode(patch, patch.validate())?),
        PreferenceChange::Transport(patch) => {
            (Section::Transport, encode(patch, patch.validate())?)
        }
        PreferenceChange::Bandwidth(patch) => {
            (Section::Bandwidth, encode(patch, patch.validate())?)
        }
        PreferenceChange::RelayServer(patch) => {
            (Section::RelayServer, encode(patch, patch.validate())?)
        }
    })
}

fn encode(patch: &impl Serialize, validation: Result<()>) -> Result<Value> {
    validation?;
    serde_json::to_value(patch).map_err(|_| Error::InvalidConfiguration {
        reason: "selected preferences cannot be encoded",
    })
}

fn decode<T: DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| Error::InvalidConfiguration {
        reason: "selected preferences do not match the native schema",
    })
}
