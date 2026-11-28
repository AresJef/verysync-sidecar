//! Single credential writes and explicit, bounded read-only reauthentication.
use super::{workflow_write_result, Client};
use crate::{
    ApiKey, ApiKeyRotation, ConnectOptions, Error, GuiAuthenticationConfig,
    GuiCredentialWorkflowReport, GuiLoginOptions, GuiSession, OperationOptions, OperationPhase,
    ReadRetryDecision, ResponseDiagnostic, Result,
};
use std::time::Duration;
use tokio::time::Instant;

impl Client {
    pub(crate) async fn connect_management_replacement(
        &self,
        options: ConnectOptions,
    ) -> Result<Client> {
        let _guard = self.connection.mutation_lock.lock().await;
        let mut client = Client::connect(options).await?;
        client.connection.mutation_lock = self.connection.mutation_lock.clone();
        client.transient_read_retries = self.transient_read_retries;
        client.read_retry_budget = self.read_retry_budget.clone();
        Ok(client)
    }
    /// Select local GUI authentication with one explicit username/password PATCH,
    /// then read configuration through the unchanged API key after GUI reload.
    /// Password presence is separate from actual password/login verification.
    /// Cancellation or an unknown outcome never retries or rolls back the write.
    pub async fn set_local_gui_credentials(
        &self,
        credentials: &crate::GuiCredentials,
        timeout: Duration,
    ) -> Result<crate::GuiCredentialUpdate> {
        let body = serde_json::json!({"user":credentials.username,"password":credentials.password,"authMode":"static"});
        let (client, configuration, write_acknowledged) = self
            .patch_gui_configuration(body, timeout, "set local GUI credentials")
            .await?;
        Ok(crate::GuiCredentialUpdate {
            username_matches: configuration.username == credentials.username,
            configuration,
            client,
            write_acknowledged,
        })
    }

    /// Set explicit local GUI credentials and try one independent login.
    /// This submits one credential update. A stored password or the existing
    /// username cannot establish a match to the supplied password. After the
    /// native reload, verify the selected device through the existing API key
    /// before attempting a GUI login. A transient reauthentication may be
    /// tried one additional time only on a client with safe reads enabled.
    /// Keep or explicitly close a returned session.
    pub async fn set_local_gui_credentials_and_verify(
        &self,
        credentials: &crate::GuiCredentials,
        options: OperationOptions,
    ) -> Result<GuiCredentialWorkflowReport> {
        const CHANGE: &str = "set selected local GUI credentials";
        const READ: &str = "check local GUI credentials after update";
        const LOGIN: &str = "verify the new local GUI login";
        let url = self.connection.management_url("rest/config/gui", &[])?;
        let login_options =
            GuiLoginOptions::new(self.connection.endpoint.clone(), credentials.clone())
                .expected_device_id(self.instance.device_id.clone())
                .transport(self.connection.transport.clone())
                .version_policy(self.connection.version_policy)
                .request_timeout(self.connection.timeout)?
                .response_limit(self.connection.response_limit)?;
        let body = serde_json::json!({"user": credentials.username, "password": credentials.password, "authMode": "static"});
        let context = options.start()?;
        let mut guard = None;
        let mut write = Default::default();
        let mut selected = None;
        let attempted = context
            .wait(context.dispatch_deadline(), CHANGE, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                self.observe_control_identity().await?;
                let generation =
                    self.system_status()
                        .await?
                        .start_time
                        .ok_or(Error::InvalidConfiguration {
                            reason: "the selected instance did not report its start time",
                        })?;
                let before = self.gui_authentication().await?;
                if !before.enabled || !before.key_matches(&self.connection.key) {
                    return Err(Error::ConfigurationChanged);
                }
                self.require_configuration_generation(&generation).await?;
                if Instant::now() >= context.dispatch_deadline() {
                    return Err(Error::Timeout { operation: CHANGE });
                }
                selected = Some(generation);
                let request =
                    self.connection
                        .authorized_request(reqwest::Method::PATCH, url, Some(&body));
                let reply = self
                    .connection
                    .send_workflow_write(CHANGE, request, &context, &mut write)
                    .await?;
                Ok(ResponseDiagnostic::new(reply.status, reply.body))
            })
            .await;
        let original = workflow_write_result(CHANGE, write, attempted);
        let refused = write.response_complete
            && matches!(
                original,
                Err(Error::Authentication { .. } | Error::AccessDenied { .. })
            );
        let mut report = GuiCredentialWorkflowReport {
            write,
            original,
            configuration: None,
            configuration_matches: None,
            reconnect_attempts: 0,
            first_reconnect_error: None,
            retry_decision: None,
            observation_error: None,
            login: None,
            login_wait_error: None,
        };
        if let Some(generation) = selected.filter(|_| write.dispatched && !refused) {
            context.phase(OperationPhase::Verifying);
            let enabled = context.read_retries_enabled(self.transient_read_retries);
            let first_deadline = if enabled {
                context
                    .deadline
                    .min(Instant::now() + Duration::from_secs(2))
            } else {
                context.deadline
            };
            let mut observed = context
                .wait(first_deadline, READ, async {
                    report.reconnect_attempts = 1;
                    self.read_changed_gui_credentials(&generation, credentials)
                        .await
                })
                .await;
            if let Err(error) = observed {
                const BACKOFF: Duration = Duration::from_millis(200);
                let decision = if !enabled {
                    ReadRetryDecision::Disabled
                } else if !matches!(error, Error::Timeout { .. } | Error::Transport { .. }) {
                    ReadRetryDecision::CauseNotEligible
                } else if context.deadline.saturating_duration_since(Instant::now()) <= BACKOFF {
                    ReadRetryDecision::InsufficientTime
                } else if !self.read_retry_budget.take() {
                    ReadRetryDecision::SharedBudgetExhausted
                } else {
                    ReadRetryDecision::Permitted
                };
                report.retry_decision = Some(decision);
                observed = if decision == ReadRetryDecision::Permitted {
                    report.first_reconnect_error = Some(error);
                    context.phase(OperationPhase::WaitingToRetry);
                    context
                        .wait(context.deadline, READ, async {
                            tokio::time::sleep(BACKOFF).await;
                            context.phase(OperationPhase::Verifying);
                            report.reconnect_attempts = 2;
                            self.read_changed_gui_credentials(&generation, credentials)
                                .await
                        })
                        .await
                } else {
                    Err(error)
                };
            }
            match observed {
                Ok((fresh, configuration)) => {
                    let matches = configuration.enabled
                        && configuration.username == credentials.username
                        && configuration.mode == crate::GuiAuthMode::Static
                        && configuration.password_is_set()
                        && configuration.key_matches(&self.connection.key);
                    report.configuration_matches = Some(matches);
                    report.configuration = Some(configuration);
                    if matches {
                        match context
                            .wait(context.deadline, LOGIN, async {
                                Ok(GuiSession::login_with_outcome(login_options).await)
                            })
                            .await
                        {
                            Ok(result) => {
                                report.login = Some(result);
                                report.login_wait_error = context
                                    .wait(context.deadline, LOGIN, async {
                                        fresh.require_configuration_generation(&generation).await
                                    })
                                    .await
                                    .err();
                            }
                            Err(error) => report.login_wait_error = Some(error),
                        }
                    }
                }
                Err(error) => report.observation_error = Some(error),
            }
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }

    async fn read_changed_gui_credentials(
        &self,
        generation: &str,
        credentials: &crate::GuiCredentials,
    ) -> Result<(Client, GuiAuthenticationConfig)> {
        let fresh = self
            .reconnect_with_api_key(self.connection.key.clone())
            .await
            .map_err(|error| match error {
                Error::IncompatibleVersion { actual } => Error::IncompatibleVersion {
                    actual: actual
                        .replace(&credentials.username, "[REDACTED]")
                        .replace(&credentials.password, "[REDACTED]"),
                },
                other => other,
            })?;
        fresh.require_configuration_generation(generation).await?;
        let current = fresh.gui_authentication().await?;
        fresh.require_configuration_generation(generation).await?;
        Ok((fresh, current))
    }

    /// Select static or LDAP GUI authentication with one PATCH. LDAP directory
    /// configuration is a separate operation and this readback is not login proof.
    pub async fn set_gui_auth_mode(
        &self,
        mode: &crate::GuiAuthMode,
        timeout: Duration,
    ) -> Result<crate::GuiAuthModeUpdate> {
        if matches!(mode, crate::GuiAuthMode::Unknown(_)) {
            return Err(Error::InvalidConfiguration {
                reason: "unknown GUI authentication mode cannot be submitted",
            });
        }
        let (client, configuration, write_acknowledged) = self
            .patch_gui_configuration(
                serde_json::json!({"authMode":mode}),
                timeout,
                "set native GUI authentication mode",
            )
            .await?;
        Ok(crate::GuiAuthModeUpdate {
            requested_mode_matches: configuration.mode == *mode,
            configuration,
            client,
            write_acknowledged,
        })
    }

    pub(super) async fn patch_gui_configuration(
        &self,
        body: serde_json::Value,
        timeout: Duration,
        operation: &'static str,
    ) -> Result<(Client, GuiAuthenticationConfig, bool)> {
        if timeout.is_zero() || std::time::Instant::now().checked_add(timeout).is_none() {
            return Err(Error::InvalidConfiguration {
                reason: "GUI change requires a nonzero representable deadline",
            });
        }
        tokio::runtime::Handle::try_current().map_err(|_| Error::InvalidConfiguration {
            reason: "GUI change requires a Tokio runtime with I/O and timers",
        })?;
        let unknown = |source| Error::MutationOutcomeUnknown {
            operation,
            source: Box::new(source),
        };
        let mut write_started = false;
        let change = async {
            let _guard = self.connection.mutation_lock.lock().await;
            self.system_status().await?;
            let url = self.connection.management_url("rest/config/gui", &[])?;
            write_started = true;
            let acknowledged = match self
                .connection
                .request_bytes(operation, reqwest::Method::PATCH, url, Some(&body), true)
                .await
            {
                Ok(_) => true,
                Err(Error::MutationOutcomeUnknown { .. }) => false,
                Err(error) => return Err(error),
            };
            loop {
                let client = match self
                    .reconnect_with_api_key(self.connection.key.clone())
                    .await
                {
                    Ok(client) => client,
                    Err(error) if retry_read(&error) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                    Err(Error::IncompatibleVersion { mut actual }) => {
                        for value in body
                            .as_object()
                            .into_iter()
                            .flat_map(|m| m.values())
                            .filter_map(serde_json::Value::as_str)
                            .filter(|s| !s.is_empty())
                        {
                            actual = actual.replace(value, "[REDACTED]");
                        }
                        return Err(unknown(Error::IncompatibleVersion { actual }));
                    }
                    Err(error) => return Err(unknown(error)),
                };
                let configuration = client.gui_authentication().await.map_err(unknown)?;
                return Ok((client, configuration, acknowledged));
            }
        };
        tokio::time::timeout(timeout, change)
            .await
            .unwrap_or_else(|_| {
                let error = Error::Timeout { operation };
                Err(if write_started { unknown(error) } else { error })
            })
    }

    /// Read management GUI authentication settings, independently of a GUI login
    /// session or official VerySync account. Debug omits private values.
    pub async fn gui_authentication(&self) -> Result<GuiAuthenticationConfig> {
        self.connection
            .get_json("read GUI authentication configuration", "rest/config/gui")
            .await
    }

    /// Authenticate a fresh connection to the same explicit endpoint with a
    /// supplied key, preserving timeout, size and version policy and requiring
    /// the original device identity. Performs only reads; old clones retain
    /// their old credential. The new connection shares their mutation lock.
    pub async fn reconnect_with_api_key(&self, key: ApiKey) -> Result<Client> {
        let options = ConnectOptions::new(self.connection.endpoint.clone(), key)
            .transport(self.connection.transport.clone())
            .expected_device_id(self.instance.device_id.clone())
            .version_policy(self.connection.version_policy)
            .request_timeout(self.connection.timeout)?
            .response_limit(self.connection.response_limit)?;
        let mut client = Client::connect(options).await?;
        client.connection.mutation_lock = self.connection.mutation_lock.clone();
        client.transient_read_retries = self.transient_read_retries;
        client.read_retry_budget = self.read_retry_budget.clone();
        Ok(client)
    }

    /// PATCH one new API key, then bound read-only reconnects across native GUI
    /// reload. Never repeats the write. The key must differ and contain at least
    /// 20 ASCII bytes, matching private owned-state restart admission.
    ///
    /// Success returns actual key readback, old-key refusal and a freshly
    /// authenticated Client separately. Old clones remain unchanged. Check both
    /// booleans: an open GUI policy may accept nonmatching keys too.
    ///
    /// A total timeout includes lock acquisition, identity check, the single
    /// PATCH and all reads. After a timeout/cancellation following that write,
    /// retain the supplied key and explicitly `reconnect_with_api_key`; no
    /// rollback, restart, force-stop or further mutation is performed.
    pub async fn rotate_api_key(&self, key: ApiKey, timeout: Duration) -> Result<ApiKeyRotation> {
        if timeout.is_zero() || std::time::Instant::now().checked_add(timeout).is_none() {
            return Err(Error::InvalidConfiguration {
                reason: "credential rotation requires a nonzero representable deadline",
            });
        }
        tokio::runtime::Handle::try_current().map_err(|_| Error::InvalidConfiguration {
            reason: "credential rotation requires a Tokio runtime with I/O and timers",
        })?;
        if key.header().as_bytes().len() < 20 || key.header() == self.connection.key.header() {
            return Err(Error::InvalidCredential {
                reason: "replacement API key must differ and contain at least 20 ASCII bytes",
            });
        }
        let header = key.header();
        let value = header.to_str().map_err(|_| Error::InvalidCredential {
            reason: "replacement key cannot be encoded",
        })?;
        let body = serde_json::json!({"apiKey":value});
        let mut write_started = false;
        let operation = async {
            let _guard = self.connection.mutation_lock.lock().await;
            self.system_status().await?;
            let url = self.connection.management_url("rest/config/gui", &[])?;
            write_started = true;
            let write_acknowledged = match self
                .connection
                .request_bytes(
                    "rotate management API key",
                    reqwest::Method::PATCH,
                    url,
                    Some(&body),
                    true,
                )
                .await
            {
                Ok(_) => true,
                Err(Error::MutationOutcomeUnknown { .. }) => false,
                Err(error) => return Err(error),
            };
            loop {
                let client = match self.reconnect_with_api_key(key.clone()).await {
                    Ok(client) => client,
                    Err(error) if retry_read(&error) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                    Err(error) => return Err(rotation_unknown(error)),
                };
                let configuration = client
                    .gui_authentication()
                    .await
                    .map_err(rotation_unknown)?;
                let requested_key_matches = configuration.key_matches(&key);
                let previous_key_rejected = match self
                    .reconnect_with_api_key(self.connection.key.clone())
                    .await
                {
                    Ok(_) => false,
                    Err(Error::Authentication { status: 401 }) => true,
                    Err(Error::AccessDenied { response }) if response.status() == 403 => true,
                    Err(error) if retry_read(&error) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                    Err(error) => return Err(rotation_unknown(error)),
                };
                return Ok(ApiKeyRotation {
                    client,
                    write_acknowledged,
                    requested_key_matches,
                    previous_key_rejected,
                    configuration,
                });
            }
        };
        tokio::time::timeout(timeout, operation)
            .await
            .unwrap_or_else(|_| {
                let source = Error::Timeout {
                    operation: "rotate management API key",
                };
                Err(if write_started {
                    rotation_unknown(source)
                } else {
                    source
                })
            })
    }
}
fn retry_read(error: &Error) -> bool {
    matches!(
        error,
        Error::Transport { .. }
            | Error::Timeout { .. }
            | Error::Authentication { .. }
            | Error::AccessDenied { .. }
    )
}
fn rotation_unknown(source: Error) -> Error {
    Error::MutationOutcomeUnknown {
        operation: "reconcile management API key rotation",
        source: Box::new(source),
    }
}
