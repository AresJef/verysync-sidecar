//! Single credential writes and explicit, bounded read-only reauthentication.
use super::Client;
use crate::{ApiKey, ApiKeyRotation, ConnectOptions, Error, GuiAuthenticationConfig, Result};
use std::time::Duration;

impl Client {
    /// Select local GUI authentication with one explicit username/password PATCH,
    /// then read configuration through the unchanged API key after GUI reload.
    /// Password presence is separate from actual password/login verification.
    /// Cancellation or an unknown outcome never retries or rolls back the write.
    pub async fn set_local_gui_credentials(
        &self,
        credentials: &crate::GuiCredentials,
        timeout: Duration,
    ) -> Result<crate::GuiCredentialUpdate> {
        if timeout.is_zero() || std::time::Instant::now().checked_add(timeout).is_none() {
            return Err(Error::InvalidConfiguration {
                reason: "GUI credential update requires a nonzero representable deadline",
            });
        }
        tokio::runtime::Handle::try_current().map_err(|_| Error::InvalidConfiguration {
            reason: "GUI credential update requires a Tokio runtime with I/O and timers",
        })?;
        let body = serde_json::json!({"user":credentials.username,"password":credentials.password,"authMode":"static"});
        let mut write_started = false;
        let operation = async {
            let _guard = self.connection.mutation_lock.lock().await;
            self.system_status().await?;
            let url = self.connection.management_url("rest/config/gui", &[])?;
            write_started = true;
            let write_acknowledged = match self
                .connection
                .request_bytes(
                    "set local GUI credentials",
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
                let client = match self
                    .reconnect_with_api_key(self.connection.key.clone())
                    .await
                {
                    Ok(client) => client,
                    Err(error) if retry_read(&error) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                    Err(Error::IncompatibleVersion { actual }) => {
                        return Err(gui_credential_unknown(Error::IncompatibleVersion {
                            actual: actual
                                .replace(&credentials.password, "[REDACTED]")
                                .replace(&credentials.username, "[REDACTED]"),
                        }))
                    }
                    Err(error) => return Err(gui_credential_unknown(error)),
                };
                let configuration = client
                    .gui_authentication()
                    .await
                    .map_err(gui_credential_unknown)?;
                return Ok(crate::GuiCredentialUpdate {
                    username_matches: configuration.username == credentials.username,
                    configuration,
                    client,
                    write_acknowledged,
                });
            }
        };
        tokio::time::timeout(timeout, operation)
            .await
            .unwrap_or_else(|_| {
                let error = Error::Timeout {
                    operation: "set local GUI credentials",
                };
                Err(if write_started {
                    gui_credential_unknown(error)
                } else {
                    error
                })
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
            .expected_device_id(self.instance.device_id.clone())
            .version_policy(self.connection.version_policy)
            .request_timeout(self.connection.timeout)?
            .response_limit(self.connection.response_limit)?;
        let mut client = Client::connect(options).await?;
        client.connection.mutation_lock = self.connection.mutation_lock.clone();
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

fn gui_credential_unknown(source: Error) -> Error {
    Error::MutationOutcomeUnknown {
        operation: "reconcile local GUI credential update",
        source: Box::new(source),
    }
}
