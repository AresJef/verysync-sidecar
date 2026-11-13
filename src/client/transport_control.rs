//! Explicit options changes and fresh tracker/NAT observations.
use super::Client;
use crate::{
    DeviceId, Error, Result, TransportConfig, TransportPatch, TransportStatus, TransportUpdate,
};
use serde::Deserialize;

impl Client {
    /// Read current transport settings without enabling any protocol.
    pub async fn transport_configuration(&self) -> Result<TransportConfig> {
        #[derive(Deserialize)]
        struct Config {
            options: TransportConfig,
        }
        let config: Config = self
            .connection
            .get_json("read transport configuration", "rest/config")
            .await?;
        Ok(config.options)
    }
    /// Patch only explicit fields after a fresh identity check. No write retry.
    /// Readback is not tracker registration, NAT traversal or a live peer receipt.
    pub async fn update_transport_configuration(
        &self,
        patch: &TransportPatch,
    ) -> Result<TransportUpdate> {
        patch.validate()?;
        let body = serde_json::to_value(patch).map_err(|_| Error::InvalidConfiguration {
            reason: "transport patch cannot be encoded",
        })?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let url = self.connection.management_url("rest/config/options", &[])?;
        self.connection
            .request_bytes(
                "update transport configuration",
                reqwest::Method::PATCH,
                url,
                Some(&body),
                true,
            )
            .await?;
        let configuration = self.transport_configuration().await.map_err(|source| {
            Error::MutationOutcomeUnknown {
                operation: "read back changed transport configuration",
                source: Box::new(source),
            }
        })?;
        Ok(TransportUpdate {
            requested_fields_match: patch.matches(&configuration),
            configuration,
        })
    }
    /// Read fresh reported tracker/NAT state, checking the response's identity.
    pub async fn transport_status(&self) -> Result<TransportStatus> {
        #[derive(Deserialize)]
        struct Status {
            #[serde(rename = "myID")]
            identity: DeviceId,
            #[serde(flatten)]
            transport: TransportStatus,
        }
        let status: Status = self
            .connection
            .get_json("read transport status", "rest/system/status")
            .await?;
        if status.identity != self.instance.device_id {
            return Err(Error::IdentityMismatch {
                expected: self.instance.device_id.clone(),
                actual: status.identity,
            });
        }
        Ok(status.transport)
    }
}
