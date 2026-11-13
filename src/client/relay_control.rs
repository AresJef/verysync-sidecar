//! Guarded relay configuration and separately observed runtime.
use super::Client;
use crate::{
    Error, RelayProbe, RelayServerConfig, RelayServerPatch, RelayServerStatus, RelayServerUpdate,
    Result,
};
use serde::Deserialize;
impl Client {
    /// Ask this engine to probe one explicit relay URL. This emits network traffic.
    /// No probe is automatic or retried; its result remains distinct from HTTP
    /// success and from an independent cross-WAN acceptance.
    pub async fn probe_relay(&self, address: &str) -> Result<RelayProbe> {
        let url = url::Url::parse(address).map_err(|_| Error::InvalidConfiguration {
            reason: "relay probe requires an absolute relay URL",
        })?;
        if url.scheme() != "relay"
            || url.host_str().is_none()
            || url.port().is_none_or(|p| p == 0)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || address.chars().any(char::is_control)
        {
            return Err(Error::InvalidConfiguration{reason:"relay probe requires a relay host and nonzero port without userinfo or fragment"});
        }
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let url = self
            .connection
            .management_url("rest/svc/test/relay", &[("relay", address)])?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                "probe selected relay",
                reqwest::Method::GET,
                url,
                None,
                true,
            )
            .await?;
        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse {
            operation: "read relay probe result",
            response: crate::ResponseDiagnostic::new(status, bytes),
        })
    }

    /// Read stored relay options without starting a relay or probing its URL.
    pub async fn relay_server_configuration(&self) -> Result<RelayServerConfig> {
        #[derive(Deserialize)]
        struct Config {
            #[serde(rename = "relayServer")]
            relay: RelayServerConfig,
        }
        let config: Config = self
            .connection
            .get_json("read relay configuration", "rest/config")
            .await?;
        Ok(config.relay)
    }
    /// Patch selected relay fields once, with fresh target identity and readback.
    /// Matching readback is separate from runtime state or token enforcement.
    pub async fn update_relay_server_configuration(
        &self,
        patch: &RelayServerPatch,
    ) -> Result<RelayServerUpdate> {
        patch.validate()?;
        let body = serde_json::to_value(patch).map_err(|_| Error::InvalidConfiguration {
            reason: "relay patch cannot be encoded",
        })?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let url = self
            .connection
            .management_url("rest/config/relayserver", &[])?;
        self.connection
            .request_bytes(
                "update relay configuration",
                reqwest::Method::PATCH,
                url,
                Some(&body),
                true,
            )
            .await?;
        let configuration = self.relay_server_configuration().await.map_err(|source| {
            Error::MutationOutcomeUnknown {
                operation: "read back changed relay configuration",
                source: Box::new(source),
            }
        })?;
        Ok(RelayServerUpdate {
            requested_fields_match: patch.matches(&configuration),
            configuration,
        })
    }
    /// Read actual relay state after a fresh management identity check.
    pub async fn relay_server_status(&self) -> Result<RelayServerStatus> {
        self.system_status().await?;
        self.connection
            .get_json("read relay status", "rest/relaysrv/status")
            .await
    }
    /// Read the engine's bounded rate-history array without inventing its units
    /// or timestamps. An empty array is distinct from a failed request.
    pub async fn relay_rate_samples(&self) -> Result<Vec<u64>> {
        self.system_status().await?;
        self.connection
            .get_json("read relay rate samples", "rest/relaysrv/rates")
            .await
    }
}
