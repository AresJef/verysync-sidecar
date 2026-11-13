//! Authenticated network settings and separately observed live state.
use super::Client;
use crate::{
    ConnectionSnapshot, DeviceId, DiscoveryRecord, Error, ListenerStatus, NetworkConfig,
    NetworkPatch, NetworkUpdate, Result,
};
use serde::Deserialize;
use std::collections::BTreeMap;

impl Client {
    /// Read actual listener/discovery settings, preserving unmodeled options.
    pub async fn network_configuration(&self) -> Result<NetworkConfig> {
        #[derive(Deserialize)]
        struct Config {
            options: NetworkConfig,
        }
        let config: Config = self
            .connection
            .get_json("read network configuration", "rest/config")
            .await?;
        Ok(config.options)
    }
    /// Patch only explicit options, recheck identity and read actual configuration.
    /// No mutation is retried. Matching settings do not establish reachability;
    /// inspect listeners, discovery and actual connections separately.
    pub async fn update_network_configuration(
        &self,
        patch: &NetworkPatch,
    ) -> Result<NetworkUpdate> {
        patch.validate()?;
        let body = serde_json::to_value(patch).map_err(|_| Error::InvalidConfiguration {
            reason: "network patch cannot be encoded",
        })?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let url = self.connection.management_url("rest/config/options", &[])?;
        self.connection
            .request_bytes(
                "update network configuration",
                reqwest::Method::PATCH,
                url,
                Some(&body),
                true,
            )
            .await?;
        let configuration =
            self.network_configuration()
                .await
                .map_err(|source| Error::MutationOutcomeUnknown {
                    operation: "read back changed network configuration",
                    source: Box::new(source),
                })?;
        Ok(NetworkUpdate {
            requested_fields_match: patch.matches(&configuration),
            configuration,
        })
    }
    /// Read a fresh peer snapshot after checking the target identity.
    /// A missing peer is distinct from a present `connected: false` entry.
    pub async fn connections(&self) -> Result<ConnectionSnapshot> {
        self.system_status().await?;
        self.connection
            .get_json("read peer connections", "rest/system/connections")
            .await
    }
    /// Read actual listener/service addresses and errors with identity checking.
    /// External-address reports are not an independent test of WAN reachability.
    pub async fn listener_status(&self) -> Result<BTreeMap<String, ListenerStatus>> {
        #[derive(Deserialize)]
        struct Status {
            #[serde(rename = "myID")]
            identity: DeviceId,
            #[serde(rename = "connectionServiceStatus")]
            listeners: BTreeMap<String, ListenerStatus>,
        }
        let status: Status = self
            .connection
            .get_json("read listener status", "rest/system/status")
            .await?;
        if status.identity != self.instance.device_id {
            return Err(Error::IdentityMismatch {
                expected: self.instance.device_id.clone(),
                actual: status.identity,
            });
        }
        Ok(status.listeners)
    }
    /// Read the current discovery cache without starting discovery or resolving.
    /// Cache keys are preserved as upstream strings, not normalized into IDs.
    /// Empty data, protocol errors and malformed responses remain distinct.
    pub async fn discovery_cache(&self) -> Result<BTreeMap<String, DiscoveryRecord>> {
        self.system_status().await?;
        self.connection
            .get_json("read discovery cache", "rest/system/discovery")
            .await
    }
}
