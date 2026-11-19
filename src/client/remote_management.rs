//! One explicit native tunnel probe without discovery, retries or license changes.
use super::{mutation_error, Client, ConnectOptions};
use crate::{
    ApiKey, DeviceId, DeviceTunnelProbe, Error, ManagementEndpoint, ResponseDiagnostic, Result,
};

impl ConnectOptions {
    /// Connect through an explicitly supplied official remote-management gateway.
    /// Append the exact target device ID beneath its HTTP(S) base path and require
    /// that identity during the normal authenticated handshake. Supply the target
    /// instance's API key. This does not start a gateway, grant permission, probe
    /// a peer, acquire a license or choose a default port. A licensed native
    /// remote session has separate acceptance requirements.
    pub fn remote_tunnel(
        gateway: ManagementEndpoint,
        target: DeviceId,
        target_api_key: ApiKey,
    ) -> Result<Self> {
        let mut url = gateway.http_url().cloned().ok_or(Error::InvalidEndpoint {
            reason: "remote management gateway must be an explicit HTTP(S) endpoint",
        })?;
        url.path_segments_mut()
            .map_err(|_| Error::InvalidEndpoint {
                reason: "remote management gateway cannot contain path segments",
            })?
            .pop_if_empty()
            .push(target.as_str())
            .push("");
        let endpoint = ManagementEndpoint::http(url.as_str())?;
        Ok(Self::new(endpoint, target_api_key).expected_device_id(target))
    }
}

impl Client {
    /// Probe one exact configured remote peer using the native tunnel handler.
    /// This GET can initiate peer traffic, so it serializes with mutations and
    /// checks the local identity first. It does not resume devices, open a GUI
    /// session, select a gateway or alter authorization. Negative native results
    /// are returned as data. No probe is retried or HTTP redirect followed.
    pub async fn probe_device_tunnel(&self, peer: &DeviceId) -> Result<DeviceTunnelProbe> {
        const OPERATION: &str = "probe native device tunnel";
        self.require_remote_device(peer)?;
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        self.device(peer).await?;
        let mut url = self.connection.management_url("rest/tunnel/test/", &[])?;
        // The fixed native handler redirects the unsuffixed form. Build the
        // canonical route explicitly rather than following credential redirects.
        url.path_segments_mut()
            .map_err(|_| Error::InvalidEndpoint {
                reason: "native tunnel URL cannot contain path segments",
            })?
            .pop_if_empty()
            .push(peer.as_str())
            .push("");
        let (status, bytes) = self
            .connection
            .request_bytes(OPERATION, reqwest::Method::GET, url, None, true)
            .await?;
        let probe: DeviceTunnelProbe = serde_json::from_slice(&bytes).map_err(|_| {
            mutation_error(
                OPERATION,
                true,
                Error::InvalidResponse {
                    operation: OPERATION,
                    response: ResponseDiagnostic::new(status, bytes.clone()),
                },
            )
        })?;
        if probe.device_id() != peer {
            return Err(mutation_error(
                OPERATION,
                true,
                Error::IdentityMismatch {
                    expected: peer.clone(),
                    actual: probe.device.clone(),
                },
            ));
        }
        Ok(probe)
    }
}
