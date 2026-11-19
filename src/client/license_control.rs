//! Native license reads and single explicit state-changing GET requests.
use super::{mutation_error, Client};
use crate::{
    DeviceId, Error, LicenseChange, LicenseRequestKind, LicenseStatus, ResponseDiagnostic, Result,
};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct LicenseStatusWire {
    #[serde(rename = "myID")]
    device_id: DeviceId,
    #[serde(rename = "myLicense")]
    license: LicenseStatus,
}
impl Client {
    /// Read actual `myLicense` with a fresh device identity check. Missing/null
    /// license data is a response error; an empty object is retained. This does
    /// not refresh a license, contact its issuer or test any licensed feature.
    pub async fn license_status(&self) -> Result<LicenseStatus> {
        let wire: LicenseStatusWire = self
            .connection
            .get_json("read native licenses", "rest/system/status")
            .await?;
        if wire.device_id != self.instance.device_id {
            return Err(Error::IdentityMismatch {
                expected: self.instance.device_id.clone(),
                actual: wire.device_id,
            });
        }
        Ok(wire.license)
    }
    /// Explicitly request one native license refresh. This can contact the
    /// issuer and persist native data. An acknowledgement and observed records
    /// do not establish a paid feature's actual behavior. No request is retried.
    pub async fn fetch_licenses(&self) -> Result<LicenseChange> {
        self.change_licenses(LicenseRequestKind::Refresh).await
    }
    /// Explicitly request one native Pro trial. This can contact VerySync,
    /// consume trial eligibility and persist authorization data. The library
    /// never calls this implicitly, accepts terms or purchases a license.
    /// Real trial issuance and licensed effects have separate acceptance gates.
    pub async fn request_pro_trial(&self) -> Result<LicenseChange> {
        self.change_licenses(LicenseRequestKind::ProTrial).await
    }
    async fn change_licenses(&self, request: LicenseRequestKind) -> Result<LicenseChange> {
        let (route, operation) = match request {
            LicenseRequestKind::Refresh => ("rest/license/fetch", "refresh native licenses"),
            LicenseRequestKind::ProTrial => ("rest/license/trial", "request native Pro trial"),
        };
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let (status, bytes) = self
            .connection
            .request_bytes(
                operation,
                reqwest::Method::GET,
                self.connection.management_url(route, &[])?,
                None,
                true,
            )
            .await?;
        let native: BTreeMap<String, serde_json::Value> =
            serde_json::from_slice(&bytes).map_err(|_| {
                mutation_error(
                    operation,
                    true,
                    Error::InvalidResponse {
                        operation,
                        response: ResponseDiagnostic::new(status, bytes.clone()),
                    },
                )
            })?;
        if native.get("error").is_some_and(|v| !v.is_null()) {
            return Err(mutation_error(
                operation,
                true,
                Error::Api {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes),
                },
            ));
        }
        let observed = self
            .license_status()
            .await
            .map_err(|e| mutation_error(operation, true, e))?;
        Ok(LicenseChange {
            request,
            status: observed,
            acknowledgement: ResponseDiagnostic::new(status, bytes),
        })
    }
}
