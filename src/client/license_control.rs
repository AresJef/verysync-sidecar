//! Native license reads and single explicit state-changing GET requests.
use super::{mutation_error, workflow_write_result, Client};
use crate::{
    DeviceId, Error, LicenseChange, LicenseRequestKind, LicenseStatus, LicenseWorkflowReport,
    ManagementWriteEvidence, OperationOptions, OperationPhase, ResponseDiagnostic, Result,
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
    /// Submit the selected license refresh or trial request once and read the
    /// current license data within the same deadline. A trial request can
    /// consume eligibility. The SDK preserves an unknown reply even when the
    /// latest license data reports Pro. It never retries a request or exercise
    /// paid features implicitly.
    pub async fn request_license_and_verify(
        &self,
        request: LicenseRequestKind,
        observed_unix_seconds: i64,
        options: OperationOptions,
    ) -> Result<LicenseWorkflowReport> {
        let context = options.start()?;
        let (route, operation) = license_route(request);
        let url = self.connection.management_url(route, &[])?;
        let write_deadline = context.dispatch_deadline();
        let mut guard = None;
        let mut write = ManagementWriteEvidence::default();
        let mut before = None;
        let attempt = context
            .wait(write_deadline, operation, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                before = Some(self.license_status().await?);
                if tokio::time::Instant::now() >= write_deadline {
                    return Err(Error::Timeout { operation });
                }
                let outgoing = self
                    .connection
                    .authorized_request(reqwest::Method::GET, url, None);
                let response = self
                    .connection
                    .send_workflow_write(operation, outgoing, &context, &mut write)
                    .await?;
                license_acknowledgement(operation, response.status, response.body)
            })
            .await;
        let original = workflow_write_result(operation, write, attempt);
        let (observed, observation_error) = if write.dispatched
            && !matches!(
                original,
                Err(Error::Authentication { .. }
                    | Error::AccessDenied { .. }
                    | Error::LicenseRequired { .. })
            ) {
            context.phase(OperationPhase::Verifying);
            match context
                .wait(
                    context.deadline,
                    "check the current license records",
                    self.license_status(),
                )
                .await
            {
                Ok(status) => (Some(status), None),
                Err(source) => (None, Some(source)),
            }
        } else {
            (None, None)
        };
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(LicenseWorkflowReport {
            request,
            write,
            original,
            before,
            current_pro: observed
                .as_ref()
                .map(|status| status.pro_at(observed_unix_seconds)),
            observed,
            observation_error,
        })
    }

    async fn change_licenses(&self, request: LicenseRequestKind) -> Result<LicenseChange> {
        let (route, operation) = license_route(request);
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
        let acknowledgement = license_acknowledgement(operation, status, bytes)?;
        let observed = self
            .license_status()
            .await
            .map_err(|e| mutation_error(operation, true, e))?;
        Ok(LicenseChange {
            request,
            status: observed,
            acknowledgement,
        })
    }
}

fn license_route(request: LicenseRequestKind) -> (&'static str, &'static str) {
    match request {
        LicenseRequestKind::Refresh => ("rest/license/fetch", "refresh native licenses"),
        LicenseRequestKind::ProTrial => ("rest/license/trial", "request native Pro trial"),
    }
}

fn license_acknowledgement(
    operation: &'static str,
    status: u16,
    bytes: Vec<u8>,
) -> Result<ResponseDiagnostic> {
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
    Ok(ResponseDiagnostic::new(status, bytes))
}
