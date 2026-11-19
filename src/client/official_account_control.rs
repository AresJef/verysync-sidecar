//! Explicit native official-account calls, never GUI-session operations.
use super::{mutation_error, Client};
use crate::{
    DeviceId, Error, OfficialAccountChange, OfficialAccountCredentials, OfficialAccountState,
    OfficialAccountStatus, ResponseDiagnostic, Result,
};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct AccountStatusWire {
    #[serde(rename = "myID")]
    device_id: DeviceId,
    account: OfficialAccountStatus,
}

impl Client {
    /// Read the actual official-account object and verify the handshake identity.
    /// Missing/null/malformed account data is an error, not an empty logged-out
    /// state. No cloud request, login, license refresh or GUI change is made.
    pub async fn official_account_status(&self) -> Result<OfficialAccountStatus> {
        let wire: AccountStatusWire = self
            .connection
            .get_json("read official account status", "rest/system/status")
            .await?;
        if wire.device_id != self.instance.device_id {
            return Err(Error::IdentityMismatch {
                expected: self.instance.device_id.clone(),
                actual: wire.device_id,
            });
        }
        Ok(wire.account)
    }

    /// Submit explicit official credentials once to this core. The core can
    /// contact its cloud service and persist a session. This does not register
    /// an account, accept terms, consume a trial or change GUI credentials.
    /// Inspect both the acknowledgement and observed state; unknown outcomes
    /// are never retried, rolled back or turned into authentication success.
    pub async fn login_official_account(
        &self,
        credentials: &OfficialAccountCredentials,
    ) -> Result<OfficialAccountChange> {
        let body =
            serde_json::json!({"username":credentials.username,"password":credentials.password});
        self.change_official_account(
            reqwest::Method::POST,
            "rest/account/login",
            Some(&body),
            OfficialAccountState::LoggedIn,
            "log in to native official account",
        )
        .await
    }

    /// Explicitly request official-account logout once. The native GET changes
    /// account state and is serialized as a mutation. It does not log out the
    /// local GUI, rotate its API key, stop the core or revoke every cloud token.
    pub async fn logout_official_account(&self) -> Result<OfficialAccountChange> {
        self.change_official_account(
            reqwest::Method::GET,
            "rest/account/logout",
            None,
            OfficialAccountState::LoggedOut,
            "log out of native official account",
        )
        .await
    }

    async fn change_official_account(
        &self,
        method: reqwest::Method,
        route: &'static str,
        body: Option<&serde_json::Value>,
        expected: OfficialAccountState,
        operation: &'static str,
    ) -> Result<OfficialAccountChange> {
        let _guard = self.connection.mutation_lock.lock().await;
        self.system_status().await?;
        let url = self.connection.management_url(route, &[])?;
        let (status, bytes) = self
            .connection
            .request_bytes(operation, method, url, body, true)
            .await?;
        let invalid = || {
            mutation_error(
                operation,
                true,
                Error::InvalidResponse {
                    operation,
                    response: ResponseDiagnostic::new(status, bytes.clone()),
                },
            )
        };
        let native: BTreeMap<String, serde_json::Value> =
            serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if let Some(error) = native.get("error").filter(|v| !v.is_null()) {
            let code = error
                .get("code")
                .and_then(serde_json::Value::as_i64)
                .ok_or_else(invalid)?;
            if !error
                .get("message")
                .is_some_and(serde_json::Value::is_string)
            {
                return Err(invalid());
            }
            return Err(Error::OfficialAccountRejected {
                code,
                response: ResponseDiagnostic::new(status, bytes),
            });
        }
        let observed = self
            .official_account_status()
            .await
            .map_err(|error| mutation_error(operation, true, error))?;
        Ok(OfficialAccountChange {
            expected_state_matches: observed.state() == expected,
            status: observed,
            acknowledgement: ResponseDiagnostic::new(status, bytes),
        })
    }
}
