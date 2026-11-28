//! Explicit native official-account calls, never GUI-session operations.
use super::{mutation_error, workflow_write_result, Client};
use crate::{
    DeviceId, Error, OfficialAccountChange, OfficialAccountCredentials, OfficialAccountState,
    OfficialAccountStatus, OfficialAccountWorkflowOutcome, OfficialAccountWorkflowReport,
    OperationOptions, OperationPhase, ResponseDiagnostic, Result,
};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct AccountStatusWire {
    #[serde(rename = "myID")]
    device_id: DeviceId,
    account: OfficialAccountStatus,
}

enum AccountRequest<'a> {
    Login(&'a OfficialAccountCredentials),
    Logout,
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

    /// Sign in once and check the resulting account on the selected device.
    ///
    /// Supply a known positive native UID to verify the intended account even
    /// if the reply is lost. A matching existing UID needs no new login.
    /// Checking the SDK's local account report does not contact the provider or
    /// confirm cloud-token revocation or entitlement.
    pub async fn login_official_account_and_verify(
        &self,
        credentials: &OfficialAccountCredentials,
        expected_uid: Option<i64>,
        options: OperationOptions,
    ) -> Result<OfficialAccountWorkflowReport> {
        self.official_account_workflow(AccountRequest::Login(credentials), expected_uid, options)
            .await
    }

    /// Sign out once, then check the selected device's current account state.
    /// An already signed-out device needs no new request. When an expected UID
    /// is supplied, the SDK refuses to sign out a different account.
    pub async fn logout_official_account_and_verify(
        &self,
        expected_uid: Option<i64>,
        options: OperationOptions,
    ) -> Result<OfficialAccountWorkflowReport> {
        self.official_account_workflow(AccountRequest::Logout, expected_uid, options)
            .await
    }

    async fn official_account_workflow(
        &self,
        request: AccountRequest<'_>,
        expected_uid: Option<i64>,
        options: OperationOptions,
    ) -> Result<OfficialAccountWorkflowReport> {
        use OfficialAccountState::{LoggedIn, LoggedOut, Unknown};
        use OfficialAccountWorkflowOutcome as Outcome;
        if expected_uid.is_some_and(|uid| uid <= 0) {
            return Err(Error::InvalidIdentity {
                reason: "an expected official account ID must be positive",
            });
        }
        let context = options.start()?;
        let (method, route, body, desired, operation) = match request {
            AccountRequest::Login(credentials) => (
                reqwest::Method::POST,
                "rest/account/login",
                Some(
                    serde_json::json!({"username":credentials.username,"password":credentials.password}),
                ),
                LoggedIn,
                "log in to native official account",
            ),
            AccountRequest::Logout => (
                reqwest::Method::GET,
                "rest/account/logout",
                None,
                LoggedOut,
                "log out of native official account",
            ),
        };
        let url = self.connection.management_url(route, &[])?;
        let mut report = OfficialAccountWorkflowReport {
            expected_state: desired,
            outcome: Outcome::NotSubmitted,
            write: Default::default(),
            original: None,
            before: None,
            observed: None,
            observation_error: None,
        };
        let dispatch = context.started
            + context
                .deadline
                .duration_since(context.started)
                .mul_f64(2.0 / 3.0);
        let mut guard = None;
        let attempt = context
            .wait(dispatch, operation, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.connection.mutation_lock.lock().await);
                let before = self.official_account_status().await?;
                let state = before.state();
                let exact_uid = expected_uid.is_some_and(|uid| before.user_id() == Some(uid));
                let already = state == desired && (desired == LoggedOut || exact_uid);
                report.before = Some(before);
                if already {
                    return Ok(None);
                }
                if state == Unknown
                    || (state == LoggedIn
                        && (desired == LoggedIn || (expected_uid.is_some() && !exact_uid)))
                {
                    return Err(Error::InvalidConfiguration {
                        reason: "the current account does not match the authorized account change",
                    });
                }
                if tokio::time::Instant::now() >= dispatch {
                    return Err(Error::Timeout { operation });
                }
                let request = self
                    .connection
                    .authorized_request(method, url, body.as_ref());
                let response = self
                    .connection
                    .send_workflow_write(operation, request, &context, &mut report.write)
                    .await?;
                account_acknowledgement(operation, response.status, response.body).map(Some)
            })
            .await;
        match workflow_write_result(operation, report.write, attempt) {
            Ok(None) => report.outcome = Outcome::AlreadyMatches,
            attempted => {
                report.original = Some(attempted.and_then(|ack| {
                    ack.ok_or(Error::ManagedFailure {
                        reason: "the account workflow did not retain its acknowledgement",
                    })
                }));
                if report.write.response_complete
                    && matches!(
                        report.original,
                        Some(Err(Error::Authentication { .. }
                            | Error::AccessDenied { .. }
                            | Error::OfficialAccountRejected { .. }))
                    )
                {
                    report.outcome = Outcome::Rejected;
                } else if report.write.dispatched {
                    context.phase(OperationPhase::Verifying);
                    match context
                        .wait(
                            context.deadline,
                            "check the current official account",
                            self.official_account_status(),
                        )
                        .await
                    {
                        Ok(observed) => {
                            let state = observed.state();
                            let acknowledged = matches!(report.original, Some(Ok(_)));
                            report.outcome = match state {
                                Unknown => Outcome::Unconfirmed,
                                state if state != desired => Outcome::CurrentDiffers,
                                LoggedOut => Outcome::CurrentMatches,
                                LoggedIn => match expected_uid {
                                    Some(uid) if observed.user_id() != Some(uid) => {
                                        Outcome::CurrentDiffers
                                    }
                                    Some(_) => Outcome::CurrentMatches,
                                    None if acknowledged => Outcome::CurrentMatches,
                                    None => Outcome::Unconfirmed,
                                },
                            };
                            report.observed = Some(observed);
                        }
                        Err(source) => {
                            report.outcome = Outcome::Unconfirmed;
                            report.observation_error = Some(source);
                        }
                    }
                }
            }
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
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
        let acknowledgement = account_acknowledgement(operation, status, bytes)?;
        let observed = self
            .official_account_status()
            .await
            .map_err(|error| mutation_error(operation, true, error))?;
        Ok(OfficialAccountChange {
            expected_state_matches: observed.state() == expected,
            status: observed,
            acknowledgement,
        })
    }
}

fn account_acknowledgement(
    operation: &'static str,
    status: u16,
    bytes: Vec<u8>,
) -> Result<ResponseDiagnostic> {
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
    Ok(ResponseDiagnostic::new(status, bytes))
}
