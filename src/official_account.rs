//! Official VerySync accounts, separate from local GUI authentication.
use crate::{Error, ManagementWriteEvidence, OperationCompletion, ResponseDiagnostic, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// Explicit credentials sent to the selected core's official-account login.
/// The native core can contact VerySync's account service and persist a session.
/// Ordinary formatting omits both values; this is not a GUI cookie or API key.
#[derive(Serialize)]
pub struct OfficialAccountCredentials {
    pub(crate) username: String,
    pub(crate) password: String,
}
impl OfficialAccountCredentials {
    /// Preserve a nonblank username of at most 1024 bytes and a nonempty password
    /// of at most 4096 bytes. Usernames cannot contain controls; passwords cannot
    /// contain NUL. No trimming, hashing, login, registration or consent occurs.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Result<Self> {
        let (username, password) = (username.into(), password.into());
        if username.is_empty()
            || username.len() > 1024
            || username.chars().all(char::is_whitespace)
            || username.chars().any(char::is_control)
            || password.is_empty()
            || password.len() > 4096
            || password.contains('\0')
        {
            return Err(Error::InvalidConfiguration {
                reason: "official account credentials exceed the documented input bounds",
            });
        }
        Ok(Self { username, password })
    }
}
impl fmt::Debug for OfficialAccountCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfficialAccountCredentials")
            .finish_non_exhaustive()
    }
}

/// An observed native official-account state, independent of GUI authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfficialAccountState {
    /// The native account object is empty or explicitly reports a nonpositive UID.
    LoggedOut,
    /// The native account reports a positive UID, matching the fixed GUI's test.
    /// This is not proof that a cloud token is still valid or a license applies.
    LoggedIn,
    /// A nonempty future account shape has no usable UID.
    Unknown,
}

/// A fresh identity-checked account object reported by the native core.
/// Personal identifiers and unmodeled session values require explicit access.
#[derive(Clone, Deserialize)]
#[serde(try_from = "BTreeMap<String, serde_json::Value>")]
pub struct OfficialAccountStatus {
    user_id: Option<i64>,
    extra: BTreeMap<String, serde_json::Value>,
}
impl TryFrom<BTreeMap<String, serde_json::Value>> for OfficialAccountStatus {
    type Error = &'static str;
    fn try_from(
        mut value: BTreeMap<String, serde_json::Value>,
    ) -> std::result::Result<Self, Self::Error> {
        let user_id = match value.remove("uid") {
            None => None,
            Some(serde_json::Value::Null) => {
                value.insert("uid".to_owned(), serde_json::Value::Null);
                None
            }
            Some(serde_json::Value::Number(n)) => Some(
                n.as_i64()
                    .ok_or("VerySync did not provide a valid numeric account ID.")?,
            ),
            Some(_) => return Err("VerySync did not provide a valid numeric account ID."),
        };
        Ok(Self {
            user_id,
            extra: value,
        })
    }
}
impl OfficialAccountStatus {
    /// Classify only the reported UID/empty-object conditions, without a cloud call.
    pub fn state(&self) -> OfficialAccountState {
        match self.user_id {
            Some(id) if id > 0 => OfficialAccountState::LoggedIn,
            Some(_) => OfficialAccountState::LoggedOut,
            None if self.extra.is_empty() => OfficialAccountState::LoggedOut,
            None => OfficialAccountState::Unknown,
        }
    }
    /// Explicitly inspect the native personal UID; absent is not a fabricated zero.
    pub fn user_id(&self) -> Option<i64> {
        self.user_id
    }
    /// Explicit private native fields, potentially including session data.
    pub fn extra(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.extra
    }
}
impl fmt::Debug for OfficialAccountStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfficialAccountStatus")
            .field("state", &self.state())
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// One native account acknowledgement followed by a fresh account observation.
/// HTTP acknowledgement is separate from the observed requested state, live
/// cloud authentication, license refresh and persistence across a restart.
#[derive(Debug)]
pub struct OfficialAccountChange {
    /// Actual identity-checked post-request account state.
    pub status: OfficialAccountStatus,
    /// Whether readback reports LoggedIn for login or LoggedOut for logout.
    pub expected_state_matches: bool,
    /// Bounded private native response bytes, omitted by ordinary formatting.
    pub acknowledgement: ResponseDiagnostic,
}

/// The result of changing the account reported by the selected VerySync device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OfficialAccountWorkflowOutcome {
    /// The selected account state already matched and no request was needed.
    AlreadyMatches,
    /// The device now reports the requested state and, when given, account ID.
    CurrentMatches,
    /// The device reports another account or a different state.
    CurrentDiffers,
    /// The workflow stopped before submitting an account change.
    NotSubmitted,
    /// A complete reply reported a refusal.
    Rejected,
    /// There is insufficient evidence to confirm the requested state.
    Unconfirmed,
}

/// The original request, its response boundary, and the selected device's
/// current official account. The report contains no credentials or replay authority.
#[derive(Debug)]
#[non_exhaustive]
pub struct OfficialAccountWorkflowReport {
    /// Local account state requested by the application.
    pub expected_state: OfficialAccountState,
    /// What the SDK could verify.
    pub outcome: OfficialAccountWorkflowOutcome,
    /// Dispatch and response facts about the one optional native request.
    pub write: ManagementWriteEvidence,
    /// Preflight failure, complete acknowledgement or original dispatch error.
    pub original: Option<Result<ResponseDiagnostic>>,
    /// Device account snapshot before any request.
    pub before: Option<OfficialAccountStatus>,
    /// Authenticated account readback after the request, if available.
    pub observed: Option<OfficialAccountStatus>,
    /// Reason no trustworthy account readback was available.
    pub observation_error: Option<Error>,
}

impl OfficialAccountWorkflowReport {
    /// Summarize the selected device's account state without asserting a live
    /// provider session or any paid rights.
    pub fn completion(&self) -> OperationCompletion {
        match self.outcome {
            OfficialAccountWorkflowOutcome::AlreadyMatches
            | OfficialAccountWorkflowOutcome::CurrentMatches => OperationCompletion::Completed,
            OfficialAccountWorkflowOutcome::Unconfirmed => OperationCompletion::Unconfirmed,
            _ => OperationCompletion::GoalNotMet,
        }
    }
}

impl fmt::Display for OfficialAccountWorkflowReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match self.outcome {
            OfficialAccountWorkflowOutcome::AlreadyMatches => "The selected device already reports the requested account state.",
            OfficialAccountWorkflowOutcome::CurrentMatches => "The selected device now reports the requested account state.",
            OfficialAccountWorkflowOutcome::CurrentDiffers => "The selected device reports a different account or sign-in state. Check its account settings before trying again.",
            OfficialAccountWorkflowOutcome::NotSubmitted => "The call ended before sending an account change.",
            OfficialAccountWorkflowOutcome::Rejected => "VerySync declined the account change. Check the sign-in details and permissions for this device.",
            OfficialAccountWorkflowOutcome::Unconfirmed => "The requested account state could not be confirmed. Check the account on the selected device before trying again.",
        };
        f.write_str(state)?;
        if self.outcome == OfficialAccountWorkflowOutcome::NotSubmitted {
            if let Some(Err(source)) = &self.original {
                write!(f, " {source}")?;
            }
        }
        Ok(())
    }
}
