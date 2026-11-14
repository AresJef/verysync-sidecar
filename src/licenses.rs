//! Native license observations and explicitly selected license requests.
use crate::ResponseDiagnostic;
use serde::Deserialize;
use std::{collections::BTreeMap, fmt};

/// Comparison of a reported expiry with one caller-supplied Unix-second value.
/// This is not a verdict about signatures, scope, machine binding or revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LicenseExpiry {
    /// The native zero expiry uses the fixed GUI's permanent-license convention.
    Perpetual,
    /// The reported nonzero expiry is later than the supplied reference.
    NotExpired,
    /// The reported nonzero expiry is at or before the supplied reference.
    Expired,
}

/// One native license record. Unreported fields stay absent; unknown data and
/// subjects remain explicit, private observations rather than inferred rights.
#[derive(Clone, Deserialize)]
pub struct LicenseRecord {
    subject: String,
    #[serde(rename = "expire")]
    expires: Option<i64>,
    issued_at: Option<i64>,
    trial: Option<bool>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}
impl LicenseRecord {
    /// Exact native subject. Only the literal `Pro` has a fixed-GUI mapping here.
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// Whether the subject is exactly `Pro`, independent of actual applicability.
    pub fn is_pro(&self) -> bool {
        self.subject == "Pro"
    }
    /// Exact optional native expiry in Unix seconds; zero is kept as zero.
    pub fn expires_unix_seconds(&self) -> Option<i64> {
        self.expires
    }
    /// Exact optional native issue time in Unix seconds.
    pub fn issued_unix_seconds(&self) -> Option<i64> {
        self.issued_at
    }
    /// Explicit native trial flag; absence is not a fabricated false value.
    pub fn trial(&self) -> Option<bool> {
        self.trial
    }
    /// Compare the reported expiry with an explicit reference. No controller or
    /// target clock is read and no licensed control is enabled or exercised.
    pub fn expiry_at(&self, unix_seconds: i64) -> Option<LicenseExpiry> {
        self.expires.map(|expiry| {
            if expiry == 0 {
                LicenseExpiry::Perpetual
            } else if expiry > unix_seconds {
                LicenseExpiry::NotExpired
            } else {
                LicenseExpiry::Expired
            }
        })
    }
    /// Explicit private fields, potentially including signed authorization data.
    pub fn extra(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.extra
    }
}
impl fmt::Debug for LicenseRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LicenseRecord")
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// Preserve the native collection container without converting opaque map keys
/// into list indexes. Nonempty licensed list/map shapes have synthetic contract
/// coverage; real authorized schema/effect validation remains separate.
#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub enum LicenseEntries {
    /// Explicit native list order.
    List(Vec<LicenseRecord>),
    /// Explicit native opaque keys; keys and values can contain private context.
    Map(BTreeMap<String, LicenseRecord>),
    /// An explicitly reported null container, distinct from an absent field.
    Null,
}
impl fmt::Debug for LicenseEntries {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::List(v) => f
                .debug_struct("LicenseEntries::List")
                .field("count", &v.len())
                .finish(),
            Self::Map(v) => f
                .debug_struct("LicenseEntries::Map")
                .field("count", &v.len())
                .finish(),
            Self::Null => f.write_str("LicenseEntries::Null"),
        }
    }
}

/// Fresh native `myLicense` data, independent of account state and Pro controls.
#[derive(Clone, Deserialize)]
#[serde(try_from = "BTreeMap<String, serde_json::Value>")]
pub struct LicenseStatus {
    licenses: Option<LicenseEntries>,
    extra: BTreeMap<String, serde_json::Value>,
}
impl TryFrom<BTreeMap<String, serde_json::Value>> for LicenseStatus {
    type Error = &'static str;
    fn try_from(mut value: BTreeMap<String, serde_json::Value>) -> Result<Self, Self::Error> {
        let licenses = value
            .remove("licenses")
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| "invalid native license collection")?;
        Ok(Self {
            licenses,
            extra: value,
        })
    }
}
impl LicenseStatus {
    /// Reported collection; absence is not a positive/negative entitlement check.
    pub fn licenses(&self) -> Option<&LicenseEntries> {
        self.licenses.as_ref()
    }
    /// Explicit private native metadata. Debug omits values and personal bindings.
    pub fn extra(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.extra
    }
}
impl fmt::Debug for LicenseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LicenseStatus")
            .field("licenses", &self.licenses)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// The explicit changing license request selected by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LicenseRequestKind {
    /// Ask the native core to refresh its license data.
    Refresh,
    /// Explicitly request a Pro trial; this can consume trial eligibility.
    ProTrial,
}
/// A native acknowledgement plus a fresh license observation, without a promise
/// that a trial was issued, a signature is valid or any paid feature now works.
#[derive(Debug)]
pub struct LicenseChange {
    /// Actual explicit request kind.
    pub request: LicenseRequestKind,
    /// Actual identity-checked post-request metadata.
    pub status: LicenseStatus,
    /// Bounded private acknowledgement bytes, omitted by ordinary formatting.
    pub acknowledgement: ResponseDiagnostic,
}
