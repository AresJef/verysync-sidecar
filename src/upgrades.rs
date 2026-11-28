//! Kernel-managed upgrade metadata, distinct from fixed SDK artifact selection.
use serde::Deserialize;
use std::{collections::BTreeMap, fmt};

use crate::{Error, UpgradeOperationResult, UpgradeReceipt};

/// The original transient error when a second read was considered.
#[derive(Debug)]
#[non_exhaustive]
pub struct FailedUpgradeRead {
    /// What the SDK observed at the first attempt's request boundary.
    pub receipt: UpgradeReceipt,
    /// The first error, including its original typed causes.
    pub source: Error,
}

/// The result of a running engine's release query.
#[derive(Debug)]
#[non_exhaustive]
pub struct UpgradeQueryReport {
    /// The initial failure if the operation entered its bounded retry phase.
    pub first_failed_attempt: Option<FailedUpgradeRead>,
    /// The only or last attempt. Inspect its receipt to see whether it dispatched.
    pub final_attempt: UpgradeOperationResult<KernelUpgradeCheck>,
}

pub(crate) const NO_MATCHING_RELEASE: &[u8] = b"couldn't find a release to download";
pub(crate) fn is_missing_release(response: &crate::ResponseDiagnostic) -> bool {
    response.status() == 500
        && response.body_bytes().strip_suffix(b"\n") == Some(NO_MATCHING_RELEASE)
}

/// The kernel's own provider check. It may use a moving release feed and makes
/// no archive checksum, compatibility or successful installation guarantee.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KernelUpgradeCheck {
    /// Actual running version reported by the upgrade service.
    pub running: String,
    /// Latest version currently returned by the kernel's provider.
    pub latest: String,
    /// Whether the provider reports a newer version.
    pub newer: bool,
    /// Whether the provider reports a newer major version.
    pub major_newer: bool,
    /// Unmodeled provider metadata, potentially private.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for KernelUpgradeCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelUpgradeCheck")
            .field("newer", &self.newer)
            .field("major_newer", &self.major_newer)
            .finish_non_exhaustive()
    }
}
