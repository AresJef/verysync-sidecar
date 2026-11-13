//! Kernel-managed upgrade metadata, distinct from fixed SDK artifact selection.
use serde::Deserialize;
use std::{collections::BTreeMap, fmt};

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
