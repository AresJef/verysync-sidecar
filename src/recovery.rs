//! A marker-service acknowledgement, separate from filesystem recovery.
use serde::Deserialize;
use std::{collections::BTreeMap, fmt};

/// The fixed engine's marker-repair response. Success reports the service's
/// acknowledgement; observe folder state/files separately for actual recovery.
#[derive(Clone, Deserialize)]
pub struct MarkerRepairResult {
    /// Actual engine success flag. The typed method rejects false responses.
    pub success: bool,
    /// Actual error text, potentially containing private paths; hidden in Debug.
    pub error: String,
    /// Unmodeled fields, potentially private.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for MarkerRepairResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MarkerRepairResult")
            .field("success", &self.success)
            .field("has_error", &!self.error.is_empty())
            .finish_non_exhaustive()
    }
}
