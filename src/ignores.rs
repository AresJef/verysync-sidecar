//! Exact engine ignore syntax, without host-path conversion or parser guesses.
use crate::{Error, Result};
use serde::{Deserialize, Deserializer};
use std::{collections::BTreeMap, fmt};

/// Ordered ignore-file lines, including comments and directives.
///
/// These are engine patterns rather than native filesystem paths. The SDK
/// preserves them exactly and checks only input size and line boundaries.
#[derive(Clone)]
pub struct IgnorePatterns(Vec<String>);
impl IgnorePatterns {
    /// Retain at most 4096 lines and 256 KiB of UTF-8 content. Empty is an
    /// explicit replacement with no patterns, distinct from restoring defaults.
    pub fn new(patterns: Vec<String>) -> Result<Self> {
        let bytes = patterns
            .iter()
            .try_fold(0usize, |n, s| n.checked_add(s.len()));
        if patterns.len() > 4096
            || bytes.is_none_or(|n| n > 262_144)
            || patterns.iter().any(|s| s.contains(['\0', '\r', '\n']))
        {
            return Err(Error::InvalidConfiguration {
                reason: "ignore patterns exceed SDK bounds or contain embedded line terminators",
            });
        }
        Ok(Self(patterns))
    }
    /// Exact ordered lines; glob/path syntax remains the engine's responsibility.
    pub fn patterns(&self) -> &[String] {
        &self.0
    }
}
impl fmt::Debug for IgnorePatterns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IgnorePatterns")
            .field("line_count", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Actual ignore-file state, including a reported parsing failure.
#[derive(Clone, Deserialize)]
pub struct IgnoreSnapshot {
    /// Actual file lines. The engine returns null for an explicitly empty file.
    #[serde(rename = "ignore", deserialize_with = "nullable_lines")]
    pub patterns: Option<Vec<String>>,
    /// Actual expanded engine patterns, without SDK normalization.
    #[serde(rename = "expanded")]
    pub expanded_patterns: Vec<String>,
    /// Actual parser error, potentially containing private patterns or paths.
    #[serde(rename = "error", deserialize_with = "nullable_error")]
    pub parse_error: Option<String>,
    /// Unmodeled values, potentially private.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
fn nullable_lines<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Vec<String>>, D::Error> {
    Option::<Vec<String>>::deserialize(d)
}
fn nullable_error<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}
impl fmt::Debug for IgnoreSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IgnoreSnapshot")
            .field("line_count", &self.patterns.as_ref().map(Vec::len))
            .field("expanded_count", &self.expanded_patterns.len())
            .field("has_parse_error", &self.parse_error.is_some())
            .finish_non_exhaustive()
    }
}
/// A parsed replacement and separately observed current file lines.
#[derive(Clone, Debug)]
pub struct IgnoreUpdate {
    /// Fresh state read after the modifying response.
    pub snapshot: IgnoreSnapshot,
    /// Exact ordered input equality; a returned null matches only empty input.
    pub requested_patterns_match: bool,
}
