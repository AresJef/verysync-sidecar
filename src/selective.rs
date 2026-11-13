//! Selective index browsing, explicit scopes and unobserved request receipts.
use crate::{Error, PathStyle, ResponseDiagnostic, Result, TargetPath};
use serde::Deserialize;
use std::{collections::BTreeMap, fmt};

/// A whole configured folder or one strictly relative path on its target.
#[derive(Clone)]
pub enum SelectiveScope {
    /// The root of the configured folder, represented by an empty API prefix.
    FolderRoot,
    /// An exact relative file/directory path in the target's syntax.
    Path(TargetPath),
}
impl SelectiveScope {
    pub(crate) fn protocol(&self, style: PathStyle) -> Result<&str> {
        match self {
            Self::FolderRoot => Ok(""),
            Self::Path(path) => crate::scans::validate_subpath(path, style),
        }
    }
}
impl fmt::Debug for SelectiveScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FolderRoot => "SelectiveScope::FolderRoot",
            Self::Path(_) => "SelectiveScope::Path([REDACTED])",
        })
    }
}
/// Explicitly bounded tree browse request. The SDK never follows children.
#[derive(Clone, Debug)]
pub struct SelectiveBrowseOptions {
    pub(crate) scope: SelectiveScope,
    pub(crate) levels: u8,
    pub(crate) directories_only: bool,
}
impl SelectiveBrowseOptions {
    /// Select a scope and one level. SDK depth is bounded to 1..=32.
    pub fn new(scope: SelectiveScope) -> Self {
        Self {
            scope,
            levels: 1,
            directories_only: false,
        }
    }
    /// Choose a nonzero bounded tree depth.
    pub fn levels(mut self, value: u8) -> Self {
        self.levels = value;
        self
    }
    /// Request only directories, without interpreting names as local paths.
    pub fn directories_only(mut self, value: bool) -> Self {
        self.directories_only = value;
        self
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if !(1..=32).contains(&self.levels) {
            return Err(Error::InvalidConfiguration {
                reason: "selective browse depth must be between one and 32",
            });
        }
        Ok(())
    }
}
/// One explicit search page. Cursor and returned paths remain opaque strings.
#[derive(Clone)]
pub struct SelectiveSearchOptions {
    pub(crate) scope: SelectiveScope,
    pub(crate) search: String,
    pub(crate) limit: u16,
    pub(crate) cursor: Option<String>,
    pub(crate) directories_only: bool,
}
impl SelectiveSearchOptions {
    /// Search the whole folder with a default SDK page limit of 100.
    pub fn new(search: impl Into<String>) -> Result<Self> {
        let result = Self {
            scope: SelectiveScope::FolderRoot,
            search: search.into(),
            limit: 100,
            cursor: None,
            directories_only: false,
        };
        result.validate()?;
        Ok(result)
    }
    /// Limit searching to an explicit target scope.
    pub fn scope(mut self, scope: SelectiveScope) -> Self {
        self.scope = scope;
        self
    }
    /// Choose 1..=1000 requested items; the response byte bound still applies.
    pub fn limit(mut self, value: u16) -> Self {
        self.limit = value;
        self
    }
    /// Use the exact opaque cursor returned by a prior page.
    pub fn after_cursor(mut self, value: impl Into<String>) -> Self {
        self.cursor = Some(value.into());
        self
    }
    /// Include only directory matches.
    pub fn directories_only(mut self, value: bool) -> Self {
        self.directories_only = value;
        self
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.search.trim().is_empty()
            || self.search.len() > 4096
            || self.search.contains('\0')
            || !(1..=1000).contains(&self.limit)
            || self
                .cursor
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 16384 || s.contains('\0'))
        {
            return Err(Error::InvalidConfiguration {
                reason: "selective search or page parameters are outside SDK bounds",
            });
        }
        Ok(())
    }
}
impl fmt::Debug for SelectiveSearchOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SelectiveSearchOptions")
            .field("limit", &self.limit)
            .field("has_cursor", &self.cursor.is_some())
            .finish_non_exhaustive()
    }
}
/// An actual index entry. Names, timestamps and extra fields may be private.
#[derive(Clone, Deserialize)]
pub struct SelectiveEntry {
    /// Exact untrusted name; the SDK never joins it to a native filesystem path.
    pub name: String,
    /// Whether the entry is a directory according to the engine.
    #[serde(rename = "isdir")]
    pub is_directory: bool,
    /// Actual modification timestamp, without timezone conversion.
    #[serde(rename = "mtime")]
    pub modified: Option<String>,
    /// Reported byte size; a directory's zero is preserved as reported.
    pub size: Option<u64>,
    /// Actual selective flag; it does not certify a completed download.
    #[serde(rename = "selectived")]
    pub selected: bool,
    /// Actual engine existence observation, not a local SDK filesystem probe.
    #[serde(rename = "exists")]
    pub exists_locally: bool,
    /// Children present within the explicitly requested tree depth.
    #[serde(rename = "entry")]
    pub children: Option<SelectiveTree>,
    /// Additional actual metadata, potentially private.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for SelectiveEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SelectiveEntry")
            .field("is_directory", &self.is_directory)
            .field("selected", &self.selected)
            .field("exists_locally", &self.exists_locally)
            .finish_non_exhaustive()
    }
}
/// Exact tree keys and nodes, with private names omitted from Debug.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct SelectiveTree {
    /// Untrusted engine entry names and their actual metadata.
    pub entries: BTreeMap<String, SelectiveEntry>,
}
impl fmt::Debug for SelectiveTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SelectiveTree")
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}
/// An actual search result with a path in the engine's index namespace.
#[derive(Clone, Deserialize)]
pub struct SelectiveMatch {
    /// Untrusted index-relative path, preserved without host normalization.
    pub path: String,
    /// Actual node fields.
    #[serde(flatten)]
    pub entry: SelectiveEntry,
}
impl fmt::Debug for SelectiveMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SelectiveMatch")
            .field("entry", &self.entry)
            .finish_non_exhaustive()
    }
}
/// One actual search page; has_more is retained even on a full final page.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectiveSearchPage {
    /// Actual explicit search mode marker.
    pub search: bool,
    /// Actual page items, without automatic cursor traversal.
    pub items: Vec<SelectiveMatch>,
    /// Engine continuation flag, not an SDK count estimate.
    pub has_more: bool,
    /// Exact continuation cursor; no native path interpretation.
    pub next_cursor: Option<String>,
    /// Unmodeled values, potentially private.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for SelectiveSearchPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SelectiveSearchPage")
            .field("item_count", &self.items.len())
            .field("has_more", &self.has_more)
            .finish_non_exhaustive()
    }
}
/// Explicit selection intent. Global removal can affect every connected node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectiveAction {
    /// Request selected state.
    Select,
    /// Request deselection without the global-removal flag.
    Deselect,
    /// Request deselection with the explicit removefromall flag.
    RemoveFromAll,
}
/// HTTP acknowledgement only; licensed success schema/effects remain unverified.
#[derive(Debug)]
pub struct SelectiveAcknowledgement {
    /// Actual bounded successful response, explicitly inspectable by the caller.
    pub response: ResponseDiagnostic,
}
/// Actual selective mode settings, distinct from selected files or readiness.
#[derive(Clone, Deserialize)]
pub struct FolderSelectiveConfig {
    /// Actual configured selective-mode switch.
    #[serde(rename = "selectiveEnabled")]
    pub enabled: bool,
    /// Unmodeled fields, potentially including private keys and paths.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for FolderSelectiveConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderSelectiveConfig")
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}
/// Mode readback; this is not proof of authorized selective downloads.
#[derive(Clone, Debug)]
pub struct FolderSelectiveUpdate {
    /// Actual current configuration.
    pub configuration: FolderSelectiveConfig,
    /// Whether the explicitly requested mode matches readback.
    pub requested_mode_match: bool,
}
