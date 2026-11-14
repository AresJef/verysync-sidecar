//! Native folder type, block/copy strategy and extended-attribute filters.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

/// Explicit native selector. A stored value is not proof of data-path effects.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub enum FolderType {
    /// Native bidirectional folder type.
    #[serde(rename = "sendreceive")]
    SendReceive,
    /// Native send-only folder type.
    #[serde(rename = "sendonly")]
    SendOnly,
    /// Native receive-only folder type.
    #[serde(rename = "receiveonly")]
    ReceiveOnly,
    /// Initial receive-encrypted type; existing transitions to or from it are refused.
    #[serde(rename = "receiveencrypted")]
    ReceiveEncrypted,
    /// Unknown native readback; typed edits reject it.
    #[serde(untagged)]
    Unknown(String),
}
impl FolderType {
    pub(crate) fn native_name(&self) -> &str {
        match self {
            Self::SendReceive => "sendreceive",
            Self::SendOnly => "sendonly",
            Self::ReceiveOnly => "receiveonly",
            Self::ReceiveEncrypted => "receiveencrypted",
            Self::Unknown(v) => v,
        }
    }
}
impl fmt::Debug for FolderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SendReceive => f.write_str("FolderType::SendReceive"),
            Self::SendOnly => f.write_str("FolderType::SendOnly"),
            Self::ReceiveOnly => f.write_str("FolderType::ReceiveOnly"),
            Self::ReceiveEncrypted => f.write_str("FolderType::ReceiveEncrypted"),
            Self::Unknown(_) => f.write_str("FolderType::Unknown([REDACTED])"),
        }
    }
}

/// Explicit native selector. A stored value is not proof of data-path effects.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub enum BlockPullOrder {
    /// Native standard block selection.
    #[serde(rename = "standard")]
    Standard,
    /// Native random block selection.
    #[serde(rename = "random")]
    Random,
    /// Native sequential block selection.
    #[serde(rename = "inOrder")]
    InOrder,
    /// Unknown native readback; typed edits reject it.
    #[serde(untagged)]
    Unknown(String),
}
impl fmt::Debug for BlockPullOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Standard => f.write_str("BlockPullOrder::Standard"),
            Self::Random => f.write_str("BlockPullOrder::Random"),
            Self::InOrder => f.write_str("BlockPullOrder::InOrder"),
            Self::Unknown(_) => f.write_str("BlockPullOrder::Unknown([REDACTED])"),
        }
    }
}

/// Explicit native selector. A stored value is not proof of data-path effects.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub enum CopyRangeMethod {
    /// Native standard copy selection.
    #[serde(rename = "standard")]
    Standard,
    /// Native copy_file_range selection; actual OS use is separate.
    #[serde(rename = "copy_file_range")]
    CopyFileRange,
    /// Native ioctl selection; actual filesystem support is separate.
    #[serde(rename = "ioctl")]
    Ioctl,
    /// Native sendfile selection; actual OS use is separate.
    #[serde(rename = "sendfile")]
    Sendfile,
    /// Native duplicate-extents selection; actual filesystem support is separate.
    #[serde(rename = "duplicate_extents")]
    DuplicateExtents,
    /// Native selection of its available strategies and fallback policy.
    #[serde(rename = "all")]
    All,
    /// Unknown native readback; typed edits reject it.
    #[serde(untagged)]
    Unknown(String),
}
impl fmt::Debug for CopyRangeMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Standard => f.write_str("CopyRangeMethod::Standard"),
            Self::CopyFileRange => f.write_str("CopyRangeMethod::CopyFileRange"),
            Self::Ioctl => f.write_str("CopyRangeMethod::Ioctl"),
            Self::Sendfile => f.write_str("CopyRangeMethod::Sendfile"),
            Self::DuplicateExtents => f.write_str("CopyRangeMethod::DuplicateExtents"),
            Self::All => f.write_str("CopyRangeMethod::All"),
            Self::Unknown(_) => f.write_str("CopyRangeMethod::Unknown([REDACTED])"),
        }
    }
}

/// One ordered native extended-attribute name rule. Target pattern semantics
/// apply; the SDK does not reinterpret it as a controller regular expression.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct ExtendedAttributeRule {
    #[serde(rename = "match")]
    pattern: String,
    permit: bool,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}
impl ExtendedAttributeRule {
    /// Retain a nonempty bounded native pattern and its explicit permit flag.
    pub fn new(pattern: impl Into<String>, permit: bool) -> Result<Self> {
        let value = Self {
            pattern: pattern.into(),
            permit,
            extra: BTreeMap::new(),
        };
        value.validate()?;
        Ok(value)
    }
    /// Explicitly inspect the exact target pattern.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
    /// Whether this rule permits matching target attributes.
    pub fn permits(&self) -> bool {
        self.permit
    }
    fn validate(&self) -> Result<()> {
        if self.pattern.is_empty()
            || self.pattern.len() > 4096
            || self.pattern.chars().any(char::is_control)
        {
            return Err(invalid(
                "extended-attribute pattern exceeds its text bounds",
            ));
        }
        Ok(())
    }
}
impl fmt::Debug for ExtendedAttributeRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtendedAttributeRule")
            .field("permit", &self.permit)
            .finish_non_exhaustive()
    }
}
/// Ordered native attribute rules and explicit size selectors. Actual metadata
/// collection/transfer and filesystem support are independently observable.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct ExtendedAttributeFilter {
    entries: Vec<ExtendedAttributeRule>,
    #[serde(rename = "maxSingleEntrySize")]
    max_single_entry_size: u32,
    #[serde(rename = "maxTotalSize")]
    max_total_size: u32,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}
impl ExtendedAttributeFilter {
    /// Choose 0..=512 ordered rules and native byte-size selectors. Zero values
    /// retain native interpretation; the SDK does not reserve memory or space.
    pub fn new(
        entries: Vec<ExtendedAttributeRule>,
        max_single_entry_size: u32,
        max_total_size: u32,
    ) -> Result<Self> {
        let value = Self {
            entries,
            max_single_entry_size,
            max_total_size,
            extra: BTreeMap::new(),
        };
        value.validate()?;
        Ok(value)
    }
    /// Inspect the rules in their original order.
    pub fn rules(&self) -> &[ExtendedAttributeRule] {
        &self.entries
    }
    /// Actual native maximum individual attribute size selector.
    pub fn max_single_entry_size(&self) -> u32 {
        self.max_single_entry_size
    }
    /// Actual native total size selector.
    pub fn max_total_size(&self) -> u32 {
        self.max_total_size
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.entries.len() > 512
            || self.max_single_entry_size > i32::MAX as u32
            || self.max_total_size > i32::MAX as u32
        {
            return Err(invalid(
                "extended-attribute filter exceeds its explicit bounds",
            ));
        }
        for rule in &self.entries {
            rule.validate()?;
        }
        Ok(())
    }
}
impl fmt::Debug for ExtendedAttributeFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtendedAttributeFilter")
            .field("rule_count", &self.entries.len())
            .field("max_single_entry_size", &self.max_single_entry_size)
            .field("max_total_size", &self.max_total_size)
            .finish_non_exhaustive()
    }
}
fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfiguration { reason }
}
