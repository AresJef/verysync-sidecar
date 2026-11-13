//! Folder scan scheduling and strictly relative scan scopes.
use crate::{Error, PathStyle, Result, TargetPath};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, path::Component};

/// Actual scan settings. Readback alone does not prove a watcher is active.
#[derive(Clone, Deserialize)]
pub struct FolderScanConfig {
    /// Automatic full rescan interval in whole seconds; zero disables it.
    #[serde(rename = "rescanIntervalS")]
    pub rescan_interval_seconds: u32,
    /// Whether filesystem notifications are enabled.
    #[serde(rename = "fsWatcherEnabled")]
    pub watcher_enabled: bool,
    /// Notification coalescing delay in seconds, including fractional seconds.
    #[serde(rename = "fsWatcherDelayS")]
    pub watcher_delay_seconds: f64,
    /// Configured watcher timeout in whole seconds.
    #[serde(rename = "fsWatcherTimeoutS")]
    pub watcher_timeout_seconds: u32,
    /// Scan progress reporting interval; minus one retains the upstream default.
    #[serde(rename = "scanProgressIntervalS")]
    pub progress_interval_seconds: i32,
    /// Whether the initial scan is disabled.
    #[serde(rename = "disableInitialScan")]
    pub disable_initial_scan: bool,
    /// Additional actual fields, potentially including private configuration.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for FolderScanConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderScanConfig")
            .field("rescan_interval_seconds", &self.rescan_interval_seconds)
            .field("watcher_enabled", &self.watcher_enabled)
            .field("watcher_delay_seconds", &self.watcher_delay_seconds)
            .finish_non_exhaustive()
    }
}

/// Partial scan-setting update. Unselected fields are never submitted.
#[derive(Clone, Debug, Default, Serialize)]
pub struct FolderScanPatch {
    #[serde(rename = "rescanIntervalS", skip_serializing_if = "Option::is_none")]
    rescan: Option<u32>,
    #[serde(rename = "fsWatcherEnabled", skip_serializing_if = "Option::is_none")]
    watcher: Option<bool>,
    #[serde(rename = "fsWatcherDelayS", skip_serializing_if = "Option::is_none")]
    delay: Option<f64>,
    #[serde(rename = "fsWatcherTimeoutS", skip_serializing_if = "Option::is_none")]
    timeout: Option<u32>,
    #[serde(
        rename = "scanProgressIntervalS",
        skip_serializing_if = "Option::is_none"
    )]
    progress: Option<i32>,
    #[serde(rename = "disableInitialScan", skip_serializing_if = "Option::is_none")]
    disable_initial: Option<bool>,
}
impl FolderScanPatch {
    /// Set the periodic scan interval; zero explicitly disables periodic scans.
    pub fn rescan_interval_seconds(mut self, value: u32) -> Self {
        self.rescan = Some(value);
        self
    }
    /// Enable or disable filesystem notifications.
    pub fn watcher(mut self, value: bool) -> Self {
        self.watcher = Some(value);
        self
    }
    /// Set notification coalescing delay in seconds.
    pub fn watcher_delay_seconds(mut self, value: f64) -> Self {
        self.delay = Some(value);
        self
    }
    /// Set the watcher timeout in whole seconds, preserving zero as submitted.
    pub fn watcher_timeout_seconds(mut self, value: u32) -> Self {
        self.timeout = Some(value);
        self
    }
    /// Set scan progress reporting interval; minus one selects the default.
    pub fn progress_interval_seconds(mut self, value: i32) -> Self {
        self.progress = Some(value);
        self
    }
    /// Explicitly enable or disable the initial scan.
    pub fn disable_initial_scan(mut self, value: bool) -> Self {
        self.disable_initial = Some(value);
        self
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.rescan.is_none()
            && self.watcher.is_none()
            && self.delay.is_none()
            && self.timeout.is_none()
            && self.progress.is_none()
            && self.disable_initial.is_none()
        {
            return Err(Error::InvalidConfiguration {
                reason: "scan patch must contain at least one field",
            });
        }
        if self.rescan.is_some_and(|x| x > i32::MAX as u32)
            || self.timeout.is_some_and(|x| x > i32::MAX as u32)
            || self
                .delay
                .is_some_and(|x| !x.is_finite() || !(0.0..=f64::from(i32::MAX)).contains(&x))
            || self.progress.is_some_and(|x| x < -1)
        {
            return Err(Error::InvalidConfiguration {
                reason: "scan interval is outside the supported numeric range",
            });
        }
        Ok(())
    }
    pub(crate) fn matches(&self, v: &FolderScanConfig) -> bool {
        self.rescan.is_none_or(|x| x == v.rescan_interval_seconds)
            && self.watcher.is_none_or(|x| x == v.watcher_enabled)
            && self.delay.is_none_or(|x| x == v.watcher_delay_seconds)
            && self.timeout.is_none_or(|x| x == v.watcher_timeout_seconds)
            && self
                .progress
                .is_none_or(|x| x == v.progress_interval_seconds)
            && self
                .disable_initial
                .is_none_or(|x| x == v.disable_initial_scan)
    }
}
/// Setting readback, with no claim of scan completion or watcher readiness.
#[derive(Clone, Debug)]
pub struct FolderScanUpdate {
    /// Actual settings read after one mutation.
    pub configuration: FolderScanConfig,
    /// Whether all explicitly requested fields match actual readback.
    pub requested_fields_match: bool,
}

pub(crate) fn validate_subpath(path: &TargetPath, style: PathStyle) -> Result<&str> {
    let invalid = || Error::InvalidPath {
        reason:
            "scan subpaths must be nonempty relative target paths without parent or root components",
    };
    if path.style() != style {
        return Err(invalid());
    }
    let text = path.to_protocol()?;
    if let Some(native) = path.local_path() {
        if native
            .components()
            .any(|x| !matches!(x, Component::Normal(_)))
        {
            return Err(invalid());
        }
    } else {
        let separator = |c| c == '/' || (style == PathStyle::Windows && c == '\\');
        if text.starts_with(separator)
            || (style == PathStyle::Windows && text.contains(':'))
            || text
                .split(separator)
                .any(|x| x.is_empty() || x == "." || x == "..")
        {
            return Err(invalid());
        }
    }
    Ok(text)
}
