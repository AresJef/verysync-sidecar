//! Configuration templates and native application state.
mod disk_space;
mod snapshot;
pub use disk_space::{DiskFreeRequirement, DiskSpaceUnit};
use serde::{Deserialize, Serialize};
pub use snapshot::{ConfigurationSnapshot, ConfigurationUpdate};
use std::{collections::BTreeMap, fmt};

/// Current creation template. It is independent of existing folder settings.
///
/// The template may contain an empty ID/path and sharing secrets. Those fields
/// remain in `extra`; actual folder paths are represented by [`crate::TargetPath`]
/// when creating or reading a registered folder. Debug omits template values.
#[derive(Clone, Deserialize, Serialize)]
pub struct FolderDefaults {
    /// Default display label.
    pub label: String,
    /// Default folder pause layer.
    pub paused: bool,
    /// Default periodic rescan interval; zero disables periodic rescanning.
    #[serde(rename = "rescanIntervalS")]
    pub rescan_interval_seconds: u32,
    /// Whether newly registered folders request native filesystem watching.
    #[serde(rename = "fsWatcherEnabled")]
    pub watcher_enabled: bool,
    /// Remaining actual template fields, potentially including secrets.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for FolderDefaults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderDefaults")
            .field("paused", &self.paused)
            .field("rescan_interval_seconds", &self.rescan_interval_seconds)
            .field("watcher_enabled", &self.watcher_enabled)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// Explicit changes to the creation template; omitted fields are never sent.
#[derive(Clone, Default, Serialize)]
pub struct FolderDefaultsPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paused: Option<bool>,
    #[serde(rename = "rescanIntervalS", skip_serializing_if = "Option::is_none")]
    rescan_interval_seconds: Option<u32>,
    #[serde(rename = "fsWatcherEnabled", skip_serializing_if = "Option::is_none")]
    watcher_enabled: Option<bool>,
}
impl FolderDefaultsPatch {
    /// Change the label inherited by subsequent registrations.
    pub fn label(mut self, value: impl Into<String>) -> Self {
        self.label = Some(value.into());
        self
    }
    /// Change the pause setting inherited by subsequent registrations.
    pub fn paused(mut self, value: bool) -> Self {
        self.paused = Some(value);
        self
    }
    /// Set the periodic interval in seconds; zero disables periodic rescanning.
    pub fn rescan_interval_seconds(mut self, value: u32) -> Self {
        self.rescan_interval_seconds = Some(value);
        self
    }
    /// Request filesystem watching for subsequent registrations.
    pub fn watcher_enabled(mut self, value: bool) -> Self {
        self.watcher_enabled = Some(value);
        self
    }
}
impl fmt::Debug for FolderDefaultsPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderDefaultsPatch")
            .field("changes_label", &self.label.is_some())
            .field("paused", &self.paused)
            .field("rescan_interval_seconds", &self.rescan_interval_seconds)
            .field("watcher_enabled", &self.watcher_enabled)
            .finish()
    }
}

/// Actual section readback after one PATCH. This is not a durability receipt.
#[derive(Clone, Debug)]
pub struct ConfigurationSectionUpdate<T> {
    /// Current actual section, including retained upstream fields.
    pub configuration: T,
    /// Every submitted field equals this readback; application is separate.
    pub requested_fields_match: bool,
}

/// General engine options. Runtime scheduling effects require separate observation.
#[derive(Clone, Deserialize, Serialize)]
pub struct GeneralOptions {
    /// Configured retention interval for temporary files, in hours.
    #[serde(rename = "keepTemporariesH")]
    pub keep_temporaries_hours: u32,
    /// Configured progress reporting interval, in seconds.
    #[serde(rename = "progressUpdateIntervalS")]
    pub progress_update_interval_seconds: i64,
    /// Native folder-concurrency setting, including the engine's zero policy.
    #[serde(rename = "maxFolderConcurrency")]
    pub max_folder_concurrency: u32,
    /// Native concurrent-dial setting, including the engine's zero policy.
    #[serde(rename = "maxDialConcurrent")]
    pub max_dial_concurrent: u32,
    /// Native incoming-request budget in KiB, including its zero policy.
    #[serde(rename = "maxConcurrentIncomingRequestKiB")]
    pub max_concurrent_incoming_request_kib: u32,
    /// Whether the engine requests a lower process priority.
    #[serde(rename = "setLowPriority")]
    pub set_low_priority: bool,
    /// Whether the engine requests sleep prevention during synchronization.
    #[serde(rename = "disableSystemSleepOnSync")]
    pub disable_system_sleep_on_sync: bool,
    /// Native minimum free space for configuration/index storage, when reported.
    #[serde(rename = "minHomeDiskFree", skip_serializing_if = "Option::is_none")]
    pub min_home_disk_free: Option<DiskFreeRequirement>,
    /// Minimum temporary-file block count for index publication, when reported.
    #[serde(rename = "tempIndexMinBlocks", skip_serializing_if = "Option::is_none")]
    pub temp_index_min_blocks: Option<u32>,
    /// Native global preference for adopting announced remote names.
    #[serde(
        rename = "overwriteRemoteDeviceNamesOnConnect",
        skip_serializing_if = "Option::is_none"
    )]
    pub overwrite_remote_device_names_on_connect: Option<bool>,
    /// Configured full-index resend on a native program upgrade.
    #[serde(
        rename = "sendFullIndexOnUpgrade",
        skip_serializing_if = "Option::is_none"
    )]
    pub send_full_index_on_upgrade: Option<bool>,
    /// Configured IP traffic-class byte; not proof of OS or router handling.
    #[serde(rename = "trafficClass", skip_serializing_if = "Option::is_none")]
    pub traffic_class: Option<u8>,
    /// Remaining upstream options; values may be private and are omitted by Debug.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for GeneralOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneralOptions")
            .field("keep_temporaries_hours", &self.keep_temporaries_hours)
            .field(
                "progress_update_interval_seconds",
                &self.progress_update_interval_seconds,
            )
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// Partial general options. Matching readback does not establish a throughput,
/// resource-consumption or operating-system power-management guarantee.
#[derive(Clone, Debug, Default, Serialize)]
pub struct GeneralOptionsPatch {
    #[serde(rename = "keepTemporariesH", skip_serializing_if = "Option::is_none")]
    keep_temporaries_hours: Option<u32>,
    #[serde(
        rename = "progressUpdateIntervalS",
        skip_serializing_if = "Option::is_none"
    )]
    progress_update_interval_seconds: Option<i64>,
    #[serde(
        rename = "maxFolderConcurrency",
        skip_serializing_if = "Option::is_none"
    )]
    max_folder_concurrency: Option<u32>,
    #[serde(rename = "maxDialConcurrent", skip_serializing_if = "Option::is_none")]
    max_dial_concurrent: Option<u32>,
    #[serde(
        rename = "maxConcurrentIncomingRequestKiB",
        skip_serializing_if = "Option::is_none"
    )]
    max_concurrent_incoming_request_kib: Option<u32>,
    #[serde(rename = "setLowPriority", skip_serializing_if = "Option::is_none")]
    set_low_priority: Option<bool>,
    #[serde(
        rename = "disableSystemSleepOnSync",
        skip_serializing_if = "Option::is_none"
    )]
    disable_system_sleep_on_sync: Option<bool>,
    #[serde(rename = "minHomeDiskFree", skip_serializing_if = "Option::is_none")]
    min_home_disk_free: Option<DiskFreeRequirement>,
    #[serde(rename = "tempIndexMinBlocks", skip_serializing_if = "Option::is_none")]
    temp_index_min_blocks: Option<u32>,
    #[serde(
        rename = "overwriteRemoteDeviceNamesOnConnect",
        skip_serializing_if = "Option::is_none"
    )]
    overwrite_remote_device_names_on_connect: Option<bool>,
    #[serde(
        rename = "sendFullIndexOnUpgrade",
        skip_serializing_if = "Option::is_none"
    )]
    send_full_index_on_upgrade: Option<bool>,
    #[serde(rename = "trafficClass", skip_serializing_if = "Option::is_none")]
    traffic_class: Option<u8>,
}
impl GeneralOptionsPatch {
    /// Set the engine's temporary-file retention interval in hours.
    pub fn keep_temporaries_hours(mut self, value: u32) -> Self {
        self.keep_temporaries_hours = Some(value);
        self
    }
    /// Set whole seconds, or explicitly select -1 to disable progress reporting.
    pub fn progress_update_interval_seconds(mut self, value: i64) -> Self {
        self.progress_update_interval_seconds = Some(value);
        self
    }
    /// Set native folder concurrency; interpret zero according to the engine.
    pub fn max_folder_concurrency(mut self, value: u32) -> Self {
        self.max_folder_concurrency = Some(value);
        self
    }
    /// Set native dial concurrency; interpret zero according to the engine.
    pub fn max_dial_concurrent(mut self, value: u32) -> Self {
        self.max_dial_concurrent = Some(value);
        self
    }
    /// Set the native incoming request budget in KiB.
    pub fn max_concurrent_incoming_request_kib(mut self, value: u32) -> Self {
        self.max_concurrent_incoming_request_kib = Some(value);
        self
    }
    /// Request the engine's low-priority policy.
    pub fn set_low_priority(mut self, value: bool) -> Self {
        self.set_low_priority = Some(value);
        self
    }
    /// Request the engine's sleep-prevention policy during synchronization.
    pub fn disable_system_sleep_on_sync(mut self, value: bool) -> Self {
        self.disable_system_sleep_on_sync = Some(value);
        self
    }
    /// Select the target configuration/index volume's native free-space threshold.
    pub fn min_home_disk_free(mut self, value: DiskFreeRequirement) -> Self {
        self.min_home_disk_free = Some(value);
        self
    }
    /// Set the native temporary-file index block threshold.
    pub fn temp_index_min_blocks(mut self, value: u32) -> Self {
        self.temp_index_min_blocks = Some(value);
        self
    }
    /// Select the global native remote-name adoption preference.
    pub fn overwrite_remote_device_names_on_connect(mut self, value: bool) -> Self {
        self.overwrite_remote_device_names_on_connect = Some(value);
        self
    }
    /// Select full-index resend after a separately chosen native upgrade.
    pub fn send_full_index_on_upgrade(mut self, value: bool) -> Self {
        self.send_full_index_on_upgrade = Some(value);
        self
    }
    /// Set the native IP traffic-class byte; downstream handling remains separate.
    pub fn traffic_class(mut self, value: u8) -> Self {
        self.traffic_class = Some(value);
        self
    }
    pub(crate) fn validate(&self) -> crate::Result<()> {
        if self
            .progress_update_interval_seconds
            .is_some_and(|s| s < -1)
        {
            return Err(crate::Error::InvalidConfiguration {
                reason: "progress reporting interval must be -1 or nonnegative seconds",
            });
        }
        if let Some(requirement) = &self.min_home_disk_free {
            requirement.validate()?;
        }
        Ok(())
    }
}

/// Native configuration application state, separate from disk persistence.
#[derive(Clone, Deserialize)]
pub struct ConfigurationSyncState {
    /// Engine-reported `configInSync`. False can require an explicit restart.
    /// True does not prove that a save has reached stable storage.
    #[serde(rename = "configInSync")]
    pub config_in_sync: bool,
    /// Other upstream status fields. Debug omits their values.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for ConfigurationSyncState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigurationSyncState")
            .field("config_in_sync", &self.config_in_sync)
            .field("extra_field_count", &self.extra.len())
            .finish_non_exhaustive()
    }
}
