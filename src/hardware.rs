//! Private target hardware observations from the selected native program.
use serde::Deserialize;
use std::{collections::BTreeMap, fmt};
/// Native physical CPU inventory, without a performance interpretation.
#[derive(Clone, Deserialize)]
pub struct NativeCpuHardware {
    /// Native physical core count.
    pub total_cores: u32,
    /// Native hardware thread count.
    pub total_threads: u32,
    /// Native packages; null entries remain unknown.
    pub processors: Option<Vec<Option<NativeCpuPackage>>>,
    /// Other private native fields, retained without interpretation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for NativeCpuHardware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeCpuHardware").finish_non_exhaustive()
    }
}
/// One native CPU package; private labels are omitted from Debug.
#[derive(Clone, Deserialize)]
pub struct NativeCpuPackage {
    /// Native package identifier, not a vector index.
    pub id: i64,
    /// Native package physical cores.
    pub total_cores: u32,
    /// Native package hardware threads.
    pub total_threads: u32,
    /// Private native vendor text.
    pub vendor: String,
    /// Private native model text.
    pub model: String,
    /// Native capability labels, without enabling features.
    pub capabilities: Option<Vec<String>>,
    /// Native core records; null entries are retained.
    pub cores: Option<Vec<Option<NativeCpuCore>>>,
    /// Other private native fields, retained without interpretation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for NativeCpuPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeCpuPackage").finish_non_exhaustive()
    }
}
/// One native physical core observation.
#[derive(Clone, Deserialize)]
pub struct NativeCpuCore {
    /// Native physical core identifier.
    pub id: i64,
    /// Native thread count for this core.
    pub total_threads: u32,
    /// Native logical processor identifiers, when reported.
    pub logical_processors: Option<Vec<i64>>,
    /// Other private native fields, retained without interpretation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for NativeCpuCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeCpuCore").finish_non_exhaustive()
    }
}
/// Native physical memory inventory; unavailable native backends return an error.
#[derive(Clone, Deserialize)]
pub struct NativeMemoryHardware {
    /// Exact native physical bytes; negative unknown markers are retained.
    pub total_physical_bytes: i64,
    /// Exact native usable bytes, not controller free memory.
    pub total_usable_bytes: i64,
    /// Native supported page sizes in bytes.
    pub supported_page_sizes: Option<Vec<u64>>,
    /// Native module records; absence and null entries are preserved.
    pub modules: Option<Vec<Option<NativeMemoryModule>>>,
    /// Other private native fields, retained without interpretation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for NativeMemoryHardware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeMemoryHardware")
            .finish_non_exhaustive()
    }
}
/// One native memory module observation.
#[derive(Clone, Deserialize)]
pub struct NativeMemoryModule {
    /// Private native module label.
    pub label: String,
    /// Native slot description, not a filesystem path.
    pub location: String,
    /// Private native module serial number.
    pub serial_number: String,
    /// Exact native bytes, retaining negative unknown markers.
    pub size_bytes: i64,
    /// Private native manufacturer text.
    pub vendor: String,
    /// Other private native fields, retained without interpretation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for NativeMemoryModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeMemoryModule").finish_non_exhaustive()
    }
}
/// Native block inventory; totals are not a free-space or unique-capacity estimate.
#[derive(Clone, Deserialize)]
pub struct NativeBlockHardware {
    /// Exact native aggregate bytes, without recomputing or deduplicating.
    pub total_size_bytes: u64,
    /// Native disk records; null observations remain unknown.
    pub disks: Option<Vec<Option<NativeBlockDisk>>>,
    /// Other private native fields, retained without interpretation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for NativeBlockHardware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeBlockHardware")
            .finish_non_exhaustive()
    }
}
/// One native disk observation; names, identifiers and serials remain private.
#[derive(Clone, Deserialize)]
pub struct NativeBlockDisk {
    /// Native disk identifier, not a controller path.
    pub name: String,
    /// Native disk capacity in bytes.
    pub size_bytes: u64,
    /// Native physical block size in bytes.
    pub physical_block_size_bytes: u64,
    /// Exact native drive category, including future spellings.
    pub drive_type: String,
    /// Native removable-device observation.
    pub removable: bool,
    /// Exact native controller category.
    pub storage_controller: String,
    /// Native hardware bus identifier; never used for controller I/O.
    pub bus_path: String,
    /// Private native vendor text.
    pub vendor: String,
    /// Private native disk model.
    pub model: String,
    /// Private native serial number.
    pub serial_number: String,
    /// Private native world-wide identifier.
    pub wwn: String,
    /// Private native world-wide identifier without extension.
    #[serde(rename = "wwnNoExtension")]
    pub wwn_no_extension: String,
    /// Native partition observations, including null entries.
    pub partitions: Option<Vec<Option<NativeBlockPartition>>>,
    /// Other private native fields, retained without interpretation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for NativeBlockDisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeBlockDisk").finish_non_exhaustive()
    }
}
/// One native partition; mount locations retain connected-target path context.
#[derive(Clone, Deserialize)]
pub struct NativeBlockPartition {
    /// Private native partition identifier.
    pub name: String,
    /// Private native partition label.
    pub label: String,
    /// Exact native mount text, accessed explicitly.
    #[serde(rename = "mount_point")]
    pub(crate) native_mount_point: String,
    /// Native partition bytes.
    pub size_bytes: u64,
    /// Exact native partition type.
    #[serde(rename = "type")]
    pub partition_type: String,
    /// Native read-only observation, not an authorization grant.
    pub read_only: bool,
    /// Private native partition or volume identifier.
    pub uuid: String,
    /// Private native filesystem label.
    pub filesystem_label: String,
    #[serde(skip)]
    pub(crate) path_style: Option<crate::PathStyle>,
    /// Other private native fields, retained without interpretation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for NativeBlockPartition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeBlockPartition")
            .finish_non_exhaustive()
    }
}
/// Native NIC inventory; this does not configure interfaces or measure throughput.
#[derive(Clone, Deserialize)]
pub struct NativeNetworkHardware {
    /// Native interfaces, retaining null and unavailable entries.
    pub nics: Option<Vec<Option<NativeNetworkInterface>>>,
    /// Other private native fields, retained without interpretation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for NativeNetworkHardware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeNetworkHardware")
            .finish_non_exhaustive()
    }
}
/// One private native NIC observation.
#[derive(Clone, Deserialize)]
pub struct NativeNetworkInterface {
    /// Native interface name.
    pub name: String,
    /// Private native hardware address.
    pub mac_address: String,
    /// Native virtual-interface observation.
    pub is_virtual: bool,
    /// Native reported capability states.
    pub capabilities: Option<Vec<Option<NativeNicCapability>>>,
    /// Private native PCI identifier, when provided.
    pub pci_address: Option<String>,
    /// Native speed label, without unit conversion or throughput claims.
    pub speed: String,
    /// Exact native duplex text.
    pub duplex: String,
    /// Native supported link labels.
    pub supported_link_modes: Option<Vec<String>>,
    /// Native supported port labels.
    pub supported_ports: Option<Vec<String>>,
    /// Native supported FEC labels.
    pub supported_fec_modes: Option<Vec<String>>,
    /// Native advertised link labels.
    pub advertised_link_modes: Option<Vec<String>>,
    /// Native advertised FEC labels.
    pub advertised_fec_modes: Option<Vec<String>>,
    /// Other private native fields, retained without interpretation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for NativeNetworkInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeNetworkInterface")
            .finish_non_exhaustive()
    }
}
/// One native NIC capability state; this is not a setter.
#[derive(Clone, Deserialize)]
pub struct NativeNicCapability {
    /// Exact native capability name.
    pub name: String,
    /// Native current capability state.
    pub is_enabled: bool,
    /// Native ability observation, without changing it.
    pub can_enable: bool,
    /// Other private native fields, retained without interpretation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl fmt::Debug for NativeNicCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeNicCapability")
            .finish_non_exhaustive()
    }
}
impl NativeBlockPartition {
    /// Read exact native mount text. It can be empty or a native placeholder.
    pub fn native_mount_point(&self) -> &str {
        &self.native_mount_point
    }
    /// Interpret nonempty mount text with the connected target's path syntax.
    /// This does not establish a live mount, expand placeholders, or access files.
    /// Values deserialized outside a Client lack target context and return an error.
    pub fn mount_point(&self) -> crate::Result<Option<crate::TargetPath>> {
        if self.native_mount_point.is_empty() {
            return Ok(None);
        }
        let style = self.path_style.ok_or(crate::Error::InvalidConfiguration {
            reason: "native partition lacks target path context",
        })?;
        crate::TargetPath::remote(style, self.native_mount_point.clone()).map(Some)
    }
}
