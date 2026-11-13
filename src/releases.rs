//! Fixed official artifact identities, distinct from controller/runtime support.
use crate::{Error, Result, BASELINE_ENGINE_VERSION};
use serde::Deserialize;
use url::Url;

/// An explicitly pinned numeric upstream version. No moving version selectors.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PinnedVersion(String);
impl PinnedVersion {
    /// Accept canonical vMAJOR.MINOR.PATCH; this does not add it to the catalog.
    pub fn new(value: &str) -> Result<Self> {
        if value.len() > 33 {
            return Err(Error::InvalidConfiguration {
                reason: "version exceeds canonical numeric component bounds",
            });
        }
        let parts: Vec<_> = value.strip_prefix('v').unwrap_or("").split('.').collect();
        if parts.len() != 3
            || parts.iter().any(|p| {
                p.is_empty()
                    || !p.bytes().all(|b| b.is_ascii_digit())
                    || (p.len() > 1 && p.starts_with('0'))
                    || p.parse::<u32>().is_err()
            })
        {
            return Err(Error::InvalidConfiguration {
                reason: "version must be an explicit canonical vMAJOR.MINOR.PATCH",
            });
        }
        Ok(Self(value.to_owned()))
    }
    /// Exact pinned version, including its v prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Official program OS family; independent of the Rust controller's host.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ProgramOs {
    /// Official macOS artifacts (upstream runtime reports darwin).
    MacOs,
    /// Official Windows artifacts.
    Windows,
    /// Official Linux artifacts.
    Linux,
}
impl ProgramOs {
    fn id(self) -> &'static str {
        match self {
            Self::MacOs => "macos",
            Self::Windows => "windows",
            Self::Linux => "linux",
        }
    }
}
/// Exact official architecture labels; ARM families and endianness are distinct.
/// The label alone does not establish libc, floating-point ABI or minimum OS.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ProgramArchitecture {
    /// Official 386 label.
    X86,
    /// Official amd64 label.
    Amd64,
    /// Official arm64 label.
    Arm64,
    /// Official arm label; ABI conditions require separate inspection.
    Arm,
    /// Official armhf label, not an alias of arm or armv6.
    ArmHf,
    /// Official armv6 label.
    ArmV6,
    /// Official mips label.
    Mips,
    /// Official mipsle label.
    MipsLe,
    /// Official mips64 label.
    Mips64,
    /// Official mips64le label.
    Mips64Le,
    /// Official ppc64le label.
    Ppc64Le,
    /// Official riscv64 label.
    RiscV64,
    /// Official s390x label.
    S390x,
    /// Official loong64 label.
    Loong64,
}
impl ProgramArchitecture {
    fn id(self) -> &'static str {
        match self {
            Self::X86 => "386",
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
            Self::Arm => "arm",
            Self::ArmHf => "armhf",
            Self::ArmV6 => "armv6",
            Self::Mips => "mips",
            Self::MipsLe => "mipsle",
            Self::Mips64 => "mips64",
            Self::Mips64Le => "mips64le",
            Self::Ppc64Le => "ppc64le",
            Self::RiscV64 => "riscv64",
            Self::S390x => "s390x",
            Self::Loong64 => "loong64",
        }
    }
}
/// Explicit standard/legacy selection; there is no silent fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum BuildVariant {
    /// Official standard build.
    Standard,
    /// Separately published official legacy build.
    Legacy,
}
impl BuildVariant {
    fn id(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Legacy => "legacy",
        }
    }
}
/// Exact requested program tuple, without guessing from the controller triple.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ProgramTarget {
    os: ProgramOs,
    architecture: ProgramArchitecture,
    variant: BuildVariant,
}
impl ProgramTarget {
    /// Construct a request only. OfficialProgram::select checks listed availability.
    pub fn new(os: ProgramOs, architecture: ProgramArchitecture, variant: BuildVariant) -> Self {
        Self {
            os,
            architecture,
            variant,
        }
    }
    /// Selected official OS family.
    pub fn os(self) -> ProgramOs {
        self.os
    }
    /// Selected exact official architecture family.
    pub fn architecture(self) -> ProgramArchitecture {
        self.architecture
    }
    /// Explicitly selected build family.
    pub fn variant(self) -> BuildVariant {
        self.variant
    }
    /// Catalog identifier, not a native filesystem path.
    pub fn id(self) -> String {
        format!(
            "{}-{}-{}",
            self.os.id(),
            self.architecture.id(),
            self.variant.id()
        )
    }
}
/// Expected archive encoding, not inferred from a caller's local OS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveFormat {
    /// ZIP archive.
    Zip,
    /// gzip-compressed tar archive.
    TarGz,
}
/// Recorded compatibility conditions; a package's existence is not runtime proof.
#[derive(Clone, Debug)]
pub struct ProgramAbi {
    /// Candidate Rust controller triples, distinct from the upstream executable ABI.
    pub controller_target_candidates: Vec<String>,
    /// Actual extent of upstream runtime ABI evidence; unknown remains explicit.
    pub runtime_abi_note: String,
    /// Mapping confidence and remaining validation conditions.
    pub mapping_note: String,
    /// Reported minimum OS family/conditions, not a tested minimum guarantee.
    pub minimum_os_note: String,
    /// Whether the exact minimum OS has separate runtime evidence.
    pub minimum_os_runtime_verified: bool,
}
/// One immutable fixed official artifact, with its archive SHA-256.
/// Construction performs no filesystem access, HTTP request or execution.
#[derive(Clone, Debug)]
pub struct OfficialProgram {
    version: PinnedVersion,
    target: ProgramTarget,
    url: Url,
    filename: String,
    sha256: [u8; 32],
    bytes: u64,
    format: ArchiveFormat,
    executable_name: String,
    abi: ProgramAbi,
}
impl OfficialProgram {
    /// Select a listed version/tuple only; unknown requests never fall back.
    pub fn select(version: &PinnedVersion, target: ProgramTarget) -> Result<Self> {
        if version.as_str() != BASELINE_ENGINE_VERSION {
            return Err(Error::UnlistedProgramVersion);
        }
        official_programs()?
            .into_iter()
            .find(|a| a.target == target)
            .ok_or(Error::UnsupportedProgramTarget { target })
    }
    /// Fixed upstream version.
    pub fn version(&self) -> &PinnedVersion {
        &self.version
    }
    /// Exact official program target, distinct from this controller's host.
    pub fn target(&self) -> ProgramTarget {
        self.target
    }
    /// Fixed official HTTPS source. Availability is not guaranteed indefinitely.
    pub fn download_url(&self) -> &Url {
        &self.url
    }
    /// Exact single archive filename.
    pub fn archive_filename(&self) -> &str {
        &self.filename
    }
    /// Expected SHA-256 of the complete archive, not the inner executable.
    pub fn archive_sha256(&self) -> [u8; 32] {
        self.sha256
    }
    /// Published fixed archive byte length.
    pub fn archive_bytes(&self) -> u64 {
        self.bytes
    }
    /// Expected encoding of this target's archive.
    pub fn archive_format(&self) -> ArchiveFormat {
        self.format
    }
    /// Expected executable basename; no directory is accessed here.
    pub fn executable_name(&self) -> &str {
        &self.executable_name
    }
    /// Compatibility evidence and remaining ABI/minimum OS conditions.
    pub fn abi(&self) -> &ProgramAbi {
        &self.abi
    }
}

#[derive(Deserialize)]
struct Manifest {
    schema_version: u32,
    version: String,
    packages: Vec<Asset>,
}
#[derive(Deserialize)]
struct Asset {
    id: String,
    os: String,
    upstream_arch: String,
    variant: String,
    url: String,
    filename: String,
    sha256: String,
    bytes: u64,
    archive_format: String,
    executable_name: String,
    in_scope: bool,
    controller_target_candidates: Vec<String>,
    runtime_abi_note: String,
    mapping_note: String,
    minimum_os_note: String,
    minimum_os_runtime_verified: bool,
}
fn invalid() -> Error {
    Error::InvalidConfiguration {
        reason: "embedded fixed release catalog is inconsistent",
    }
}
fn target(a: &Asset) -> Result<ProgramTarget> {
    let os = match a.os.as_str() {
        "macos" => ProgramOs::MacOs,
        "windows" => ProgramOs::Windows,
        "linux" => ProgramOs::Linux,
        _ => return Err(invalid()),
    };
    let architecture = match a.upstream_arch.as_str() {
        "386" => ProgramArchitecture::X86,
        "amd64" => ProgramArchitecture::Amd64,
        "arm64" => ProgramArchitecture::Arm64,
        "arm" => ProgramArchitecture::Arm,
        "armhf" => ProgramArchitecture::ArmHf,
        "armv6" => ProgramArchitecture::ArmV6,
        "mips" => ProgramArchitecture::Mips,
        "mipsle" => ProgramArchitecture::MipsLe,
        "mips64" => ProgramArchitecture::Mips64,
        "mips64le" => ProgramArchitecture::Mips64Le,
        "ppc64le" => ProgramArchitecture::Ppc64Le,
        "riscv64" => ProgramArchitecture::RiscV64,
        "s390x" => ProgramArchitecture::S390x,
        "loong64" => ProgramArchitecture::Loong64,
        _ => return Err(invalid()),
    };
    let variant = match a.variant.as_str() {
        "standard" => BuildVariant::Standard,
        "legacy" => BuildVariant::Legacy,
        _ => return Err(invalid()),
    };
    Ok(ProgramTarget::new(os, architecture, variant))
}
/// Read the embedded 21 in-scope artifact facts, without I/O or runtime selection.
/// The two FreeBSD reference records remain outside this library's project scope.
pub fn official_programs() -> Result<Vec<OfficialProgram>> {
    let manifest: Manifest =
        serde_json::from_str(include_str!("../releases/verysync-v2.33.2.json"))
            .map_err(|_| invalid())?;
    if manifest.schema_version != 1 || manifest.version != BASELINE_ENGINE_VERSION {
        return Err(invalid());
    }
    let version = PinnedVersion::new(&manifest.version)?;
    let mut ids = std::collections::BTreeSet::new();
    manifest
        .packages
        .into_iter()
        .filter(|a| a.in_scope)
        .map(|a| {
            let target = target(&a)?;
            if a.id != target.id()
                || !ids.insert(a.id.clone())
                || a.sha256.len() != 64
                || !a.sha256.is_ascii()
                || a.bytes == 0
                || a.filename.contains(['/', '\\'])
                || a.executable_name.contains(['/', '\\'])
            {
                return Err(invalid());
            }
            let url = Url::parse(&a.url).map_err(|_| invalid())?;
            let channel = if target.variant() == BuildVariant::Legacy {
                "releases/legacy"
            } else {
                "releases"
            };
            if url.scheme() != "https"
                || url.host_str() != Some("dl-cn.verysync.com")
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != format!("/{}/{}/{}", channel, version.as_str(), a.filename)
            {
                return Err(invalid());
            }
            let mut sha256 = [0u8; 32];
            for (i, byte) in sha256.iter_mut().enumerate() {
                *byte =
                    u8::from_str_radix(&a.sha256[i * 2..i * 2 + 2], 16).map_err(|_| invalid())?;
            }
            let format = match a.archive_format.as_str() {
                "zip" => ArchiveFormat::Zip,
                "tar.gz" => ArchiveFormat::TarGz,
                _ => return Err(invalid()),
            };
            Ok(OfficialProgram {
                version: version.clone(),
                target,
                url,
                filename: a.filename,
                sha256,
                bytes: a.bytes,
                format,
                executable_name: a.executable_name,
                abi: ProgramAbi {
                    controller_target_candidates: a.controller_target_candidates,
                    runtime_abi_note: a.runtime_abi_note,
                    mapping_note: a.mapping_note,
                    minimum_os_note: a.minimum_os_note,
                    minimum_os_runtime_verified: a.minimum_os_runtime_verified,
                },
            })
        })
        .collect()
}
