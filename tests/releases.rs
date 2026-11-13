//! Pure source selection; no runtime, download or executable inspection.
use verysync_sidecar::{
    official_programs, ArchiveFormat, BuildVariant, EngineSource, LocalProgram, OfficialProgram,
    PinnedVersion, ProgramArchitecture, ProgramOs, ProgramTarget,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn fixed_catalog_is_complete_in_scope_and_keeps_archive_identity() -> TestResult {
    let catalog = official_programs()?;
    assert_eq!(catalog.len(), 21);
    let mut ids = std::collections::BTreeSet::new();
    for asset in catalog {
        assert!(ids.insert(asset.target().id()));
        assert_eq!(asset.version().as_str(), "v2.33.2");
        assert_eq!(asset.download_url().scheme(), "https");
        assert_eq!(asset.download_url().host_str(), Some("dl-cn.verysync.com"));
        assert!(asset.download_url().path().contains("/v2.33.2/"));
        assert!(!asset.archive_sha256().iter().all(|b| *b == 0));
        assert!(asset.archive_bytes() > 0);
        assert!(!asset.abi().minimum_os_runtime_verified);
        assert!(!asset.abi().runtime_abi_note.is_empty());
        assert_eq!(
            asset.archive_format(),
            if asset.target().os() == ProgramOs::Linux {
                ArchiveFormat::TarGz
            } else {
                ArchiveFormat::Zip
            }
        );
    }
    Ok(())
}
#[test]
fn standard_legacy_arm_families_and_controller_abis_are_not_aliases() -> TestResult {
    let version = PinnedVersion::new("v2.33.2")?;
    let target = |arch, variant| ProgramTarget::new(ProgramOs::Windows, arch, variant);
    let standard = OfficialProgram::select(
        &version,
        target(ProgramArchitecture::Amd64, BuildVariant::Standard),
    )?;
    let legacy = OfficialProgram::select(
        &version,
        target(ProgramArchitecture::Amd64, BuildVariant::Legacy),
    )?;
    assert_ne!(standard.archive_sha256(), legacy.archive_sha256());
    assert_ne!(
        standard.abi().controller_target_candidates,
        legacy.abi().controller_target_candidates
    );
    let arm = OfficialProgram::select(
        &version,
        ProgramTarget::new(
            ProgramOs::Linux,
            ProgramArchitecture::Arm,
            BuildVariant::Standard,
        ),
    )?;
    let hf = OfficialProgram::select(
        &version,
        ProgramTarget::new(
            ProgramOs::Linux,
            ProgramArchitecture::ArmHf,
            BuildVariant::Standard,
        ),
    )?;
    assert_ne!(arm.target(), hf.target());
    assert_ne!(arm.archive_sha256(), hf.archive_sha256());
    assert!(arm.abi().runtime_abi_note.contains("Unknown"));
    Ok(())
}
#[test]
fn unknown_versions_and_combinations_fail_without_io_or_runtime() -> TestResult {
    assert!(PinnedVersion::new("latest").is_err());
    assert!(PinnedVersion::new("v2.33.2/escape").is_err());
    let unknown = PinnedVersion::new("v999.0.0")?;
    let target = ProgramTarget::new(
        ProgramOs::MacOs,
        ProgramArchitecture::Arm64,
        BuildVariant::Standard,
    );
    assert!(OfficialProgram::select(&unknown, target).is_err());
    let known = PinnedVersion::new("v2.33.2")?;
    assert!(OfficialProgram::select(
        &known,
        ProgramTarget::new(
            ProgramOs::MacOs,
            ProgramArchitecture::Mips,
            BuildVariant::Legacy
        )
    )
    .is_err());
    let path = std::env::temp_dir().join("synthetic-nonexistent-program");
    let source = EngineSource::Local(LocalProgram::new(path.clone())?);
    assert!(matches!(source,EngineSource::Local(p)if p.path()==path));
    let source = EngineSource::from(OfficialProgram::select(&known, target)?);
    assert!(matches!(source, EngineSource::Official(_)));
    Ok(())
}
