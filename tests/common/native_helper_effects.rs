//! Native helper results are checked independently from raw research calls.
use super::managed_fixture::{options, TestResult};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use verysync_sidecar::{Error, ManagedInstance};

#[tokio::test]
async fn actual_native_helpers_normalize_ids_collect_reports_and_preserve_explicit_boundaries(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vshelpers-")
        .tempdir()?
        .keep();
    let mut owner = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = owner.client().instance().device_id.clone();
    for value in [
        identity.to_string(),
        identity.as_str().to_lowercase(),
        identity.as_str().replace('-', ""),
    ] {
        assert_eq!(owner.client().normalize_device_id(&value).await?, identity);
    }
    assert!(matches!(
        owner.client().normalize_device_id("invalid").await,
        Err(Error::Api { .. })
    ));
    let mut checksum = identity.as_str().as_bytes().to_vec();
    let last = checksum.last_mut().ok_or("identity absent")?;
    *last = if *last == b'A' { b'B' } else { b'A' };
    let checksum = String::from_utf8(checksum)?;
    assert!(verysync_sidecar::DeviceId::parse(&checksum).is_ok());
    assert!(matches!(
        owner.client().normalize_device_id(&checksum).await,
        Err(Error::Api { .. })
    ));
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let lookup = owner.client().lookup_target_ip(ip).await?;
        assert_eq!(lookup.ip, ip);
        assert!(
            lookup.province.is_empty() && lookup.city.is_empty() && lookup.description.is_empty()
        );
    }
    let before = owner.client().diagnostics_options().await?;
    let report = owner.client().collect_native_usage_report().await?;
    assert_eq!(report.version, verysync_sidecar::BASELINE_ENGINE_VERSION);
    let version = &owner.client().instance().version;
    assert_eq!(report.platform, format!("{}-{}", version.os, version.arch));
    assert_eq!(report.device_count, 1);
    assert!(!report.unique_id.as_deref().unwrap_or("").is_empty());
    let after = owner.client().diagnostics_options().await?;
    assert_eq!(before.usage_accepted_version, after.usage_accepted_version);
    assert_eq!(before.usage_seen_version, after.usage_seen_version);
    assert_eq!(before.usage_identifier(), after.usage_identifier());
    assert_eq!(before.usage_report_url(), after.usage_report_url());
    assert_eq!(
        before.crash_reporting_enabled,
        after.crash_reporting_enabled
    );
    for _ in 0..3 {
        let _native_number = owner.client().native_random_number().await?;
    }
    let pending = owner.client().pending_native_link().await?;
    assert!(pending.link().is_none());
    assert!(owner.client().folders().await?.is_empty());
    assert_eq!(owner.client().system_status().await?.device_id, identity);
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_helper_effects=10 native_id_normalization_and_checksum_rejection=true explicit_loopback_lookup=true report_collection_without_consent_change=true random_quality_not_asserted=true empty_link_only_native_effect=true");
    Ok(())
}
