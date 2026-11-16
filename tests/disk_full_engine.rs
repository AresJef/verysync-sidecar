//! Real bounded-filesystem exhaustion, separately provisioned by the CI driver.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
#[path = "common/resource_faults.rs"]
mod resource_faults;
#[path = "common/resource_fixture.rs"]
mod resource_fixture;
use managed_fixture::{options, TestResult};
use std::{path::PathBuf, time::Duration};
use verysync_sidecar::{Error, ManagedInstance, ResourceTransferOptions};

fn bounded_filesystem() -> TestResult<(PathBuf, String, u64, u64)> {
    let path = PathBuf::from(
        std::env::var_os("VERYSYNC_TEST_BOUNDED_FS")
            .ok_or("explicit bounded filesystem required; use the CI driver")?,
    );
    let nonce = std::env::var("VERYSYNC_TEST_BOUNDED_FS_NONCE")?;
    assert!(nonce.len() == 64 && nonce.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(path.is_absolute() && path.is_dir());
    #[cfg(unix)]
    assert!(!std::fs::symlink_metadata(&path)?.file_type().is_symlink());
    assert_eq!(
        std::fs::read_to_string(path.join("owned-volume.txt"))?,
        nonce
    );
    let total = fs2::total_space(&path)?;
    let free = fs2::available_space(&path)?;
    // A failed mount must never turn this into a host-disk filling test.
    assert!((4 * 1024 * 1024..=40 * 1024 * 1024).contains(&total));
    assert!(free >= 2 * 1024 * 1024 && free <= total);
    Ok((path, nonce, total, free))
}

#[tokio::test]
async fn public_real_disk_full_retains_prefix_and_recovers_after_explicit_release() -> TestResult {
    let (volume, nonce, capacity, free_before) = bounded_filesystem()?;
    let root = tempfile::Builder::new().prefix("vdf-").tempdir()?.keep();
    let state = root.join("core");
    let mut core = ManagedInstance::start(options(&state)?).await?;
    let identity = core.client().instance().device_id.clone();
    let volumes = core.client().resource_volumes().await?;
    let (profile, remote, _) = resource_fixture::owned_base(&core, &volumes)?;
    let source = profile.join("bounded-disk-source.bin");
    let total = 64 * 1024 * 1024;
    let (pattern, expected) = resource_faults::write_pattern(&source, total)?;
    let recovery_source = profile.join("bounded-disk-recovery.bin");
    let recovery_bytes = 1024 * 1024;
    let (_, recovery_hash) = resource_faults::write_pattern(&recovery_source, recovery_bytes)?;
    let config = std::fs::read(state.join("setting.dat"))?;
    let destination = volume.join("partial-download.bin");
    let options = ResourceTransferOptions {
        max_bytes: total,
        deadline: Duration::from_secs(30),
    };
    let result = core
        .client()
        .download_resource(
            &remote.clone().child("bounded-disk-source.bin")?,
            &destination,
            None,
            &options,
        )
        .await;
    let code = match result {
        Err(Error::LocalIo { source, .. }) => source.raw_os_error(),
        other => panic!("real full filesystem must return its native local I/O error: {other:?}"),
    };
    #[cfg(unix)]
    assert_eq!(code, Some(libc::ENOSPC));
    #[cfg(windows)]
    assert!(
        matches!(code, Some(39 | 112)),
        "native disk-full code: {code:?}"
    );
    let (retained, _) = resource_faults::verify_pattern(&destination, &pattern, total)?;
    assert!(retained > 0 && retained < total);
    let free_at_failure = fs2::available_space(&volume)?;
    assert_eq!(
        std::fs::read_to_string(volume.join("owned-volume.txt"))?,
        nonce
    );
    assert_eq!(
        resource_faults::verify_pattern(&source, &pattern, total)?,
        (total, expected)
    );
    assert_eq!(std::fs::read(state.join("setting.dat"))?, config);
    assert_eq!(core.client().system_status().await?.device_id, identity);
    // The caller deliberately releases only its partial output. The SDK never
    // silently removes data, retries the request, or resets engine state.
    std::fs::remove_file(&destination)?;
    let free_after_release = fs2::available_space(&volume)?;
    assert!(free_after_release > free_at_failure);
    let recovered = volume.join("explicit-recovery.bin");
    let receipt = core
        .client()
        .download_resource(
            &remote.child("bounded-disk-recovery.bin")?,
            &recovered,
            None,
            &options,
        )
        .await?;
    assert_eq!(
        (receipt.bytes, receipt.sha256),
        (recovery_bytes, recovery_hash)
    );
    assert_eq!(
        resource_faults::verify_pattern(&recovered, &pattern, recovery_bytes)?,
        (recovery_bytes, recovery_hash)
    );
    assert_eq!(
        std::fs::read_to_string(volume.join("owned-volume.txt"))?,
        nonce
    );
    assert_eq!(std::fs::read(state.join("setting.dat"))?, config);
    let normal = core.shutdown(Duration::from_secs(10)).await?;
    assert!(
        normal.tree_stopped && normal.state_released && !normal.forced && normal.code == Some(0)
    );
    std::fs::remove_file(recovered)?;
    println!(
        "native disk-full evidence: {}",
        serde_json::json!({"capacity_bytes":capacity,"free_before_bytes":free_before,
        "free_at_failure_bytes":free_at_failure,"free_after_explicit_release_bytes":free_after_release,
        "native_disk_full_error":code,"source_bytes":total,"retained_exact_prefix_bytes":retained,
        "actual_source_configuration_identity_preserved":true,"sentinel_preserved":true,
        "explicit_release_and_new_download_complete":true,"recovery_bytes":recovery_bytes,
        "actual_normal_owned_tree_exit":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
