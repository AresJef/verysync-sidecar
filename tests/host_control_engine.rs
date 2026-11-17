//! Host actions are explicit; the privileged case is only for a disposable CI VM.
#[cfg(feature = "host-configuration-tests")]
#[path = "common/linux_sleep_inhibitor_cases.rs"]
mod linux_sleep_inhibitor_cases;
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
#[cfg(target_os = "linux")]
use std::path::Path;
use std::{path::PathBuf, time::Duration};
use verysync_sidecar::{
    ManagedInstance, NativeWatchLimitObservation as O, NativeWatchLimitOutcome as R,
};

async fn stopped_owner() -> TestResult<(PathBuf, ManagedInstance)> {
    let root = tempfile::Builder::new().prefix("vhost-").tempdir()?.keep();
    std::fs::write(
        root.join("sample.txt"),
        b"host actions retain synthetic bytes",
    )?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    assert!(matches!(
        core.request_native_file_watch_limit(0, Duration::from_secs(10))
            .await,
        Err(verysync_sidecar::Error::ManagedFailure { .. })
    ));
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    Ok((root, core))
}
#[cfg(target_os = "linux")]
fn kernel_limit() -> TestResult<u64> {
    Ok(
        std::fs::read_to_string(Path::new("/proc/sys/fs/inotify/max_user_watches"))?
            .trim()
            .parse()?,
    )
}
#[cfg(target_os = "linux")]
fn effective_uid() -> TestResult<u32> {
    let status = std::fs::read_to_string(Path::new("/proc/self/status"))?;
    Ok(status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_whitespace().nth(2))
        .ok_or("effective UID unavailable")?
        .parse()?)
}
#[tokio::test]
async fn native_host_watch_limit_preserves_noop_refusal_and_private_state() -> TestResult {
    let (root, mut core) = stopped_owner().await?;
    let names = ["setting.dat", "key.pem", "cert.pem"];
    let before = names
        .iter()
        .map(|n| std::fs::read(core.state_directory().join(n)))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(matches!(
        core.request_native_file_watch_limit(u64::MAX, Duration::from_secs(10))
            .await,
        Err(verysync_sidecar::Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        core.request_native_file_watch_limit(0, Duration::ZERO)
            .await,
        Err(verysync_sidecar::Error::InvalidConfiguration { .. })
    ));
    #[cfg(unix)]
    {
        let outside = root.join("outside.txt");
        std::fs::write(&outside, b"outside host action state")?;
        let alias = core
            .state_directory()
            .join("profile")
            .join("unexpected-alias");
        std::os::unix::fs::symlink(&outside, &alias)?;
        assert!(matches!(
            core.request_native_file_watch_limit(0, Duration::from_secs(10))
                .await,
            Err(verysync_sidecar::Error::UnmanagedState)
        ));
        assert_eq!(std::fs::read(&outside)?, b"outside host action state");
        std::fs::remove_file(alias)?;
    }
    #[cfg(target_os = "linux")]
    let original = kernel_limit()?;
    let receipt = core
        .request_native_file_watch_limit(0, Duration::from_secs(10))
        .await?;
    assert!(receipt.tree_stopped);
    #[cfg(target_os = "linux")]
    {
        assert_eq!(receipt.code, Some(0));
        assert_eq!(receipt.outcome, R::MinimumObserved);
        assert_eq!(receipt.before, O::Value(original));
        assert_eq!(receipt.after, O::Value(original));
        assert_eq!(kernel_limit()?, original);
        // The ordinary suite must never make an elevated host mutation.
        assert_ne!(
            effective_uid()?,
            0,
            "use only the explicit privileged CI case as root"
        );
        let denied = core
            .request_native_file_watch_limit(
                original.checked_add(1).ok_or("kernel limit overflow")?,
                Duration::from_secs(10),
            )
            .await?;
        assert_eq!(
            denied.code,
            Some(0),
            "the fixed native CLI swallows its write error"
        );
        assert_eq!(denied.outcome, R::MinimumNotObserved);
        assert_eq!(denied.after, O::Value(original));
        assert_eq!(kernel_limit()?, original);
    }
    #[cfg(not(target_os = "linux"))]
    {
        assert_ne!(receipt.code, Some(0));
        assert_eq!(receipt.outcome, R::NativeFailure);
        assert_eq!(receipt.before, O::NotAvailableOnHost);
        assert_eq!(receipt.after, O::NotAvailableOnHost);
    }
    for (name, bytes) in names.iter().zip(&before) {
        assert_eq!(&std::fs::read(core.state_directory().join(name))?, bytes);
    }
    assert_eq!(
        std::fs::read(root.join("sample.txt"))?,
        b"host actions retain synthetic bytes"
    );
    std::fs::remove_dir_all(root)?;
    println!("native_host_watch_limit_noop_or_unsupported_observed=true zero_exit_not_assumed_applied=true invalid_inputs_and_state_alias_refused=true private_bytes_retained=true normal_owned_core_exit=true");
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "host-configuration-tests"))]
#[tokio::test]
async fn privileged_native_watch_limit_is_raised_then_independently_restored() -> TestResult {
    assert_eq!(
        std::env::var("VERYSYNC_TEST_ALLOW_HOST_CONFIGURATION")?,
        "github-actions-isolated-linux-vm"
    );
    assert_eq!(std::env::var("GITHUB_ACTIONS")?, "true");
    assert_eq!(
        effective_uid()?,
        0,
        "privileged test binary must be launched explicitly by CI"
    );
    struct Restore {
        original: u64,
        armed: bool,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            if self.armed {
                let _ = std::fs::write(
                    Path::new("/proc/sys/fs/inotify/max_user_watches"),
                    format!("{}\n", self.original),
                );
            }
        }
    }
    let original = kernel_limit()?;
    let mut restore = Restore {
        original,
        armed: true,
    };
    let requested = original.checked_add(1).ok_or("kernel limit overflow")?;
    let (root, mut core) = stopped_owner().await?;
    let receipt = core
        .request_native_file_watch_limit(requested, Duration::from_secs(10))
        .await?;
    assert!(receipt.tree_stopped && receipt.code == Some(0));
    assert_eq!(receipt.before, O::Value(original));
    assert_eq!(receipt.after, O::Value(requested));
    assert_eq!(receipt.outcome, R::MinimumObserved);
    assert_eq!(kernel_limit()?, requested);
    // The native operation only raises; this independent test oracle restores
    // the exact original VM setting after observing the real kernel change.
    std::fs::write(
        Path::new("/proc/sys/fs/inotify/max_user_watches"),
        format!("{original}\n"),
    )?;
    assert_eq!(kernel_limit()?, original);
    restore.armed = false;
    assert_eq!(
        std::fs::read(root.join("sample.txt"))?,
        b"host actions retain synthetic bytes"
    );
    std::fs::remove_dir_all(root)?;
    println!("native_host_actual_kernel_raised_by_one=true independently_read_before_after=true exact_original_kernel_limit_restored=true private_sample_retained=true normal_owned_core_exit=true no_service_or_persistent_configuration=true");
    Ok(())
}
