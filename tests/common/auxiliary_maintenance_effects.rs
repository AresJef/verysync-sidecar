//! Native deletion effects are observed independently from receipts.
use super::managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::{
    CreateFolderOptions, Error, FolderId, FolderState, ManagedInstance, TargetPath,
};

#[cfg(unix)]
struct CleanupBlocker(std::path::PathBuf);
#[cfg(unix)]
impl CleanupBlocker {
    fn new(marker: &std::path::Path) -> TestResult<Self> {
        use std::os::unix::fs::PermissionsExt;
        let path = marker.join("denied.tmp");
        std::fs::create_dir(&path)?;
        std::fs::write(path.join("retain.bin"), b"retained synthetic bytes")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500))?;
        Ok(Self(path))
    }
    fn sample(&self) -> std::path::PathBuf {
        self.0.join("retain.bin")
    }
}
#[cfg(unix)]
impl Drop for CleanupBlocker {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
    }
}
#[cfg(windows)]
struct CleanupBlocker {
    path: std::path::PathBuf,
    _file: std::fs::File,
}
#[cfg(windows)]
impl CleanupBlocker {
    fn new(marker: &std::path::Path) -> TestResult<Self> {
        use std::os::windows::fs::OpenOptionsExt;
        let path = marker.join("denied.tmp");
        std::fs::write(&path, b"retained synthetic bytes")?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(&path)?;
        Ok(Self { path, _file: file })
    }
    fn sample(&self) -> std::path::PathBuf {
        self.path.clone()
    }
}

#[tokio::test]
async fn actual_native_temporary_cleanup_and_paths_preserve_other_data_and_restart() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vsauxmaintenance-")
        .tempdir()?
        .keep();
    let mut owner = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = owner.client().instance().device_id.clone();
    let paths = owner.client().native_system_paths().await?;
    assert_eq!(
        std::fs::canonicalize(paths.configuration_directory.to_protocol()?)?,
        std::fs::canonicalize(root.join("core"))?
    );
    assert_eq!(
        std::fs::canonicalize(paths.data_directory.to_protocol()?)?,
        std::fs::canonicalize(root.join("core"))?
    );
    assert!(std::path::Path::new(paths.configuration_file.to_protocol()?).is_file());
    assert!(std::path::Path::new(paths.database_directory.to_protocol()?).is_dir());
    #[cfg(unix)]
    assert_eq!(paths.extra.get("logFile").map(String::as_str), Some("-"));
    #[cfg(windows)]
    {
        let reported = paths
            .extra
            .get("logFile")
            .ok_or("native log location missing")?;
        let expected = root.join("core").join("verysync.log");
        assert_eq!(std::path::Path::new(reported), expected);
    }
    let data = root.join("synthetic & + % 测试");
    std::fs::create_dir(&data)?;
    let id = FolderId::parse("auxiliary-temp-cleanup")?;
    owner
        .client()
        .create_folder(&CreateFolderOptions::new(
            id.clone(),
            TargetPath::local(&data),
        ))
        .await?;
    let marker = data.join(".verysync");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if marker.is_dir()
                && owner.client().folder_status(&id).await?.state == Some(FolderState::Idle)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        TestResult::Ok(())
    })
    .await??;
    let nested = marker.join("nested");
    std::fs::create_dir(&nested)?;
    let blocked = marker.join("blocked.tmp");
    std::fs::create_dir(&blocked)?;
    std::fs::write(
        blocked.join("remove.bin"),
        b"matching directory contents are removed",
    )?;
    let blocker = CleanupBlocker::new(&marker)?;
    let preserved = [
        data.join("sentinel.bin"),
        data.join("ordinary.tmp"),
        marker.join("retain.bin"),
        nested.join("retain.tmp"),
        root.join("other-folder.tmp"),
    ];
    for (index, file) in preserved.iter().enumerate() {
        std::fs::write(file, b"retained synthetic bytes").map_err(|error| {
            format!("synthetic preservation sample {index} creation failed: {error}")
        })?;
    }
    let temporary = [marker.join("synthetic.tmp"), marker.join("synthetic.sess")];
    for file in &temporary {
        std::fs::write(file, b"remove only this synthetic native temporary")?;
    }
    assert!(preserved.iter().all(|file| file.is_file()));
    assert!(temporary.iter().all(|file| file.is_file()));
    let receipt = owner.client().request_folder_temporary_cleanup(&id).await?;
    assert_eq!(receipt.folder, id);
    assert!(temporary.iter().all(|file| !file.exists()));
    assert!(!blocked.exists());
    // A real OS refusal is logged by the native cleaner, but its HTTP receipt
    // still succeeds. Do not turn that receipt into a complete-removal claim.
    assert_eq!(
        std::fs::read(blocker.sample())?,
        b"retained synthetic bytes"
    );
    drop(blocker);
    for (index, file) in preserved.iter().enumerate() {
        let bytes = std::fs::read(file)
            .map_err(|error| format!("synthetic sample {index} after cleanup: {error}"))?;
        assert_eq!(bytes, b"retained synthetic bytes");
    }
    let missing = FolderId::parse("unregistered-synthetic-folder")?;
    assert!(matches!(
        owner
            .client()
            .request_folder_temporary_cleanup(&missing)
            .await,
        Err(Error::FolderNotFound { .. })
    ));
    owner.client().pause_folder(&id).await?;
    owner.restart(Duration::from_secs(30)).await?;
    let after = owner.client().native_system_paths().await?;
    assert_eq!(after.configuration_directory, paths.configuration_directory);
    assert_eq!(after.database_directory, paths.database_directory);
    assert!(matches!(
        owner.client().request_folder_temporary_cleanup(&id).await,
        Err(Error::MutationOutcomeUnknown { .. })
    ));
    assert_eq!(owner.client().system_status().await?.device_id, identity);
    for file in &preserved {
        assert_eq!(std::fs::read(file)?, b"retained synthetic bytes");
    }
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native_auxiliary_maintenance_effects=12 exact_temp_and_session_removal=true matching_directories_removed=true nonmatching_and_nested_bytes_preserved=true partial_io_failure_still_acknowledged=true native_paths_and_restart_preserved=true");
    Ok(())
}
