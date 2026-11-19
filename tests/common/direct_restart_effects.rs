//! The native inner-process restart exit and explicit owned relaunch are distinct.
use super::managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::{CreateFolderOptions, FolderId, ManagedInstance, TargetPath};

#[tokio::test]
async fn actual_native_restart_request_exits_inner_core_and_explicit_relaunch_retains_state(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vsaction-")
        .tempdir()?
        .keep();
    let mut owner = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = owner.client().instance().device_id.clone();
    let before = owner
        .client()
        .system_status()
        .await?
        .start_time
        .ok_or("original start time absent")?;
    let data = root.join("synthetic");
    std::fs::create_dir(&data)?;
    let sentinel = data.join("sentinel.bin");
    std::fs::write(&sentinel, b"explicit restart retains synthetic data")?;
    let folder = FolderId::parse("direct-restart-effect")?;
    owner
        .client()
        .create_folder(
            &CreateFolderOptions::new(folder.clone(), TargetPath::local(&data)).paused(true),
        )
        .await?;
    let borrowed = owner.client().clone();
    borrowed.request_restart().await?;
    let exited = tokio::time::timeout(Duration::from_secs(10), owner.wait_for_exit()).await??;
    assert_eq!(exited.code, Some(3));
    assert!(exited.tree_stopped && exited.state_released && !exited.forced);
    // The observed owned-tree exit establishes that this owner has ended.
    // Do not probe an endpoint after release: another process could reuse it.
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"explicit restart retains synthetic data"
    );
    owner.restart(Duration::from_secs(30)).await?;
    let after = owner.client().system_status().await?;
    assert_eq!(after.device_id, identity);
    assert_ne!(after.start_time.as_deref(), Some(before.as_str()));
    assert!(after.start_time.is_some());
    assert!(owner.client().folder(&folder).await?.paused);
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"explicit restart retains synthetic data"
    );
    let exited = owner.shutdown(Duration::from_secs(10)).await?;
    assert_eq!(exited.code, Some(0));
    assert!(exited.tree_stopped && exited.state_released && !exited.forced);
    std::fs::remove_dir_all(root)?;
    println!("native_direct_restart_effects=9 receipt_then_actual_unforced_exit3=true explicit_owned_relaunch_same_identity_and_new_start=true folder_and_bytes_retained=true");
    Ok(())
}
