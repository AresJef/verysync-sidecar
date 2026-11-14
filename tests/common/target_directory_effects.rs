//! Native picker locations, directory contents and explicit filesystem effects.
use super::managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::{Error, ManagedInstance, TargetPath};

#[tokio::test]
async fn actual_target_directory_helpers_create_read_and_retain_only_explicit_synthetic_paths(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vsdirs-").tempdir()?.keep();
    let mut owner = ManagedInstance::start(options(&root.join("core"))?).await?;
    let data = root.join("synthetic & + % 测试");
    std::fs::create_dir(&data)?;
    std::fs::create_dir(data.join("child"))?;
    let sentinel = data.join("sample.txt");
    std::fs::write(&sentinel, b"native directory helpers preserve file bytes")?;
    let locations = owner.client().target_directory_locations().await?;
    assert!(!locations.is_empty());
    for location in &locations {
        assert_eq!(location.path.style(), TargetPath::local(&data).style());
        assert!(location.path.local_path().is_none());
        assert!(!location.path.to_protocol()?.is_empty());
        assert!(!location.title.is_empty());
    }
    let entries = owner
        .client()
        .target_directories(&TargetPath::local(&data))
        .await?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "child");
    assert!(entries[0].is_directory);
    assert!(!format!("{:?}", entries[0]).contains("child"));
    let added = data.join("new & + % 测试");
    assert!(!added.exists());
    let created = owner
        .client()
        .create_target_directory(&TargetPath::local(&added))
        .await?;
    assert!(added.is_dir());
    assert!(!created.native_message.is_empty());
    assert!(created.path.local_path().is_none());
    assert!(owner
        .client()
        .target_directories(&TargetPath::local(&added))
        .await?
        .is_empty());
    // Existing directories are native idempotent success; files are preserved.
    owner
        .client()
        .create_target_directory(&TargetPath::local(&added))
        .await?;
    assert!(matches!(
        owner
            .client()
            .target_directories(&TargetPath::local(&sentinel))
            .await,
        Err(Error::Api { .. })
    ));
    assert!(matches!(
        owner
            .client()
            .create_target_directory(&TargetPath::local(&sentinel))
            .await,
        Err(Error::MutationOutcomeUnknown { .. })
    ));
    let absent = data.join("still-absent");
    assert!(matches!(
        owner
            .client()
            .target_directories(&TargetPath::local(&absent))
            .await,
        Err(Error::Api { .. })
    ));
    assert!(!absent.exists());
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"native directory helpers preserve file bytes"
    );
    assert!(owner.client().folders().await?.is_empty());
    let exit = owner.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    assert!(added.is_dir());
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"native directory helpers preserve file bytes"
    );
    std::fs::remove_dir_all(root)?;
    println!("native_target_directory_effects=11 actual_path_creation=true existing_file_retained=true no_sync_registration=true normal_owned_exit=true");
    Ok(())
}
