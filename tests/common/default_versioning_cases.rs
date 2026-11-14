//! Native default inheritance with real selected-archive browsing and restore.
use super::*;

async fn join(
    core: &ManagedInstance,
    path: &std::path::Path,
    paused: bool,
) -> verysync_sidecar::Result<FolderConfig> {
    let share = core.client().generate_share().await?;
    let prepared = core
        .client()
        .validate_share_key(&share.read_write_key)
        .await?;
    Ok(core
        .client()
        .join_folder(&JoinFolderOptions::new(prepared, TargetPath::local(path)).paused(paused))
        .await?
        .configuration)
}

#[tokio::test]
async fn native_default_versioning_inheritance_selects_real_archives_and_retains_old_folders(
) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-default-versioning-")
        .tempdir()?
        .keep();
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let old_path = root.join("old");
    let fresh_path = root.join("fresh");
    let later_path = root.join("later");
    let archive = root.join("selected archives");
    for path in [&old_path, &fresh_path, &later_path, &archive] {
        std::fs::create_dir(path)?;
    }
    let old = join(&core, &old_path, true).await?;
    let old_policy = core.client().folder_versioning(&old.id).await?;
    assert!(
        core.client()
            .set_folder_default_versioning(FolderVersioningPolicy::Simple {
                keep: 2,
                cleanout_days: 0,
                cleanup_interval_seconds: 3600,
            })
            .await?
            .requested_fields_match
    );
    assert!(
        core.client()
            .set_folder_default_archive_location(&VersionArchiveLocation::BasicDirectory(
                TargetPath::local(archive.clone())
            ))
            .await?
            .requested_fields_match
    );
    assert_eq!(core.client().folder_versioning(&old.id).await?, old_policy);
    std::fs::write(
        fresh_path.join("versioned.txt"),
        b"current synthetic contents",
    )?;
    let fresh = join(&core, &fresh_path, false).await?;
    let inherited = core.client().folder_versioning(&fresh.id).await?;
    assert_eq!(inherited.kind, "simple");
    assert_eq!(inherited.params["keep"], "2");
    assert_eq!(
        inherited.filesystem_path,
        archive.to_str().ok_or("synthetic path not UTF8")?
    );
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let state = core.client().folder_status(&fresh.id).await?;
            if state.state == Some(FolderState::Idle) && state.local_files == Some(1) {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    // Deliberately seed a synthetic archive. This proves actual selection and
    // restore, not that these fixture bytes were produced by remote versioning.
    std::fs::write(
        archive.join("versioned~20000101-000000.txt"),
        b"selected synthetic archived bytes",
    )?;
    let retained = archive.join("untouched~20000102-000000.bin");
    std::fs::write(&retained, b"independent archive sentinel")?;
    let ignored_default = fresh_path.join(".verysync").join("Archive");
    std::fs::create_dir_all(&ignored_default)?;
    std::fs::write(
        ignored_default.join("unselected~20000101-000000.bin"),
        b"unselected default archive bytes",
    )?;
    let versions = core.client().folder_versions(&fresh.id, None).await?;
    assert!(versions.0.contains_key("versioned.txt"));
    assert!(!versions.0.contains_key("unselected.bin"));
    let stamp = versions.0["versioned.txt"][0].version_time.clone();
    let restored = core
        .client()
        .restore_file_versions(
            &fresh.id,
            &[FileVersionRestore::new(
                TargetPath::local(std::path::Path::new("versioned.txt")),
                stamp,
            )?],
        )
        .await?;
    assert_eq!(restored.error_count(), 0);
    assert_eq!(
        std::fs::read(fresh_path.join("versioned.txt"))?,
        b"selected synthetic archived bytes"
    );
    assert!(
        core.client()
            .set_folder_default_archive_location(&VersionArchiveLocation::FolderDefault)
            .await?
            .requested_fields_match
    );
    assert_eq!(
        core.client()
            .folder_versioning(&fresh.id)
            .await?
            .filesystem_path,
        inherited.filesystem_path
    );
    let later = join(&core, &later_path, true).await?;
    let later_policy = core.client().folder_versioning(&later.id).await?;
    assert_eq!(later_policy.kind, "simple");
    assert_eq!(later_policy.filesystem_path, "");
    let mut snapshot = core.client().configuration().await?;
    snapshot.set_folder_default_versioning(FolderVersioningPolicy::Disabled)?;
    let future_archive = root.join("snapshot future archive");
    snapshot.set_folder_default_archive_location(&VersionArchiveLocation::BasicDirectory(
        TargetPath::local(future_archive.clone()),
    ))?;
    let mut expected_normalized = snapshot.native_document().clone();
    let native_default_params =
        expected_normalized["defaults"]["folder"]["versioning"]["params"].clone();
    let old_document = expected_normalized["folders"]
        .as_array_mut()
        .ok_or("folder array absent")?
        .iter_mut()
        .find(|f| f["id"].as_str() == Some(old.id.as_str()))
        .ok_or("old folder absent")?;
    assert!(old_document["versioning"]["params"]
        .as_object()
        .is_some_and(|m| m.is_empty()));
    old_document["versioning"]["params"] = native_default_params.clone();
    let mut normalized_old_policy = old_policy.clone();
    normalized_old_policy.params = serde_json::from_value(native_default_params)?;
    let saved = core.client().replace_configuration(&snapshot).await?;
    // Complete native decoding fills these previously empty inactive parameters.
    // The exact full-document mismatch must remain visible to the caller.
    assert!(!saved.requested_fields_match);
    assert!(
        saved.configuration.native_document() == &expected_normalized,
        "native full save differed beyond the verified inactive-parameter normalization"
    );
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(core.client().instance().device_id, identity);
    let template = core.client().folder_default_versioning().await?;
    assert_eq!(template.kind, "");
    assert_eq!(
        template.filesystem_path,
        future_archive.to_str().ok_or("synthetic path not UTF8")?
    );
    assert_eq!(
        core.client().folder_versioning(&old.id).await?,
        normalized_old_policy
    );
    assert_eq!(
        core.client().folder_versioning(&later.id).await?,
        later_policy
    );
    assert_eq!(
        core.client()
            .folder_versioning(&fresh.id)
            .await?
            .filesystem_path,
        inherited.filesystem_path
    );
    assert_eq!(std::fs::read(&retained)?, b"independent archive sentinel");
    for folder in [&old.id, &fresh.id, &later.id] {
        assert!(
            core.client()
                .remove_folder_keep_files(folder)
                .await?
                .configuration_absent
        );
    }
    assert_eq!(
        std::fs::read(fresh_path.join("versioned.txt"))?,
        b"selected synthetic archived bytes"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    println!("native_default_versioning_effects=18 actual_archive_selection_and_restore=true remotely_generated_fixture_versions_not_claimed=true");
    Ok(())
}
