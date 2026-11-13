//! Real different-version transitions, not same-version reinstall evidence.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::{path::PathBuf, time::Duration};
use verysync_sidecar::{
    Error, FolderScanPatch, JoinFolderOptions, LocalProgram, ManagedInstance, ManagedOptions,
    VersionCompatibility, VersionPolicy,
};

fn upgrade_source() -> TestResult<LocalProgram> {
    let path = PathBuf::from(
        std::env::var_os("VERYSYNC_TEST_UPGRADE_SOURCE_BINARY")
            .ok_or("explicit older upgrade-source program required")?,
    );
    let hex = std::env::var("VERYSYNC_TEST_UPGRADE_SOURCE_SHA256")?;
    if hex.len() != 64 {
        return Err("explicit older program SHA-256 required".into());
    }
    let mut sha = [0; 32];
    for (i, v) in sha.iter_mut().enumerate() {
        *v = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    Ok(LocalProgram::new(path)?.expected_sha256(sha))
}

fn baseline_asset() -> TestResult<verysync_sidecar::OfficialProgram> {
    use verysync_sidecar::{BuildVariant, ProgramArchitecture, ProgramOs};
    let os = match std::env::consts::OS {
        "macos" => ProgramOs::MacOs,
        "windows" => ProgramOs::Windows,
        "linux" => ProgramOs::Linux,
        _ => return Err("unsupported native host".into()),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => ProgramArchitecture::Amd64,
        "aarch64" => ProgramArchitecture::Arm64,
        _ => return Err("unsupported native architecture".into()),
    };
    verysync_sidecar::official_programs()?
        .into_iter()
        .find(|p| {
            p.target().os() == os
                && p.target().architecture() == arch
                && p.target().variant() == BuildVariant::Standard
        })
        .ok_or_else(|| "fixed native archive missing".into())
}

#[tokio::test]
async fn kernel_provider_upgrade_replaces_only_the_owned_old_copy() -> TestResult {
    kernel_upgrade(false).await
}
#[tokio::test]
async fn kernel_streamed_archive_upload_replaces_only_the_owned_old_copy() -> TestResult {
    kernel_upgrade(true).await
}
async fn kernel_upgrade(upload: bool) -> TestResult {
    use sha2::{Digest, Sha256};
    use verysync_sidecar::{CreateFolderOptions, FolderId, ManagedUpgradeChecks};
    let root = tempfile::Builder::new().prefix("vku-").tempdir()?.keep();
    let source = upgrade_source()?;
    let program = root.join(source.path().file_name().ok_or("program name missing")?);
    std::fs::copy(source.path(), &program)?;
    let old_sha: [u8; 32] = Sha256::digest(std::fs::read(&program)?).into();
    let base = options(&root.join("c"))?;
    let settings = ManagedOptions::new(
        LocalProgram::new(&program)?.expected_sha256(old_sha),
        base.state_directory(),
        base.management_endpoint().clone(),
    )?
    .version_policy(VersionPolicy::AllowUnverified);
    let mut core = ManagedInstance::start(settings.clone()).await?;
    assert!(matches!(core.client().check_kernel_upgrade().await,
        Err(Error::Http { response }) if response.status() == 501));
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    let mut core =
        ManagedInstance::start(settings.upgrade_checks(ManagedUpgradeChecks::Manual)).await?;
    let identity = core.client().system_status().await?.device_id;
    assert_eq!(
        core.client().network_configuration().await?.extra["autoUpgradeIntervalH"],
        0
    );
    let data = root.join("data");
    std::fs::create_dir(&data)?;
    std::fs::write(data.join("retained.bin"), b"native upgrade retained bytes")?;
    let id = FolderId::parse("native-kernel-upgrade")?;
    core.client()
        .create_folder(&CreateFolderOptions::new(
            id.clone(),
            verysync_sidecar::TargetPath::local(&data),
        ))
        .await?;
    core.client()
        .update_folder_scan_configuration(
            &id,
            &FolderScanPatch::default()
                .watcher(false)
                .rescan_interval_seconds(0)
                .disable_initial_scan(true),
        )
        .await?;
    core.client().request_scan(&id).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if core.client().folder_status(&id).await?.local_files == Some(1) {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let before = core.client().folder(&id).await?;
    if !upload {
        match core
            .client()
            .check_kernel_upgrade()
            .await
            .inspect_err(|error| {
                if let Error::Http { response } | Error::UpgradeReleaseUnavailable { response } =
                    error
                {
                    report_upgrade_diagnostic("provider-check", response.body_bytes());
                }
            }) {
            Ok(checked) => {
                assert_eq!(checked.running, "v2.33.1");
                assert_eq!(
                    checked.latest, "v2.33.2",
                    "provider changed: no unpinned program may be fetched"
                );
                assert!(checked.newer && !checked.major_newer);
            }
            Err(Error::UpgradeReleaseUnavailable { .. }) => {
                assert_eq!(
                    (std::env::consts::OS, std::env::consts::ARCH),
                    ("windows", "aarch64")
                );
                let config = std::fs::read(base.state_directory().join("setting.dat"))?;
                assert!(matches!(
                    core.client().request_server_selected_upgrade().await,
                    Err(Error::UpgradeReleaseUnavailable { .. })
                ));
                assert_eq!(Sha256::digest(std::fs::read(&program)?).as_slice(), old_sha);
                assert_eq!(
                    std::fs::read(base.state_directory().join("setting.dat"))?,
                    config
                );
                assert_eq!(core.client().system_status().await?.device_id, identity);
                assert_eq!(core.client().version().await?.version, "v2.33.1");
                assert_eq!(core.client().folder_status(&id).await?.local_files, Some(1));
                assert_eq!(
                    std::fs::read(data.join("retained.bin"))?,
                    b"native upgrade retained bytes"
                );
                let exit = core.shutdown(Duration::from_secs(10)).await?;
                assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
                std::fs::remove_dir_all(root)?;
                println!(
                    "public provider release absence evidence: {}",
                    serde_json::json!({
                    "actual_get_reports_typed_no_matching_release":true,"actual_post_reports_typed_no_matching_release":true,
                    "actual_executable_sha_and_configuration_unchanged":true,"actual_old_version_and_identity_retained":true,
                    "actual_folder_index_and_sample_bytes_retained":true,"actual_normal_owned_tree_exit":true,
                    "positive_provider_upgrade":"pending","manual_upload_case":"separate_required_case"})
                );
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
    }

    let result = if upload {
        let invalid = root.join("bad.zip");
        std::fs::write(&invalid, b"invalid archive")?;
        assert!(matches!(
            core.client()
                .upload_kernel_upgrade(&invalid, &baseline_asset()?)
                .await,
            Err(Error::ProgramRejected { .. })
        ));
        assert_eq!(Sha256::digest(std::fs::read(&program)?).as_slice(), old_sha);
        core.client()
            .upload_kernel_upgrade(
                PathBuf::from(
                    std::env::var_os("VERYSYNC_TEST_ARCHIVE")
                        .ok_or("fixed local archive required")?,
                ),
                &baseline_asset()?,
            )
            .await
    } else {
        core.client().request_server_selected_upgrade().await
    };
    if let Err(e) = &result {
        let mut detail = format!("{e:?}");
        if let Error::MutationOutcomeUnknown { source, .. } = e {
            if let Error::InvalidResponse { response, .. } | Error::Http { response } =
                source.as_ref()
            {
                detail.push_str(&format!(
                    " status={} body={:?}",
                    response.status(),
                    response.body_bytes()
                ));
            }
        }
        std::fs::write(root.join("upgrade-response.txt"), &detail)?;
        eprintln!("Native upgrade response requires inspection of private task-owned diagnostics.");
    }
    let exit = tokio::time::timeout(Duration::from_secs(20), core.wait_for_exit()).await??;
    assert!(exit.tree_stopped && !exit.forced);
    let new_sha: [u8; 32] = Sha256::digest(std::fs::read(&program)?).into();
    assert_ne!(new_sha, old_sha);
    assert_eq!(
        new_sha,
        Sha256::digest(std::fs::read(base.program().path())?).as_slice()
    );
    core.restart_with_program(
        LocalProgram::new(&program)?.expected_sha256(new_sha),
        Duration::from_secs(35),
    )
    .await?;
    assert_eq!(core.program_info().version, "v2.33.2");
    assert_eq!(core.client().system_status().await?.device_id, identity);
    assert_eq!(core.client().folder_status(&id).await?.local_files, Some(1));
    let after = core.client().folder(&id).await?;
    assert_eq!(before.id, after.id);
    for field in ["secretKey", "readOnlySecret", "readWriteSecret"] {
        assert_eq!(before.extra.get(field), after.extra.get(field));
    }
    assert_eq!(
        std::fs::read(data.join("retained.bin"))?,
        b"native upgrade retained bytes"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    result?;
    std::fs::remove_dir_all(root)?;
    println!(
        "public native kernel upgrade evidence: {}",
        serde_json::json!({"mode":if upload { "streamed_archive" } else { "provider" },
        "default_check_rejected_without_program_change":true,"manual_periodic_checks_disabled":true,
        "actual_explicit_mode_prerequisites_checked":true,"actual_old_program_normally_stopped":true,
        "actual_owned_program_replaced_with_fixed_baseline_sha":true,"actual_new_version_authenticated":true,
        "actual_identity_and_folder_keys_preserved":true,"actual_old_index_loaded_without_initial_scan":true,
        "actual_sample_bytes_preserved":true,"actual_new_tree_normally_stopped":true})
    );
    Ok(())
}

#[tokio::test]
async fn offline_backup_restore_preserves_old_index_and_rejects_corruption() -> TestResult {
    use verysync_sidecar::{CreateFolderOptions, FolderId, FolderPatch, StateBackupOptions};
    let root = tempfile::Builder::new().prefix("vub-").tempdir()?.keep();
    let settings = options(&root.join("c"))?;
    let mut core = ManagedInstance::start(settings.clone()).await?;
    let identity = core.client().instance().device_id.clone();
    let id = FolderId::parse("state-backup-index")?;
    let data = root.join("data");
    std::fs::create_dir(&data)?;
    std::fs::write(data.join("retained.bin"), b"retained snapshot sample")?;
    core.client()
        .create_folder(
            &CreateFolderOptions::new(id.clone(), verysync_sidecar::TargetPath::local(&data))
                .label("before snapshot"),
        )
        .await?;
    core.client()
        .update_folder_scan_configuration(
            &id,
            &FolderScanPatch::default()
                .watcher(false)
                .rescan_interval_seconds(0)
                .disable_initial_scan(true),
        )
        .await?;
    core.client().request_scan(&id).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if core.client().folder_status(&id).await?.local_files == Some(1) {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let active = root.join("active-rejected");
    assert!(core
        .backup_state(StateBackupOptions::new(&active)?)
        .await
        .is_err());
    assert!(!active.exists());
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    assert!(core
        .backup_state(StateBackupOptions::new(root.join("too-small"))?.max_total_bytes(1)?)
        .await
        .is_err());
    let backup = core
        .backup_state(StateBackupOptions::new(root.join("backup"))?)
        .await?;
    assert!(backup.info().file_count >= 5 && backup.info().total_bytes > 0);
    assert_eq!(backup.info().device_id, identity);
    assert!(!format!("{backup:?}").contains(root.to_str().unwrap()));
    assert!(verysync_sidecar::StateBackup::open(
        backup.directory(),
        [0; 32],
        Duration::from_secs(10)
    )
    .await
    .is_err());
    let backup = verysync_sidecar::StateBackup::open(
        backup.directory(),
        backup.info().manifest_sha256,
        Duration::from_secs(10),
    )
    .await?;
    core.restart(Duration::from_secs(30)).await?;
    core.client()
        .update_folder(&id, &FolderPatch::default().label("after snapshot"))
        .await?;
    std::fs::write(
        data.join("later.bin"),
        b"later data remains outside the state snapshot",
    )?;
    core.client().request_scan(&id).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if core.client().folder_status(&id).await?.local_files == Some(2) {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    let restored = backup
        .restore_to(root.join("restored"), Duration::from_secs(30))
        .await?;
    assert!(backup
        .restore_to(&restored, Duration::from_secs(30))
        .await
        .is_err());
    let new_settings = ManagedOptions::new(
        settings.program().clone(),
        &restored,
        #[cfg(unix)]
        verysync_sidecar::ManagementEndpoint::unix_socket(restored.join("gui.sock"))?,
        #[cfg(windows)]
        {
            let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            verysync_sidecar::ManagementEndpoint::http(&format!(
                "http://{}/",
                listener.local_addr()?
            ))?
        },
    )?;
    let mut restored_core = ManagedInstance::start(new_settings).await?;
    assert_eq!(
        restored_core.client().system_status().await?.device_id,
        identity
    );
    assert_eq!(
        restored_core.client().folder(&id).await?.label,
        "before snapshot"
    );
    assert_eq!(
        restored_core.client().folder_status(&id).await?.local_files,
        Some(1)
    );
    assert_eq!(
        std::fs::read(data.join("retained.bin"))?,
        b"retained snapshot sample"
    );
    assert_eq!(
        std::fs::read(data.join("later.bin"))?,
        b"later data remains outside the state snapshot"
    );
    let exit = restored_core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::write(
        backup.directory().join("data").join("cert.pem"),
        b"corrupt snapshot certificate",
    )?;
    let rejected = root.join("corrupt-rejected");
    assert!(backup
        .restore_to(&rejected, Duration::from_secs(30))
        .await
        .is_err());
    assert!(!rejected.join(".verysync-sidecar-state").exists());
    std::fs::write(
        rejected.join(".verysync-sidecar-state"),
        b"verysync-sidecar private state v1\n",
    )?;
    assert!(matches!(
        ManagedInstance::start(options(&rejected)?).await,
        Err(Error::UnmanagedState)
    ));
    std::fs::remove_dir_all(root)?;
    println!(
        "public offline state backup evidence: {}",
        serde_json::json!({
            "active_core_backup_rejected_before_destination_creation":true,"explicit_byte_bound_rejected":true,
            "actual_complete_private_state_snapshot":true,"actual_device_identity_in_snapshot":true,
            "original_state_changed_after_snapshot":true,"restore_requires_new_destination":true,
            "actual_restored_core_authenticates_same_identity":true,"actual_old_configuration_restored":true,
            "actual_old_sqlite_index_restored_without_initial_scan":true,
            "synced_data_not_rolled_back_or_deleted_by_state_restore":true,
            "corrupt_file_rejected_before_state_admission":true,"all_actual_normal_tree_exits":true
        ,"pinned_manifest_reopens_without_prior_handle":true,"wrong_manifest_hash_rejected":true,
        "incomplete_restore_rejected_even_with_valid_state_marker":true
        })
    );
    Ok(())
}

#[tokio::test]
async fn failed_program_selection_stays_selected_until_explicit_reselection() -> TestResult {
    let root = tempfile::Builder::new().prefix("vuf-").tempdir()?.keep();
    let settings = options(&root.join("c"))?;
    let mut core = ManagedInstance::start(settings.clone()).await?;
    let original = core.program_info().clone();
    let identity = core.client().instance().device_id.clone();
    let config = std::fs::read(core.state_directory().join("setting.dat"))?;
    let rejected_path = root.join(
        settings
            .program()
            .path()
            .file_name()
            .ok_or("program name missing")?,
    );
    std::fs::copy(settings.program().path(), &rejected_path)?;
    let rejected = LocalProgram::new(&rejected_path)?.expected_sha256([0; 32]);
    let error = core
        .restart_with_program(rejected, Duration::from_secs(30))
        .await
        .unwrap_err();
    assert!(matches!(error, Error::ProgramRejected { .. }));
    let exit = core.wait_for_exit().await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    assert_eq!(core.selected_program().path(), rejected_path);
    assert_eq!(core.program_info(), &original);
    assert!(matches!(
        core.restart(Duration::from_secs(30)).await,
        Err(Error::ProgramRejected { .. })
    ));
    assert_eq!(core.selected_program().path(), rejected_path);
    assert_eq!(
        std::fs::read(core.state_directory().join("setting.dat"))?,
        config
    );
    let transition = core
        .restart_with_program(settings.program().clone(), Duration::from_secs(30))
        .await?;
    assert!(transition.previous_exit.tree_stopped && !transition.previous_exit.forced);
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public failed program selection evidence: {}",
        serde_json::json!({
            "old_tree_normally_stopped_before_rejection":true,"wrong_program_hash_is_rejected":true,
            "failed_selection_retained":true,"plain_retry_does_not_restore_previous_program":true,
            "last_ready_program_information_retained":true,"rejected_attempts_preserve_configuration_bytes":true,
            "explicit_reselection_restores_authenticated_readiness":true,"actual_identity_retained":true,
            "actual_final_normal_tree_exit":true
        })
    );
    Ok(())
}

#[tokio::test]
async fn actual_2331_to_baseline_switch_preserves_index_identity_and_credentials() -> TestResult {
    let root = tempfile::Builder::new().prefix("vug-").tempdir()?.keep();
    let base = options(&root.join("c"))?;
    let old = ManagedOptions::new(
        upgrade_source()?,
        base.state_directory(),
        base.management_endpoint().clone(),
    )?
    .startup_timeout(Duration::from_secs(25))?;
    let rejection = ManagedInstance::start(old.clone()).await.unwrap_err();
    assert!(matches!(rejection, Error::ProgramRejected { .. }));
    for name in ["setting.dat", "key.pem", "cert.pem"] {
        assert!(!base.state_directory().join(name).exists());
    }
    let old = old.version_policy(VersionPolicy::AllowUnverified);
    let mut core = ManagedInstance::start(old.clone()).await?;
    assert_eq!(core.program_info().version, "v2.33.1");
    assert_eq!(
        core.client().instance().compatibility,
        VersionCompatibility::Unverified
    );
    assert_eq!(
        old.connect_existing().await?.instance().version.version,
        "v2.33.1"
    );
    let identity = core.client().instance().device_id.clone();
    let old_program = core.program_info().clone();
    let keys = core.client().generate_share().await?;
    let rw = core
        .client()
        .validate_share_key(&keys.read_write_key)
        .await?;
    let data = root.join("data");
    std::fs::create_dir(&data)?;
    let samples = [
        ("first.bin", b"old-index first synthetic bytes".as_slice()),
        ("second.bin", b"old-index second synthetic bytes".as_slice()),
    ];
    for (name, bytes) in samples {
        std::fs::write(data.join(name), bytes)?;
    }
    let folder = core
        .client()
        .join_folder(
            &JoinFolderOptions::new(rw, verysync_sidecar::TargetPath::local(&data)).paused(true),
        )
        .await?;
    core.client()
        .update_folder_scan_configuration(
            &folder.configuration.id,
            &FolderScanPatch::default()
                .watcher(false)
                .rescan_interval_seconds(0)
                .disable_initial_scan(true),
        )
        .await?;
    core.client()
        .resume_folder(&folder.configuration.id)
        .await?;
    core.client().request_scan(&folder.configuration.id).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let s = core
                .client()
                .folder_status(&folder.configuration.id)
                .await?;
            if s.local_files == Some(2) && s.state == Some(verysync_sidecar::FolderState::Idle) {
                return Ok::<_, Error>(s);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let before = core.client().folder(&folder.configuration.id).await?;
    assert!(before
        .extra
        .get("secretKey")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| !s.is_empty()));
    let config_before = std::fs::read(base.state_directory().join("setting.dat"))?;
    let old_config = rmpv::decode::read_value(&mut std::io::Cursor::new(config_before))?;
    let db = std::fs::read(base.state_directory().join("index-v2").join("main.db"))?;
    assert!(db.starts_with(b"SQLite format 3\0"));
    let stopped = core.shutdown(Duration::from_secs(10)).await?;
    assert!(stopped.tree_stopped && !stopped.forced && stopped.code == Some(0));
    let saved_old = core
        .backup_state(verysync_sidecar::StateBackupOptions::new(
            root.join("before-upgrade"),
        )?)
        .await?;
    assert_eq!(saved_old.info().source_program.version, "v2.33.1");
    let transition = core
        .restart_with_program(base.program().clone(), Duration::from_secs(45))
        .await?;
    assert!(
        transition.previous_exit.tree_stopped
            && !transition.previous_exit.forced
            && transition.previous_exit.code == Some(0)
    );
    assert_eq!(transition.previous_program, old_program);
    assert_eq!(transition.current_program, core.program_info().clone());
    assert_eq!(core.program_info().version, "v2.33.2");
    assert_eq!(
        core.client().instance().compatibility,
        VersionCompatibility::ValidatedBaseline
    );
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let after = core.client().folder(&folder.configuration.id).await?;
    assert_eq!(before.id, after.id);
    for field in ["secretKey", "readOnlySecret", "readWriteSecret"] {
        assert!(before.extra.get(field) == after.extra.get(field));
    }
    let new_config = rmpv::decode::read_value(&mut std::io::Cursor::new(std::fs::read(
        base.state_directory().join("setting.dat"),
    )?))?;
    for field in ["3", "4", "6"] {
        assert!(old_config["4"][field] == new_config["4"][field]);
    }
    let status = core
        .client()
        .folder_status(&folder.configuration.id)
        .await?;
    assert_eq!(status.local_files, Some(2));
    assert_eq!(
        status.local_bytes,
        Some(samples.iter().map(|(_, b)| b.len() as u64).sum())
    );
    let scan = core
        .client()
        .folder_scan_configuration(&folder.configuration.id)
        .await?;
    assert!(
        scan.disable_initial_scan && !scan.watcher_enabled && scan.rescan_interval_seconds == 0
    );
    for (name, bytes) in samples {
        assert_eq!(std::fs::read(data.join(name))?, bytes);
    }
    core.client()
        .update_folder(
            &folder.configuration.id,
            &verysync_sidecar::FolderPatch::default().label("after upgrade candidate"),
        )
        .await?;
    std::fs::write(
        data.join("after-upgrade.bin"),
        b"newer generation data remains",
    )?;
    core.client().request_scan(&folder.configuration.id).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if core
                .client()
                .folder_status(&folder.configuration.id)
                .await?
                .local_files
                == Some(3)
            {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    let restored = saved_old
        .restore_to(root.join("rollback"), Duration::from_secs(30))
        .await?;
    let endpoint = options(&restored)?.management_endpoint().clone();
    let restored_options = ManagedOptions::new(upgrade_source()?, &restored, endpoint)?
        .version_policy(VersionPolicy::AllowUnverified);
    let mut old_again = ManagedInstance::start(restored_options).await?;
    assert_eq!(old_again.program_info().version, "v2.33.1");
    assert_eq!(
        old_again.client().system_status().await?.device_id,
        identity
    );
    let rolled = old_again.client().folder(&folder.configuration.id).await?;
    assert_eq!(rolled.label, before.label);
    assert_eq!(
        old_again
            .client()
            .folder_status(&folder.configuration.id)
            .await?
            .local_files,
        Some(2)
    );
    for field in ["secretKey", "readOnlySecret", "readWriteSecret"] {
        assert!(rolled.extra.get(field) == before.extra.get(field));
    }
    let rolled_config = rmpv::decode::read_value(&mut std::io::Cursor::new(std::fs::read(
        restored.join("setting.dat"),
    )?))?;
    for field in ["3", "4", "6"] {
        assert!(rolled_config["4"][field] == old_config["4"][field]);
    }
    assert_eq!(
        std::fs::read(data.join("after-upgrade.bin"))?,
        b"newer generation data remains"
    );
    for (name, bytes) in samples {
        assert_eq!(std::fs::read(data.join(name))?, bytes);
    }
    let exit = old_again.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public different-version switch evidence: {}",
        serde_json::json!({
            "default_rejects_old_program_before_identity_generation":true,
            "explicit_unverified_policy_starts_actual_2331":true,"explicit_existing_connection_uses_same_policy":true,
            "actual_old_sqlite_index_populated":true,"actual_old_tree_normally_stopped":true,
            "actual_new_2332_program_and_management_version":true,"actual_same_device_identity":true,
            "actual_same_folder_id_and_sharing_keys":true,"actual_same_api_and_gui_authentication":true,
            "actual_old_database_file_counts_loaded_without_initial_scan":true,
            "actual_scan_policy_and_complete_sample_bytes_retained":true,"actual_new_tree_normally_stopped":true,
            "actual_saved_clean_old_state_before_upgrade":true,"actual_new_version_state_changed_after_upgrade":true,
            "actual_restore_uses_snapshot_instead_of_database_downgrade":true,
            "actual_rollback_runs_pinned_2331_and_same_identity":true,
            "actual_old_index_and_configuration_restored_after_upgrade":true,
            "actual_rollback_sharing_and_auth_material_preserved":true,
            "later_synced_data_preserved_outside_restored_state":true,
            "actual_restored_old_tree_normally_stopped":true
        })
    );
    Ok(())
}

#[tokio::test]
async fn stopped_owner_cli_checks_and_upgrades_the_dedicated_program() -> TestResult {
    use sha2::{Digest, Sha256};
    use verysync_sidecar::KernelUpgradeCommand;
    for provider in [false, true] {
        let root = tempfile::Builder::new().prefix("vcl-").tempdir()?.keep();
        let old = upgrade_source()?;
        let program = root.join(old.path().file_name().ok_or("program name missing")?);
        std::fs::copy(old.path(), &program)?;
        let old_sha: [u8; 32] = Sha256::digest(std::fs::read(&program)?).into();
        let base = options(&root.join("c"))?;
        let settings = ManagedOptions::new(
            LocalProgram::new(&program)?.expected_sha256(old_sha),
            base.state_directory(),
            base.management_endpoint().clone(),
        )?
        .version_policy(VersionPolicy::AllowUnverified);
        let mut core = ManagedInstance::start(settings).await?;
        let identity = core.client().system_status().await?.device_id;
        assert!(core
            .run_cli_upgrade(KernelUpgradeCommand::Check, Duration::from_secs(20))
            .await
            .is_err());
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
        let check = core
            .run_cli_upgrade(KernelUpgradeCommand::Check, Duration::from_secs(20))
            .await?;
        report_upgrade_diagnostic("cli-check", check.diagnostic.body_bytes());
        eprintln!(
            "native CLI upgrade check: code={:?} output_bytes={}",
            check.code,
            check.diagnostic.body_bytes().len()
        );
        assert!(check.tree_stopped);
        assert_eq!(
            check.code,
            Some(if check.release_unavailable { 1 } else { 0 })
        );
        if check.release_unavailable {
            assert_eq!(
                (std::env::consts::OS, std::env::consts::ARCH),
                ("windows", "aarch64")
            );
        }
        assert_eq!(Sha256::digest(std::fs::read(&program)?).as_slice(), old_sha);
        core.restart(Duration::from_secs(30)).await?;
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
        let unchanged_config = std::fs::read(base.state_directory().join("setting.dat"))?;
        let command = if provider {
            KernelUpgradeCommand::Provider
        } else {
            let mut url = baseline_asset()?.download_url().clone();
            url.set_scheme("http")
                .map_err(|_| "cannot select explicit local test archive source")?;
            KernelUpgradeCommand::FromUrl(url)
        };
        let upgraded = core
            .run_cli_upgrade(command, Duration::from_secs(30))
            .await?;
        report_upgrade_diagnostic("cli-upgrade", upgraded.diagnostic.body_bytes());
        std::fs::write(
            root.join("cli-upgrade-output.bin"),
            upgraded.diagnostic.body_bytes(),
        )?;
        eprintln!(
            "native CLI upgrade outcome: provider={provider} code={:?} output_bytes={}",
            upgraded.code,
            upgraded.diagnostic.body_bytes().len()
        );
        if provider && upgraded.release_unavailable {
            assert_eq!(
                (std::env::consts::OS, std::env::consts::ARCH),
                ("windows", "aarch64")
            );
            assert_eq!(upgraded.code, Some(1));
            assert!(upgraded.tree_stopped);
            assert_eq!(Sha256::digest(std::fs::read(&program)?).as_slice(), old_sha);
            assert_eq!(
                std::fs::read(base.state_directory().join("setting.dat"))?,
                unchanged_config
            );
            core.restart(Duration::from_secs(30)).await?;
            assert_eq!(core.program_info().version, "v2.33.1");
            assert_eq!(core.client().system_status().await?.device_id, identity);
            let exit = core.shutdown(Duration::from_secs(10)).await?;
            assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
            std::fs::remove_dir_all(root)?;
            println!(
                "public CLI provider release absence evidence: {}",
                serde_json::json!({
                "actual_cli_reports_known_missing_release_and_exit1":true,"actual_cli_containment_stopped":true,
                "actual_old_program_sha_and_configuration_retained":true,"actual_old_version_identity_restarts":true,
                "actual_normal_owned_tree_exit":true,"positive_provider_upgrade":"pending"})
            );
            continue;
        }
        assert!(!upgraded.release_unavailable);
        assert!(upgraded.tree_stopped);
        assert_eq!(upgraded.code, Some(if provider { 4 } else { 0 }));
        let actual: [u8; 32] = Sha256::digest(std::fs::read(&program)?).into();
        assert_ne!(actual, old_sha);
        assert_eq!(
            actual,
            Sha256::digest(std::fs::read(base.program().path())?).as_slice()
        );
        core.restart_with_program(
            LocalProgram::new(&program)?.expected_sha256(actual),
            Duration::from_secs(35),
        )
        .await?;
        assert_eq!(core.program_info().version, "v2.33.2");
        assert_eq!(core.client().system_status().await?.device_id, identity);
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
        std::fs::remove_dir_all(root)?;
        println!(
            "public CLI upgrade evidence: {}",
            serde_json::json!({"mode":if provider { "provider" } else { "archive_url" },
            "actual_running_owner_rejected":true,"actual_old_tree_normally_stopped":true,
            "actual_cli_check_exit_and_exact_program_unchanged":true,"actual_cli_upgrade_containment_stopped":true,
            "actual_program_replaced_with_fixed_baseline_sha":true,"actual_new_version_authenticated":true,
            "actual_same_device_identity":true,"actual_new_tree_normally_stopped":true})
        );
    }
    Ok(())
}

async fn copying_partial(path: &std::path::Path, full: u64) -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match std::fs::metadata(path) {
                Ok(m) if m.len() > 0 && m.len() < full => {
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                }
                Ok(m) if m.len() >= full => {
                    return Err("copy completed before the cancellation observation".into())
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await?
}
async fn released_copy_lease(path: &std::path::Path) -> TestResult {
    use fs2::FileExt;
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?;
            match file.try_lock_exclusive() {
                Ok(()) => return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(()),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.raw_os_error() == Some(33) => {}
                Err(e) => return Err(e.into()),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?
}
#[tokio::test]
async fn cancelled_copies_release_real_leases_and_never_admit_partial_state() -> TestResult {
    use verysync_sidecar::{StateBackup, StateBackupOptions};
    let root = tempfile::Builder::new().prefix("vbc-").tempdir()?.keep();
    let settings = options(&root.join("c"))?;
    let mut core = ManagedInstance::start(settings.clone()).await?;
    let identity = core.client().system_status().await?.device_id;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    let name = "bounded-cancellation-sample.bin";
    let bytes = 128 * 1024 * 1024;
    let file = std::fs::File::create(settings.state_directory().join(name))?;
    file.set_len(bytes)?;
    drop(file);
    let partial = root.join("partial-backup");
    let partial_file = partial.join("data").join(name);
    let mut pending = Box::pin(core.backup_state(StateBackupOptions::new(&partial)?));
    tokio::select! {
        result=&mut pending => { result?; return Err("backup completed before cancellation".into()); },
        observed=copying_partial(&partial_file,bytes) => { observed?; }
    }
    drop(pending);
    released_copy_lease(&settings.state_directory().join(".verysync-sidecar-lease")).await?;
    assert!(partial.join(".snapshot-incomplete").is_file());
    assert!(!partial.join("manifest.json").exists());
    assert!(
        StateBackup::open(&partial, [0; 32], Duration::from_secs(10))
            .await
            .is_err()
    );
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    let backup = core
        .backup_state(StateBackupOptions::new(root.join("complete"))?)
        .await?;
    let destination = root.join("partial-restore");
    let restored_file = destination.join(name);
    let mut pending = Box::pin(backup.restore_to(&destination, Duration::from_secs(30)));
    tokio::select! {
        result=&mut pending => { result?; return Err("restore completed before cancellation".into()); },
        observed=copying_partial(&restored_file,bytes) => { observed?; }
    }
    drop(pending);
    released_copy_lease(&destination.join(".verysync-sidecar-lease")).await?;
    assert!(destination
        .join(".verysync-sidecar-restore-incomplete")
        .is_file());
    assert!(!destination.join(".verysync-sidecar-state").exists());
    std::fs::write(
        destination.join(".verysync-sidecar-state"),
        b"verysync-sidecar private state v1\n",
    )?;
    assert!(matches!(
        ManagedInstance::start(options(&destination)?).await,
        Err(Error::UnmanagedState)
    ));
    assert_eq!(
        std::fs::metadata(settings.state_directory().join(name))?.len(),
        bytes
    );
    std::fs::remove_dir_all(root)?;
    println!(
        "public cancelled copy evidence: {}",
        serde_json::json!({
        "actual_backup_cancelled_after_nonempty_partial_copy":true,"actual_source_lease_released_after_cancellation":true,
        "actual_incomplete_backup_rejected":true,"actual_source_restarts_with_same_identity":true,
        "actual_restore_cancelled_after_nonempty_partial_copy":true,"actual_destination_lease_released_after_cancellation":true,
        "actual_incomplete_restore_rejected_even_with_admission_marker":true,"actual_source_content_preserved":true})
    );
    Ok(())
}

async fn exact_program_pids(program: &std::path::Path) -> TestResult<Vec<u32>> {
    let program = program.to_owned();
    tokio::task::spawn_blocking(move || {
        #[cfg(windows)]
        let python = "python";
        #[cfg(unix)]
        let python = "python3";
        let output = std::process::Command::new(python)
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("scripts")
                    .join("prepare-test-engine.py"),
            )
            .arg("list-owned-processes")
            .env("VERYSYNC_TEST_BINARY", program)
            .output()?;
        if !output.status.success() {
            return Err("exact test-program inventory failed".into());
        }
        let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        parsed["pids"]
            .as_array()
            .ok_or("exact inventory missing PIDs")?
            .iter()
            .map(|v| {
                v.as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .filter(|n| *n > 0)
                    .ok_or_else(|| "invalid exact PID".into())
            })
            .collect::<TestResult<Vec<u32>>>()
    })
    .await?
}
#[tokio::test]
async fn cancelled_new_version_start_retains_selection_and_releases_exact_tree() -> TestResult {
    use sha2::{Digest, Sha256};
    use verysync_sidecar::{ManagementEndpoint, StateBackupOptions};
    let root = tempfile::Builder::new().prefix("vsc-").tempdir()?.keep();
    let next = root.join(
        upgrade_source()?
            .path()
            .file_name()
            .ok_or("program basename missing")?,
    );
    let base = options(&root.join("c"))?;
    std::fs::copy(base.program().path(), &next)?;
    let next_sha: [u8; 32] = Sha256::digest(std::fs::read(&next)?).into();
    let reservation = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = reservation.local_addr()?;
    let endpoint = ManagementEndpoint::http(&format!("http://{address}/"))?;
    let settings = ManagedOptions::new(upgrade_source()?, base.state_directory(), endpoint)?
        .version_policy(VersionPolicy::AllowUnverified);
    drop(reservation);
    let mut core = ManagedInstance::start(settings).await?;
    let identity = core.client().system_status().await?.device_id;
    let old_info = core.program_info().clone();
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_file(base.state_directory().join(".verysync-sidecar-core.log"))?;
    let blocker = std::net::TcpListener::bind(address)?;
    let selected = LocalProgram::new(&next)?.expected_sha256(next_sha);
    let mut pending = Box::pin(core.restart_with_program(selected, Duration::from_secs(30)));
    tokio::select! {
        outcome=&mut pending=>{ outcome?; return Err("new version became ready before cancellation".into()); },
        observed=async {
            tokio::time::timeout(Duration::from_secs(15),async { loop {
                if base.state_directory().join(".verysync-sidecar-core.log").exists()&&!exact_program_pids(&next).await?.is_empty() {
                    return Ok::<_,Box<dyn std::error::Error+Send+Sync>>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }}).await?
        }=>{ observed?; }
    }
    drop(pending);
    assert_eq!(core.selected_program().path(), next);
    assert_eq!(core.program_info(), &old_info);
    assert!(core
        .backup_state(StateBackupOptions::new(root.join("unsafe-backup"))?)
        .await
        .is_err());
    assert!(!root.join("unsafe-backup").exists());
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            if exact_program_pids(&next).await?.is_empty() {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    released_copy_lease(&base.state_directory().join(".verysync-sidecar-lease")).await?;
    drop(blocker);
    core.restart(Duration::from_secs(35)).await?;
    assert_eq!(core.program_info().version, "v2.33.2");
    assert_eq!(core.client().system_status().await?.device_id, identity);
    assert_eq!(Sha256::digest(std::fs::read(&next)?).as_slice(), next_sha);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    assert!(exact_program_pids(&next).await?.is_empty());
    std::fs::remove_dir_all(root)?;
    println!(
        "public cancelled version switch evidence: {}",
        serde_json::json!({
        "actual_new_core_created_before_cancelled_readiness":true,"actual_new_selection_retained_after_cancel":true,
        "actual_last_ready_metadata_retained_separately":true,"actual_unknown_generation_backup_refused":true,
        "actual_exact_new_program_tree_and_state_lease_released":true,
        "explicit_retry_starts_new_version_with_same_identity":true,"actual_program_bytes_preserved":true,
        "actual_recovered_new_tree_normally_stopped":true})
    );
    Ok(())
}

async fn bounded_request_head(stream: &mut tokio::net::TcpStream) -> TestResult<String> {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= 16384 {
            return Err("private request header exceeded bound".into());
        }
        bytes.push(stream.read_u8().await?);
    }
    Ok(String::from_utf8(bytes)?)
}
#[tokio::test]
async fn cancelled_cli_download_stops_exact_helper_without_program_or_state_replacement(
) -> TestResult {
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use verysync_sidecar::KernelUpgradeCommand;
    let root = tempfile::Builder::new().prefix("vcc-").tempdir()?.keep();
    let old = upgrade_source()?;
    let program = root.join(old.path().file_name().ok_or("program basename missing")?);
    std::fs::copy(old.path(), &program)?;
    let sha: [u8; 32] = Sha256::digest(std::fs::read(&program)?).into();
    let base = options(&root.join("c"))?;
    let settings = ManagedOptions::new(
        LocalProgram::new(&program)?.expected_sha256(sha),
        base.state_directory(),
        base.management_endpoint().clone(),
    )?
    .version_policy(VersionPolicy::AllowUnverified);
    let mut core = ManagedInstance::start(settings).await?;
    let identity = core.client().system_status().await?.device_id;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    let config = std::fs::read(base.state_directory().join("setting.dat"))?;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let archive_name = baseline_asset()?.archive_filename().to_owned();
    let url = url::Url::parse(&format!(
        "http://{}/{}",
        listener.local_addr()?,
        archive_name
    ))?;
    let archive =
        std::fs::read(std::env::var_os("VERYSYNC_TEST_ARCHIVE").ok_or("fixed archive required")?)?;
    assert_eq!(archive.len() as u64, baseline_asset()?.archive_bytes());
    let (started, ready) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        assert!(bounded_request_head(&mut stream)
            .await?
            .starts_with(&format!("GET /{archive_name} ")));
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    archive.len()
                )
                .as_bytes(),
            )
            .await?;
        stream.write_all(&archive[..65536]).await?;
        stream.flush().await?;
        let _ = started.send(());
        let mut byte = [0];
        match tokio::time::timeout(Duration::from_secs(12), stream.read(&mut byte)).await? {
            Ok(0) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => {}
            _ => return Err("cancelled CLI did not close its actual archive connection".into()),
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let mut pending =
        Box::pin(core.run_cli_upgrade(KernelUpgradeCommand::FromUrl(url), Duration::from_secs(30)));
    tokio::select! {result=&mut pending=>{result?;return Err("CLI ended before partial-download cancellation".into());},observed=ready=>{observed?;}}
    assert!(!exact_program_pids(&program).await?.is_empty());
    drop(pending);
    server.await??;
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            if exact_program_pids(&program).await?.is_empty() {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    released_copy_lease(&base.state_directory().join(".verysync-sidecar-lease")).await?;
    assert_eq!(Sha256::digest(std::fs::read(&program)?).as_slice(), sha);
    assert_eq!(
        std::fs::read(base.state_directory().join("setting.dat"))?,
        config
    );
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(core.program_info().version, "v2.33.1");
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public cancelled CLI upgrade evidence: {}",
        serde_json::json!({
        "actual_cli_running_after_partial_archive_delivery":true,"actual_archive_connection_closed_after_cancel":true,
        "actual_exact_cli_tree_and_state_lease_released":true,"actual_old_program_sha_and_configuration_retained":true,
        "actual_explicit_old_version_restart_and_identity":true,"actual_final_normal_tree_exit":true})
    );
    Ok(())
}

#[tokio::test]
async fn cancelled_streamed_upload_ends_actual_partial_request_without_program_replacement(
) -> TestResult {
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use verysync_sidecar::{ApiKey, Client, ConnectOptions, ManagementEndpoint};
    let root = tempfile::Builder::new().prefix("vcu-").tempdir()?.keep();
    let old = upgrade_source()?;
    let program = root.join(old.path().file_name().ok_or("program basename missing")?);
    std::fs::copy(old.path(), &program)?;
    let sha: [u8; 32] = Sha256::digest(std::fs::read(&program)?).into();
    let reservation = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = reservation.local_addr()?;
    drop(reservation);
    let base = options(&root.join("c"))?;
    let settings = ManagedOptions::new(
        LocalProgram::new(&program)?.expected_sha256(sha),
        base.state_directory(),
        ManagementEndpoint::http(&format!("http://{address}/"))?,
    )?
    .version_policy(VersionPolicy::AllowUnverified);
    let mut core = ManagedInstance::start(settings).await?;
    let identity = core.client().system_status().await?.device_id;
    let config = std::fs::read(base.state_directory().join("setting.dat"))?;
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(&config))?;
    let key = ApiKey::new(value["4"]["6"].as_str().ok_or("private API key missing")?)?;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let endpoint = ManagementEndpoint::http(&format!("http://{}/", listener.local_addr()?))?;
    let (started, ready) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut started = Some(started);
        for _ in 0..4 {
            let (mut client, _) = listener.accept().await?;
            let head = bounded_request_head(&mut client).await?;
            let upload = head.starts_with("POST /rest/system/upgrade/upload ");
            let rewritten = head
                .lines()
                .filter(|line| {
                    !line.is_empty() && !line.to_ascii_lowercase().starts_with("connection:")
                })
                .collect::<Vec<_>>()
                .join("\r\n")
                + "\r\nConnection: close\r\n\r\n";
            let mut upstream = tokio::net::TcpStream::connect(address).await?;
            upstream.write_all(rewritten.as_bytes()).await?;
            if upload {
                let mut buffer = [0; 65536];
                client.read_exact(&mut buffer).await?;
                upstream.write_all(&buffer).await?;
                let _ = started.take().ok_or("duplicate upload")?.send(());
                let drained = tokio::time::timeout(Duration::from_secs(10), async {
                    let mut total = 65536;
                    loop {
                        match client.read(&mut buffer).await {
                            Ok(0) => {
                                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(total)
                            }
                            Ok(n) => {
                                total += n;
                                if total > 8 * 1024 * 1024 {
                                    return Err(
                                        "cancelled uploader kept sending the full body".into()
                                    );
                                }
                            }
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    std::io::ErrorKind::ConnectionReset
                                        | std::io::ErrorKind::ConnectionAborted
                                ) =>
                            {
                                return Ok(total)
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                })
                .await??;
                assert!(drained < 8 * 1024 * 1024);
                drop(upstream);
            } else {
                tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
            }
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let client = Client::connect(
        ConnectOptions::new(endpoint, key)
            .expected_device_id(identity.clone())
            .version_policy(VersionPolicy::AllowUnverified),
    )
    .await?;
    let asset = baseline_asset()?;
    let archive =
        PathBuf::from(std::env::var_os("VERYSYNC_TEST_ARCHIVE").ok_or("fixed archive required")?);
    let mut pending = Box::pin(client.upload_kernel_upgrade(archive, &asset));
    tokio::select! {result=&mut pending=>{result?;return Err("upload ended before partial-request cancellation".into());},observed=ready=>{observed?;}}
    drop(pending);
    server.await??;
    assert_eq!(Sha256::digest(std::fs::read(&program)?).as_slice(), sha);
    assert_eq!(
        std::fs::read(base.state_directory().join("setting.dat"))?,
        config
    );
    assert_eq!(core.client().system_status().await?.device_id, identity);
    assert_eq!(core.client().version().await?.version, "v2.33.1");
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public cancelled HTTP upgrade evidence: {}",
        serde_json::json!({
        "actual_authenticated_upload_reaches_real_kernel_with_partial_body":true,
        "actual_client_connection_ends_after_future_cancellation":true,"actual_incomplete_archive_never_fully_forwarded":true,
        "actual_program_sha_and_configuration_preserved":true,"actual_old_version_identity_still_authenticated":true,
        "actual_final_normal_tree_exit":true})
    );
    Ok(())
}

fn report_upgrade_diagnostic(stage: &str, bytes: &[u8]) {
    use sha2::{Digest, Sha256};
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let categories: [(&str, &[&str]); 9] = [
        (
            "certificate",
            &["x509", "certificate", "certgetcertificatechain"],
        ),
        ("dns", &["no such host", "lookup ", "name resolution"]),
        ("tls", &["tls:", "handshake", "ssl"]),
        ("http_forbidden", &["403", "forbidden"]),
        ("timeout", &["timeout", "deadline exceeded"]),
        (
            "missing_matching_release",
            &[
                "couldn't find a release to download",
                "no version",
                "no release",
                "not found",
                "no asset",
                "unsupported platform",
            ],
        ),
        (
            "connection",
            &["connectex", "connection refused", "network is unreachable"],
        ),
        ("proxy", &["proxyconnect", "proxy error"]),
        ("json", &["invalid character", "json:", "unmarshal"]),
    ];
    let tags = categories
        .iter()
        .filter(|(_, patterns)| patterns.iter().any(|p| text.contains(p)))
        .map(|(tag, _)| *tag)
        .collect::<Vec<_>>();
    let sha = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    eprintln!(
        "Native upgrade private diagnostic classification: {}",
        serde_json::json!({"stage":stage,"bytes":bytes.len(),"sha256":sha,"categories":tags})
    );
}
