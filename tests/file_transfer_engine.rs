//! Actual file payloads through public APIs, independent of raw characterization.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
#[path = "common/resource_faults.rs"]
mod resource_faults;
#[path = "common/resource_fixture.rs"]
mod resource_fixture;
use managed_fixture::{options, TestResult};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, path::Path, time::Duration};
use verysync_sidecar::{
    CreateFolderOptions, Error, FolderId, ManagedInstance, ResourceArchiveFormat,
    ResourceByteRange, ResourceChecksum, ResourcePath, ResourceTransferOptions,
    ResourceUploadConflict, TargetPath,
};

async fn mount(
    core: &ManagedInstance,
) -> TestResult<(std::path::PathBuf, ResourcePath, std::path::PathBuf)> {
    let volumes = core.client().resource_volumes().await?;
    resource_fixture::owned_base(core, &volumes)
}
fn digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[tokio::test]
async fn public_owned_process_failure_retains_partial_download_and_recovers_explicitly(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vpf-").tempdir()?.keep();
    let state = root.join("core");
    println!("native process fault phase: before_initial_start");
    let mut core = ManagedInstance::start(options(&state)?).await?;
    println!("native process fault phase: initial_ready");
    let identity = core.client().instance().device_id.clone();
    let original_pid = core.process_id();
    let config = std::fs::read(state.join("setting.dat"))?;
    let (profile, volume, _) = mount(&core).await?;
    println!("native process fault phase: native_resources_mounted");
    let source = profile.join("owned-process-source.bin");
    let total = 128 * 1024 * 1024;
    let generated = source.clone();
    let (pattern, expected) =
        tokio::task::spawn_blocking(move || resource_faults::write_pattern(&generated, total))
            .await??;
    println!("native process fault phase: synthetic_source_ready");
    let output = root.join("interrupted-download.bin");
    let path = volume.child("owned-process-source.bin")?;
    let client = core.client().clone();
    let destination = output.clone();
    let operation = ResourceTransferOptions {
        max_bytes: total,
        deadline: Duration::from_secs(30),
    };
    let limits = operation.clone();
    let download = tokio::spawn(async move {
        client
            .download_resource(&path, &destination, None, &limits)
            .await
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(metadata) = tokio::fs::metadata(&output).await {
                if metadata.len() > 0 {
                    assert!(
                        metadata.len() < total,
                        "must inject a real inflight process failure"
                    );
                    break;
                }
            }
            assert!(
                !download.is_finished(),
                "download completed before the failure boundary"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    let exit = core.force_stop(Duration::from_secs(10)).await?;
    assert!(exit.forced && exit.tree_stopped && exit.state_released);
    println!("native process fault phase: actual_owned_force_stop_verified");
    let result = tokio::time::timeout(Duration::from_secs(10), download).await??;
    assert!(
        matches!(
            result,
            Err(Error::Transport { .. }) | Err(Error::ResourceTransferRejected { .. })
        ),
        "a truncated native connection must remain a transport/integrity failure: {result:?}"
    );
    let (retained, _) = verify_fault_pattern(&output, &pattern, total).await?;
    assert!(retained > 0 && retained < total);
    assert_eq!(
        verify_fault_pattern(&source, &pattern, total).await?,
        (total, expected)
    );
    assert_eq!(std::fs::read(state.join("setting.dat"))?, config);
    println!("native process fault phase: before_explicit_restart");
    core.restart(Duration::from_secs(30)).await?;
    println!("native process fault phase: explicit_restart_returned_ready");
    assert_ne!(core.process_id(), original_pid);
    assert_eq!(core.client().system_status().await?.device_id, identity);
    println!("native process fault phase: restarted_identity_verified");
    let (_, volume, _) = mount(&core).await?;
    let recovered = root.join("explicit-recovered-download.bin");
    let receipt = core
        .client()
        .download_resource(
            &volume.child("owned-process-source.bin")?,
            &recovered,
            None,
            &operation,
        )
        .await?;
    assert_eq!((receipt.bytes, receipt.sha256), (total, expected));
    println!("native process fault phase: recovered_download_receipt_verified");
    assert_eq!(
        verify_fault_pattern(&recovered, &pattern, total).await?,
        (total, expected)
    );
    assert_eq!(
        verify_fault_pattern(&output, &pattern, total).await?.0,
        retained
    );
    assert_eq!(std::fs::read(state.join("setting.dat"))?, config);
    println!("native process fault phase: before_recovered_normal_shutdown");
    let normal = core.shutdown(Duration::from_secs(10)).await?;
    assert!(
        normal.tree_stopped && normal.state_released && !normal.forced && normal.code == Some(0)
    );
    println!(
        "native process failure recovery evidence: {}",
        serde_json::json!({
        "actual_nonempty_inflight_download":true,"actual_exact_owned_tree_force_stop":true,
        "actual_truncated_connection_is_error":true,"retained_prefix_bytes":retained,"source_bytes":total,
        "actual_source_and_configuration_unchanged":true,"explicit_restart_preserved_identity":true,
        "actual_new_root_process":true,"explicit_new_destination_download_complete_and_hashed":true,
        "old_partial_output_preserved":true,"actual_recovered_normal_tree_exit":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Large independent byte oracles must not starve the management HTTP reactor.
async fn verify_fault_pattern(
    path: &Path,
    pattern: &[u8],
    limit: u64,
) -> TestResult<(u64, [u8; 32])> {
    let path = path.to_path_buf();
    let pattern = pattern.to_vec();
    tokio::task::spawn_blocking(move || resource_faults::verify_pattern(&path, &pattern, limit))
        .await?
}

// Archive entry names are native output, never controller filesystem paths.
fn archive_key(path: &Path) -> String {
    path.components()
        .map(|c| {
            c.as_os_str()
                .to_str()
                .expect("synthetic UTF-8 archive component")
        })
        .collect::<Vec<_>>()
        .join("/")
}
fn expected_selected_batch(relative: &Path) -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        (
            archive_key(&relative.join("batch").join("first.txt")),
            b"first".to_vec(),
        ),
        (
            archive_key(&relative.join("batch").join("second.txt")),
            b"second".to_vec(),
        ),
    ])
}
fn assert_directory_payloads(actual: BTreeMap<String, Vec<u8>>, relative: &Path) {
    let directory_relative = BTreeMap::from([
        ("first.txt".into(), b"first".to_vec()),
        ("second.txt".into(), b"second".to_vec()),
    ]);
    // The fixed Windows archiver retains volume-relative prefixes; Unix can
    // emit paths relative to the requested directory. Both exact sets contain
    // only the two intended files with all their expected bytes.
    if actual != directory_relative {
        assert_eq!(actual, expected_selected_batch(relative));
    }
}

#[tokio::test]
async fn public_native_paths_match_long_unicode_case_and_link_filesystem_effects() -> TestResult {
    let root = tempfile::Builder::new().prefix("vpath-").tempdir()?.keep();
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let (profile, volume, _) = mount(&core).await?;
    let directory = profile.join("paths \u{4e2d}\u{6587} %2e%2e +#");
    std::fs::create_dir(&directory)?;
    let remote = volume.clone().child("paths \u{4e2d}\u{6587} %2e%2e +#")?;
    let payload = b"owned native path bytes: Unicode, percent, case and links";
    std::fs::write(directory.join("source.txt"), payload)?;
    let mut long_directory = directory.clone();
    let mut long_remote = remote.clone();
    for index in 0..8 {
        let component = format!("s{index:02}_{}", "x".repeat(40));
        long_directory.push(&component);
        long_remote = long_remote.child(component)?;
    }
    std::fs::create_dir_all(&long_directory)?;
    let leaf = "\u{4e2d}\u{6587} %2e%2e +#.txt";
    let long_file = long_directory.join(leaf);
    std::fs::write(&long_file, payload)?;
    let path_units = long_file
        .to_str()
        .ok_or("synthetic UTF-8 path required")?
        .encode_utf16()
        .count();
    assert!(
        path_units > 320,
        "fixture must actually exceed the legacy path length"
    );
    let native_long = core
        .client()
        .resource_info(&long_remote.child(leaf)?)
        .await?;
    assert_eq!(
        native_long.content.as_deref(),
        Some(std::str::from_utf8(payload)?)
    );
    assert_eq!(native_long.size, payload.len() as u64);

    let mut equivalence = Vec::new();
    for (first, second, label) in [
        ("CaseProbe.txt", "caseprobe.txt", "case"),
        ("\u{e9}.txt", "e\u{301}.txt", "unicode_normalization"),
    ] {
        std::fs::write(directory.join(first), b"first independent native file")?;
        let equivalent = match std::fs::read(directory.join(second)) {
            Ok(bytes) => {
                assert_eq!(bytes, b"first independent native file");
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        if !equivalent {
            std::fs::write(directory.join(second), b"second independent native file")?;
        }
        for (name, bytes) in [
            (first, b"first independent native file".as_slice()),
            (
                second,
                if equivalent {
                    b"first independent native file".as_slice()
                } else {
                    b"second independent native file".as_slice()
                },
            ),
        ] {
            let actual = core
                .client()
                .resource_info(&remote.clone().child(name)?)
                .await?;
            assert_eq!(actual.content.as_deref(), Some(std::str::from_utf8(bytes)?));
            let expected: String = Sha256::digest(bytes)
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect();
            assert_eq!(
                core.client()
                    .resource_checksum(&remote.clone().child(name)?, ResourceChecksum::Sha256)
                    .await?,
                expected
            );
            assert_eq!(std::fs::read(directory.join(name))?, bytes);
        }
        equivalence.push(
            serde_json::json!({"dimension": label, "native_names_equivalent": equivalent,
            "actual_sdk_content_and_hash_match_native_files": true}),
        );
    }

    let real_parent = root.join("native destination parent");
    let branch = real_parent.join("branch");
    std::fs::create_dir_all(&branch)?;
    let alias = root.join("directory alias");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&branch, &alias)?;
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&branch, &alias)?;
    // Ask the real OS first. Windows and POSIX can resolve parent components
    // differently; the SDK must preserve that native behavior without guessing.
    std::fs::write(
        alias.join("..").join("oracle.txt"),
        b"independent native path oracle",
    )?;
    let uses_real_parent = real_parent.join("oracle.txt").is_file();
    let uses_lexical_parent = root.join("oracle.txt").is_file();
    assert_ne!(uses_real_parent, uses_lexical_parent);
    let destination = alias.join("..").join("received \u{4e8c} %.txt");
    let expected_destination = if uses_real_parent {
        &real_parent
    } else {
        &root
    }
    .join("received \u{4e8c} %.txt");
    let unused_destination = if uses_real_parent {
        &root
    } else {
        &real_parent
    }
    .join("received \u{4e8c} %.txt");
    let receipt = core
        .client()
        .download_resource(
            &remote.clone().child("source.txt")?,
            &destination,
            None,
            &ResourceTransferOptions {
                max_bytes: 1024,
                deadline: Duration::from_secs(20),
            },
        )
        .await?;
    assert_eq!(receipt.bytes, payload.len() as u64);
    assert_eq!(receipt.sha256, digest(payload));
    assert_eq!(std::fs::read(&expected_destination)?, payload);
    assert!(
        !unused_destination.exists(),
        "SDK must not choose different parent semantics"
    );
    assert!(std::fs::symlink_metadata(&alias)?.file_type().is_symlink());

    // A remote directory alias is interpreted by the target, not normalized
    // using the controller's filesystem syntax.
    let remote_alias = profile.join("resource directory alias");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&directory, &remote_alias)?;
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&directory, &remote_alias)?;
    let linked = volume
        .clone()
        .child("resource directory alias")?
        .child("source.txt")?;
    assert_eq!(
        core.client()
            .resource_info(&linked)
            .await?
            .content
            .as_deref(),
        Some(std::str::from_utf8(payload)?)
    );
    assert_eq!(std::fs::read(remote_alias.join("source.txt"))?, payload);

    #[cfg(unix)]
    let invalid_name = {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(vec![b'n', 0xff])
    };
    #[cfg(windows)]
    let invalid_name = {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(&[b'n' as u16, 0xd800])
    };
    let before = core.client().configuration().await?.native_document()["folders"].clone();
    assert!(before.is_array());
    let invalid = root.join(&invalid_name);
    let native_encoding_error =
        match std::fs::write(&invalid, b"independent native encoding oracle") {
            Ok(()) => None,
            Err(error) => {
                #[cfg(unix)]
                assert!(matches!(
                    error.raw_os_error(),
                    Some(libc::EINVAL | libc::EILSEQ)
                ));
                #[cfg(windows)]
                assert_eq!(
                    error.raw_os_error(),
                    Some(windows_sys::Win32::Foundation::ERROR_INVALID_NAME as i32)
                );
                Some(
                    error
                        .raw_os_error()
                        .ok_or("native encoding error code missing")?,
                )
            }
        };
    let mut native_destination_name = invalid_name;
    native_destination_name.push("-received");
    let native_destination = root.join(native_destination_name);
    let native_output = core
        .client()
        .download_resource(
            &remote.clone().child("source.txt")?,
            &native_destination,
            None,
            &ResourceTransferOptions {
                max_bytes: 1024,
                deadline: Duration::from_secs(20),
            },
        )
        .await;
    if let Some(expected) = native_encoding_error {
        assert!(matches!(native_output, Err(Error::LocalIo { source, .. }) if source.raw_os_error()==Some(expected)),
            "local native filesystem encoding error must not be converted to a protocol error or replacement filename");
    } else {
        assert_eq!(native_output?.sha256, digest(payload));
        assert_eq!(std::fs::read(&native_destination)?, payload);
        assert_eq!(
            std::fs::read(&invalid)?,
            b"independent native encoding oracle"
        );
    }
    let result = core
        .client()
        .create_folder(
            &CreateFolderOptions::new(
                FolderId::parse("invalid-native-encoding")?,
                TargetPath::local(invalid),
            )
            .paused(true),
        )
        .await;
    assert!(matches!(result, Err(Error::PathEncoding)));
    assert!(
        core.client().configuration().await?.native_document()["folders"] == before,
        "invalid encoding must leave the complete native folder configuration unchanged"
    );
    assert_eq!(core.client().system_status().await?.device_id, identity);
    assert_eq!(std::fs::read(&long_file)?, payload);
    assert_eq!(std::fs::read(directory.join("source.txt"))?, payload);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(&root)?;
    println!(
        "native path boundary evidence: {}",
        serde_json::json!({
        "actual_long_native_path_utf16_units": path_units, "actual_long_file_content_and_size": true,
        "unicode_percent_space_and_plus_are_literal_data": true, "equivalence": equivalence,
        "native_parent_resolves_through_link": uses_real_parent,
        "actual_sdk_download_destination_matches_native_oracle": true, "other_parent_destination_absent": true,
        "actual_remote_directory_alias_content_matches": true, "local_alias_retained": true,
        "nonrepresentable_native_path_typed_rejection_and_unchanged_registration": true,
        "native_local_destination_encoding_matches_independent_filesystem_oracle": true,
        "native_local_encoding_supported": native_encoding_error.is_none(),
        "synthetic_source_and_received_bytes_retained_until_explicit_cleanup": true,
        "same_identity_and_normal_owned_tree_exit": true})
    );
    Ok(())
}

#[tokio::test]
async fn public_download_streams_full_ranges_and_archives_without_overwriting_outputs() -> TestResult
{
    let root = tempfile::Builder::new().prefix("vfd-").tempdir()?.keep();
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let (profile, volume, relative_base) = mount(&core).await?;
    let data: Vec<_> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    std::fs::write(profile.join("payload 二 %.bin"), &data)?;
    std::fs::create_dir(profile.join("batch"))?;
    for (name, bytes) in [
        ("first.txt", b"first".as_slice()),
        ("second.txt", b"second".as_slice()),
    ] {
        std::fs::write(profile.join("batch").join(name), bytes)?;
    }
    let path = volume.clone().child("payload 二 %.bin")?;
    let options = ResourceTransferOptions {
        max_bytes: 4 * 1024 * 1024,
        deadline: Duration::from_secs(30),
    };
    let output = root.join("full.bin");
    let full = core
        .client()
        .download_resource(&path, &output, None, &options)
        .await?;
    assert_eq!(std::fs::read(&output)?, data);
    assert_eq!(full.bytes, data.len() as u64);
    assert_eq!(full.sha256, digest(&data));
    assert!(!format!("{full:?}").contains("payload"));
    assert!(core
        .client()
        .download_resource(&path, &output, None, &options)
        .await
        .is_err());
    assert_eq!(std::fs::read(&output)?, data);
    let interval = root.join("range.bin");
    let range = core
        .client()
        .download_resource(
            &path,
            &interval,
            Some(ResourceByteRange::new(1023, 65538)?),
            &options,
        )
        .await?;
    assert_eq!(std::fs::read(&interval)?, data[1023..=65538]);
    assert_eq!(range.sha256, digest(&data[1023..=65538]));
    assert_eq!(range.content_range(), Some("bytes 1023-65538/2097152"));
    let bounded = root.join("bounded.bin");
    assert!(core
        .client()
        .download_resource(
            &path,
            &bounded,
            None,
            &ResourceTransferOptions {
                max_bytes: 1024,
                ..options.clone()
            }
        )
        .await
        .is_err());
    assert!(!bounded.exists());
    let missing = root.join("missing.bin");
    assert!(core
        .client()
        .download_resource(&volume.clone().child("missing")?, &missing, None, &options)
        .await
        .is_err());
    assert!(!missing.exists());
    let directory = volume.clone().child("batch")?;
    let archive = root.join("directory.zip");
    let result = core
        .client()
        .download_resource_archive(&directory, ResourceArchiveFormat::Zip, &archive, &options)
        .await?;
    assert_eq!(result.media_type(), Some("application/zip"));
    assert_directory_payloads(zip_contents(&archive)?, &relative_base);
    let selected = root.join("selected.zip");
    let result = core
        .client()
        .download_selected_resources(
            &volume,
            &[
                TargetPath::local(Path::new("batch").join("second.txt")),
                TargetPath::local(Path::new("batch").join("first.txt")),
            ],
            ResourceArchiveFormat::Zip,
            &selected,
            &options,
        )
        .await?;
    assert_eq!(result.sha256, digest(&std::fs::read(&selected)?));
    assert_eq!(
        zip_contents(&selected)?,
        expected_selected_batch(&relative_base)
    );
    let nested = root.join("nested-base.zip");
    core.client()
        .download_selected_resources(
            &directory,
            &[
                TargetPath::local(Path::new("second.txt")),
                TargetPath::local(Path::new("first.txt")),
            ],
            ResourceArchiveFormat::Zip,
            &nested,
            &options,
        )
        .await?;
    assert_eq!(
        zip_contents(&nested)?,
        expected_selected_batch(&relative_base)
    );
    std::fs::write(
        profile.join("literal comma, %.txt"),
        b"comma percent content",
    )?;
    let comma = root.join("comma.zip");
    core.client()
        .download_selected_resources(
            &volume,
            &[TargetPath::local(Path::new("literal comma, %.txt"))],
            ResourceArchiveFormat::Zip,
            &comma,
            &options,
        )
        .await?;
    assert_eq!(
        zip_contents(&comma)?,
        BTreeMap::from([(
            archive_key(&relative_base.join("literal comma, %.txt")),
            b"comma percent content".to_vec()
        )])
    );
    for format in [ResourceArchiveFormat::Zip, ResourceArchiveFormat::Tar] {
        let rejected = root.join("file-as-archive.bin");
        assert!(core
            .client()
            .download_resource_archive(&path, format, &rejected, &options)
            .await
            .is_err());
        assert!(!rejected.exists());
    }

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&output, root.join("link"))?;
        assert!(core
            .client()
            .download_resource(&path, &root.join("link"), None, &options)
            .await
            .is_err());
        assert_eq!(std::fs::read(&output)?, data);
    }
    assert_eq!(std::fs::read(profile.join("payload 二 %.bin"))?, data);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public resource download evidence: {}",
        serde_json::json!({
        "actual_two_mib_stream_exceeds_management_buffer":true,"actual_full_payload_bytes_and_sha256":true,
        "actual_unicode_percent_remote_name":true,"actual_existing_output_retained":true,
        "actual_finite_range_exact_bytes_sha256_and_content_range":true,"actual_preannounced_bound_no_output":true,
        "actual_missing_resource_no_output":true,"actual_directory_zip_members_and_contents":true,
        "actual_selected_zip_members_contents_and_sha256":true,"actual_comma_percent_selection_preserves_filename_and_contents":true,"actual_nested_selection_base_uses_full_volume_relative_paths":true,
        "private_download_debug_redacted":true,"actual_source_bytes_preserved":true,"actual_normal_owned_tree_exit":true})
    );
    Ok(())
}

#[tokio::test]
async fn public_upload_streams_real_inputs_checks_remote_digest_and_controls_replacement(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vfu-").tempdir()?.keep();
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let (profile, volume, _relative_base) = mount(&core).await?;
    let data: Vec<_> = (0..3 * 1024 * 1024)
        .map(|i| ((i * 7) % 251) as u8)
        .collect();
    let input = root.join("input.bin");
    std::fs::write(&input, &data)?;
    let target = volume.clone().child("upload 二 %.bin")?;
    let options = ResourceTransferOptions {
        max_bytes: 4 * 1024 * 1024,
        deadline: Duration::from_secs(30),
    };
    let result = core
        .client()
        .upload_resource(
            &target,
            &input,
            ResourceUploadConflict::RejectExisting,
            &options,
        )
        .await?;
    assert_eq!(result.bytes, data.len() as u64);
    assert_eq!(result.sha256, digest(&data));
    assert_eq!(std::fs::read(profile.join("upload 二 %.bin"))?, data);
    let text = root.join("large-text.txt");
    let text_bytes = vec![b'x'; 2 * 1024 * 1024];
    std::fs::write(&text, &text_bytes)?;
    let text_result = core
        .client()
        .upload_resource(
            &volume.clone().child("large-text.txt")?,
            &text,
            ResourceUploadConflict::RejectExisting,
            &options,
        )
        .await?;
    assert_eq!(text_result.sha256, digest(&text_bytes));
    assert_eq!(std::fs::read(profile.join("large-text.txt"))?, text_bytes);
    let replacement = b"explicit synthetic replacement";
    let second = root.join("second.bin");
    std::fs::write(&second, replacement)?;
    assert!(core
        .client()
        .upload_resource(
            &target,
            &second,
            ResourceUploadConflict::RejectExisting,
            &options
        )
        .await
        .is_err());
    assert_eq!(std::fs::read(profile.join("upload 二 %.bin"))?, data);
    let replaced = core
        .client()
        .upload_resource(&target, &second, ResourceUploadConflict::Replace, &options)
        .await?;
    assert_eq!(replaced.sha256, digest(replacement));
    assert_eq!(std::fs::read(profile.join("upload 二 %.bin"))?, replacement);
    let empty = root.join("empty.bin");
    std::fs::write(&empty, [])?;
    let result = core
        .client()
        .upload_resource(
            &volume.clone().child("empty.bin")?,
            &empty,
            ResourceUploadConflict::RejectExisting,
            &options,
        )
        .await?;
    assert_eq!(result.bytes, 0);
    assert_eq!(result.sha256, digest(&[]));
    assert_eq!(std::fs::read(profile.join("empty.bin"))?, Vec::<u8>::new());
    assert!(core
        .client()
        .upload_resource(
            &volume.clone().child("bounded.bin")?,
            &input,
            ResourceUploadConflict::RejectExisting,
            &ResourceTransferOptions {
                max_bytes: 1,
                ..options.clone()
            }
        )
        .await
        .is_err());
    assert!(!profile.join("bounded.bin").exists());
    assert!(core
        .client()
        .upload_resource(&target, &root, ResourceUploadConflict::Replace, &options)
        .await
        .is_err());
    assert_eq!(std::fs::read(profile.join("upload 二 %.bin"))?, replacement);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&input, root.join("link"))?;
        assert!(core
            .client()
            .upload_resource(
                &target,
                &root.join("link"),
                ResourceUploadConflict::Replace,
                &options
            )
            .await
            .is_err());
        assert_eq!(std::fs::read(profile.join("upload 二 %.bin"))?, replacement);
    }
    assert_eq!(std::fs::read(&input)?, data);
    assert_eq!(std::fs::read(&second)?, replacement);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public resource upload evidence: {}",
        serde_json::json!({
        "actual_three_mib_stream_and_remote_sha256":true,"actual_two_mib_plain_text_and_digest":true,"actual_unicode_percent_target":true,
        "actual_duplicate_refusal_preserves_original_target":true,"actual_explicit_replace_bytes_and_sha256":true,
        "actual_empty_upload_and_digest":true,"actual_byte_bound_rejected_before_target_creation":true,
        "actual_nonregular_input_rejected_preserving_target":true,"actual_all_local_inputs_unchanged":true,
        "actual_normal_owned_tree_exit":true})
    );
    Ok(())
}

#[tokio::test]
async fn public_inflight_cancellation_retains_explicit_partial_outputs_and_owned_core() -> TestResult
{
    use std::io::Write;
    let root = tempfile::Builder::new().prefix("vfc-").tempdir()?.keep();
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let (profile, volume, _relative_base) = mount(&core).await?;
    let block: Vec<_> = (0..65536).map(|i| (i % 251) as u8).collect();
    let source = root.join("large-input.bin");
    let mut file = std::fs::File::create(&source)?;
    for _ in 0..1024 {
        file.write_all(&block)?;
    }
    file.sync_all()?;
    drop(file);
    let total = std::fs::metadata(&source)?.len();
    assert_eq!(total, 64 * 1024 * 1024);
    std::fs::copy(&source, profile.join("large-download.bin"))?;
    let transfer = ResourceTransferOptions {
        max_bytes: total,
        deadline: Duration::from_secs(30),
    };
    let path = volume.clone().child("large-download.bin")?;
    let output = root.join("partial-download.bin");
    let client = core.client().clone();
    let out = output.clone();
    let opts = transfer.clone();
    let download =
        tokio::spawn(async move { client.download_resource(&path, &out, None, &opts).await });
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(meta) = tokio::fs::metadata(&output).await {
                if meta.len() > 0 {
                    assert!(meta.len() < total);
                    break;
                }
            }
            assert!(
                !download.is_finished(),
                "download completed before inflight observation"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    download.abort();
    assert!(download.await.unwrap_err().is_cancelled());
    core.client().system_status().await?;
    let target = volume.clone().child("partial-upload.bin")?;
    let native = profile.join("partial-upload.bin");
    let client = core.client().clone();
    let input = source.clone();
    let opts = transfer.clone();
    let upload = tokio::spawn(async move {
        client
            .upload_resource(
                &target,
                &input,
                ResourceUploadConflict::RejectExisting,
                &opts,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(meta) = tokio::fs::metadata(&native).await {
                if meta.len() > 0 {
                    assert!(meta.len() < total);
                    break;
                }
            }
            assert!(
                !upload.is_finished(),
                "upload completed before inflight observation"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    upload.abort();
    assert!(upload.await.unwrap_err().is_cancelled());
    core.client().system_status().await?;
    let replaced_native = profile.join("replace-cancel.bin");
    std::fs::write(&replaced_native, b"previous synthetic target bytes")?;
    let target = volume.clone().child("replace-cancel.bin")?;
    let client = core.client().clone();
    let input = source.clone();
    let opts = transfer.clone();
    let replace = tokio::spawn(async move {
        client
            .upload_resource(&target, &input, ResourceUploadConflict::Replace, &opts)
            .await
    });
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(meta) = tokio::fs::metadata(&replaced_native).await {
                if meta.len() > 65536 {
                    assert!(meta.len() < total);
                    break;
                }
            }
            assert!(
                !replace.is_finished(),
                "replacement completed before inflight observation"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    replace.abort();
    assert!(replace.await.unwrap_err().is_cancelled());
    core.client().system_status().await?;

    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    let downloaded = std::fs::read(&output)?;
    let uploaded = match std::fs::read(&native) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let replaced = match std::fs::read(&replaced_native) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    // A native HTTP handler may finish already-received bytes after cancellation.
    // Report retained effects; do not equate future cancellation with rollback.
    assert!(!downloaded.is_empty() && downloaded.len() <= total as usize);
    if let Some(bytes) = &uploaded {
        assert!(!bytes.is_empty() && bytes.len() <= total as usize);
    }
    for bytes in std::iter::once(&downloaded)
        .chain(uploaded.as_ref())
        .chain(replaced.as_ref())
    {
        assert!(bytes
            .iter()
            .enumerate()
            .all(|(i, b)| *b == block[i % block.len()]));
    }
    assert_eq!(
        std::fs::read(&source)?,
        std::fs::read(profile.join("large-download.bin"))?
    );
    let mut file = std::fs::File::open(&source)?;
    let mut read = vec![0; 65536];
    let mut count = 0;
    loop {
        let n = file.read(&mut read)?;
        if n == 0 {
            break;
        }
        assert_eq!(&read[..n], &block[..n]);
        count += n;
    }
    assert_eq!(count as u64, total);
    println!(
        "public resource cancellation evidence: {}",
        serde_json::json!({
        "actual_download_cancel_after_nonempty_inflight_output":true,
        "actual_upload_cancel_after_nonempty_inflight_target":true,
        "actual_all_three_futures_join_as_cancelled":true,"actual_download_partial_retained":true,"actual_upload_effect_reconciled_after_cancel":true,"actual_replace_cancel_after_nonempty_inflight_overwrite":true,"actual_replace_cancel_effect_reconciled_without_fake_rollback":true,
        "actual_retained_outputs_match_source_prefix":true,"actual_sources_complete_and_unchanged":true,
        "actual_client_authentication_survives_all_three_cancels":true,"actual_normal_owned_tree_exit":true,
        "source_bytes":total,"retained_download_bytes":downloaded.len(),"retained_upload_bytes":uploaded.as_ref().map(Vec::len),"upload_target_state_after_cancel":if uploaded.is_some(){"present"}else{"absent"},"replace_target_state_after_cancel":if replaced.is_some(){"present"}else{"absent"},"retained_replace_bytes":replaced.as_ref().map(Vec::len)})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn zip_contents(path: &Path) -> TestResult<BTreeMap<String, Vec<u8>>> {
    let mut buffer = vec![0; rawzip::RECOMMENDED_BUFFER_SIZE];
    let zip = rawzip::ZipArchive::from_file(std::fs::File::open(path)?, &mut buffer)?;
    let mut entries = zip.entries(&mut buffer);
    let mut result = BTreeMap::new();
    while let Some(member) = entries.next_entry()? {
        if member.is_dir() {
            continue;
        }
        assert!(member.uncompressed_size_hint() < 65536);
        let name = std::str::from_utf8(member.file_path().as_bytes())?.to_owned();
        let entry = zip.get_entry(member.wayfinder())?;
        let mut bytes = Vec::new();
        match member.compression_method() {
            rawzip::CompressionMethod::STORE => {
                entry
                    .verifying_reader(entry.reader())
                    .read_to_end(&mut bytes)?;
            }
            rawzip::CompressionMethod::DEFLATE => {
                entry
                    .verifying_reader(flate2::read::DeflateDecoder::new(entry.reader()))
                    .read_to_end(&mut bytes)?;
            }
            _ => return Err("unexpected synthetic archive encoding".into()),
        }
        assert!(result.insert(name, bytes).is_none());
    }
    Ok(result)
}

#[tokio::test]
async fn public_native_archives_preserve_directory_and_selected_payloads_in_all_seven_formats(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vfa-").tempdir()?.keep();
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let (profile, volume, relative_base) = mount(&core).await?;
    std::fs::create_dir(profile.join("batch"))?;
    for (name, bytes) in [
        ("first.txt", b"first".as_slice()),
        ("second.txt", b"second".as_slice()),
    ] {
        std::fs::write(profile.join("batch").join(name), bytes)?;
    }
    let options = ResourceTransferOptions {
        max_bytes: 1024 * 1024,
        deadline: Duration::from_secs(20),
    };
    let selected = [
        TargetPath::local(Path::new("batch").join("second.txt")),
        TargetPath::local(Path::new("batch").join("first.txt")),
    ];
    for (name, format) in [
        ("zip", ResourceArchiveFormat::Zip),
        ("tar", ResourceArchiveFormat::Tar),
        ("targz", ResourceArchiveFormat::TarGzip),
        ("tarbz2", ResourceArchiveFormat::TarBzip2),
        ("tarxz", ResourceArchiveFormat::TarXz),
        ("tarlz4", ResourceArchiveFormat::TarLz4),
        ("tarsz", ResourceArchiveFormat::TarSnappy),
    ] {
        let directory = root.join(format!("directory-{name}.bin"));
        let result = core
            .client()
            .download_resource_archive(
                &volume.clone().child("batch")?,
                format,
                &directory,
                &options,
            )
            .await?;
        assert_eq!(result.sha256, digest(&std::fs::read(&directory)?));
        assert_directory_payloads(archive_contents(&directory, format)?, &relative_base);
        let output = root.join(format!("selected-{name}.bin"));
        let result = core
            .client()
            .download_selected_resources(&volume, &selected, format, &output, &options)
            .await?;
        assert_eq!(result.sha256, digest(&std::fs::read(&output)?));
        assert_eq!(
            archive_contents(&output, format)?,
            expected_selected_batch(&relative_base)
        );
        println!(
            "public resource archive format evidence: {}",
            serde_json::json!({"format":name,"actual_directory_member_contents":true,"actual_selected_member_contents":true,"actual_both_streamed_archive_hashes":true})
        );
    }
    assert_eq!(
        std::fs::read(profile.join("batch").join("first.txt"))?,
        b"first"
    );
    assert_eq!(
        std::fs::read(profile.join("batch").join("second.txt"))?,
        b"second"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public resource archives evidence: {}",
        serde_json::json!({"all_seven_actual_formats_decoded_independently":true,"actual_sources_unchanged":true,"actual_normal_owned_tree_exit":true})
    );
    Ok(())
}

fn archive_contents(
    path: &Path,
    format: ResourceArchiveFormat,
) -> TestResult<BTreeMap<String, Vec<u8>>> {
    if format == ResourceArchiveFormat::Zip {
        return zip_contents(path);
    }
    let file = std::fs::File::open(path)?;
    let reader: Box<dyn Read> = match format {
        ResourceArchiveFormat::Tar => Box::new(file),
        ResourceArchiveFormat::TarGzip => Box::new(flate2::read::GzDecoder::new(file)),
        ResourceArchiveFormat::TarBzip2 => Box::new(bzip2::read::BzDecoder::new(file)),
        ResourceArchiveFormat::TarXz => {
            Box::new(lzma_rust2::XzReader::new_mem_limit(file, true, 65536))
        }
        ResourceArchiveFormat::TarLz4 => Box::new(lz4_flex::frame::FrameDecoder::new(file)),
        ResourceArchiveFormat::TarSnappy => Box::new(snap::read::FrameDecoder::new(file)),
        ResourceArchiveFormat::Zip => unreachable!(),
    };
    // Decode bounded synthetic output only; no archive path is extracted.
    let mut archive = tar::Archive::new(reader.take(1024 * 1024));
    let mut result = BTreeMap::new();
    let mut count = 0;
    for entry in archive.entries()? {
        let mut entry = entry?;
        count += 1;
        assert!(count <= 4);
        if entry.header().entry_type().is_dir() {
            continue;
        }
        assert!(entry.header().entry_type().is_file());
        assert!(entry.size() < 65536);
        let name = entry
            .path()?
            .to_str()
            .ok_or("synthetic archive path encoding")?
            .to_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        assert!(result.insert(name, bytes).is_none());
    }
    Ok(result)
}
