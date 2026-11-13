//! Actual file payloads through public APIs, independent of raw characterization.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, path::Path, time::Duration};
use verysync_sidecar::{
    ManagedInstance, ResourceArchiveFormat, ResourceByteRange, ResourcePath,
    ResourceTransferOptions, ResourceUploadConflict, TargetPath,
};

async fn mount(core: &ManagedInstance) -> TestResult<(std::path::PathBuf, ResourcePath)> {
    let profile = std::fs::canonicalize(core.state_directory().join("profile"))?;
    let volumes = core.client().resource_volumes().await?;
    let volume = volumes
        .into_iter()
        .find(|v| {
            v.kind == "local" && std::fs::canonicalize(&v.path).ok().as_ref() == Some(&profile)
        })
        .ok_or("exact private resource mount absent")?;
    Ok((
        profile,
        ResourcePath::root(volume.id, TargetPath::local(Path::new("sample")).style()),
    ))
}
fn digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[tokio::test]
async fn public_download_streams_full_ranges_and_archives_without_overwriting_outputs() -> TestResult
{
    let root = tempfile::Builder::new().prefix("vfd-").tempdir()?.keep();
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let (profile, volume) = mount(&core).await?;
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
    let expected = BTreeMap::from([
        ("first.txt".into(), b"first".to_vec()),
        ("second.txt".into(), b"second".to_vec()),
    ]);
    assert_eq!(zip_contents(&archive)?, expected);
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
        BTreeMap::from([
            ("batch/first.txt".into(), b"first".to_vec()),
            ("batch/second.txt".into(), b"second".to_vec())
        ])
    );
    assert!(core
        .client()
        .download_selected_resources(
            &volume,
            &[TargetPath::local(Path::new("has,comma"))],
            ResourceArchiveFormat::Zip,
            &root.join("bad.zip"),
            &options
        )
        .await
        .is_err());
    assert!(!root.join("bad.zip").exists());
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
        "actual_selected_zip_members_contents_and_sha256":true,"ambiguous_comma_selection_rejected_without_output":true,
        "private_download_debug_redacted":true,"actual_source_bytes_preserved":true,"actual_normal_owned_tree_exit":true})
    );
    Ok(())
}

#[tokio::test]
async fn public_upload_streams_real_inputs_checks_remote_digest_and_controls_replacement(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vfu-").tempdir()?.keep();
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let (profile, volume) = mount(&core).await?;
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
    let (profile, volume) = mount(&core).await?;
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
    let (profile, volume) = mount(&core).await?;
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
        assert_eq!(
            archive_contents(&directory, format)?,
            BTreeMap::from([
                ("first.txt".into(), b"first".to_vec()),
                ("second.txt".into(), b"second".to_vec())
            ])
        );
        let output = root.join(format!("selected-{name}.bin"));
        let result = core
            .client()
            .download_selected_resources(&volume, &selected, format, &output, &options)
            .await?;
        assert_eq!(result.sha256, digest(&std::fs::read(&output)?));
        assert_eq!(
            archive_contents(&output, format)?,
            BTreeMap::from([
                ("batch/first.txt".into(), b"first".to_vec()),
                ("batch/second.txt".into(), b"second".to_vec())
            ])
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
