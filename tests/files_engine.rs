//! Public file-manager effects use only one task-owned native profile volume.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::{path::Path, time::Duration};
use verysync_sidecar::{Error, ManagedInstance, ResourceChecksum, ResourcePath, TargetPath};

#[tokio::test]
async fn public_file_metadata_browses_owned_volume_and_hashes_actual_samples() -> TestResult {
    let root = tempfile::Builder::new().prefix("vfr-").tempdir()?.keep();
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let profile = std::fs::canonicalize(core.state_directory().join("profile"))?;
    let directory = profile.join("web-samples");
    std::fs::create_dir(&directory)?;
    let payload = b"synthetic file manager bytes";
    std::fs::write(directory.join("sample.txt"), payload)?;
    std::fs::write(
        directory.join("二 空格 %2e%2e %.txt"),
        b"literal Unicode percent data",
    )?;
    std::fs::create_dir(directory.join("empty"))?;
    #[cfg(unix)]
    std::fs::write(
        directory.join("line\nbreak.txt"),
        b"native Unix newline filename",
    )?;
    let volumes = core.client().resource_volumes().await?;
    assert!(!volumes.is_empty());
    let volume = volumes
        .iter()
        .find(|v| {
            v.kind == "local" && std::fs::canonicalize(&v.path).ok().as_ref() == Some(&profile)
        })
        .ok_or("exact private profile mount missing")?;
    assert!(!format!("{volumes:?}").contains(root.to_str().ok_or("temporary root encoding")?));
    let style = TargetPath::local(&directory).style();
    let mount = ResourcePath::root(volume.id.clone(), style);
    let info = core.client().resource_info(&mount).await?;
    assert!(info.is_dir && info.items.is_some());
    let relative = TargetPath::local(Path::new("web-samples"));
    let folder = ResourcePath::relative(volume.id.clone(), &relative)?;
    let listing = core.client().resource_info(&folder).await?;
    assert!(listing.is_dir);
    let items = listing.items.ok_or("actual directory entries missing")?;
    assert_eq!(items.len(), if cfg!(unix) { 4 } else { 3 });
    assert_eq!(items.iter().filter(|v| v.is_dir).count(), 1);
    for name in ["sample.txt", "二 空格 %2e%2e %.txt"] {
        assert!(items.iter().any(|v| v.name == name && !v.is_dir));
    }
    let target = folder.clone().child("sample.txt")?;
    let file = core.client().resource_info(&target).await?;
    assert!(
        !file.is_dir
            && file.size == payload.len() as u64
            && file.content.as_deref() == Some(std::str::from_utf8(payload)?)
    );
    let unicode = core
        .client()
        .resource_info(&folder.clone().child("二 空格 %2e%2e %.txt")?)
        .await?;
    assert_eq!(unicode.name, "二 空格 %2e%2e %.txt");
    assert_eq!(
        unicode.content.as_deref(),
        Some("literal Unicode percent data")
    );
    #[cfg(unix)]
    {
        let control = core
            .client()
            .resource_info(&folder.clone().child("line\nbreak.txt")?)
            .await
            .inspect_err(|_| {
                eprintln!("Native resource failure stage: exact Unix newline leaf metadata")
            })?;
        assert_eq!(control.name, "line\nbreak.txt");
        assert_eq!(
            control.content.as_deref(),
            Some("native Unix newline filename")
        );
    }
    let empty = core
        .client()
        .resource_info(&folder.clone().child("empty")?)
        .await?;
    assert!(empty.is_dir && empty.items.as_ref().is_some_and(Vec::is_empty));
    for (algorithm,expected) in [
        (ResourceChecksum::Md5,"fc4f4617c8a5da40283404bdf1619a1d"),
        (ResourceChecksum::Sha1,"192ccffad1fc72569389c7e2ebddcf4f0b3c9c99"),
        (ResourceChecksum::Sha256,"fbfc8ad9ba112cfd114e0870df05213dd82ebd1b3665a05654225e6d16b6a20b"),
        (ResourceChecksum::Sha512,"e6f799463a7ac695b3b54b78ac6ef0a10ecf8c8576724256d4bae783576a284981b3ef7beff721dd509338956a6ed0cefacf9d9196fd148bfa50b5e4e101d86b"),
    ]{assert_eq!(core.client().resource_checksum(&target,algorithm).await?,expected);}
    assert!(
        matches!(core.client().resource_info(&folder.clone().child("missing")?).await,Err(Error::Http{response})if response.status()==404)
    );
    assert!(folder.clone().child("..").is_err());
    let wrong_style = if style == verysync_sidecar::PathStyle::Unix {
        verysync_sidecar::PathStyle::Windows
    } else {
        verysync_sidecar::PathStyle::Unix
    };
    assert!(matches!(
        core.client()
            .resource_info(&ResourcePath::root(volume.id.clone(), wrong_style))
            .await,
        Err(Error::InvalidPath { .. })
    ));
    assert!(!format!("{file:?} {folder:?}").contains("sample.txt"));
    assert_eq!(std::fs::read(directory.join("sample.txt"))?, payload);
    assert_eq!(
        std::fs::read(directory.join("二 空格 %2e%2e %.txt"))?,
        b"literal Unicode percent data"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public resource browse evidence: {}",
        serde_json::json!({
        "actual_mount_ids_and_exact_private_profile_volume":true,"actual_logical_volume_root_listing":true,
        "actual_directory_and_native_names":true,"actual_text_content_and_byte_size":true,
        "actual_unicode_and_literal_percent_names":true,"actual_empty_directory_observation":true,
        "actual_md5_sha1_sha256_sha512_match_sample_bytes":true,"actual_missing_resource_is_error":true,
        "parent_and_wrong_target_syntax_rejected":true,"private_resource_debug_redacted":true,
        "actual_all_sample_bytes_retained":true,"actual_normal_owned_tree_exit":true})
    );
    Ok(())
}

#[tokio::test]
async fn public_native_thumbnails_read_actual_image_content_and_preserve_sources() -> TestResult {
    let root = tempfile::Builder::new().prefix("vft-").tempdir()?.keep();
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let profile = std::fs::canonicalize(core.state_directory().join("profile"))?;
    let volumes = core.client().resource_volumes().await?;
    let volume = volumes
        .iter()
        .find(|v| {
            v.kind == "local" && std::fs::canonicalize(&v.path).ok().as_ref() == Some(&profile)
        })
        .ok_or("private profile mount missing")?;
    let base = ResourcePath::root(volume.id.clone(), TargetPath::local(&profile).style());
    let mut previews = Vec::new();
    const IMAGE_0: &[u8] = &[
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 2, 0, 0, 0, 1, 0, 8, 6,
        0, 0, 0, 197, 144, 206, 103, 0, 0, 4, 60, 73, 68, 65, 84, 120, 156, 237, 214, 161, 1, 0,
        32, 0, 195, 176, 253, 255, 52, 124, 1, 162, 17, 241, 149, 221, 217, 14, 0, 208, 178, 223,
        1, 0, 192, 123, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200,
        0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0,
        0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0,
        0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0,
        65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64,
        144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100,
        0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0,
        0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0,
        130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128,
        32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200,
        0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0,
        0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0,
        0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0,
        65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64,
        144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100,
        0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0,
        0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0,
        130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128,
        32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200,
        0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0,
        0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0,
        0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0,
        65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64,
        144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100,
        0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0,
        0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0,
        130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128,
        32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200,
        0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0,
        0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0,
        0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0,
        65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64,
        144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100,
        0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0,
        0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0,
        130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128,
        32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200,
        0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0,
        0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0, 65, 6, 0, 0, 130, 12, 0,
        0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64, 144, 1, 0, 128, 32, 3, 0, 0,
        65, 6, 0, 0, 130, 12, 0, 0, 4, 25, 0, 0, 8, 50, 0, 0, 16, 100, 0, 0, 32, 200, 0, 0, 64,
        208, 5, 231, 237, 59, 197, 208, 162, 160, 245, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96,
        130,
    ];
    const IMAGE_1: &[u8] = &[
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 2, 0, 0, 0, 1, 0, 8, 6,
        0, 0, 0, 197, 144, 206, 103, 0, 0, 4, 123, 73, 68, 65, 84, 120, 156, 237, 206, 33, 1, 192,
        64, 16, 4, 177, 243, 111, 250, 235, 98, 7, 52, 32, 60, 119, 247, 30, 0, 240, 55, 121, 0, 0,
        216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242, 0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236,
        229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0, 216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242,
        0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236, 229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0,
        216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242, 0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236,
        229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0, 216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242,
        0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236, 229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0,
        216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242, 0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236,
        229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0, 216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242,
        0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236, 229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0,
        216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242, 0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236,
        229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0, 216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242,
        0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236, 229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0,
        216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242, 0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236,
        229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0, 216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242,
        0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236, 229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0,
        216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242, 0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236,
        229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0, 216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242,
        0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236, 229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0,
        216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242, 0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236,
        229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0, 216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242,
        0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236, 229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0,
        216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242, 0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236,
        229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0, 216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242,
        0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236, 229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0,
        216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242, 0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236,
        229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0, 216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242,
        0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236, 229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0,
        216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242, 0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236,
        229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0, 216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242,
        0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236, 229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0,
        216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242, 0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236,
        229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0, 216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242,
        0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236, 229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0,
        216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242, 0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236,
        229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0, 216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242,
        0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236, 229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0,
        216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242, 0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236,
        229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0, 216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242,
        0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236, 229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0,
        216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242, 0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236,
        229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0, 216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242,
        0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236, 229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0,
        216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242, 0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236,
        229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0, 216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242,
        0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236, 229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0,
        216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242, 0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236,
        229, 1, 0, 96, 47, 15, 0, 0, 123, 121, 0, 0, 216, 203, 3, 0, 192, 94, 30, 0, 0, 246, 242,
        0, 0, 176, 151, 7, 0, 128, 189, 60, 0, 0, 236, 229, 1, 0, 96, 237, 3, 172, 41, 59, 197,
        179, 162, 41, 251, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
    ];
    for (name, source) in [("red %.png", IMAGE_0), ("blue 二.png", IMAGE_1)] {
        std::fs::write(profile.join(name), source)?;
        let result = core
            .client()
            .resource_thumbnail(&base.clone().child(name)?)
            .await?;
        assert!(result.media_type().starts_with("image/"));
        let (width, height) = raster_dimensions(result.body_bytes())?;
        assert!(width > 0 && height > 0 && width <= 512 && height <= 256);
        assert!(!format!("{result:?}").contains(name));
        assert_eq!(std::fs::read(profile.join(name))?, source);
        previews.push(result.body_bytes().to_vec());
    }
    assert_ne!(previews[0], previews[1]);
    assert!(core
        .client()
        .resource_thumbnail(&base.child("absent.png")?)
        .await
        .is_err());
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public resource preview evidence: {}",
        serde_json::json!({
        "actual_png_source_previews_from_two_distinct_images":true,"actual_image_media_type_and_raster_dimensions":true,
        "actual_different_preview_content_for_different_pixels":true,"actual_all_original_image_bytes_retained":true,
        "actual_absent_preview_is_error":true,"private_preview_debug_redacted":true,"actual_normal_owned_tree_exit":true})
    );
    Ok(())
}
fn raster_dimensions(bytes: &[u8]) -> TestResult<(u32, u32)> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") && bytes.len() >= 24 {
        return Ok((
            u32::from_be_bytes(bytes[16..20].try_into()?),
            u32::from_be_bytes(bytes[20..24].try_into()?),
        ));
    }
    if bytes.starts_with(&[0xff, 0xd8]) {
        let mut i = 2;
        while i + 4 <= bytes.len() {
            if bytes[i] != 0xff {
                return Err("invalid native JPEG marker".into());
            }
            let marker = bytes[i + 1];
            i += 2;
            if marker == 0xff {
                i -= 1;
                continue;
            }
            if marker == 0xd9 || marker == 0xda {
                break;
            }
            let len = u16::from_be_bytes(bytes[i..i + 2].try_into()?) as usize;
            if len < 2 || i + len > bytes.len() {
                return Err("truncated native JPEG segment".into());
            }
            if [0xc0, 0xc1, 0xc2].contains(&marker) && len >= 7 {
                return Ok((
                    u16::from_be_bytes(bytes[i + 5..i + 7].try_into()?) as u32,
                    u16::from_be_bytes(bytes[i + 3..i + 5].try_into()?) as u32,
                ));
            }
            i += len;
        }
    }
    Err("native preview is not a complete identified PNG/JPEG raster".into())
}
