use super::{mount, options, TestResult};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Write},
    time::{Duration, Instant},
};
use verysync_sidecar::{ManagedInstance, RawMethod, RawRequest, RequestEffect, ResourceChecksum};

#[tokio::test]
async fn native_version_binding_for_single_file_resume() -> TestResult {
    let root = tempfile::Builder::new().prefix("vsv-").tempdir()?;
    let mut core = ManagedInstance::start(options(&root.path().join("c"))?).await?;
    let probe: TestResult<Value> = async {
        let (profile, volume, relative) = mount(&core).await?;
        let name = "version-probe.bin";
        let first = b"old-abcdefghij";
        let second = b"new-0123456789";
        let path = profile.join(name);
        fs::write(&path, first)?;
        let mtime = fs::metadata(&path)?.modified()?;
        let resource = volume.clone().child(name)?;
        let first_sum = core
            .client()
            .resource_checksum(&resource, ResourceChecksum::Sha256)
            .await?;
        let mut route = vec!["rest", "f", "api", "raw", volume.volume().as_str()];
        for piece in relative.components() {
            route.push(piece.as_os_str().to_str().ok_or("invalid synthetic profile path")?);
        }
        route.push(name);
        let read = RawRequest::new(RawMethod::Get, route, RequestEffect::ReadOnly)?
            .query("algo", "none");
        let original = core.client().raw_request(&read).await?;
        let exact_original = original.status() == 200 && original.body_bytes() == first;
        let original_etag = header(&original, "etag");
        let original_modified = header(&original, "last-modified");
        let same_path = profile.join("version-probe.replacement");
        fs::write(&same_path, second)?;
        fs::OpenOptions::new()
            .write(true)
            .open(&same_path)?
            .set_times(fs::FileTimes::new().set_modified(mtime))?;
        #[cfg(windows)]
        fs::remove_file(&path)?;
        fs::rename(&same_path, &path)?;
        let second_sum = core
            .client()
            .resource_checksum(&resource, ResourceChecksum::Sha256)
            .await?;
        let changed = core.client().raw_request(&read).await?;
        let wrong_validator = read
            .clone()
            .header("Range", "bytes=4-8")?
            .header("If-Range", "\"synthetic-never-matches\"")?;
        let wrong_range = core.client().raw_request(&wrong_validator).await?;
        let old_validator = if let Some(value) = original_etag.as_deref().or(original_modified.as_deref()) {
            let request = read.header("Range", "bytes=4-8")?.header("If-Range", value)?;
            let result = core.client().raw_request(&request).await?;
            Some(json!({"status":result.status(), "range":header(&result,"content-range"),
                        "changed_suffix":result.body_bytes()==&second[4..=8], "whole_changed":result.body_bytes()==second}))
        } else {
            None
        };
        Ok(json!({
            "full_original_exact": exact_original, "full_replacement_exact": changed.status()==200 && changed.body_bytes()==second,
            "equal_length": first.len()==second.len(), "same_path_mtime":fs::metadata(&path)?.modified()?==mtime,
            "original_etag":original_etag, "replacement_etag":header(&changed,"etag"),
            "original_last_modified":original_modified, "replacement_last_modified":header(&changed,"last-modified"),
            "native_sha256_matches_original":first_sum.eq_ignore_ascii_case(&format!("{:x}", Sha256::digest(first))),
            "native_sha256_matches_replacement":second_sum.eq_ignore_ascii_case(&format!("{:x}", Sha256::digest(second))),
            "native_sha256_distinguishes_same_metadata":!first_sum.eq_ignore_ascii_case(&second_sum),
            "accept_ranges":header(&original,"accept-ranges"), "old_validator_request":old_validator,
            "wrong_validator_request":{"status":wrong_range.status(),"range":header(&wrong_range,"content-range"),
                "changed_suffix":wrong_range.body_bytes()==&second[4..=8],"whole_changed":wrong_range.body_bytes()==second},
        }))
    }
    .await;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    let probe = probe?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced);
    assert_eq!(probe["full_original_exact"], true);
    assert_eq!(probe["full_replacement_exact"], true);
    assert_eq!(probe["equal_length"], true);
    assert_eq!(probe["same_path_mtime"], true);
    assert_eq!(probe["native_sha256_matches_original"], true);
    assert_eq!(probe["native_sha256_matches_replacement"], true);
    assert_eq!(probe["native_sha256_distinguishes_same_metadata"], true);
    println!("Single-file version probe: {probe}");
    println!("Owned fixture exited normally with its state released");
    Ok(())
}

fn header(response: &verysync_sidecar::RawResponse, wanted: &str) -> Option<String> {
    response.headers().find_map(|(name, bytes)| {
        name.eq_ignore_ascii_case(wanted)
            .then(|| String::from_utf8_lossy(bytes).into_owned())
    })
}

#[tokio::test]
async fn native_resume_qualification_large_source_exposes_stable_digest_with_bounded_metadata(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vsl-").tempdir()?;
    let mut core = ManagedInstance::start(options(&root.path().join("c"))?).await?;
    let result: TestResult<Value> = async {
        let (profile, base, _) = mount(&core).await?;
        let path = profile.join("synthetic-resume-large.bin");
        let total = 32 * 1024 * 1024u64;
        let mut block = vec![0; 65_536];
        for (index, value) in block.iter_mut().enumerate() {
            *value = (index as u8).wrapping_mul(23).wrapping_add(31);
        }
        let mut source = fs::File::create(&path)?;
        let mut hash = Sha256::new();
        for _ in 0..total / block.len() as u64 {
            source.write_all(&block)?;
            hash.update(&block);
        }
        source.sync_all()?;
        drop(source);
        let expected: [u8; 32] = hash.finalize().into();
        let expected_hex = expected
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let resource = base.child("synthetic-resume-large.bin")?;
        let metadata = core.client().resource_info(&resource).await?;
        assert!(!metadata.is_dir && metadata.size == total);
        let mut checksum_us = Vec::new();
        for _ in 0..3 {
            let start = Instant::now();
            let reading = core
                .client()
                .resource_checksum(&resource, ResourceChecksum::Sha256)
                .await?;
            checksum_us.push(start.elapsed().as_micros());
            assert!(reading.eq_ignore_ascii_case(&expected_hex));
        }
        let destination = root.path().join("verified-local.bin");
        let start = Instant::now();
        let fetched = core
            .client()
            .download_resource(
                &resource,
                &destination,
                None,
                &verysync_sidecar::ResourceTransferOptions {
                    max_bytes: total,
                    deadline: Duration::from_secs(25),
                },
            )
            .await?;
        let transfer_us = start.elapsed().as_micros();
        assert_eq!(fetched.bytes, total);
        assert_eq!(fetched.sha256, expected);
        let count = fs::metadata(&destination)?.len();
        let mut copied = fs::File::open(destination)?;
        let mut independent = Sha256::new();
        io::copy(&mut copied, &mut independent)?;
        assert_eq!(<[u8; 32]>::from(independent.finalize()), expected);
        assert_eq!(count, total);
        Ok(json!({
            "qualification_only":true,"native_regular_file_size":metadata.size,
            "bounded_checksum_read_and_actual_file_match":true,
            "native_checksum_read_us":checksum_us,"full_loopback_transfer_us":transfer_us,
            "independent_download_size":count
        }))
    }
    .await;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced);
    println!("Native large source qualification: {}", result?);
    Ok(())
}
