//! The selected threshold changes actual temporary-block advertisement.
use super::managed_fixture::{options, TestResult};
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};
use verysync_sidecar::*;

fn first_block_matches(path: &Path, bytes: &[u8]) -> TestResult<bool> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let mut block = vec![0; 128 * 1024];
    match file.read_exact(&mut block) {
        Ok(()) => Ok(block == bytes[..block.len()]),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn actual_partial_block_present(directory: &Path, bytes: &[u8]) -> TestResult<bool> {
    // The fixed native SyncTempName hashes the input name and places the file
    // below .verysync. Discover only bounded regular files in this owned
    // directory; a retention-compatible .vs.<name>.tmp is not its live path.
    for (index, entry) in std::fs::read_dir(directory.join(".verysync"))?.enumerate() {
        if index >= 64 {
            return Err("owned native temporary directory exceeded observation bound".into());
        }
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry.path().extension() == Some(std::ffi::OsStr::new("tmp"))
            && first_block_matches(&entry.path(), bytes)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[tokio::test]
async fn native_temporary_index_threshold_controls_partial_block_advertisement() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vstempindex-")
        .tempdir()?
        .keep();
    let sentinel = root.join("caller-sentinel");
    std::fs::write(&sentinel, b"temporary index caller bytes")?;
    let source = root.join("source");
    let received = root.join("received");
    std::fs::create_dir(&source)?;
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let aid = a.client().instance().device_id.clone();
    let bid = b.client().instance().device_id.clone();
    for core in [&a, &b] {
        assert!(
            core.client()
                .update_general_options(
                    &GeneralOptionsPatch::default()
                        .overwrite_remote_device_names_on_connect(false)
                        .disable_system_sleep_on_sync(false)
                        .progress_update_interval_seconds(1)
                )
                .await?
                .requested_fields_match
        );
        core.client()
            .update_network_configuration(&NetworkPatch::default().reconnection_interval_seconds(5))
            .await?;
    }
    let address = super::configuration_policy_listener(&b).await?;
    for (client, peer, addresses) in [
        (a.client(), &bid, vec![format!("tcp://{address}")]),
        (b.client(), &aid, vec!["dynamic".into()]),
    ] {
        client
            .create_device(
                &CreateDeviceOptions::new(peer.clone()).settings(
                    DevicePatch::default()
                        .name("temporary-index controlled peer")
                        .addresses(addresses)
                        .compression(DeviceCompression::Never)
                        .allowed_transports(vec![DeviceTransport::Tcp])
                        .advanced_configuration(
                            DeviceAdvancedPatch::default().num_connections(1),
                        )?,
                ),
            )
            .await?;
    }
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&source)))
        .await?;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(&received)))
        .await?;
    assert!(
        b.client()
            .update_folder_advanced_configuration(
                &bf.configuration.id,
                &FolderAdvancedPatch::default().block_pull_order(BlockPullOrder::InOrder),
            )
            .await?
            .requested_fields_match
    );
    a.client()
        .share_folder_with(&af.configuration.id, &bid)
        .await?;
    b.client()
        .share_folder_with(&bf.configuration.id, &aid)
        .await?;
    // Establish actual authentication and data readiness at ordinary speed.
    std::fs::write(
        source.join("readiness.bin"),
        b"real temporary-index readiness",
    )?;
    a.client().request_scan(&af.configuration.id).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        while !std::fs::read(received.join("readiness.bin"))
            .is_ok_and(|v| v == b"real temporary-index readiness")
        {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await?;
    super::name_policy_connection_pair(&a, &b, true).await?;
    assert!(
        a.client()
            .update_bandwidth_configuration(
                &BandwidthPatch::default()
                    .max_send_kib_per_second(256)
                    .limit_in_lan(true)
            )
            .await?
            .requested_fields_match
    );
    let before_a = a.client().configuration().await?;
    let before_b = b.client().configuration().await?;
    let protected = ["key.pem", "cert.pem"];
    let credentials_a = protected
        .iter()
        .map(|p| std::fs::read(a.state_directory().join(p)))
        .collect::<std::io::Result<Vec<_>>>()?;
    let credentials_b = protected
        .iter()
        .map(|p| std::fs::read(b.state_directory().join(p)))
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut samples = Vec::new();
    for (phase, selected) in [1_i64, 512, 1].into_iter().enumerate() {
        assert!(
            b.client()
                .pause_folder(&bf.configuration.id)
                .await?
                .requested_fields_match
        );
        assert!(
            b.client()
                .update_general_options(
                    &GeneralOptionsPatch::default().temp_index_min_blocks(selected)
                )
                .await?
                .requested_fields_match
        );
        b.restart(Duration::from_secs(30)).await?;
        assert_eq!(
            b.client().general_options().await?.temp_index_min_blocks,
            Some(selected)
        );
        let address = super::configuration_policy_listener(&b).await?;
        a.client()
            .update_device(
                &bid,
                &DevicePatch::default().addresses(vec![format!("tcp://{address}")]),
            )
            .await?;
        super::name_policy_connection_pair(&a, &b, true).await?;
        let name = format!("index-threshold-{phase}-二.bin");
        let mut random = 0x5278_91b3_u32.wrapping_add(phase as u32);
        let bytes: Vec<u8> = (0..8 * 1024 * 1024)
            .map(|_| {
                random ^= random << 13;
                random ^= random >> 17;
                random ^= random << 5;
                random as u8
            })
            .collect();
        std::fs::write(source.join(&name), &bytes)?;
        a.client().request_scan(&af.configuration.id).await?;
        let indexed = a
            .client()
            .index_file_info(&af.configuration.id, &TargetPath::local(&name))
            .await?;
        assert!(indexed.global.num_blocks > 1 && indexed.global.num_blocks < 512);
        assert!(!received.join(&name).try_exists()?);
        b.client().resume_folder(&bf.configuration.id).await?;
        let mut partial_observations = 0;
        let mut partial_started = None;
        let mut partial_span = Duration::ZERO;
        let mut advertised = false;
        let mut explicit_null_availability_seen = false;
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                let state = b.client().folder_status(&bf.configuration.id).await?.state;
                if state == Some(FolderState::Syncing)
                    && !received.join(&name).try_exists()?
                    && actual_partial_block_present(&received, &bytes)?
                {
                    let raw = a
                        .client()
                        .raw_request(
                            &RawRequest::new(
                                RawMethod::Get,
                                ["rest", "db", "file"],
                                RequestEffect::ReadOnly,
                            )?
                            .query("folder", af.configuration.id.as_str())
                            .query("file", &name),
                        )
                        .await?;
                    assert_eq!(raw.status(), 200);
                    let document: serde_json::Value = serde_json::from_slice(raw.body_bytes())?;
                    let native_availability = document
                        .get("availability")
                        .ok_or("native availability field absent")?;
                    if !native_availability.is_null() && !native_availability.is_array() {
                        return Err("native availability field malformed".into());
                    }
                    explicit_null_availability_seen |= native_availability.is_null();
                    // Preserve the distinction between an explicit native null
                    // slice and a missing field; never infer absence from a
                    // missing response member or an HTTP error.
                    let info: IndexFileInfo = serde_json::from_value(document)?;
                    // The complete final file must still be absent after the
                    // source's authenticated observation, not just before it.
                    if !received.join(&name).try_exists()? {
                        partial_observations += 1;
                        let start = partial_started.get_or_insert_with(Instant::now);
                        partial_span = start.elapsed();
                        let active = info
                            .availability
                            .unwrap_or_default()
                            .iter()
                            .any(|v| v.device_id == bid && v.from_temporary);
                        advertised |= active;
                        if selected == 512 {
                            assert!(
                                !active,
                                "above-file-block-count threshold advertised temporary data"
                            );
                        }
                    }
                }
                if received.join(&name).is_file() && state == Some(FolderState::Idle) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            TestResult::Ok(())
        })
        .await??;
        assert!(partial_observations >= 3 && partial_span >= Duration::from_secs(3),
            "actual incomplete first-block transfer coverage too short: observations={partial_observations}, span={partial_span:?}");
        assert_eq!(
            advertised,
            selected == 1,
            "temporary advertisement must follow selected threshold"
        );
        assert_eq!(std::fs::read(received.join(&name))?, bytes);
        println!(
            "native temporary index threshold evidence: {}",
            serde_json::json!({
                "selected":selected,"actual_file_blocks":indexed.global.num_blocks,
                "actual_incomplete_first_block_bytes_verified":true,"actual_partial_observations":partial_observations,
                "actual_partial_span_ms":partial_span.as_millis(),"actual_peer_temporary_availability_observed":advertised,
            "explicit_native_null_availability_observed":explicit_null_availability_seen,
                "actual_normal_restart_retained_policy":true,"actual_new_file_bytes_received":true,
                "throughput_or_memory_cap_claimed":false
            })
        );
        samples.push((name, bytes));
    }
    for (name, bytes) in &samples {
        assert_eq!(&std::fs::read(source.join(name))?, bytes);
        assert_eq!(&std::fs::read(received.join(name))?, bytes);
    }
    for (core, before, identity, credentials) in [
        (&a, &before_a, &aid, &credentials_a),
        (&b, &before_b, &bid, &credentials_b),
    ] {
        assert_eq!(&core.client().system_status().await?.device_id, identity);
        let after = core.client().configuration().await?;
        for section in ["gui", "folders", "defaults", "ldap"] {
            assert!(before.native_document()[section] == after.native_document()[section]);
        }
        for (name, expected) in protected.iter().zip(credentials) {
            assert!(
                std::fs::read(core.state_directory().join(name))? == *expected,
                "native credentials changed"
            );
        }
    }
    assert_eq!(std::fs::read(sentinel)?, b"temporary index caller bytes");
    for core in [&mut a, &mut b] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!("native temporary index threshold cleanup evidence: actual_three_source_receiver_payloads_and_sentinel_retained=true actual_identities_keys_certificates_and_unrelated_sections_retained=true actual_both_normal_owned_tree_and_state_exit=true");
    Ok(())
}
