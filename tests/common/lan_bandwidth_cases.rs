//! Separate LAN inclusion control; the existing S4 protocol is unchanged.
use super::*;
use std::time::Instant;
use verysync_sidecar::{BandwidthPatch, DeviceCompression, DeviceTransport, JoinFolderOptions};

async fn finished(client: &verysync_sidecar::Client, folder: &FolderId, count: u64) -> TestResult {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let status = client.folder_status(folder).await?;
            if status.local_files == Some(count) && status.need_bytes == Some(0) {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn actual_lan_bandwidth_toggle_changes_enforcement_and_preserves_bytes() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vss-lan-rate-")
        .tempdir()?
        .keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    for core in [&a, &b] {
        private_redial::configure(core.client()).await?;
    }
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    let _a_address = private_tcp(a.client()).await?;
    let b_address = private_tcp(b.client()).await?;
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    let source = root.join("source");
    let receiver = root.join("receiver");
    std::fs::create_dir(&source)?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&source)).paused(true))
        .await?;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(&receiver)).paused(true))
        .await?;
    for (client, folder, peer, address) in [
        (a.client(), &af.configuration.id, &b_id, b_address),
        (
            b.client(),
            &bf.configuration.id,
            &a_id,
            "dynamic".to_owned(),
        ),
    ] {
        client
            .create_device(
                &CreateDeviceOptions::new(peer.clone()).settings(
                    DevicePatch::default()
                        .addresses(vec![address])
                        .allowed_transports(vec![DeviceTransport::Tcp])
                        .compression(DeviceCompression::Never),
                ),
            )
            .await?;
        client.share_folder_with(folder, peer).await?;
        client.resume_folder(folder).await?;
    }
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if b.client()
                .connections()
                .await?
                .connections
                .get(&a_id)
                .is_some_and(|p| {
                    p.connected
                        && p.is_local == Some(true)
                        && p.started_at
                            .as_deref()
                            .is_some_and(|t| !t.starts_with("0001-"))
                })
            {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    clear_bandwidth(&a, &b).await?;
    let configured = b
        .client()
        .update_bandwidth_configuration(
            &BandwidthPatch::default()
                .max_receive_kib_per_second(64)
                .limit_in_lan(false),
        )
        .await?;
    assert!(configured.requested_fields_match);
    let folder = &bf.configuration.id;
    let mut payloads = Vec::new();
    let mut observations = Vec::new();
    for case in 0..2u64 {
        if case == 1 {
            assert!(
                b.client()
                    .update_bandwidth_configuration(&BandwidthPatch::default().limit_in_lan(true))
                    .await?
                    .requested_fields_match
            );
        }
        let config = b.client().bandwidth_configuration().await?;
        assert_eq!(config.max_receive_kib_per_second, 64);
        assert_eq!(config.limit_in_lan, case == 1);
        let mut state = 0x726174656c616eu64 ^ (case + 1);
        let content: Vec<u8> = (0..4_194_304)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        let name = format!("lan-{case}.bin");
        let started = Instant::now();
        let (mut before, mut first_epoch) = incoming_observation(b.client(), &a_id).await?;
        std::fs::write(source.join(&name), &content)?;
        a.client().request_scan(&af.configuration.id).await?;
        let elapsed;
        if case == 0 {
            finished(b.client(), folder, 1).await?;
            elapsed = started.elapsed();
            assert!(
                elapsed <= Duration::from_secs(15),
                "LAN exemption completion exceeded its complete functional window"
            );
        } else {
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    if b.client()
                        .folder_status(folder)
                        .await?
                        .need_bytes
                        .is_some_and(|n| n > 0)
                    {
                        return Ok::<_, Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await??;
            let window = Instant::now();
            (before, first_epoch) = incoming_observation(b.client(), &a_id).await?;
            tokio::time::sleep(Duration::from_secs(3)).await;
            let (after, epoch) = incoming_observation(b.client(), &a_id).await?;
            elapsed = window.elapsed();
            let delta = after
                .checked_sub(before)
                .ok_or("LAN limited byte counter decreased")?;
            let upper = 1_048_576.0 + 65_536.0 * elapsed.as_secs_f64();
            assert!((3.0..=6.0).contains(&elapsed.as_secs_f64()));
            assert!(
                first_epoch.is_some() && first_epoch == epoch,
                "LAN included connection epochs: {first_epoch:?} -> {epoch:?}"
            );
            assert!(delta > 0 && (delta as f64) <= upper);
            assert!(b
                .client()
                .folder_status(folder)
                .await?
                .need_bytes
                .is_some_and(|n| n > 0));
            observations.push(json!({"lan_included":true,"before":before,"after":after,"delta":delta,"elapsed_ns":elapsed.as_nanos(),"upper_bytes":upper,"same_connection_epoch":true,"nonempty_need":true}));
            // Keep the numeric limit unchanged; only exempt this local connection.
            assert!(
                b.client()
                    .update_bandwidth_configuration(&BandwidthPatch::default().limit_in_lan(false))
                    .await?
                    .requested_fields_match
            );
            assert_eq!(
                b.client()
                    .bandwidth_configuration()
                    .await?
                    .max_receive_kib_per_second,
                64
            );
            finished(b.client(), folder, 2).await?;
        }
        if case == 0 {
            let (after, epoch) = incoming_observation(b.client(), &a_id).await?;
            let outer_elapsed = started.elapsed();
            let delta = after
                .checked_sub(before)
                .ok_or("LAN exempt byte counter decreased")?;
            let upper = 1_048_576.0 + 65_536.0 * outer_elapsed.as_secs_f64();
            assert!(first_epoch.is_some() && first_epoch == epoch, "LAN exempt connection epochs: {first_epoch:?} -> {epoch:?}; bytes {before} -> {after}");
            assert!(outer_elapsed <= Duration::from_secs(15) && (delta as f64) > upper);
            observations.push(json!({"lan_included":false,"before":before,"after":after,"delta":delta,"elapsed_ns":outer_elapsed.as_nanos(),"identical_limit_upper_bytes":upper,"same_connection_epoch":true,"complete_payload_bytes":content.len()}));
        }
        assert_eq!(std::fs::read(receiver.join(&name))?, content);
        payloads.push((name, content));
    }
    for (name, content) in &payloads {
        assert_eq!(std::fs::read(source.join(name))?, *content);
    }
    for (client, peer) in [(a.client(), &b_id), (b.client(), &a_id)] {
        client.pause_device(peer).await?;
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if !a
                .client()
                .connections()
                .await?
                .connections
                .get(&b_id)
                .is_some_and(|p| p.connected)
                && !b
                    .client()
                    .connections()
                    .await?
                    .connections
                    .get(&a_id)
                    .is_some_and(|p| p.connected)
            {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    for core in [&mut b, &mut a] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!(
        "public LAN bandwidth inclusion evidence: {}",
        json!({"protocol":"VS033-LAN-inclusion-v1","actual_engine_local_connection":true,"fixed_receive_kib_per_second":64,"observations":observations,"two_distinct_4_mib_payloads_preserved":true,"only_lan_flag_changed_between_effects":true,"both_normal_tree_and_state_exits":true})
    );
    Ok(())
}
