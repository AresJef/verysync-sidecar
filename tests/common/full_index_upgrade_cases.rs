//! Full-index policy is observed across a real program version change.
use super::managed_fixture::{options, TestResult};
use std::time::{Duration, Instant};
use verysync_sidecar::*;

async fn listener(core: &ManagedInstance) -> TestResult<std::net::SocketAddr> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for status in core.client().listener_status().await?.into_values() {
                for text in status.lan_addresses {
                    if let Some(address) = text
                        .strip_prefix("tcp://")
                        .and_then(|v| v.parse::<std::net::SocketAddr>().ok())
                        .filter(|v| {
                            v.ip() == std::net::Ipv4Addr::LOCALHOST
                                && !matches!(v.port(), 0 | 18886)
                        })
                    {
                        return TestResult::Ok(address);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await?
}

async fn connected(a: &ManagedInstance, b: &ManagedInstance) -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let aa = a.client().connections().await?;
            let bb = b.client().connections().await?;
            if aa
                .connections
                .get(&b.client().instance().device_id)
                .is_some_and(|v| v.connected)
                && bb
                    .connections
                    .get(&a.client().instance().device_id)
                    .is_some_and(|v| v.connected)
            {
                return TestResult::Ok(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await?
}

fn items(
    event: EngineEvent,
    last_id: &mut u64,
    folder: &FolderId,
    peer: &DeviceId,
) -> TestResult<u64> {
    assert!(event.cursor.last_id > *last_id);
    *last_id = event.cursor.last_id;
    if event.kind != EventKind::Unknown("RemoteIndexUpdated".into()) {
        return Ok(0);
    }
    let data = event.data();
    if data["folder"] != folder.as_str() || data["device"] != peer.as_str() {
        return Ok(0);
    }
    data["items"]
        .as_u64()
        .ok_or_else(|| "native remote-index item count missing".into())
}

#[tokio::test]
async fn native_full_index_upgrade_policy_changes_actual_unchanged_index_resend() -> TestResult {
    for selected in [false, true] {
        let root = tempfile::Builder::new()
            .prefix("vsfullindex-")
            .tempdir()?
            .keep();
        let sentinel = root.join("caller-sentinel");
        std::fs::write(&sentinel, b"full-index upgrade caller bytes")?;
        let base = options(&root.join("a"))?;
        let settings = ManagedOptions::new(
            super::upgrade_source()?,
            base.state_directory(),
            base.management_endpoint().clone(),
        )?
        .version_policy(VersionPolicy::AllowUnverified);
        let mut a = ManagedInstance::start(settings).await?;
        let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
        assert_eq!(a.program_info().version, "v2.33.1");
        assert_eq!(b.program_info().version, "v2.33.2");
        let aid = a.client().instance().device_id.clone();
        let bid = b.client().instance().device_id.clone();
        let receiver_pid = b.process_id();
        for core in [&a, &b] {
            core.client()
                .update_general_options(
                    &GeneralOptionsPatch::default()
                        .overwrite_remote_device_names_on_connect(false)
                        .disable_system_sleep_on_sync(false),
                )
                .await?;
            core.client()
                .update_network_configuration(
                    &NetworkPatch::default().reconnection_interval_seconds(5),
                )
                .await?;
        }
        assert!(
            a.client()
                .update_general_options(
                    &GeneralOptionsPatch::default().send_full_index_on_upgrade(selected)
                )
                .await?
                .requested_fields_match
        );
        let address = listener(&b).await?;
        for (client, peer, addresses) in [
            (a.client(), &bid, vec![format!("tcp://{address}")]),
            (b.client(), &aid, vec!["dynamic".into()]),
        ] {
            client
                .create_device(
                    &CreateDeviceOptions::new(peer.clone()).settings(
                        DevicePatch::default()
                            .name("full-index controlled peer")
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
        let source = root.join("source");
        let received = root.join("received");
        std::fs::create_dir(&source)?;
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
        for (client, folder) in [
            (a.client(), &af.configuration.id),
            (b.client(), &bf.configuration.id),
        ] {
            client
                .update_folder_scan_configuration(
                    folder,
                    &FolderScanPatch::default()
                        .watcher(false)
                        .rescan_interval_seconds(0)
                        .disable_initial_scan(true),
                )
                .await?;
        }
        let event_options = EventOptions::default()
            .poll_interval(Duration::from_millis(20))?
            .queue_capacity(256)?
            .reconnect_attempts(0)?;
        let mut events = b.client().subscribe_events(event_options.clone()).await?;
        let mut last_id = events.cursor().last_id;
        a.client()
            .share_folder_with(&af.configuration.id, &bid)
            .await?;
        b.client()
            .share_folder_with(&bf.configuration.id, &aid)
            .await?;
        let samples: Vec<_> = (0..4)
            .map(|i| {
                (
                    format!("unchanged-{i}-二.bin"),
                    (0..4096)
                        .map(|n| ((n * 37 + i * 41) % 251) as u8)
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        for (name, bytes) in &samples {
            std::fs::write(source.join(name), bytes)?;
        }
        a.client().request_scan(&af.configuration.id).await?;
        let mut initial_items = 0;
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                tokio::select! {
                    event = events.next() => {
                        let EventStreamItem::Event(event) = event.ok_or("initial index event stream ended")??
                            else { return Err("initial index continuity lost".into()); };
                        initial_items += items(event, &mut last_id, &bf.configuration.id, &aid)?;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(25)) => {}
                }
                if initial_items >= 4 && samples.iter().all(|(name, bytes)| std::fs::read(received.join(name)).is_ok_and(|v| &v == bytes))
                    && b.client().folder_status(&bf.configuration.id).await?.local_files == Some(4) { break; }
            }
            TestResult::Ok(())
        }).await??;
        events.close().await?;
        connected(&a, &b).await?;
        let before_a = a.client().configuration().await?;
        let before_b = b.client().configuration().await?;
        let before_index = a.client().folder_status(&af.configuration.id).await?;
        assert_eq!(before_index.local_files, Some(4));
        let credentials = ["key.pem", "cert.pem"]
            .iter()
            .map(|name| std::fs::read(a.state_directory().join(name)))
            .collect::<std::io::Result<Vec<_>>>()?;
        let receiver_credentials = ["key.pem", "cert.pem"]
            .iter()
            .map(|name| std::fs::read(b.state_directory().join(name)))
            .collect::<std::io::Result<Vec<_>>>()?;
        // A new source-bound head excludes the demonstrated initial full index.
        let mut events = b.client().subscribe_events(event_options).await?;
        let receiver_generation = events.cursor().engine_started_at.clone();
        let mut last_id = events.cursor().last_id;
        a.restart_with_program(base.program().clone(), Duration::from_secs(35))
            .await?;
        assert_eq!(a.program_info().version, "v2.33.2");
        assert_eq!(a.client().instance().device_id, aid);
        assert_eq!(b.process_id(), receiver_pid);
        assert_eq!(
            a.client()
                .general_options()
                .await?
                .send_full_index_on_upgrade,
            Some(selected)
        );
        connected(&a, &b).await?;
        let started = Instant::now();
        let mut resent_items = 0;
        while started.elapsed() < Duration::from_secs(10) {
            tokio::select! {
                event = events.next() => {
                    let EventStreamItem::Event(event) = event.ok_or("post-upgrade index stream ended")??
                        else { return Err("post-upgrade index continuity lost".into()); };
                    assert_eq!(event.cursor.engine_started_at, receiver_generation);
                    resent_items += items(event, &mut last_id, &bf.configuration.id, &aid)?;
                }
                _ = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
        }
        events.close().await?;
        if selected {
            assert!(
                resent_items >= 4,
                "actual full index was not resent: {resent_items}"
            );
        } else {
            assert_eq!(
                resent_items, 0,
                "unchanged index unexpectedly resent with policy disabled"
            );
        }
        assert_eq!(
            a.client()
                .folder_status(&af.configuration.id)
                .await?
                .local_files,
            Some(4)
        );
        assert_eq!(
            b.client()
                .folder_status(&bf.configuration.id)
                .await?
                .local_files,
            Some(4)
        );
        let new_name = "after-upgrade.bin";
        std::fs::write(source.join(new_name), b"actual post-upgrade data transfer")?;
        a.client().request_scan(&af.configuration.id).await?;
        tokio::time::timeout(Duration::from_secs(20), async {
            while !std::fs::read(received.join(new_name))
                .is_ok_and(|v| v == b"actual post-upgrade data transfer")
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await?;
        for (name, bytes) in &samples {
            assert_eq!(&std::fs::read(source.join(name))?, bytes);
            assert_eq!(&std::fs::read(received.join(name))?, bytes);
        }
        for (core, before, identity) in [(&a, &before_a, &aid), (&b, &before_b, &bid)] {
            assert_eq!(&core.client().system_status().await?.device_id, identity);
            let after = core.client().configuration().await?;
            for section in ["gui", "folders", "devices", "defaults", "ldap"] {
                assert!(before.native_document()[section] == after.native_document()[section]);
            }
        }
        for (core, credentials) in [(&a, &credentials), (&b, &receiver_credentials)] {
            for (name, expected) in ["key.pem", "cert.pem"].iter().zip(credentials) {
                assert!(
                    std::fs::read(core.state_directory().join(name))? == *expected,
                    "native credentials changed"
                );
            }
        }
        assert_eq!(std::fs::read(sentinel)?, b"full-index upgrade caller bytes");
        for core in [&mut a, &mut b] {
            let exit = core.shutdown(Duration::from_secs(10)).await?;
            assert!(
                exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0)
            );
        }
        std::fs::remove_dir_all(root)?;
        println!(
            "native full-index upgrade evidence: {}",
            serde_json::json!({
                "selected":selected,"actual_source_version_changed":"v2.33.1->v2.33.2",
                "actual_initial_index_items":initial_items,"actual_unchanged_index_items_resent":resent_items,
                "actual_same_receiver_process_and_gap_free_event_source":true,
                "actual_unchanged_files_and_index_retained_without_initial_scan":true,
                "actual_new_post_upgrade_file_transferred":true,
                "actual_credentials_identities_unrelated_sections_sentinel_retained":true,
                "actual_both_normal_owned_tree_and_state_exit":true
            })
        );
    }
    Ok(())
}
