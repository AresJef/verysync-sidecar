//! Native-to-native local discovery on an explicitly isolated CI VM only.
use super::*;
use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    path::Path,
};
use verysync_sidecar::{JoinFolderOptions, TargetPath};

async fn stop_normal(core: &mut ManagedInstance, role: &str, stage: &str) -> TestResult {
    let started = std::time::Instant::now();
    let result = core.shutdown(Duration::from_secs(10)).await;
    let timed_out = matches!(&result, Err(Error::Timeout { .. }));
    println!(
        "native announcement shutdown: {}",
        json!({"role": role, "stage": stage, "deadline_ms": 10_000,
               "elapsed_ms": started.elapsed().as_millis(), "timed_out": timed_out,
               "success": result.is_ok()})
    );
    if timed_out {
        let observation = tokio::time::timeout(Duration::from_secs(2), core.wait_for_exit()).await;
        println!(
            "native announcement shutdown after timeout: {}",
            json!({"role": role, "stage": stage, "observed_tree_and_state_exit": matches!(&observation, Ok(Ok(_))),
                   "observation_window_expired": observation.is_err()})
        );
    }
    let exit = result?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    Ok(())
}

async fn restart_normal(core: &mut ManagedInstance, state: &Path, peer: &DeviceId) -> TestResult {
    core.client().pause_device(peer).await?;
    connection(core.client(), peer, false).await?;
    let identity = core.client().instance().device_id.clone();
    let role = state
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("private-peer");
    stop_normal(core, role, "before restart").await?;
    *core = ManagedInstance::start(options(state)?).await?;
    assert_eq!(core.client().instance().device_id, identity);
    core.client().resume_device(peer).await?;
    Ok(())
}

async fn setup(client: &Client, port: u16, multicast: &str, enabled: bool) -> TestResult {
    let changed = client
        .update_network_configuration(
            &NetworkPatch::default()
                .listen_addresses(vec!["tcp://0.0.0.0:0".into()])
                .global_discovery(false)
                .local_discovery(enabled)
                .local_discovery_port(port)
                .local_discovery_multicast(multicast)
                .reconnection_interval_seconds(5),
        )
        .await?;
    assert!(changed.requested_fields_match);
    Ok(())
}

async fn tcp_ports(client: &Client) -> TestResult<Vec<u16>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let ports: Vec<_> = client
                .listener_status()
                .await?
                .into_values()
                .filter(|s| s.error.is_none())
                .flat_map(|s| s.lan_addresses)
                .filter_map(|s| {
                    s.strip_prefix("tcp://")
                        .and_then(|a| a.parse::<SocketAddr>().ok())
                })
                .filter(|a| a.port() > 0 && a.port() != 18886)
                .map(|a| a.port())
                .collect();
            if !ports.is_empty() {
                return Ok::<_, Error>(ports);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?
    .map_err(Into::into)
}

async fn no_peer_for(client: &Client, peer: &DeviceId, seconds: u64) -> TestResult {
    let until = tokio::time::Instant::now() + Duration::from_secs(seconds);
    while tokio::time::Instant::now() < until {
        assert!(!client
            .connections()
            .await?
            .connections
            .get(peer)
            .is_some_and(|p| p.connected));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

#[tokio::test]
async fn probe_pending_device_after_unknown_native_announcement() -> TestResult {
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    assert_eq!(
        std::env::var("VERYSYNC_TEST_LOCAL_ANNOUNCEMENT").as_deref(),
        Ok("github-actions-isolated-vm")
    );
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = socket.local_addr()?.port();
    assert!(!matches!(port, 0 | 18886 | 21027));
    drop(socket);
    let multicast = format!("[ff12::5653:{port:x}]:{port}");
    let root = tempfile::Builder::new()
        .prefix("vss-unknown-announce-")
        .tempdir()?
        .keep();
    let sentinel = root.join("caller-sentinel");
    std::fs::write(&sentinel, b"retained private probe")?;
    let mut receiving = ManagedInstance::start(options(&root.join("receiving"))?).await?;
    let mut announcing = ManagedInstance::start(options(&root.join("announcing"))?).await?;
    let receiving_id = receiving.client().instance().device_id.clone();
    let announcing_id = announcing.client().instance().device_id.clone();
    assert!(!receiving
        .client()
        .pending_devices()
        .await?
        .contains_key(&announcing_id));
    for core in [&mut receiving, &mut announcing] {
        setup(core.client(), port, &multicast, true).await?;
        core.restart(Duration::from_secs(30)).await?;
        let applied = core.client().network_configuration().await?;
        assert!(applied.local_announce_enabled && !applied.global_announce_enabled);
    }
    let expected_ports = tcp_ports(announcing.client()).await?;
    let until = tokio::time::Instant::now() + Duration::from_secs(45);
    let mut saw_owned_announcement = false;
    let mut saw_pending_record = false;
    let mut observations = 0_u32;
    while tokio::time::Instant::now() < until {
        let cache = receiving.client().discovery_cache().await?;
        saw_owned_announcement |= cache
            .get(announcing_id.as_str())
            .into_iter()
            .flat_map(|record| &record.addresses)
            .filter_map(|address| address.strip_prefix("tcp://"))
            .filter_map(|address| address.parse::<SocketAddr>().ok())
            .any(|address| expected_ports.contains(&address.port()));
        let pending = receiving.client().pending_devices().await?;
        observations += 1;
        if pending.contains_key(&announcing_id) {
            saw_pending_record = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    assert!(observations > 0);
    assert_eq!(
        receiving.client().system_status().await?.device_id,
        receiving_id
    );
    assert_eq!(
        announcing.client().system_status().await?.device_id,
        announcing_id
    );
    assert!(matches!(
        receiving.client().device(&announcing_id).await,
        Err(Error::DeviceNotFound { .. })
    ));
    let announcing_exit = announcing.shutdown(Duration::from_secs(10)).await?;
    assert!(
        announcing_exit.tree_stopped
            && announcing_exit.state_released
            && !announcing_exit.forced
            && announcing_exit.code == Some(0)
    );
    let mut dismissed_owned_record = false;
    if saw_pending_record {
        receiving
            .client()
            .dismiss_pending_device(&announcing_id)
            .await?;
        assert!(!receiving
            .client()
            .pending_devices()
            .await?
            .contains_key(&announcing_id));
        dismissed_owned_record = true;
    }
    let exit = receiving.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    assert_eq!(std::fs::read(sentinel)?, b"retained private probe");
    std::fs::remove_dir_all(root)?;
    println!(
        "owned unknown announcement probe: {}",
        json!({
            "owned_identity_in_discovery_cache": saw_owned_announcement,
            "nonempty_owned_pending_record_observed": saw_pending_record,
            "originally_unconfigured_peer": true,
            "exact_dismissal_verified": dismissed_owned_record,
            "actual_observations": observations,
            "both_normal_owned_exits": true
        })
    );
    Ok(())
}

#[tokio::test]
async fn actual_local_announcements_discover_dynamic_peers_and_stop_after_restart() -> TestResult {
    // Local broadcast/multicast and wildcard P2P listeners are confined to an
    // explicit ephemeral CI VM; never enable them on the user's current Mac.
    assert_eq!(
        std::env::var("GITHUB_ACTIONS").as_deref(),
        Ok("true"),
        "local announcements require an explicitly isolated CI VM"
    );
    assert_eq!(
        std::env::var("VERYSYNC_TEST_LOCAL_ANNOUNCEMENT").as_deref(),
        Ok("github-actions-isolated-vm")
    );
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = socket.local_addr()?.port();
    assert_ne!(port, 18886);
    assert_ne!(port, 21027);
    drop(socket);
    let multicast = format!("[ff12::5653:{port:x}]:{port}");
    let root = tempfile::Builder::new()
        .prefix("vss-local-announce-")
        .tempdir()?
        .keep();
    let a_state = root.join("a");
    let b_state = root.join("b");
    let c_state = root.join("c");
    let mut a = ManagedInstance::start(options(&a_state)?).await?;
    let mut b = ManagedInstance::start(options(&b_state)?).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    for core in [&a, &b] {
        setup(core.client(), port, &multicast, false).await?;
    }
    for (client, peer, addresses) in [
        (a.client(), &b_id, vec!["dynamic".into()]),
        (b.client(), &a_id, Vec::new()),
    ] {
        client
            .create_device(
                &CreateDeviceOptions::new(peer.clone()).settings(
                    DevicePatch::default()
                        .addresses(addresses)
                        .allowed_transports(vec![DeviceTransport::Tcp])
                        .paused(false),
                ),
            )
            .await?;
    }
    no_peer_for(a.client(), &b_id, 6).await?;
    assert!(a.client().discovery_cache().await?.is_empty());
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    let source = root.join("source");
    let receiver = root.join("receiver");
    std::fs::create_dir(&source)?;
    let content: Vec<u8> = (0..262_181u64)
        .map(|i| (i.wrapping_mul(73) ^ (i >> 5)) as u8)
        .collect();
    std::fs::write(source.join("native-local.bin"), &content)?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&source)).paused(true))
        .await?;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(&receiver)).paused(true))
        .await?;
    a.client()
        .share_folder_with(&af.configuration.id, &b_id)
        .await?;
    b.client()
        .share_folder_with(&bf.configuration.id, &a_id)
        .await?;
    for core in [&a, &b] {
        setup(core.client(), port, &multicast, true).await?;
    }
    restart_normal(&mut b, &b_state, &a_id).await?;
    let receiver_ports = tcp_ports(b.client()).await?;
    // Start discovery on the initiating process after the receiver is listening.
    // The peer still has to discover the endpoint and connect on its own.
    restart_normal(&mut a, &a_state, &b_id).await?;
    let found = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let snapshot = a.client().connections().await?;
            if snapshot.connections.get(&b_id).is_some_and(|p| {
                p.connected
                    && p.started_at
                        .as_deref()
                        .is_some_and(|t| !t.starts_with("0001-"))
            }) {
                break Ok::<_, Error>(snapshot);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    if !matches!(&found, Ok(Ok(_))) {
        for (role, core, peer) in [("sender", &a, &b_id), ("receiver", &b, &a_id)] {
            let diagnostics: TestResult = async {
            let cfg = core.client().network_configuration().await?;
            let configured = core.client().device(peer).await?;
            let cache = core.client().discovery_cache().await?;
            let snapshot = core.client().connections().await?;
            let listeners: Vec<_> = core
                .client()
                .listener_status()
                .await?
                .into_values()
                .map(|s| {
                    json!({
                "local":s.lan_addresses,"reported_external":s.wan_addresses,"error":s.error})
                })
                .collect();
            let observed = snapshot.connections.get(peer).map(|p| json!({"connected":p.connected,
                "paused":p.paused,"address":p.address,"type":format!("{:?}",p.connection_type),
                "started_at":p.started_at,"in_bytes":p.in_bytes_total,"out_bytes":p.out_bytes_total}));
            eprintln!(
                "owned local announcement address diagnostic: {}",
                json!({"role":role,
                "own_identity":core.client().instance().device_id.as_str(),"target_peer":peer.as_str(),
                "local_enabled":cfg.local_announce_enabled,"global_enabled":cfg.global_announce_enabled,
                "reconnection_seconds":cfg.reconnection_interval_seconds,"port":cfg.local_announce_port,
                "configured_listeners":cfg.listen_addresses,"listeners":listeners,
                "configured_peer_paused":configured.paused,"configured_peer_addresses":configured.addresses,
                "configured_peer_transports":format!("{:?}",configured.allowed_transports),
                "owned_peer_candidates":cache.get(peer.as_str()).map(|r| &r.addresses),
                "total_cache_entries":cache.len(),"actual_peer":observed})
            );
            Ok(())
            }.await;
            if let Err(error) = diagnostics {
                eprintln!("owned local announcement secondary diagnostic unavailable: {error:?}");
            }
        }
    }
    let snapshot = found??;
    assert!(matches!(
        snapshot.connections[&b_id].connection_type,
        Some(PeerConnectionType::TcpClient | PeerConnectionType::TcpServer)
    ));
    connection(b.client(), &a_id, true).await?;
    let cache = a.client().discovery_cache().await?;
    assert!(cache
        .values()
        .flat_map(|r| &r.addresses)
        .filter_map(|s| s
            .strip_prefix("tcp://")
            .and_then(|a| a.parse::<SocketAddr>().ok()))
        .any(|a| receiver_ports.contains(&a.port())));
    for (client, folder) in [
        (a.client(), &af.configuration.id),
        (b.client(), &bf.configuration.id),
    ] {
        client.resume_folder(folder).await?;
    }
    a.client().request_scan(&af.configuration.id).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status = b.client().folder_status(&bf.configuration.id).await?;
            if status.local_files == Some(1)
                && status.need_bytes == Some(0)
                && std::fs::read(receiver.join("native-local.bin"))
                    .ok()
                    .as_deref()
                    == Some(content.as_slice())
            {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    for core in [&a, &b] {
        setup(core.client(), port, &multicast, false).await?;
    }
    restart_normal(&mut a, &a_state, &b_id).await?;
    restart_normal(&mut b, &b_state, &a_id).await?;
    // A fresh third identity has no saved endpoints. Existing peers may retain
    // their old connections; disabling discovery does not promise eviction.
    let mut c = ManagedInstance::start(options(&c_state)?).await?;
    let c_id = c.client().instance().device_id.clone();
    a.client()
        .create_device(
            &CreateDeviceOptions::new(c_id.clone()).settings(
                DevicePatch::default()
                    .addresses(Vec::new())
                    .allowed_transports(vec![DeviceTransport::Tcp]),
            ),
        )
        .await?;
    c.client()
        .create_device(
            &CreateDeviceOptions::new(a_id.clone()).settings(
                DevicePatch::default()
                    .addresses(vec!["dynamic".into()])
                    .allowed_transports(vec![DeviceTransport::Tcp]),
            ),
        )
        .await?;
    setup(c.client(), port, &multicast, true).await?;
    restart_normal(&mut c, &c_state, &a_id).await?;
    no_peer_for(c.client(), &a_id, 12).await?;
    assert!(c.client().discovery_cache().await?.is_empty());
    for core in [&a, &b] {
        let cfg = core.client().network_configuration().await?;
        assert!(!cfg.global_announce_enabled && !cfg.local_announce_enabled);
    }
    for (client, peer) in [
        (a.client(), &b_id),
        (b.client(), &a_id),
        (a.client(), &c_id),
        (c.client(), &a_id),
    ] {
        client.pause_device(peer).await?;
    }
    connection(a.client(), &b_id, false).await?;
    connection(b.client(), &a_id, false).await?;
    for (role, core) in [("c", &mut c), ("b", &mut b), ("a", &mut a)] {
        stop_normal(core, role, "final cleanup").await?;
    }
    assert_eq!(std::fs::read(source.join("native-local.bin"))?, content);
    assert_eq!(std::fs::read(receiver.join("native-local.bin"))?, content);
    std::fs::remove_dir_all(root)?;
    println!(
        "public native local announcement evidence: {}",
        json!({"explicit_isolated_CI_VM_only":true,"unique_nondefault_udp_port_and_multicast":true,"only_native_announcements_no_synthetic_wire_packets":true,"initial_disabled_no_peer_or_cache":true,"enabled_after_normal_restart_dynamic_peer_and_actual_cache":true,"actual_tcp_authenticated_peer":true,"actual_full_payload_bytes":262181,"disabled_after_normal_restart_fresh_third_peer_no_discovery_12s":true,"existing_connections_not_claimed_evicted":true,"all_five_normal_same_identity_restarts":true,"all_eight_normal_owned_tree_and_state_exits":true,"both_full_payloads_preserved":true,"global_discovery_disabled":true})
    );
    Ok(())
}
