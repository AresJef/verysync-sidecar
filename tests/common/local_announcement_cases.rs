//! Native-to-native local discovery on an explicitly isolated CI VM only.
use super::*;
use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    path::Path,
};
use verysync_sidecar::{JoinFolderOptions, TargetPath};

async fn restart_normal(core: &mut ManagedInstance, state: &Path, peer: &DeviceId) -> TestResult {
    core.client().pause_device(peer).await?;
    connection(core.client(), peer, false).await?;
    let identity = core.client().instance().device_id.clone();
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
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
    restart_normal(&mut a, &a_state, &b_id).await?;
    restart_normal(&mut b, &b_state, &a_id).await?;
    let receiver_ports = tcp_ports(b.client()).await?;
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
        for core in [&a, &b] {
            let cfg = core.client().network_configuration().await?;
            eprintln!(
                "owned local announcement diagnostic: {}",
                json!({"local_enabled":cfg.local_announce_enabled,"global_enabled":cfg.global_announce_enabled,"port":cfg.local_announce_port,"listeners":format!("{:?}",core.client().listener_status().await?),"cache":format!("{:?}",core.client().discovery_cache().await?),"peers":format!("{:?}",core.client().connections().await?)})
            );
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
    for core in [&mut c, &mut b, &mut a] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
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
