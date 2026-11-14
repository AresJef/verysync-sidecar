//! Actual private listener, connection, transport and discovery observations.
#[path = "common/discovery_fixture.rs"]
mod discovery_fixture;
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use serde_json::json;
use std::time::Duration;
use verysync_sidecar::{
    Client, CreateDeviceOptions, DeviceId, DevicePatch, DeviceTransport, Error, ManagedInstance,
    NetworkPatch, PeerConnectionType,
};

async fn listener(client: &Client, expected: Option<&str>) -> TestResult<String> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for status in client.listener_status().await?.into_values() {
                if status.error.is_some() {
                    continue;
                }
                for address in status.lan_addresses {
                    let valid = address
                        .strip_prefix("tcp://")
                        .and_then(|v| v.parse::<std::net::SocketAddr>().ok())
                        .is_some_and(|v| {
                            v.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                                && v.port() > 0
                                && v.port() != 18886
                        });
                    if valid && expected.is_none_or(|v| v == address) {
                        return Ok::<_, Error>(address);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??)
}
async fn connection(
    client: &Client,
    id: &DeviceId,
    connected: bool,
) -> TestResult<verysync_sidecar::ConnectionSnapshot> {
    Ok(tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let snapshot = client.connections().await?;
            if snapshot.connections.get(id).is_some_and(|v| v.connected) == connected {
                return Ok::<_, Error>(snapshot);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??)
}

#[tokio::test]
async fn actual_network_settings_listen_transition_tcp_selection_and_wrong_address_effect(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vsn-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    let original = a.client().network_configuration().await?;
    assert!(!original.global_announce_enabled && !original.local_announce_enabled);
    assert!(a.client().discovery_cache().await?.is_empty());
    let port = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let selected = port.local_addr()?;
    assert_ne!(selected.port(), 18886);
    drop(port);
    let selected = format!("tcp://{selected}");
    let updated = a
        .client()
        .update_network_configuration(
            &NetworkPatch::default()
                .listen_addresses(vec![selected.clone()])
                .global_discovery(false)
                .local_discovery(false)
                .reconnection_interval_seconds(5),
        )
        .await?;
    assert!(updated.requested_fields_match);
    assert_eq!(updated.configuration.extra, original.extra);
    assert_eq!(listener(a.client(), Some(&selected)).await?, selected);
    let b_address = listener(b.client(), None).await?;
    for (client, id, address) in [
        (a.client(), &b_id, b_address.clone()),
        (b.client(), &a_id, selected.clone()),
    ] {
        let created = client
            .create_device(
                &CreateDeviceOptions::new(id.clone()).settings(
                    DevicePatch::default()
                        .addresses(vec![address])
                        .allowed_transports(vec![DeviceTransport::Tcp])
                        .paused(false),
                ),
            )
            .await?;
        assert!(created.requested_fields_match);
        assert_eq!(
            created.configuration.allowed_transports,
            Some(vec![DeviceTransport::Tcp])
        );
    }
    let a_snapshot = connection(a.client(), &b_id, true).await?;
    let b_snapshot = connection(b.client(), &a_id, true).await?;
    for (snapshot, id) in [(&a_snapshot, &b_id), (&b_snapshot, &a_id)] {
        let peer = &snapshot.connections[id];
        assert!(matches!(
            peer.connection_type,
            Some(PeerConnectionType::TcpClient | PeerConnectionType::TcpServer)
        ));
        assert!(peer.in_bytes_total.is_some() && peer.out_bytes_total.is_some());
    }
    assert!(matches!(
        a.client()
            .update_network_configuration(&NetworkPatch::default())
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        a.client()
            .update_network_configuration(
                &NetworkPatch::default().listen_addresses(vec!["bad\naddress".into()])
            )
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        a.client()
            .update_device(
                &b_id,
                &DevicePatch::default()
                    .allowed_transports(vec![DeviceTransport::Unknown("private-unknown".into())])
            )
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    a.client().pause_device(&b_id).await?;
    b.client().pause_device(&a_id).await?;
    connection(a.client(), &b_id, false).await?;
    connection(b.client(), &a_id, false).await?;
    let wrong = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let address = wrong.local_addr()?;
    assert_ne!(address.port(), 18886);
    assert!(
        a.client()
            .update_device(
                &b_id,
                &DevicePatch::default().addresses(vec![format!("tcp://{address}")])
            )
            .await?
            .requested_fields_match
    );
    let rejected = tokio::spawn(async move {
        let (socket, _) = wrong.accept().await?;
        drop(socket);
        Ok::<_, std::io::Error>(())
    });
    a.client().resume_device(&b_id).await?;
    tokio::time::timeout(Duration::from_secs(15), rejected).await???;
    connection(a.client(), &b_id, false).await?;
    assert!(
        a.client()
            .update_device(&b_id, &DevicePatch::default().addresses(vec![b_address]))
            .await?
            .requested_fields_match
    );
    b.client().resume_device(&a_id).await?;
    connection(a.client(), &b_id, true).await?;
    connection(b.client(), &a_id, true).await?;
    assert_eq!(
        a.client().network_configuration().await?.listen_addresses,
        [selected]
    );
    // Explicitly quiesce this test's peer traffic before lifecycle teardown.
    // The networking assertions above retain the actual live/recovery checks.
    a.client().pause_device(&b_id).await?;
    b.client().pause_device(&a_id).await?;
    connection(a.client(), &b_id, false).await?;
    connection(b.client(), &a_id, false).await?;
    for instance in [&mut b, &mut a] {
        let exit = instance.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!(
        "public network control evidence: {}",
        json!({"actual_disabled_discovery_settings":true,"actual_empty_discovery_cache":true,"explicit_network_patch_readback":true,"unrelated_options_preserved":true,"exact_selected_listener_observed":true,"actual_tcp_selector_readback":true,"both_actual_private_peers_connected":true,"actual_tcp_connection_types":true,"actual_byte_counters_present":true,"invalid_and_unknown_inputs_rejected":true,"wrong_target_reached_owned_rejector":true,"wrong_address_not_peer_success":true,"restored_peer_address_reconnected":true,"management_identity_and_listener_retained":true,"both_actual_normal_tree_exits":true})
    );
    Ok(())
}

#[tokio::test]
async fn actual_builtin_discovery_client_uses_isolated_service_and_populates_cache() -> TestResult {
    let root = tempfile::Builder::new().prefix("vsnd-").tempdir()?.keep();
    let a_state = root.join("a");
    let b_state = root.join("b");
    let mut a = ManagedInstance::start(options(&a_state)?).await?;
    let mut b = ManagedInstance::start(options(&b_state)?).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    let b_address = listener(b.client(), None).await?;
    let server = discovery_fixture::DiscoveryFixture::start(
        b_state,
        a_state,
        b_id.as_str().to_owned(),
        b_address.clone(),
    )
    .await?;
    server.enable_private_routing()?;
    let updated = a
        .client()
        .update_network_configuration(
            &NetworkPatch::default()
                .global_discovery(true)
                .local_discovery(false)
                .reconnection_interval_seconds(5),
        )
        .await?;
    assert!(updated.requested_fields_match);
    // The receiver has no fixed dialing address; the sender must use discovery.
    b.client()
        .create_device(
            &CreateDeviceOptions::new(a_id.clone()).settings(
                DevicePatch::default()
                    .addresses(Vec::new())
                    .allowed_transports(vec![DeviceTransport::Tcp])
                    .paused(false),
            ),
        )
        .await?;
    a.client()
        .create_device(
            &CreateDeviceOptions::new(b_id.clone()).settings(
                DevicePatch::default()
                    .addresses(vec!["dynamic".into()])
                    .allowed_transports(vec![DeviceTransport::Tcp])
                    .paused(false),
            ),
        )
        .await?;
    eprintln!("private discovery stage: observe actual dynamically located peer");
    if let Err(error) = connection(a.client(), &b_id, true).await {
        let observed = server.close().await?;
        eprintln!("private discovery failure observations: {observed}");
        return Err(error);
    }
    connection(b.client(), &a_id, true).await?;
    let cache = a.client().discovery_cache().await?;
    assert!(cache
        .values()
        .any(|record| record.addresses.contains(&b_address)));
    assert!(
        a.client()
            .update_network_configuration(&NetworkPatch::default().global_discovery(false))
            .await?
            .requested_fields_match
    );
    a.client().pause_device(&b_id).await?;
    b.client().pause_device(&a_id).await?;
    connection(a.client(), &b_id, false).await?;
    connection(b.client(), &a_id, false).await?;
    let observed = server.close().await?;
    eprintln!("private discovery fixture observations: {observed}");
    assert!(observed["lookups"].as_u64().is_some_and(|v| v > 0));
    assert_eq!(observed["unexpected_requests"], 0);
    assert_eq!(observed["pin_parameter_not_transmitted"], true);
    for instance in [&mut b, &mut a] {
        let exit = instance.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!(
        "public private discovery evidence: {}",
        json!({"explicit_loopback_https_server":true,"builtin_discovery_requests_routed_only_to_owned_fixture":true,"actual_target_identity_lookup":true,"actual_dynamic_peer_connected":true,"actual_receiver_connected":true,"actual_cache_contains_selected_private_address":true,"no_fixed_sender_peer_address":true,"local_discovery_stayed_disabled":true,"private_server_stopped_and_joined":true,"both_actual_normal_tree_exits":true})
    );
    Ok(())
}

#[tokio::test]
async fn actual_private_udp_only_peers_and_disabled_tracker_nat_observations() -> TestResult {
    use verysync_sidecar::TransportPatch;
    let root = tempfile::Builder::new().prefix("vsnu-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    let mut addresses = Vec::new();
    for instance in [&mut a, &mut b] {
        let original = instance.client().transport_configuration().await?;
        assert!(
            !original.tracker_enabled
                && !original.udp_enabled
                && !original.nat_enabled
                && !original.relays_enabled
        );
        let status = instance.client().transport_status().await?;
        assert_eq!(status.tracker.connection_state, "disabled");
        assert_eq!(status.nat_type, "unknown");
        let reservation = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let port = reservation.local_addr()?.port();
        assert_ne!(port, 18886);
        drop(reservation);
        assert!(
            instance
                .client()
                .update_network_configuration(
                    &NetworkPatch::default()
                        .listen_addresses(Vec::new())
                        .global_discovery(false)
                        .local_discovery(false)
                        .reconnection_interval_seconds(5)
                )
                .await?
                .requested_fields_match
        );
        let before = instance.client().transport_configuration().await?;
        let updated = instance
            .client()
            .update_transport_configuration(
                &TransportPatch::default()
                    .tracker(false)
                    .udp(true)
                    .udp_port(port)
                    .nat_mapping(false)
                    .relay_client(false)
                    .tcp_punching(false)
                    .stun_servers(Vec::new())
                    .relay_addresses(Vec::new())
                    .nat_lease_minutes(120)
                    .nat_renewal_minutes(60)
                    .nat_timeout_seconds(7),
            )
            .await?;
        assert!(updated.requested_fields_match);
        assert_eq!(updated.configuration.extra, before.extra);
        instance.restart(Duration::from_secs(30)).await?;
        let persisted = instance.client().transport_configuration().await?;
        assert!(
            persisted.udp_enabled
                && !persisted.tracker_enabled
                && !persisted.nat_enabled
                && !persisted.relays_enabled
                && !persisted.tcp_punch_enabled
        );
        assert_eq!(persisted.udp_port, port);
        assert!(instance
            .client()
            .network_configuration()
            .await?
            .listen_addresses
            .is_empty());
        addresses.push(format!("udp://127.0.0.1:{port}"));
    }
    b.client()
        .create_device(
            &CreateDeviceOptions::new(a_id.clone()).settings(
                DevicePatch::default()
                    .addresses(vec![addresses[0].clone()])
                    .allowed_transports(vec![DeviceTransport::Udp])
                    .paused(false),
            ),
        )
        .await?;
    a.client()
        .create_device(
            &CreateDeviceOptions::new(b_id.clone()).settings(
                DevicePatch::default()
                    .addresses(vec![addresses[1].clone()])
                    .allowed_transports(vec![DeviceTransport::Udp])
                    .paused(false),
            ),
        )
        .await?;
    let connected = connection(a.client(), &b_id, true).await?;
    let receiver = connection(b.client(), &a_id, true).await?;
    for snapshot in [&connected, &receiver] {
        for peer in snapshot.connections.values().filter(|v| v.connected) {
            assert!(matches!(
                peer.connection_type,
                Some(PeerConnectionType::QuicClient | PeerConnectionType::QuicServer)
            ));
        }
    }
    a.client().pause_device(&b_id).await?;
    b.client().pause_device(&a_id).await?;
    connection(a.client(), &b_id, false).await?;
    connection(b.client(), &a_id, false).await?;
    let rejector = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let rejected = rejector.local_addr()?;
    assert_ne!(rejected.port(), 18886);
    assert!(
        a.client()
            .update_device(
                &b_id,
                &DevicePatch::default().addresses(vec![format!("udp://{rejected}")])
            )
            .await?
            .requested_fields_match
    );
    a.client().resume_device(&b_id).await?;
    let mut packet = [0u8; 4096];
    let (received, sender) =
        tokio::time::timeout(Duration::from_secs(20), rejector.recv_from(&mut packet)).await??;
    assert!(received > 0 && sender.ip().is_loopback());
    assert!(!a
        .client()
        .connections()
        .await?
        .connections
        .get(&b_id)
        .is_some_and(|v| v.connected));
    assert!(
        a.client()
            .update_device(
                &b_id,
                &DevicePatch::default().addresses(vec![addresses[1].clone()])
            )
            .await?
            .requested_fields_match
    );
    b.client().resume_device(&a_id).await?;
    connection(a.client(), &b_id, true).await?;
    connection(b.client(), &a_id, true).await?;
    a.client().pause_device(&b_id).await?;
    b.client().pause_device(&a_id).await?;
    connection(a.client(), &b_id, false).await?;
    connection(b.client(), &a_id, false).await?;
    drop(rejector);
    for instance in [&mut b, &mut a] {
        let exit = instance.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!(
        "public private UDP evidence: {}",
        json!({"actual_disabled_tracker_state":true,"actual_unknown_nat_retained":true,"explicit_udp_configuration_readback":true,"unrelated_options_preserved":true,"same_identity_udp_settings_persist_after_restart":true,"tcp_listeners_disabled":true,"udp_only_device_selectors":true,"actual_quic_connection_types":true,"wrong_private_address_received_udp_packet":true,"wrong_address_did_not_connect_peer":true,"restored_udp_address_reconnected":true,"actual_both_private_peers_connected":true,"unrelated_network_features_stay_disabled":true,"actual_both_normal_tree_exits":true})
    );
    Ok(())
}

async fn relay_ready(
    client: &Client,
    expected: std::net::SocketAddr,
) -> TestResult<verysync_sidecar::RelayServerStatus> {
    let mut last = None;
    let result=tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let status = client.relay_server_status().await?;
            let parsed=status.relay_url.as_deref().and_then(|value|url::Url::parse(value).ok());
            let selected=parsed.as_ref().is_some_and(|url|url.scheme()=="relay"
                &&url.host_str().and_then(|host|host.parse::<std::net::IpAddr>().ok())==Some(expected.ip())
                &&url.port()==Some(expected.port())&&url.username().is_empty()&&url.password().is_none()&&url.fragment().is_none());
            last=Some(json!({"enabled":status.enabled,"url_present":status.relay_url.is_some(),"url_parses":parsed.is_some(),"selected_owned_listener":selected}));
            if status.enabled && selected {
                return Ok::<_, Error>(status);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if result.is_err() {
        eprintln!(
            "private relay preparation diagnostic: {}",
            json!({"last":last})
        );
    }
    Ok(result??)
}
#[tokio::test]
async fn actual_owned_private_relay_session_with_tcp_and_udp_disabled() -> TestResult {
    use verysync_sidecar::{RelayProbeResult, RelayServerPatch, TransportPatch};
    let root = tempfile::Builder::new().prefix("vsnr-").tempdir()?.keep();
    let mut relay = ManagedInstance::start(options(&root.join("relay"))?).await?;
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    assert!(!relay.client().relay_server_configuration().await?.enabled);
    let initial = relay.client().relay_server_status().await?;
    assert!(!initial.enabled && initial.bytes_proxied.is_none() && initial.relay_url.is_none());
    assert!(relay.client().relay_rate_samples().await?.is_empty());
    let first = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let second = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let listen = first.local_addr()?;
    let status = second.local_addr()?;
    assert_ne!(listen.port(), 18886);
    assert_ne!(status.port(), 18886);
    drop(first);
    drop(second);
    let enabled = relay
        .client()
        .update_relay_server_configuration(
            &RelayServerPatch::default()
                .enabled(true)
                .listen(listen.to_string())
                .status_address(status.to_string())
                .public(false)
                .pool_addresses("")
                .nat_mapping(false)
                .authentication(false)
                .token("")
                .provided_by("verysync-sidecar private acceptance")
                .network_timeout_seconds(11)
                .ping_interval_seconds(3)
                .message_timeout_seconds(7),
        )
        .await?;
    assert!(enabled.requested_fields_match);
    let runtime = relay_ready(relay.client(), listen).await?;
    let effective = runtime
        .options
        .as_ref()
        .ok_or("running relay options missing")?;
    assert_eq!(effective.network_timeout_seconds, Some(11));
    assert_eq!(effective.ping_interval_seconds, Some(3));
    assert_eq!(effective.message_timeout_seconds, Some(7));
    let relay_url = runtime.relay_url.ok_or("actual relay URL missing")?;
    let probe = relay.client().probe_relay(&relay_url).await?;
    assert_eq!(probe.result, RelayProbeResult::Success);
    assert!(probe.error.as_ref().is_none_or(String::is_empty));
    let relay_probe_url = relay_url.clone();
    let parsed = url::Url::parse(&relay_url)?;
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_eq!(parsed.port(), Some(listen.port()));
    assert!(!relay.client().relay_rate_samples().await?.is_empty());
    for instance in [&mut a, &mut b] {
        assert!(
            instance
                .client()
                .update_network_configuration(
                    &NetworkPatch::default()
                        .listen_addresses(Vec::new())
                        .global_discovery(false)
                        .local_discovery(false)
                        .reconnection_interval_seconds(5)
                )
                .await?
                .requested_fields_match
        );
        assert!(
            instance
                .client()
                .update_transport_configuration(
                    &TransportPatch::default()
                        .tracker(false)
                        .udp(false)
                        .nat_mapping(false)
                        .tcp_punching(false)
                        .stun_servers(Vec::new())
                        .relay_client(true)
                        .relay_addresses(vec![relay_url.clone()])
                )
                .await?
                .requested_fields_match
        );
        instance.restart(Duration::from_secs(30)).await?;
    }
    b.client()
        .create_device(
            &CreateDeviceOptions::new(a_id.clone()).settings(
                DevicePatch::default()
                    .addresses(vec![relay_url.clone()])
                    .allowed_transports(vec![DeviceTransport::Relay])
                    .paused(false),
            ),
        )
        .await?;
    a.client()
        .create_device(
            &CreateDeviceOptions::new(b_id.clone()).settings(
                DevicePatch::default()
                    .addresses(vec![relay_url])
                    .allowed_transports(vec![DeviceTransport::Relay])
                    .paused(false),
            ),
        )
        .await?;
    let connected = connection(a.client(), &b_id, true).await?;
    let receiver = connection(b.client(), &a_id, true).await?;
    for snapshot in [&connected, &receiver] {
        for peer in snapshot.connections.values().filter(|v| v.connected) {
            assert!(matches!(
                peer.connection_type,
                Some(PeerConnectionType::RelayClient | PeerConnectionType::RelayServer)
            ));
        }
    }
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let active = relay.client().relay_server_status().await?;
            if active.num_active_sessions.is_some_and(|v| v > 0)
                && active.bytes_proxied.is_some_and(|v| v > 0)
            {
                break Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    a.client().pause_device(&b_id).await?;
    b.client().pause_device(&a_id).await?;
    connection(a.client(), &b_id, false).await?;
    connection(b.client(), &a_id, false).await?;
    for instance in [&mut b, &mut a] {
        let exit = instance.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    assert!(
        relay
            .client()
            .update_relay_server_configuration(&RelayServerPatch::default().enabled(false))
            .await?
            .requested_fields_match
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if !relay.client().relay_server_status().await?.enabled {
                break Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    assert!(tokio::net::TcpStream::connect(listen).await.is_err());
    let failed = relay.client().probe_relay(&relay_probe_url).await?;
    assert_eq!(failed.result, RelayProbeResult::Failed);
    assert!(failed.error.as_ref().is_some_and(|s| !s.is_empty()));
    let exit = relay.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public private relay evidence: {}",
        json!({"actual_disabled_runtime_and_missing_counters":true,"actual_empty_disabled_rate_samples":true,"explicit_private_listener_and_status":true,"actual_selected_private_relay_url":true,"actual_positive_relay_probe":true,"actual_closed_relay_negative_probe":true,"actual_runtime_timeout_units_seconds":true,"actual_relay_connection_types":true,"actual_running_rate_samples":true,"tcp_udp_tracker_discovery_nat_disabled":true,"relay_only_device_selectors":true,"actual_both_peers_connected":true,"actual_relay_session_and_proxied_bytes":true,"actual_server_disabled":true,"actual_owned_relay_listener_closed":true,"actual_three_normal_tree_exits":true})
    );
    Ok(())
}
