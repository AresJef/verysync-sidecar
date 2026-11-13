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
