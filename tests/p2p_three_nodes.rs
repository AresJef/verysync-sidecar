//! Native logical-node relay evidence; this is not a WAN bandwidth benchmark.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use verysync_sidecar::{
    Client, CreateDeviceOptions, DeviceId, DevicePatch, DeviceTransport, Error, FolderId,
    JoinFolderOptions, ManagedInstance, NetworkPatch, PeerConnection, PeerConnectionType,
    SharePermission, TargetPath,
};

async fn private_tcp(client: &Client) -> TestResult<String> {
    let network = client.network_configuration().await?;
    let transport = client.transport_configuration().await?;
    assert!(!network.global_announce_enabled && !network.local_announce_enabled);
    assert!(
        !transport.tracker_enabled
            && !transport.udp_enabled
            && !transport.nat_enabled
            && !transport.relays_enabled
            && !transport.tcp_punch_enabled
    );
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for status in client.listener_status().await?.into_values() {
                for address in status.lan_addresses {
                    if address
                        .strip_prefix("tcp://")
                        .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
                        .is_some_and(|s| s.ip().is_loopback() && s.port() != 0 && s.port() != 18886)
                    {
                        return Ok::<_, Error>(address);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??)
}

async fn associate(
    client: &Client,
    folder: &FolderId,
    peer: &DeviceId,
    address: &str,
    paused: bool,
) -> TestResult {
    let update = client
        .create_device(
            &CreateDeviceOptions::new(peer.clone()).settings(
                DevicePatch::default()
                    .addresses(vec![address.to_owned()])
                    .allowed_transports(vec![DeviceTransport::Tcp])
                    .paused(paused),
            ),
        )
        .await?;
    assert!(update.requested_fields_match);
    client.share_folder_with(folder, peer).await?;
    Ok(())
}

async fn connected(client: &Client, peer: &DeviceId) -> TestResult<PeerConnection> {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(connection) = client.connections().await?.connections.remove(peer) {
                if connection.connected {
                    assert!(matches!(
                        connection.connection_type,
                        Some(PeerConnectionType::TcpClient | PeerConnectionType::TcpServer)
                    ));
                    let address = connection
                        .address
                        .as_deref()
                        .ok_or("actual connected address missing")?
                        .parse::<std::net::SocketAddr>()?;
                    assert!(address.ip().is_loopback() && address.port() != 18886);
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(connection);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?
}

fn out(connection: &PeerConnection) -> TestResult<u64> {
    Ok(connection
        .out_bytes_total
        .ok_or("actual outgoing byte counter missing")?)
}

async fn received(
    client: &Client,
    folder: &FolderId,
    path: &Path,
    samples: &[(PathBuf, Vec<u8>)],
) -> TestResult {
    tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            let bytes_match = samples
                .iter()
                .all(|(name, bytes)| std::fs::read(path.join(name)).is_ok_and(|v| v == *bytes));
            if bytes_match {
                let status = client.folder_status(folder).await?;
                if status.need_bytes == Some(0) && status.local_files == Some(samples.len() as u64)
                {
                    return Ok::<_, Error>(());
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn actual_readonly_node_serves_blank_readonly_peer_after_source_exits() -> TestResult {
    let root = tempfile::Builder::new().prefix("vs3-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    assert_ne!(a_id, b_id);
    let a_address = private_tcp(a.client()).await?;
    let b_address = private_tcp(b.client()).await?;
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    assert_eq!(rw.permission(), &SharePermission::ReadWrite);
    assert_eq!(ro.permission(), &SharePermission::ReadOnly);
    assert!(ro.read_write_key().is_none());
    let source = root.join("source");
    let retained = root.join("readonly-b");
    std::fs::create_dir_all(source.join("sub"))?;
    let names = [
        PathBuf::from("first.bin"),
        Path::new("sub").join("nested.bin"),
        PathBuf::from("二 空格 %.bin"),
        PathBuf::from("last.bin"),
    ];
    let mut seed = 0x34abcdef12345678u64;
    let samples: Vec<_> = names
        .into_iter()
        .map(|name| {
            let bytes: Vec<u8> = (0..524288)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    seed as u8
                })
                .collect();
            (name, bytes)
        })
        .collect();
    for (name, bytes) in &samples {
        std::fs::write(source.join(name), bytes)?;
    }
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&source)).paused(true))
        .await?;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(&retained)).paused(true))
        .await?;
    assert_ne!(af.configuration.id, bf.configuration.id);
    assert!(bf.submitted_key_matches && bf.read_only_key_matches && bf.read_write_key_matches);
    assert_eq!(bf.configuration.extra["type"], "receiveonly");
    assert!(bf.configuration.extra["readWriteSecret"] == "");
    associate(a.client(), &af.configuration.id, &b_id, &b_address, false).await?;
    associate(b.client(), &bf.configuration.id, &a_id, &a_address, false).await?;
    let a_before = out(&connected(a.client(), &b_id).await?)?;
    let b_to_a_before = out(&connected(b.client(), &a_id).await?)?;
    a.client().resume_folder(&af.configuration.id).await?;
    b.client().resume_folder(&bf.configuration.id).await?;
    a.client().request_scan(&af.configuration.id).await?;
    received(b.client(), &bf.configuration.id, &retained, &samples).await?;
    let a_after = out(&connected(a.client(), &b_id).await?)?;
    let b_to_a_after = out(&connected(b.client(), &a_id).await?)?;
    assert!(a_after > a_before && b_to_a_after >= b_to_a_before);
    let a_exit = a.shutdown(Duration::from_secs(10)).await?;
    assert!(a_exit.tree_stopped && !a_exit.forced && a_exit.code == Some(0));

    // C has no state, files, identity or peer relationship while A is alive.
    let mut c = ManagedInstance::start(options(&root.join("c"))?).await?;
    let c_id = c.client().instance().device_id.clone();
    assert!(c_id != a_id && c_id != b_id);
    let c_address = private_tcp(c.client()).await?;
    let blank = root.join("blank-c");
    assert!(!blank.exists());
    let c_ro = c.client().validate_share_key(&keys.read_only_key).await?;
    assert_eq!(c_ro.permission(), &SharePermission::ReadOnly);
    assert!(c_ro.read_write_key().is_none());
    let cf = c
        .client()
        .join_folder(&JoinFolderOptions::new(c_ro, TargetPath::local(&blank)).paused(true))
        .await?;
    assert!(cf.submitted_key_matches && cf.read_only_key_matches && cf.read_write_key_matches);
    assert_eq!(cf.configuration.extra["type"], "receiveonly");
    assert!(cf.configuration.extra["readWriteSecret"] == "");
    assert!(samples.iter().all(|(name, _)| !blank.join(name).exists()));

    let rejector = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let rejected_address = format!("tcp://{}", rejector.local_addr()?);
    associate(b.client(), &bf.configuration.id, &c_id, &c_address, true).await?;
    associate(
        c.client(),
        &cf.configuration.id,
        &b_id,
        &rejected_address,
        false,
    )
    .await?;
    c.client()
        .update_network_configuration(&NetworkPatch::default().reconnection_interval_seconds(1))
        .await?;
    c.client().resume_folder(&cf.configuration.id).await?;
    let (rejected_stream, rejected_peer) =
        tokio::time::timeout(Duration::from_secs(15), rejector.accept()).await??;
    assert!(rejected_peer.ip().is_loopback());
    drop(rejected_stream);
    drop(rejector);
    assert!(!c
        .client()
        .connections()
        .await?
        .connections
        .get(&b_id)
        .is_some_and(|p| p.connected));
    assert!(samples.iter().all(|(name, _)| !blank.join(name).exists()));
    assert!(c
        .client()
        .devices()
        .await?
        .iter()
        .all(|d| d.device_id != a_id));
    c.client().pause_folder(&cf.configuration.id).await?;
    c.client()
        .update_device(&b_id, &DevicePatch::default().addresses(vec![b_address]))
        .await?;
    b.client().resume_device(&c_id).await?;
    let b_before = out(&connected(b.client(), &c_id).await?)?;
    let c_before = out(&connected(c.client(), &b_id).await?)?;
    c.client().resume_folder(&cf.configuration.id).await?;
    received(c.client(), &cf.configuration.id, &blank, &samples).await?;
    let b_after = out(&connected(b.client(), &c_id).await?)?;
    let c_after = out(&connected(c.client(), &b_id).await?)?;
    assert!(b_after > b_before && c_after >= c_before);
    let payload_bytes: usize = samples.iter().map(|(_, bytes)| bytes.len()).sum();
    assert!(b_after - b_before >= payload_bytes as u64);
    let mut hashes = Vec::new();
    for (name, bytes) in &samples {
        let hash = Sha256::digest(bytes);
        for path in [&source, &retained, &blank] {
            let actual = std::fs::read(path.join(name))?;
            assert_eq!(actual, *bytes);
            assert_eq!(Sha256::digest(&actual), hash);
        }
        hashes.push(format!("{hash:x}"));
    }
    assert!(b.client().folder(&bf.configuration.id).await?.extra["readWriteSecret"] == "");
    assert!(c.client().folder(&cf.configuration.id).await?.extra["readWriteSecret"] == "");
    b.client().pause_device(&c_id).await?;
    c.client().pause_device(&b_id).await?;
    for core in [&mut c, &mut b] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    println!(
        "public three-node byte observations: {}",
        json!({
            "payload_bytes":payload_bytes,"payload_sha256":hashes,
            "a_to_b_out_before":a_before,"a_to_b_out_after":a_after,
            "b_to_a_out_before":b_to_a_before,"b_to_a_out_after":b_to_a_after,
            "b_to_c_out_before":b_before,"b_to_c_out_after":b_after,
            "c_to_b_out_before":c_before,"c_to_b_out_after":c_after,
            "scope":"logical loopback peers; protocol byte counters, not WAN savings"
        })
    );
    std::fs::remove_dir_all(root)?;
    println!(
        "public readonly three-node evidence: {}",
        json!({
            "three_independent_actual_identities":true,"all_private_tcp_and_unrelated_transports_disabled":true,
            "actual_engine_generated_rw_and_ro_key_permissions":true,"engine_proposed_local_ids_not_manually_aligned":true,
            "actual_first_readonly_node_received_complete_data":true,"actual_source_normal_tree_exit_before_c_exists":true,
            "actual_c_blank_path_and_no_rw_material":true,"actual_c_has_no_source_peer_configuration":true,
            "wrong_target_reached_owned_rejector":true,"wrong_target_not_connection_or_file_success":true,
            "actual_readonly_b_serves_c_with_a_stopped":true,"actual_c_received_all_bytes_and_zero_need":true,
            "actual_a_b_c_outgoing_counters_observed":true,"actual_b_to_c_delta_covers_unique_payload":true,
            "all_three_complete_file_hashes_and_bytes_match":true,"readonly_permissions_retained_after_transfer":true,
            "all_three_actual_normal_tree_exits":true
        })
    );
    Ok(())
}
