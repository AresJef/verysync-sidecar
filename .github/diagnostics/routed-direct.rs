//! Exercise the public SDK across two isolated routed Linux network namespaces.
#[path = "../tests/common/managed_fixture.rs"]
mod managed_fixture;

use managed_fixture::{options, TestResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, CreateDeviceOptions, DeviceId, DevicePatch, DeviceTransport,
    JoinFolderOptions, ManagedInstance, ManagementEndpoint, NetworkPatch, PeerConnectionType,
    TargetPath, TransportPatch,
};

#[derive(Deserialize, Serialize)]
struct Receipt {
    device: DeviceId,
    key: String,
    peer_address: SocketAddr,
}

async fn spawn_node(root: &Path, ip: IpAddr) -> TestResult {
    let mut owned = ManagedInstance::start(options(&root.join("state"))?).await?;
    let result =
        async {
            let client = owned.client();
            let listener = std::net::TcpListener::bind((ip, 0))?;
            let peer_address = listener.local_addr()?;
            drop(listener);
            assert_ne!(peer_address.port(), 18886);
            let address = format!("tcp://{peer_address}");
            let settings = NetworkPatch::default()
                .listen_addresses(vec![address.clone()])
                .global_discovery(false)
                .local_discovery(false)
                .reconnection_interval_seconds(5);
            assert!(
                client
                    .update_network_configuration(&settings)
                    .await?
                    .requested_fields_match,
                "direct listener settings did not match",
            );
            let transports = TransportPatch::default()
                .tracker(false)
                .nat_mapping(false)
                .relay_client(false)
                .tcp_punching(false)
                .udp(false);
            assert!(
                client
                    .update_transport_configuration(&transports)
                    .await?
                    .requested_fields_match,
                "isolation settings did not match",
            );
            tokio::time::timeout(Duration::from_secs(12), async {
                loop {
                    if client.listener_status().await?.values().any(|status| {
                        status.error.is_none() && status.lan_addresses.contains(&address)
                    }) {
                        break Ok::<_, verysync_sidecar::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .map_err(|_| "configured routed listener never appeared")??;

            let config = client.configuration().await?;
            let key = config
                .native_document()
                .pointer("/gui/apiKey")
                .and_then(serde_json::Value::as_str)
                .ok_or("missing isolated management key")?;
            let receipt = Receipt {
                device: client.instance().device_id.clone(),
                key: key.to_owned(),
                peer_address,
            };
            let pending = root.join("ready.tmp");
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&pending)?;
            serde_json::to_writer(file, &receipt)?;
            println!("ROUTED_NODE core_pid={} ready", owned.process_id());
            fs::rename(pending, root.join("ready.json"))?;

            let (sender, receiver) = tokio::sync::oneshot::channel();
            std::thread::spawn(move || {
                let _ = io::stdin().read_line(&mut String::new());
                let _ = sender.send(());
            });
            let _ = tokio::time::timeout(Duration::from_secs(175), receiver).await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }
        .await;
    let exit = owned.shutdown(Duration::from_secs(20)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    println!("ROUTED_NODE normal_exit code=0 tree_stopped=true state_released=true forced=false");
    result
}

async fn connect(root: &Path) -> TestResult<(Client, Receipt)> {
    let receipt: Receipt = serde_json::from_reader(fs::File::open(root.join("ready.json"))?)?;
    let endpoint = ManagementEndpoint::unix_socket(root.join("state").join("gui.sock"))?;
    let client = Client::connect(
        ConnectOptions::new(endpoint, ApiKey::new(&receipt.key)?)
            .expected_device_id(receipt.device.clone()),
    )
    .await?;
    Ok((client, receipt))
}

async fn inspect(
    client: &Client,
    peer: &Receipt,
    connected: bool,
) -> TestResult<Option<SocketAddr>> {
    let result = tokio::time::timeout(Duration::from_secs(27), async {
        loop {
            let snapshot = client.connections().await?;
            if let Some(state) = snapshot.connections.get(&peer.device) {
                if !connected && !state.connected {
                    return Ok(None);
                }
                if connected && state.connected {
                    assert!(matches!(
                        state.connection_type,
                        Some(PeerConnectionType::TcpClient | PeerConnectionType::TcpServer)
                    ));
                    let raw = state.address.as_deref().ok_or("peer address missing")?;
                    let address: SocketAddr = raw.strip_prefix("tcp://").unwrap_or(raw).parse()?;
                    assert_eq!(address.ip(), peer.peer_address.ip());
                    return Ok(Some(address));
                }
            }
            tokio::time::sleep(Duration::from_millis(125)).await;
        }
    })
    .await
    .map_err(|_| "missing expected observed TCP connection state")?;
    result
}

async fn file_bytes(path: &Path, expected: &[u8]) -> TestResult {
    tokio::time::timeout(Duration::from_secs(29), async {
        loop {
            if path.try_exists()? && fs::read(path)? == expected {
                return Ok::<_, io::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(125)).await;
        }
    })
    .await
    .map_err(|_| "missing expected bytes on isolated receiver")??;
    Ok(())
}

async fn transfer(a_root: &Path, b_root: &Path) -> TestResult {
    let (a, a_receipt) = connect(a_root).await?;
    let (b, b_receipt) = connect(b_root).await?;
    assert_ne!(a_receipt.device, b_receipt.device);
    assert!(a_receipt.key != b_receipt.key, "management keys match");
    let a_folder = a_root.join("synthetic");
    let b_folder = b_root.join("synthetic");
    fs::create_dir(&a_folder)?;
    fs::create_dir(&b_folder)?;
    let source = a_folder.join("data.bin");
    let target = b_folder.join("data.bin");
    assert!(!target.try_exists()?);
    let initial: Vec<u8> = (0..262_181_u32).map(|i| (i ^ (i >> 7)) as u8).collect();
    fs::write(&source, &initial)?;
    for (client, peer) in [(&a, &b_receipt), (&b, &a_receipt)] {
        let device = CreateDeviceOptions::new(peer.device.clone()).settings(
            DevicePatch::default()
                .addresses(vec![format!("tcp://{}", peer.peer_address)])
                .allowed_transports(vec![DeviceTransport::Tcp])
                .paused(false),
        );
        assert!(client.create_device(&device).await?.requested_fields_match);
    }
    let keys = a.generate_share().await?;
    let rw = a.validate_share_key(&keys.read_write_key).await?;
    let ro = b.validate_share_key(&keys.read_only_key).await?;
    let af = a
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(a_folder)))
        .await?;
    let bf = b
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(b_folder)))
        .await?;
    a.share_folder_with(&af.configuration.id, &b_receipt.device)
        .await?;
    b.share_folder_with(&bf.configuration.id, &a_receipt.device)
        .await?;
    let (a_peer, b_peer) =
        tokio::try_join!(inspect(&a, &b_receipt, true), inspect(&b, &a_receipt, true))?;
    file_bytes(&target, &initial).await?;
    println!(
        "ROUTED_EFFECT first_bytes={} sha256={:x} sender_peer={} receiver_peer={}",
        initial.len(),
        Sha256::digest(&initial),
        a_peer.ok_or("sender address")?,
        b_peer.ok_or("receiver address")?,
    );

    a.pause_device(&b_receipt.device).await?;
    b.pause_device(&a_receipt.device).await?;
    tokio::try_join!(
        inspect(&a, &b_receipt, false),
        inspect(&b, &a_receipt, false)
    )?;
    let updated: Vec<_> = initial.iter().map(|v| v ^ 0x5a).collect();
    fs::write(&source, &updated)?;
    a.request_scan(&af.configuration.id).await?;
    assert_eq!(fs::read(&target)?, initial);
    println!("ROUTED_EFFECT paused_disconnected_both=true receiver_retained_first=true");
    a.resume_device(&b_receipt.device).await?;
    b.resume_device(&a_receipt.device).await?;
    tokio::try_join!(inspect(&a, &b_receipt, true), inspect(&b, &a_receipt, true))?;
    file_bytes(&target, &updated).await?;
    println!(
        "ROUTED_EFFECT recovered_bytes={} sha256={:x}",
        updated.len(),
        Sha256::digest(&updated)
    );
    Ok(())
}

#[tokio::main]
async fn main() -> TestResult {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode, root, ip] if mode == "node" => spawn_node(Path::new(root), ip.parse()?).await,
        [mode, a, b] if mode == "transfer" => transfer(Path::new(a), Path::new(b)).await,
        _ => Err("select node ROOT IP or transfer SENDER_ROOT RECEIVER_ROOT".into()),
    }
}
