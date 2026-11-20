//! Private test-only companion for the unchanged stable acceptance_node example.
use serde::Deserialize;
use serde_json::{json, Value};
use std::{fs, net::SocketAddr, path::Path, time::Duration};
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, CreateDeviceOptions, DeviceId, DevicePatch, DeviceTransport,
    JoinFolderOptions, ManagementEndpoint, NetworkPatch, PeerConnectionType, ShareKey, TargetPath,
    TransportPatch,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
struct Identity {
    endpoint: String,
    api_key: String,
    device_id: DeviceId,
    program_version: String,
}
#[derive(Deserialize)]
struct Plan {
    peer: DeviceId,
    #[serde(default)]
    listen: Option<SocketAddr>,
    #[serde(default)]
    dial: Option<SocketAddr>,
    #[serde(default)]
    read_key: Option<String>,
}

fn require(condition: bool, reason: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(reason.into())
    }
}

async fn client(root: &Path) -> Result<Client> {
    let receipt: Identity = serde_json::from_reader(fs::File::open(
        root.join("state/acceptance-connection.json"),
    )?)?;
    require(
        receipt.program_version == "v2.33.2",
        "different native version",
    )?;
    let endpoint = ManagementEndpoint::http(&receipt.endpoint)?;
    let http = endpoint.http_url().ok_or("invalid management URL")?;
    require(
        http.host_str() == Some("127.0.0.1") && http.port().is_some_and(|port| port != 18886),
        "unsafe management target",
    )?;
    let client = Client::connect(
        ConnectOptions::new(endpoint, ApiKey::new(&receipt.api_key)?)
            .expected_device_id(receipt.device_id),
    )
    .await?;
    Ok(client)
}

async fn join(client: &Client, root: &Path, share: &ShareKey) -> Result<()> {
    let path = root.join("synthetic");
    fs::create_dir(&path)?;
    let key = client.validate_share_key(share).await?;
    client
        .join_folder(&JoinFolderOptions::new(key, TargetPath::local(path)))
        .await?;
    Ok(())
}

async fn prepare(client: &Client, root: &Path, plan: Plan) -> Result<Value> {
    require(
        plan.peer != client.instance().device_id,
        "same device identity",
    )?;
    require(
        plan.listen.is_some() != plan.dial.is_some(),
        "choose one direction",
    )?;
    let advertised = plan.listen.map(|address| format!("tcp://{address}"));
    let mut settings = NetworkPatch::default()
        .global_discovery(false)
        .local_discovery(false)
        .reconnection_interval_seconds(5);
    if let Some(address) = &advertised {
        settings = settings.listen_addresses(vec![address.clone()]);
    }
    require(
        client
            .update_network_configuration(&settings)
            .await?
            .requested_fields_match,
        "network isolation settings differ",
    )?;
    let transport = TransportPatch::default()
        .tracker(false)
        .nat_mapping(false)
        .relay_client(false)
        .tcp_punching(false)
        .udp(false);
    require(
        client
            .update_transport_configuration(&transport)
            .await?
            .requested_fields_match,
        "transport isolation settings differ",
    )?;
    // An empty native address list is normalized to "dynamic". With both
    // discovery modes, tracker and relay disabled, it supplies no dial target.
    let addresses = vec![plan
        .dial
        .map_or_else(|| "dynamic".to_owned(), |value| format!("tcp://{value}"))];
    let peer = CreateDeviceOptions::new(plan.peer.clone()).settings(
        DevicePatch::default()
            .addresses(addresses)
            .allowed_transports(vec![DeviceTransport::Tcp])
            .paused(false),
    );
    require(
        client.create_device(&peer).await?.requested_fields_match,
        "peer settings differ",
    )?;
    if let Some(key) = plan.read_key {
        join(client, root, &ShareKey::new(key)?).await?;
    }
    let folders = client.folders().await?;
    let [folder] = folders.as_slice() else {
        return Err("need exactly one synthetic folder".into());
    };
    client.share_folder_with(&folder.id, &plan.peer).await?;
    if let Some(address) = advertised {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if client.listener_status().await?.values().any(|listener| {
                    listener.error.is_none() && listener.lan_addresses.contains(&address)
                }) {
                    break Ok::<_, verysync_sidecar::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await??;
    }
    Ok(json!({"isolated_tcp_settings_matched": true}))
}

async fn run(command: &str, root: &Path) -> Result<Value> {
    let client = client(root).await?;
    match command {
        "source" => {
            let keys = client.generate_share().await?;
            join(&client, root, &keys.read_write_key).await?;
            Ok(json!({"receive_share": keys.read_only_key.expose_secret()}))
        }
        "prepare" => {
            let plan = serde_json::from_reader(fs::File::open(root.join("field-plan.json"))?)?;
            prepare(&client, root, plan).await
        }
        "observe" => {
            let plan: Plan =
                serde_json::from_reader(fs::File::open(root.join("field-plan.json"))?)?;
            let snapshot = client.connections().await?;
            let Some(peer) = snapshot.connections.get(&plan.peer) else {
                return Ok(json!({"configured_peer_reported":false}));
            };
            let direction = match peer.connection_type {
                Some(PeerConnectionType::TcpClient) => "tcp_client",
                Some(PeerConnectionType::TcpServer) => "tcp_server",
                _ => "other",
            };
            Ok(
                json!({"configured_peer_reported":true, "connected":peer.connected,
                     "direction":direction, "address":peer.address}),
            )
        }
        "scan" => {
            let entries = client.folders().await?;
            let [folder] = entries.as_slice() else {
                return Err("need exactly one synthetic folder for scan".into());
            };
            client.request_scan(&folder.id).await?;
            Ok(json!({"scan_requested":true}))
        }
        _ => Err("invalid local test command".into()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let command = args.next().ok_or("command required")?;
    let root = args.next().ok_or("dedicated root required")?;
    require(args.next().is_none(), "unexpected command argument")?;
    let root = Path::new(&root);
    require(root.is_absolute(), "absolute dedicated root required")?;
    let result = run(command.to_str().ok_or("command must be UTF-8")?, root).await?;
    println!("{}", result);
    Ok(())
}
