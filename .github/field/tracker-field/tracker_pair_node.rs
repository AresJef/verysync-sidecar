//! One stable VerySync node for an explicit two-sided official tracker test.
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    env, fs,
    io::{self, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    path::{Path, PathBuf},
    time::Duration,
};
use verysync_sidecar::{
    CreateDeviceOptions, DeviceId, DevicePatch, DeviceTransport, JoinFolderOptions, LocalProgram,
    ManagedInstance, ManagedOptions, ManagementEndpoint, NetworkPatch, ShareKey, TargetPath,
    TransportPatch,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
struct PeerPlan {
    peer: DeviceId,
    #[serde(default)]
    read_only_share: Option<String>,
}

fn hash(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("explicit fixed native SHA required".into());
    }
    let mut out = [0; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(out)
}

fn output(value: &Value) -> Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{value}")?;
    stdout.flush()?;
    Ok(())
}

async fn observe(
    native: &mut ManagedInstance,
    workspace: &Path,
    listen: SocketAddrV4,
    sender: bool,
) -> Result<Value> {
    let local = native.client().instance().device_id.clone();
    let share = if sender {
        Some(native.client().generate_share().await?)
    } else {
        None
    };
    output(
        &json!({"event":"ready","device":local,"version":native.program_info().version,
        "read_only_share":share.as_ref().map(|value|value.read_only_key.expose_secret())}),
    )?;
    let path = workspace.join("peer-plan.json");
    let plan = tokio::time::timeout(Duration::from_secs(170), async {
        loop {
            if path.try_exists()? {
                return Ok::<_, Box<dyn std::error::Error>>(serde_json::from_reader(
                    fs::File::open(&path)?,
                )?);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await??;
    let plan: PeerPlan = plan;
    assert_ne!(plan.peer, local);
    let client = native.client();
    let isolated_network = NetworkPatch::default()
        .global_discovery(false)
        .local_discovery(false)
        .listen_addresses(vec![format!("tcp://{listen}")])
        .reconnection_interval_seconds(5);
    assert!(
        client
            .update_network_configuration(&isolated_network)
            .await?
            .requested_fields_match
    );
    let device = CreateDeviceOptions::new(plan.peer.clone()).settings(
        DevicePatch::default()
            .addresses(vec!["dynamic".into()])
            .allowed_transports(vec![DeviceTransport::Tcp])
            .paused(false),
    );
    assert!(client.create_device(&device).await?.requested_fields_match);
    let key = if let Some(generated) = share {
        generated.read_write_key
    } else {
        ShareKey::new(
            plan.read_only_share
                .ok_or("temporary receiver share required")?,
        )?
    };
    let target = workspace.join("sample");
    fs::create_dir(&target)?;
    if sender {
        fs::write(
            target.join("tracker-sample.bin"),
            b"isolated tracker pairing data".repeat(8192),
        )?;
    }
    let key = client.validate_share_key(&key).await?;
    let registered = client
        .join_folder(&JoinFolderOptions::new(key, TargetPath::local(&target)))
        .await?;
    client
        .share_folder_with(&registered.configuration.id, &plan.peer)
        .await?;
    let tracker = TransportPatch::default()
        .tracker(true)
        .nat_mapping(false)
        .udp(false)
        .relay_client(false)
        .tcp_punching(true)
        .stun_servers(Vec::new())
        .relay_addresses(Vec::new());
    assert!(
        client
            .update_transport_configuration(&tracker)
            .await?
            .requested_fields_match
    );
    let original_pid = native.process_id();
    native.restart(Duration::from_secs(19)).await?;
    assert_ne!(original_pid, native.process_id());
    assert_eq!(native.client().instance().device_id, local);
    let client = native.client();
    let after = client.transport_configuration().await?;
    assert!(
        after.tracker_enabled && !after.nat_enabled && !after.relays_enabled && !after.udp_enabled
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(50);
    let mut connected = false;
    let mut candidates = Vec::new();
    let mut authentic_peer = false;
    while tokio::time::Instant::now() < deadline {
        let state = client.transport_status().await?;
        connected |= state.tracker.connection_state == "connected"
            && state.tracker.extra.get("state").and_then(Value::as_str)
                == Some("state:synchronized")
            && state
                .tracker
                .extra
                .get("connectError")
                .and_then(Value::as_str)
                == Some("");
        let snapshot = client.connections().await?;
        authentic_peer |= snapshot
            .connections
            .get(&plan.peer)
            .is_some_and(|peer| peer.connected);
        if let Ok(cache) = client.discovery_cache().await {
            if let Some(record) = cache.get(plan.peer.as_str()) {
                for value in &record.addresses {
                    if !candidates.contains(value) && candidates.len() < 8 {
                        candidates.push(value.clone());
                    }
                }
            }
        }
        if connected && !candidates.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(450)).await;
    }
    let disabled = TransportPatch::default().tracker(false).tcp_punching(false);
    assert!(
        client
            .update_transport_configuration(&disabled)
            .await?
            .requested_fields_match
    );
    Ok(
        json!({"event":"result","native_version":native.program_info().version,
              "tracker_registered":connected,"dynamic_target_configured":true,
              "reported_candidates":candidates,"actual_peer_connection":authentic_peer,
              "native_mapping_disabled":true,"tracker_turned_off":true,
              "isolated_identity_preserved":true}),
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let [engine, digest, workspace, listener, mode] = args.as_slice() else {
        return Err(
            "provide fixed engine, hash, new root, dedicated IPv4 listener and role".into(),
        );
    };
    let workspace = PathBuf::from(workspace);
    let listen = listener.parse::<SocketAddrV4>()?;
    if !workspace.is_absolute()
        || workspace.exists()
        || listen.port() == 18886
        || listen.port() < 1024
        || (mode != "sender" && mode != "receiver")
    {
        return Err("fresh private scope required".into());
    }
    fs::create_dir(&workspace)?;
    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let gui = reservation.local_addr()?.port();
    if gui == 18886 || gui == listen.port() {
        return Err("reserved management socket".into());
    }
    let program = LocalProgram::new(engine)?.expected_sha256(hash(digest)?);
    let endpoint = ManagementEndpoint::http(&format!("http://127.0.0.1:{gui}"))?;
    let settings = ManagedOptions::new(program, workspace.join("state"), endpoint)?
        .startup_timeout(Duration::from_secs(15))?;
    drop(reservation);
    let mut native = ManagedInstance::start(settings).await?;
    let result = observe(&mut native, &workspace, listen, mode == "sender").await;
    let exit = native.shutdown(Duration::from_secs(17)).await?;
    assert!(
        exit.code == Some(0)
            && exit.signal.is_none()
            && !exit.forced
            && exit.tree_stopped
            && exit.state_released
    );
    let mut result = result?;
    result["normal_exit"] = json!(true);
    output(&result)
}
