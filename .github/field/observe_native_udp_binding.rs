//! Exercise the exact VerySync v2.33.2 STUN initiation conditions on loopback.
use serde_json::json;
use std::{
    env,
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    path::PathBuf,
    time::Duration,
};
use verysync_sidecar::{
    LocalProgram, ManagedInstance, ManagedOptions, ManagementEndpoint, NetworkPatch, TransportPatch,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn digest(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("explicit image digest required".into());
    }
    let mut value = [0; 32];
    for (index, byte) in value.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * index..2 * index + 2], 16)?;
    }
    Ok(value)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let [engine, sha, root, server, port, mode] = args.as_slice() else {
        return Err("explicit engine, hash, state and loopback fixture required".into());
    };
    let server = server.parse::<SocketAddrV4>()?;
    let port = port.parse::<u16>()?;
    let nat = true;
    if mode != "public-stun-only"
        || server.ip().is_loopback()
        || server.port() != 3478
        || port <= 1024
        || port == 18886
        || port == server.port()
    {
        return Err("invalid bounded public STUN qualification parameters".into());
    }
    let root = PathBuf::from(root);
    if !root.is_absolute() || root.exists() {
        return Err("new private runtime path required".into());
    }
    let program = LocalProgram::new(engine)?.expected_sha256(digest(sha)?);
    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port_number = reservation.local_addr()?.port();
    if port_number == 18886 {
        return Err("reserved management port".into());
    }
    let endpoint = ManagementEndpoint::http(&format!("http://127.0.0.1:{port_number}"))?;
    let options =
        ManagedOptions::new(program, root, endpoint)?.startup_timeout(Duration::from_secs(15))?;
    drop(reservation);
    let mut core = ManagedInstance::start(options).await?;
    let observed = async {
        assert_eq!(core.program_info().version, "v2.33.2");
        let original = core.client().system_status().await?.device_id;
        let network = NetworkPatch::default()
            .listen_addresses(Vec::new())
            .global_discovery(false)
            .local_discovery(false);
        assert!(core.client().update_network_configuration(&network).await?.requested_fields_match);
        let transport = TransportPatch::default()
            .tracker(false).udp(true).udp_port(port).nat_mapping(nat)
            .relay_client(false).tcp_punching(false)
            .relay_addresses(Vec::new()).stun_servers(vec![server.to_string()]);
        assert!(core.client().update_transport_configuration(&transport).await?.requested_fields_match);
        core.restart(Duration::from_secs(17)).await?;
        assert_eq!(core.client().system_status().await?.device_id, original);
        let settings = core.client().transport_configuration().await?;
        assert_eq!(settings.stun_servers, [server.to_string()]);
        assert!(settings.udp_enabled && !settings.tracker_enabled && !settings.relays_enabled);
        assert_eq!(settings.nat_enabled, nat);
        let start = core.client().transport_status().await?.nat_type;
        tokio::time::sleep(Duration::from_secs(23)).await;
        let end = core.client().transport_status().await?.nat_type;
        let listeners = core.client().listener_status().await?;
        let candidates = listeners.values().flat_map(|listener| {
            listener.wan_addresses.iter()
        }).collect::<Vec<_>>();
        Ok::<_, Box<dyn std::error::Error>>(json!({
            "native_version":"v2.33.2","nat_flag":nat,"exact_private_stun_settings_observed":true,
            "restart_identity_preserved":true,"reported_addresses":candidates,"initial_native_nat_type":start,"final_native_nat_type":end
        }))
    }.await;
    let exit = core.shutdown(Duration::from_secs(17)).await?;
    assert!(
        exit.code == Some(0)
            && exit.signal.is_none()
            && exit.tree_stopped
            && exit.state_released
            && !exit.forced
    );
    let mut report = observed?;
    report["native_exit"] = json!(true);
    println!("{report}");
    Ok(())
}
