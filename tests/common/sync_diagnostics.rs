//! Failure-only private peer/core observations with no raw sensitive output.
use serde_json::json;
use verysync_sidecar::{FolderId, ManagedInstance};
fn private_tcp_endpoint(value: &str) -> Option<std::net::SocketAddr> {
    let endpoint: std::net::SocketAddr = value.strip_prefix("tcp://")?.parse().ok()?;
    (endpoint.ip().is_loopback() && endpoint.port() != 0 && endpoint.port() != 18886)
        .then_some(endpoint)
}
// Failure-only bounded diagnostics; no identity/address/path/log content is printed.
// Original observation deadlines, workload and frozen rate windows stay unchanged.
pub async fn report(
    stage: &str,
    cores: &[(&ManagedInstance, &FolderId, &verysync_sidecar::DeviceId)],
) {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};
    for (role, (core, folder, peer)) in cores.iter().enumerate() {
        let status = core.client().folder_status(folder).await;
        let connections = core.client().connections().await;
        let live = connections
            .as_ref()
            .ok()
            .and_then(|c| c.connections.get(peer));
        let config = core.client().folder(folder).await;
        let configured_peer = core.client().device(peer).await;
        let peer_core = cores
            .iter()
            .find(|(candidate, _, _)| &candidate.client().instance().device_id == *peer)
            .map(|(candidate, _, _)| *candidate);
        let peer_listeners = if let Some(peer_core) = peer_core {
            peer_core
                .client()
                .listener_status()
                .await
                .ok()
                .map(|statuses| {
                    statuses
                        .into_values()
                        .flat_map(|status| status.lan_addresses)
                        .filter_map(|address| private_tcp_endpoint(&address))
                        .collect::<std::collections::BTreeSet<_>>()
                })
        } else {
            None
        };
        let address_matches_live_listener = configured_peer
            .as_ref()
            .ok()
            .zip(peer_listeners.as_ref())
            .map(|(configured, current)| {
                configured
                    .addresses
                    .iter()
                    .filter_map(|address| private_tcp_endpoint(address))
                    .any(|address| current.contains(&address))
            });
        let log = (|| -> std::io::Result<Vec<u8>> {
            let mut file =
                std::fs::File::open(core.state_directory().join(".verysync-sidecar-core.log"))?;
            let length = file.metadata()?.len();
            file.seek(SeekFrom::Start(length.saturating_sub(65536)))?;
            let mut bytes = Vec::new();
            file.take(65536).read_to_end(&mut bytes)?;
            Ok(bytes)
        })();
        let tail = log.as_ref().ok().map(|b| String::from_utf8_lossy(b));
        let hits = |needle: &str| tail.as_ref().map(|t| t.matches(needle).count());
        let value = status.as_ref().ok();
        eprintln!(
            "private sync preparation diagnostic: {}",
            json!({
                "stage":stage,"role":role,"folder_status_available":status.is_ok(),"connections_available":connections.is_ok(),
                "state":value.and_then(|s|s.state.as_ref()).map(|s|s.as_str()),
                "local_files":value.and_then(|s|s.local_files),"global_files":value.and_then(|s|s.global_files),
                "need_files":value.and_then(|s|s.need_files),"need_bytes":value.and_then(|s|s.need_bytes),
                "pull_errors":value.and_then(|s|s.pull_errors),"configured_paused":config.as_ref().ok().map(|c|c.paused),
                "configured_private_peer_present":config.as_ref().ok().and_then(|c|c.extra.get("devices")).and_then(serde_json::Value::as_array).map(|items| items.iter().any(|d|d.get("deviceID").and_then(serde_json::Value::as_str)==Some(peer.as_str()))),
                "peer_record_present":live.is_some(),"peer_connected":live.map(|p|p.connected),
                "peer_paused":live.and_then(|p|p.paused),"peer_in_bytes":live.and_then(|p|p.in_bytes_total),
                "peer_out_bytes":live.and_then(|p|p.out_bytes_total),
                "configured_peer_address_count":configured_peer.as_ref().ok().map(|peer|peer.addresses.len()),
                "remote_live_private_tcp_count":peer_listeners.as_ref().map(|addresses|addresses.len()),
                "configured_peer_address_matches_live_listener":address_matches_live_listener,
                "core_log_tail_bytes":log.as_ref().ok().map(Vec::len),
                "core_log_tail_sha256":log.as_ref().ok().map(|b|format!("{:x}",Sha256::digest(b))),
                "panic_lines":hits("panic:"),"runtime_error_lines":hits("runtime error:"),
                "folder_not_running_lines":hits("folder is not running"),
                "connection_replacing_lines":hits("Replacing"),"scan_complete_lines":hits("Completed initial scan"),
                "connection_refused_lines":hits("connection refused"),"connection_closed_lines":hits("closed"),
                "tls_handshake_lines":hits("TLS handshake"),"unknown_device_lines":hits("unknown device")
            })
        );
    }
}
