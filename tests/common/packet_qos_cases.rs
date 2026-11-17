//! A separate privileged observer sees only the owned native peer's TCP headers.
use super::managed_fixture::{options, TestResult};
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;
use verysync_sidecar::*;

struct Capture {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
}
impl Capture {
    fn start(port: u16) -> TestResult<Self> {
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(
            std::env::var("VERYSYNC_TEST_ALLOW_PACKET_CAPTURE").as_deref(),
            Ok("github-actions-owned-loopback-headers")
        );
        let python =
            std::env::var_os("VERYSYNC_TEST_PACKET_PYTHON").ok_or("explicit CI Python required")?;
        assert!(Path::new(&python).is_absolute());
        let mut child = Command::new("/usr/bin/sudo")
            .args(["-n", "--preserve-env=GITHUB_ACTIONS", "--"])
            .arg(python)
            .arg("-B")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/observe-owned-tcp-qos.py"))
            .arg("--port")
            .arg(port.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child.stdin.take();
        let output = BufReader::new(child.stdout.take().ok_or("capture stdout absent")?);
        let mut capture = Self {
            child,
            input,
            output,
        };
        let ready = capture.read()?;
        assert_eq!(ready["ready"], true);
        assert_eq!(ready["port"], port);
        assert_eq!(ready["loopback_only"], true);
        Ok(capture)
    }
    fn read(&mut self) -> TestResult<serde_json::Value> {
        let mut line = String::new();
        if self.output.read_line(&mut line)? == 0 || line.len() > 1_048_576 {
            return Err("owned packet observer response missing or oversized".into());
        }
        Ok(serde_json::from_str(&line)?)
    }
    fn finish(mut self) -> TestResult<serde_json::Value> {
        self.input.take();
        let result = self.read()?;
        assert!(self.child.wait()?.success());
        assert_eq!(result["normal_capture_exit"], true);
        Ok(result)
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        // EOF releases this observer and its exact child, even on test failure.
        // The helper's original 30s bound and 5s cleanup remain independent.
        self.input.take();
        let _ = self.child.wait();
    }
}

async fn listener(core: &ManagedInstance) -> TestResult<SocketAddr> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for status in core.client().listener_status().await?.into_values() {
                for value in status.lan_addresses {
                    if let Some(address) = value
                        .strip_prefix("tcp://")
                        .and_then(|v| v.parse::<SocketAddr>().ok())
                        .filter(|v| v.ip() == Ipv4Addr::LOCALHOST && !matches!(v.port(), 0 | 18886))
                    {
                        return Ok::<_, Error>(address);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await?
    .map_err(Into::into)
}

#[tokio::test]
async fn native_packet_class_marks_owned_tcp_data_and_retains_real_files() -> TestResult {
    assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
    let uid = Command::new("/usr/bin/id").arg("-u").output()?;
    assert!(uid.status.success());
    assert_ne!(
        std::str::from_utf8(&uid.stdout)?.trim(),
        "0",
        "the native case must remain unelevated"
    );
    let root = tempfile::Builder::new().prefix("vsqos-").tempdir()?.keep();
    let sentinel = root.join("caller-sentinel");
    std::fs::write(&sentinel, b"caller packet-policy bytes")?;
    for (phase, selected) in [16, 32, 0].into_iter().enumerate() {
        let case = root.join(phase.to_string());
        let source = case.join("source");
        let received = case.join("received");
        std::fs::create_dir_all(&source)?;
        let name = "synthetic-packet-policy.bin";
        let bytes: Vec<u8> = (0..32768).map(|n| ((n * 73 + phase) % 251) as u8).collect();
        std::fs::write(source.join(name), &bytes)?;
        let mut a = ManagedInstance::start(options(&case.join("a"))?).await?;
        let mut b = ManagedInstance::start(options(&case.join("b"))?).await?;
        let aid = a.client().instance().device_id.clone();
        let bid = b.client().instance().device_id.clone();
        for client in [a.client(), b.client()] {
            client
                .update_network_configuration(
                    &NetworkPatch::default().reconnection_interval_seconds(5),
                )
                .await?;
            client
                .update_general_options(
                    &GeneralOptionsPatch::default().disable_system_sleep_on_sync(false),
                )
                .await?;
        }
        let before = a.client().configuration().await?;
        let before_b = b.client().configuration().await?;
        let credentials: Vec<_> = ["key.pem", "cert.pem"]
            .iter()
            .map(|n| std::fs::read(a.state_directory().join(n)))
            .collect::<std::io::Result<_>>()?;
        let credentials_b: Vec<_> = ["key.pem", "cert.pem"]
            .iter()
            .map(|n| std::fs::read(b.state_directory().join(n)))
            .collect::<std::io::Result<_>>()?;
        assert!(
            a.client()
                .update_general_options(&GeneralOptionsPatch::default().traffic_class(selected))
                .await?
                .requested_fields_match
        );
        a.restart(Duration::from_secs(30)).await?;
        assert_eq!(
            a.client().general_options().await?.traffic_class,
            Some(selected)
        );
        assert_eq!(a.client().instance().device_id, aid);
        let address = listener(&b).await?;
        let capture = Capture::start(address.port())?;
        for (client, peer, addresses) in [
            (a.client(), &bid, vec![format!("tcp://{address}")]),
            (b.client(), &aid, vec!["dynamic".into()]),
        ] {
            client
                .create_device(
                    &CreateDeviceOptions::new(peer.clone()).settings(
                        DevicePatch::default()
                            .addresses(addresses)
                            .compression(DeviceCompression::Never)
                            .allowed_transports(vec![DeviceTransport::Tcp])
                            .advanced_configuration(
                                DeviceAdvancedPatch::default().num_connections(1),
                            )?,
                    ),
                )
                .await?;
        }
        let keys = a.client().generate_share().await?;
        let rw = a.client().validate_share_key(&keys.read_write_key).await?;
        let ro = b.client().validate_share_key(&keys.read_only_key).await?;
        let af = a
            .client()
            .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&source)).paused(true))
            .await?;
        let bf = b
            .client()
            .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(&received)).paused(true))
            .await?;
        a.client()
            .share_folder_with(&af.configuration.id, &bid)
            .await?;
        b.client()
            .share_folder_with(&bf.configuration.id, &aid)
            .await?;
        a.client().resume_folder(&af.configuration.id).await?;
        b.client().resume_folder(&bf.configuration.id).await?;
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if received.join(name).is_file()
                    && std::fs::read(received.join(name))? == bytes
                    && b.client().folder_status(&bf.configuration.id).await?.state
                        == Some(FolderState::Idle)
                {
                    return TestResult::Ok(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await??;
        let connections = b.client().connections().await?;
        let peer = connections
            .connections
            .get(&aid)
            .ok_or("authenticated source peer absent")?;
        assert!(peer.connected);
        let actual_source: SocketAddr = peer
            .address
            .as_deref()
            .ok_or("native source address absent")?
            .parse()?;
        assert_eq!(actual_source.ip(), Ipv4Addr::LOCALHOST);
        let observation = capture.finish()?;
        let packets: Vec<_> = observation["packets"]
            .as_array()
            .ok_or("owned packets absent")?
            .iter()
            .filter(|p| p["source_port"].as_u64() == Some(u64::from(actual_source.port())))
            .collect();
        assert!(
            !packets.is_empty(),
            "real authenticated source TCP data headers required"
        );
        assert!(packets.iter().any(|p| p["tos"]
            .as_u64()
            .is_some_and(|v| v & 0xfc == selected as u64)));
        let observed_dscp: std::collections::BTreeSet<_> = packets
            .iter()
            .filter_map(|p| p["tos"].as_u64().map(|v| v & 0xfc))
            .collect();
        if selected == 0 {
            assert!(packets
                .iter()
                .all(|p| p["tos"].as_u64().is_some_and(|v| v & 0xfc == 0)));
        }
        assert_eq!(std::fs::read(source.join(name))?, bytes);
        assert_eq!(std::fs::read(received.join(name))?, bytes);
        let after = a.client().configuration().await?;
        let after_b = b.client().configuration().await?;
        for section in ["gui", "defaults", "ldap", "relayServer"] {
            assert_eq!(
                before.native_document()[section],
                after.native_document()[section]
            );
            assert_eq!(
                before_b.native_document()[section],
                after_b.native_document()[section]
            );
        }
        for (name, bytes) in ["key.pem", "cert.pem"].iter().zip(credentials) {
            assert_eq!(std::fs::read(a.state_directory().join(name))?, bytes);
        }
        for (name, bytes) in ["key.pem", "cert.pem"].iter().zip(credentials_b) {
            assert_eq!(std::fs::read(b.state_directory().join(name))?, bytes);
        }
        assert_eq!(a.client().system_status().await?.device_id, aid);
        assert_eq!(b.client().system_status().await?.device_id, bid);
        for core in [&mut a, &mut b] {
            let exit = core.shutdown(Duration::from_secs(10)).await?;
            assert!(
                exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0)
            );
        }
        println!(
            "native packet-class evidence: {}",
            serde_json::json!({"selected":selected,
            "actual_observed_dscp_octets":observed_dscp,
            "actual_authenticated_source_port":actual_source.port(),
            "actual_authenticated_source_port_bound_tcp_data_headers":packets.len(),
            "actual_selected_dscp_observed":true,"actual_new_file_transfer_and_both_bytes_retained":true,
            "actual_normal_restart_retained_policy_and_identity":true,"actual_both_normal_owned_tree_and_state_exit":true,
            "observer_elevated_only":true,"ipv6_router_qos_or_throughput_claimed":false})
        );
    }
    assert_eq!(std::fs::read(&sentinel)?, b"caller packet-policy bytes");
    std::fs::remove_dir_all(root)?;
    Ok(())
}
