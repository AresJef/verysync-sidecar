//! One native tunnel probe with explicit auxiliary ports on an isolated CI VM.
use super::*;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};

fn reserve() -> TestResult<TcpListener> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    assert_ne!(listener.local_addr()?.port(), 18886);
    Ok(listener)
}

async fn owned_auxiliary_listeners(addresses: &[SocketAddr]) -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let output = tokio::task::spawn_blocking(|| {
                std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
                    .args(["scripts/prepare-test-engine.py", "list-owned-listeners"])
                    .output()
            })
            .await??;
            assert!(
                output.status.success(),
                "passive owned listener inventory failed"
            );
            let snapshot: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            let listeners = snapshot["tcp_listeners"]
                .as_array()
                .ok_or("owned listeners missing")?;
            if addresses.iter().all(|address| {
                listeners
                    .iter()
                    .any(|s| s["address"] == "127.0.0.1" && s["port"] == address.port())
            }) {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    Ok(())
}

async fn select_auxiliary(core: &mut ManagedInstance, address: SocketAddr) -> TestResult {
    let response = core
        .client()
        .raw_request(
            &RawRequest::new(
                RawMethod::Patch,
                ["rest", "config", "options"],
                RequestEffect::MayModify,
            )?
            .json_body(&serde_json::json!({"localTunnelAddress": address.to_string()}))?,
        )
        .await?;
    assert!((200..300).contains(&response.status()));
    let identity = core.client().instance().device_id.clone();
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(core.client().instance().device_id, identity);
    let response = core
        .client()
        .raw_request(&RawRequest::new(
            RawMethod::Get,
            ["rest", "config"],
            RequestEffect::ReadOnly,
        )?)
        .await?;
    let config: serde_json::Value = serde_json::from_slice(response.body_bytes())?;
    assert_eq!(config["options"]["localTunnelAddress"], address.to_string());
    private_redial::configure(core.client()).await?;
    Ok(())
}

async fn peer_address(client: &Client) -> TestResult<String> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for status in client.listener_status().await?.into_values() {
                for address in status.lan_addresses {
                    if address
                        .strip_prefix("tcp://")
                        .and_then(|s| s.parse::<SocketAddr>().ok())
                        .is_some_and(|a| {
                            a.ip() == Ipv4Addr::LOCALHOST && a.port() > 0 && a.port() != 18886
                        })
                    {
                        return Ok::<_, Error>(address);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??)
}

#[tokio::test]
async fn native_tunnel_probe_uses_explicit_nondefault_auxiliary_ports() -> TestResult {
    // Run native peer-side dial behavior only on a disposable CI VM. This
    // guard precedes program selection, state creation and every core start.
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("VERYSYNC_TEST_EXPLICIT_TUNNEL").as_deref()
            != Ok("github-actions-isolated-vm")
    {
        return Err("explicit tunnel probe requires an opted-in isolated CI VM".into());
    }
    let root = tempfile::Builder::new()
        .prefix("vs-explicit-tunnel-")
        .tempdir()?
        .keep();
    let sentinel = root.join("sentinel.bin");
    let bytes = b"explicit native probe preserves independent caller bytes";
    std::fs::write(&sentinel, bytes)?;
    // Reserve all three selected endpoints together to prevent duplicate ports.
    let gui = reserve()?;
    let a_aux = reserve()?;
    let b_aux = reserve()?;
    let gui_address = gui.local_addr()?;
    let a_address = a_aux.local_addr()?;
    let b_address = b_aux.local_addr()?;
    let a_options = options(&root.join("a"))?;
    let selected = options(&root.join("b"))?;
    let b_options = ManagedOptions::new(
        selected.program().clone(),
        selected.state_directory(),
        ManagementEndpoint::http(&format!("http://{gui_address}/"))?,
    )?
    .startup_timeout(Duration::from_secs(25))?;
    drop(gui);
    let mut a = ManagedInstance::start(a_options).await?;
    let mut b = ManagedInstance::start(b_options).await?;
    drop(a_aux);
    select_auxiliary(&mut a, a_address).await?;
    drop(b_aux);
    select_auxiliary(&mut b, b_address).await?;
    owned_auxiliary_listeners(&[a_address, b_address]).await?;
    let aid = a.client().instance().device_id.clone();
    let bid = b.client().instance().device_id.clone();
    let address = peer_address(b.client()).await?;
    for (client, peer, addresses) in [
        (a.client(), &bid, vec![address]),
        (b.client(), &aid, vec!["dynamic".to_owned()]),
    ] {
        let patch = DevicePatch::default()
            .addresses(addresses)
            .paused(false)
            .allow_tunnel(false)
            .remote_gui_port(gui_address.port())?;
        assert!(
            client
                .create_device(&CreateDeviceOptions::new(peer.clone()).settings(patch))
                .await?
                .requested_fields_match
        );
    }
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let (left, right) = tokio::join!(a.client().connections(), b.client().connections());
            if left?.connections.get(&bid).is_some_and(|p| p.connected)
                && right?.connections.get(&aid).is_some_and(|p| p.connected)
            {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    let denied = a.client().probe_device_tunnel(&bid).await?;
    assert!(!denied.tunnel_available());
    assert_eq!(denied.native_error(), Some("no authorization"));
    for (client, peer) in [(a.client(), &bid), (b.client(), &aid)] {
        assert!(
            client
                .update_device(peer, &DevicePatch::default().allow_tunnel(true))
                .await?
                .requested_fields_match
        );
    }
    let actual = a.client().probe_device_tunnel(&bid).await?;
    assert_eq!(actual.device_id(), &bid);
    println!(
        "explicit_native_tunnel_probe={}",
        serde_json::json!({
            "explicit_nondefault_auxiliary_addresses": true,
            "real_private_peers_connected": true,
            "denied_before_grant": true,
            "tunnel_available": actual.tunnel_available(),
            "native_error": actual.native_error(),
            "licensed_gateway_session_attempted": false,
        })
    );
    assert!(a.client().license_status().await?.licenses().is_none());
    assert_eq!(std::fs::read(&sentinel)?, bytes);
    for core in [&mut b, &mut a] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    // Keep a negative native observation as a failing positive requirement;
    // accepting any returned snapshot would conceal the remaining N-P gap.
    assert!(
        actual.tunnel_available(),
        "native explicit-port probe failed: {:?}",
        actual.native_error()
    );
    assert!(actual.native_error().is_none_or(str::is_empty));
    println!("explicit_native_tunnel_probe_positive=true normal_owned_exits=2");
    std::fs::remove_dir_all(root)?;
    Ok(())
}
