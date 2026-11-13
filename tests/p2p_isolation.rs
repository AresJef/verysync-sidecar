//! Actual auxiliary listener isolation, independently observed without connecting.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::{process::Command, time::Duration};
use verysync_sidecar::{ManagedInstance, RawMethod, RawRequest, RequestEffect};

async fn listeners() -> TestResult<serde_json::Value> {
    let output = tokio::task::spawn_blocking(|| {
        Command::new(if cfg!(windows) { "python" } else { "python3" })
            .args(["scripts/prepare-test-engine.py", "list-owned-listeners"])
            .output()
    })
    .await??;
    assert!(
        output.status.success(),
        "exact owned listener observation failed"
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[tokio::test]
async fn fresh_core_uses_independent_tunnel_address_and_only_owned_loopback_listeners() -> TestResult
{
    let root = tempfile::Builder::new().prefix("vsi-").tempdir()?.keep();
    let mut instance = ManagedInstance::start(options(&root.join("state"))?).await?;
    let response = instance
        .client()
        .raw_request(&RawRequest::new(
            RawMethod::Get,
            ["rest", "config"],
            RequestEffect::ReadOnly,
        )?)
        .await?;
    let config: serde_json::Value = serde_json::from_slice(response.body_bytes())?;
    assert_eq!(config["options"]["localTunnelAddress"], "127.0.0.1:0");
    let expected = if cfg!(windows) { 3 } else { 2 };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let observed = loop {
        let value = listeners().await?;
        let listeners = value["tcp_listeners"]
            .as_array()
            .ok_or("owned listener snapshot missing")?;
        assert!(listeners.iter().all(|s| s["address"] == "127.0.0.1"
            && s["port"]
                .as_u64()
                .is_some_and(|port| port > 0 && port != 18886)));
        if listeners.len() >= expected {
            break value;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("independent auxiliary listener not observed".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(!observed["pids"]
        .as_array()
        .ok_or("owned PID snapshot missing")?
        .is_empty());
    let identity = instance.client().instance().device_id.clone();
    let reserved = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let address = reserved.local_addr()?;
    assert_ne!(address.port(), 18886);
    drop(reserved);
    let response = instance
        .client()
        .raw_request(
            &RawRequest::new(
                RawMethod::Patch,
                ["rest", "config", "options"],
                RequestEffect::MayModify,
            )?
            .json_body(&serde_json::json!({"localTunnelAddress":address.to_string()}))?,
        )
        .await?;
    assert!((200..300).contains(&response.status()));
    instance.restart(Duration::from_secs(30)).await?;
    assert_eq!(instance.client().instance().device_id, identity);
    let response = instance
        .client()
        .raw_request(&RawRequest::new(
            RawMethod::Get,
            ["rest", "config"],
            RequestEffect::ReadOnly,
        )?)
        .await?;
    let config: serde_json::Value = serde_json::from_slice(response.body_bytes())?;
    assert_eq!(config["options"]["localTunnelAddress"], address.to_string());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = listeners().await?;
        let sockets = snapshot["tcp_listeners"]
            .as_array()
            .ok_or("owned listeners missing")?;
        if sockets
            .iter()
            .any(|s| s["address"] == "127.0.0.1" && s["port"] == address.port())
        {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("exact independently selected auxiliary listener not observed".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let exit = instance.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    println!(
        "public independent listener evidence: {}",
        serde_json::json!({"baseline_numeric_field_verified_by_actual_json":true,"explicit_ephemeral_auxiliary_address":true,"actual_owned_auxiliary_listener_observed":true,"only_loopback_owned_ipv4_tcp_listeners":true,"shared_18886_not_used":true,"passive_observation_no_probe_connections":true,"explicit_known_auxiliary_port_bound":true,"existing_address_retained_across_restart":true,"same_identity_restarted":true,"actual_normal_tree_exit":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
