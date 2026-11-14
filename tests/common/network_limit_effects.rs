//! Actual connection count under a typed maximum, separate from receipts.
use super::*;
use verysync_sidecar::DeviceAdvancedPatch;

async fn connected_count(client: &Client, peers: &[&DeviceId]) -> TestResult<usize> {
    let snapshot = client.connections().await?;
    Ok(peers
        .iter()
        .filter(|id| snapshot.connections.get(*id).is_some_and(|p| p.connected))
        .count())
}

#[tokio::test]
async fn actual_maximum_connection_cap_and_explicit_zero_restoration() -> TestResult {
    let root = tempfile::Builder::new().prefix("vsmax-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let mut c = ManagedInstance::start(options(&root.join("c"))?).await?;
    let aid = a.client().instance().device_id.clone();
    let bid = b.client().instance().device_id.clone();
    let cid = c.client().instance().device_id.clone();
    let original = b.client().network_configuration().await?;
    assert_eq!(original.connection_limit_enough, Some(0));
    let mut unrelated_before =
        b.client().configuration().await?.native_document()["options"].clone();
    unrelated_before
        .as_object_mut()
        .ok_or("options missing")?
        .remove("connectionLimitMax");
    let update = b
        .client()
        .update_network_configuration(&NetworkPatch::default().connection_limit_max(1))
        .await?;
    assert!(update.requested_fields_match);
    assert_eq!(update.configuration.connection_limit_max, Some(1));
    let mut unrelated_after =
        b.client().configuration().await?.native_document()["options"].clone();
    unrelated_after
        .as_object_mut()
        .ok_or("options missing")?
        .remove("connectionLimitMax");
    assert_eq!(unrelated_before, unrelated_after);
    let target = listener(b.client(), None).await?;
    for (client, id, addresses) in [
        (b.client(), aid.clone(), vec!["dynamic".into()]),
        (b.client(), cid.clone(), vec!["dynamic".into()]),
        (a.client(), bid.clone(), vec![target.clone()]),
        (c.client(), bid.clone(), vec![target]),
    ] {
        client
            .update_network_configuration(&NetworkPatch::default().reconnection_interval_seconds(5))
            .await?;
        let device = client
            .create_device(
                &CreateDeviceOptions::new(id).settings(
                    DevicePatch::default()
                        .addresses(addresses)
                        .allowed_transports(vec![DeviceTransport::Tcp])
                        .paused(false)
                        .advanced_configuration(
                            DeviceAdvancedPatch::default().num_connections(1),
                        )?,
                ),
            )
            .await?;
        assert_eq!(
            device
                .configuration
                .advanced_configuration()?
                .num_connections,
            Some(1)
        );
    }
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if connected_count(b.client(), &[&aid, &cid]).await? > 0 {
                break Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let began = std::time::Instant::now();
    let mut samples = 0;
    while began.elapsed() < Duration::from_secs(12) {
        assert_eq!(connected_count(b.client(), &[&aid, &cid]).await?, 1);
        samples += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        b.client()
            .update_network_configuration(&NetworkPatch::default().connection_limit_max(0))
            .await?
            .requested_fields_match
    );
    connection(b.client(), &aid, true).await?;
    connection(b.client(), &cid, true).await?;
    assert_eq!(connected_count(b.client(), &[&aid, &cid]).await?, 2);
    assert!(
        b.client()
            .update_network_configuration(&NetworkPatch::default().connection_limit_max(2))
            .await?
            .requested_fields_match
    );
    for (client, id) in [
        (a.client(), &bid),
        (c.client(), &bid),
        (b.client(), &aid),
        (b.client(), &cid),
    ] {
        client.pause_device(id).await?;
    }
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let count = connected_count(a.client(), &[&bid]).await?
                + connected_count(c.client(), &[&bid]).await?
                + connected_count(b.client(), &[&aid, &cid]).await?;
            if count == 0 {
                break Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    b.restart(Duration::from_secs(30)).await?;
    assert_eq!(b.client().instance().device_id, bid);
    assert_eq!(
        b.client()
            .network_configuration()
            .await?
            .connection_limit_max,
        Some(2)
    );
    assert!(
        b.client()
            .update_network_configuration(
                &NetworkPatch::default()
                    .connection_limit_max(
                        original
                            .connection_limit_max
                            .ok_or("original maximum absent")?
                    )
                    .reconnection_interval_seconds(original.reconnection_interval_seconds)
            )
            .await?
            .requested_fields_match
    );
    for core in [&mut a, &mut c, &mut b] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!(
        "public maximum connection limit evidence: {}",
        json!({
            "typed_max_one_receipt":true,"other_options_unchanged":true,
            "single_connection_per_device_pair_selected":true,"twelve_seconds_maximum_one_peer":true,
            "observed_samples":samples,"typed_zero_allows_both_real_incoming_peers":true,
            "typed_max_two_persists_same_identity_restart":true,"original_settings_restored":true,
            "explicit_pause_actual_disconnection_before_cleanup":true,"all_three_normal_tree_exits":true,
            "outgoing_enough_threshold_acceptance":false
        })
    );
    Ok(())
}
