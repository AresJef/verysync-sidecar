//! Observe native device and folder associations introduced by a trusted peer.
use super::{associate, connected, options, private_tcp, received, TestResult};
use std::{fs, path::PathBuf, time::Duration};
use verysync_sidecar::{
    Client, DeviceAdvancedPatch, DeviceId, DevicePatch, DeviceTransport, FolderId,
    IntroductionSource, JoinFolderOptions, ManagedInstance, TargetPath,
};

async fn set_introducer(client: &Client, via: &DeviceId, trusted: bool, keep: bool) -> TestResult {
    let patch = DevicePatch::default().advanced_configuration(
        DeviceAdvancedPatch::default()
            .introducer(trusted)
            .skip_introduction_removals(keep),
    )?;
    let update = client.update_device(via, &patch).await?;
    assert!(update.requested_fields_match);
    let actual = update.configuration.advanced_configuration()?;
    assert_eq!(actual.introducer, Some(trusted));
    assert_eq!(actual.skip_introduction_removals, Some(keep));
    Ok(())
}

async fn wait_for_disconnect(links: &[(&Client, &DeviceId)]) -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut any_connected = false;
            for (client, peer) in links {
                any_connected |= client
                    .connections()
                    .await?
                    .connections
                    .get(peer)
                    .is_some_and(|connection| connection.connected);
            }
            if !any_connected {
                return TestResult::Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?
}

async fn reconnect(client: &Client, via: &DeviceId) -> TestResult {
    assert!(client.pause_device(via).await?.configuration.paused);
    eprintln!("native introducer reconnect: waiting for paused peer disconnect");
    wait_for_disconnect(&[(client, via)]).await?;
    assert!(!client.resume_device(via).await?.configuration.paused);
    eprintln!("native introducer reconnect: waiting for resumed peer connection");
    connected(client, via).await?;
    Ok(())
}

async fn restart_receiver(
    receiver: &mut ManagedInstance,
    original_id: &DeviceId,
    via: &DeviceId,
) -> TestResult {
    receiver.restart(Duration::from_secs(20)).await?;
    assert_eq!(&receiver.client().instance().device_id, original_id);
    connected(receiver.client(), via).await?;
    Ok(())
}

async fn introduction(
    client: &Client,
    folder: &FolderId,
    via: &DeviceId,
    introduced: &DeviceId,
) -> TestResult<[bool; 3]> {
    let devices = client.devices().await?;
    let record = devices
        .iter()
        .find(|device| &device.device_id == introduced);
    let origin = record
        .map(|record| record.advanced_configuration())
        .transpose()?
        .and_then(|advanced| advanced.introduced_by);
    let folder = client.folder(folder).await?;
    let members = folder
        .extra
        .get("devices")
        .and_then(serde_json::Value::as_array)
        .ok_or("native folder association array missing")?;
    Ok([
        record.is_some(),
        origin == Some(IntroductionSource::Device(via.clone())),
        members
            .iter()
            .any(|entry| entry["deviceID"].as_str() == Some(introduced.as_str())),
    ])
}

#[tokio::test]
async fn native_trusted_introducer_adds_third_device_and_follows_withdrawal() -> TestResult {
    observe_introduction(false, false).await
}

#[tokio::test]
async fn native_trusted_introducer_retains_association_when_withdrawals_are_skipped() -> TestResult
{
    observe_introduction(true, false).await
}

#[tokio::test]
async fn native_introduced_peer_supplies_data_on_a_direct_connection() -> TestResult {
    observe_introduction(false, true).await
}

async fn observe_introduction(keep: bool, probe_direct_data: bool) -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-intro-")
        .tempdir()?
        .keep();
    let sentinel = root.join("caller-sentinel");
    fs::write(&sentinel, b"caller-owned data")?;
    eprintln!("native introducer setup: start three isolated instances");
    let mut receiver = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut introducer = ManagedInstance::start(options(&root.join("b"))?).await?;
    let mut third = ManagedInstance::start(options(&root.join("c"))?).await?;
    if probe_direct_data {
        // This controlled handoff requires a fresh connection within the
        // existing observation window. Keep the withdrawal fixtures on their
        // original scheduling.
        for node in [&receiver, &introducer, &third] {
            super::private_redial::configure(node.client()).await?;
        }
    }
    let receiver_id = receiver.client().instance().device_id.clone();
    let introducer_id = introducer.client().instance().device_id.clone();
    let third_id = third.client().instance().device_id.clone();
    assert_ne!(receiver_id, introducer_id);
    assert_ne!(receiver_id, third_id);
    assert_ne!(introducer_id, third_id);
    eprintln!("native introducer setup: observe all three loopback listeners");
    let receiver_address = private_tcp(receiver.client()).await?;
    let introducer_address = private_tcp(introducer.client()).await?;
    let third_address = private_tcp(third.client()).await?;
    let follow_withdrawal = !keep && !probe_direct_data;
    let key = introducer.client().generate_share().await?;
    let receiver_path = root.join("received");
    let source_path = root.join("source");
    let third_path = root.join("third");
    let mut folders = Vec::new();
    for (node, path) in [
        (&receiver, &receiver_path),
        (&introducer, &source_path),
        (&third, &third_path),
    ] {
        fs::create_dir(path)?;
        let code = node
            .client()
            .validate_share_key(&key.read_write_key)
            .await?;
        let joined = node
            .client()
            .join_folder(&JoinFolderOptions::new(code, TargetPath::local(path)).paused(true))
            .await?;
        folders.push(joined.configuration.id);
    }
    let [receiver_folder, source_folder, third_folder] = folders.as_slice() else {
        unreachable!("three owned folders are always registered");
    };
    for (node, directory, peer, endpoint) in [
        (
            &receiver,
            receiver_folder,
            &introducer_id,
            introducer_address.as_str(),
        ),
        (
            &introducer,
            source_folder,
            &receiver_id,
            receiver_address.as_str(),
        ),
        (
            &introducer,
            source_folder,
            &third_id,
            third_address.as_str(),
        ),
        (
            &third,
            third_folder,
            &introducer_id,
            introducer_address.as_str(),
        ),
    ] {
        associate(node.client(), directory, peer, endpoint, true).await?;
    }
    // Establish the withdrawal policy before the first direct peer session.
    set_introducer(receiver.client(), &introducer_id, false, keep).await?;
    let mut samples = vec![(
        PathBuf::from("baseline.bin"),
        b"introducer baseline bytes".repeat(2048),
    )];
    fs::write(source_path.join(&samples[0].0), &samples[0].1)?;
    for (node, directory) in [
        (&receiver, receiver_folder),
        (&introducer, source_folder),
        (&third, third_folder),
    ] {
        node.client().resume_folder(directory).await?;
    }
    for (node, peer) in [
        (&receiver, &introducer_id),
        (&introducer, &receiver_id),
        (&introducer, &third_id),
        (&third, &introducer_id),
    ] {
        assert!(
            !node
                .client()
                .resume_device(peer)
                .await?
                .configuration
                .paused
        );
    }
    eprintln!("native introducer setup: await receiver-to-introducer connection");
    connected(receiver.client(), &introducer_id).await?;
    eprintln!("native introducer setup: await third-to-introducer connection");
    connected(third.client(), &introducer_id).await?;
    eprintln!("native introducer setup: verify baseline files at both peers");
    received(
        "untrusted-introducer-baseline",
        receiver.client(),
        receiver_folder,
        &receiver_path,
        &samples,
    )
    .await?;
    received(
        "third-shares-from-introducer",
        third.client(),
        third_folder,
        &third_path,
        &samples,
    )
    .await?;
    let before = introduction(
        receiver.client(),
        receiver_folder,
        &introducer_id,
        &third_id,
    )
    .await?;

    set_introducer(receiver.client(), &introducer_id, true, keep).await?;
    reconnect(receiver.client(), &introducer_id).await?;
    samples.push((
        PathBuf::from("after-trust.bin"),
        b"introducer after trust bytes".repeat(2048),
    ));
    fs::write(source_path.join(&samples[1].0), &samples[1].1)?;
    received(
        "trusted-introducer-reconnect",
        receiver.client(),
        receiver_folder,
        &receiver_path,
        &samples,
    )
    .await?;
    let mut after = [false; 3];
    if let Ok(observed) = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            after = introduction(
                receiver.client(),
                receiver_folder,
                &introducer_id,
                &third_id,
            )
            .await?;
            if after == [true; 3] {
                return TestResult::Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    {
        observed?;
    }

    let mut withdrawal = None;
    let mut fresh_session_observed = false;
    let mut direct_data_observed = false;
    if after == [true; 3] && probe_direct_data {
        eprintln!("native introducer phase: prepare direct data path");
        received(
            "direct-case-third-baseline",
            third.client(),
            third_folder,
            &third_path,
            &samples,
        )
        .await?;
        if third
            .client()
            .devices()
            .await?
            .iter()
            .any(|peer| peer.device_id == receiver_id)
        {
            assert!(
                third
                    .client()
                    .share_folder_with(third_folder, &receiver_id)
                    .await?
                    .association_present
            );
            assert!(
                !third
                    .client()
                    .resume_device(&receiver_id)
                    .await?
                    .configuration
                    .paused
            );
        } else {
            associate(third.client(), third_folder, &receiver_id, "dynamic", false).await?;
        }
        let update = receiver
            .client()
            .update_device(
                &third_id,
                &DevicePatch::default()
                    .addresses(vec![third_address.clone()])
                    .allowed_transports(vec![DeviceTransport::Tcp])
                    .paused(false),
            )
            .await?;
        assert!(update.requested_fields_match);
        assert_eq!(
            introduction(
                receiver.client(),
                receiver_folder,
                &introducer_id,
                &third_id
            )
            .await?,
            [true; 3]
        );
        eprintln!("native introducer phase: observe receiver dialing the introduced peer");
        connected(receiver.client(), &third_id).await?;
        introducer.client().pause_folder(source_folder).await?;
        assert!(introducer.client().folder(source_folder).await?.paused);
        let direct = (
            PathBuf::from("introduced-peer-direct.bin"),
            b"direct data from owned introduced peer".repeat(2048),
        );
        fs::write(third_path.join(&direct.0), &direct.1)?;
        third
            .client()
            .request_scan_subpaths(third_folder, &[TargetPath::local(&direct.0)])
            .await?;
        let mut expected = samples.clone();
        expected.push(direct.clone());
        eprintln!("native introducer phase: receive the third peer's new file");
        received(
            "introduced-direct-data",
            receiver.client(),
            receiver_folder,
            &receiver_path,
            &expected,
        )
        .await?;
        assert!(!source_path.join(&direct.0).exists());
        assert_eq!(fs::read(third_path.join(&direct.0))?, direct.1);
        direct_data_observed = true;
    } else if after == [true; 3] {
        let change = introducer
            .client()
            .unshare_folder_from(source_folder, &third_id)
            .await?;
        assert!(!change.association_present);
        if keep {
            // Reopen the persisted receiver with the same identity and policy.
            eprintln!("native introducer phase: fresh receiver session after retained withdrawal");
            restart_receiver(&mut receiver, &receiver_id, &introducer_id).await?;
            let actual = receiver
                .client()
                .device(&introducer_id)
                .await?
                .advanced_configuration()?;
            assert_eq!(actual.introducer, Some(true));
            assert_eq!(actual.skip_introduction_removals, Some(true));
            let fresh = (
                PathBuf::from("withdrawal-confirmed.bin"),
                b"new native bytes after withdrawal".repeat(2048),
            );
            fs::write(source_path.join(&fresh.0), &fresh.1)?;
            introducer
                .client()
                .request_scan_subpaths(source_folder, &[TargetPath::local(&fresh.0)])
                .await?;
            samples.push(fresh);
            received(
                "fresh-introducer-after-withdrawal",
                receiver.client(),
                receiver_folder,
                &receiver_path,
                &samples,
            )
            .await?;
            fresh_session_observed = true;
        } else {
            reconnect(receiver.client(), &introducer_id).await?;
        }
        let mut prior = after;
        if let Ok(observed) = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                prior = introduction(
                    receiver.client(),
                    receiver_folder,
                    &introducer_id,
                    &third_id,
                )
                .await?;
                if prior == [keep; 3] {
                    return TestResult::Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        {
            observed?;
        }
        withdrawal = Some(prior);
    }
    for (name, bytes) in &samples {
        assert_eq!(fs::read(source_path.join(name))?, *bytes);
        assert_eq!(fs::read(receiver_path.join(name))?, *bytes);
    }
    assert_eq!(fs::read(third_path.join(&samples[0].0))?, samples[0].1);
    assert_eq!(fs::read(sentinel)?, b"caller-owned data");
    eprintln!(
        "native introducer state before stopping: untrusted={before:?} trusted={after:?} withdrawal={withdrawal:?} keep={keep} direct={direct_data_observed} preserved_data=true"
    );
    assert_eq!(before, [false; 3]);
    assert_eq!(
        after, [true; 3],
        "no complete automatic introduction observed"
    );
    if probe_direct_data {
        assert!(
            direct_data_observed,
            "the introduced peer did not supply the direct file"
        );
    } else {
        assert_eq!(
            withdrawal,
            Some([keep; 3]),
            "unexpected introduced association after withdrawal"
        );
        assert_eq!(fresh_session_observed, keep);
    }
    if follow_withdrawal || probe_direct_data {
        let mut peers = vec![
            (receiver.client(), &introducer_id),
            (introducer.client(), &receiver_id),
            (introducer.client(), &third_id),
            (third.client(), &introducer_id),
        ];
        if probe_direct_data {
            peers.extend([
                (receiver.client(), &third_id),
                (third.client(), &receiver_id),
            ]);
        }
        // The file and association checks are complete. Disconnect the fixture
        // links before requiring a normal exit from each independently owned node.
        eprintln!("native introducer shutdown: pause the verified fixture links");
        for &(client, peer) in &peers {
            assert!(client.pause_device(peer).await?.configuration.paused);
        }
        wait_for_disconnect(&peers).await?;
        eprintln!("native introducer shutdown: fixture links confirmed disconnected");
    }
    for (role, node) in [
        ("receiver", &mut receiver),
        ("introducer", &mut introducer),
        ("third", &mut third),
    ] {
        eprintln!("native introducer shutdown: requesting normal exit for {role}");
        let stop = node.shutdown(Duration::from_secs(10)).await?;
        assert!(
            stop.code == Some(0) && stop.tree_stopped && stop.state_released && !stop.forced,
            "{role} did not complete normal shutdown: {stop:?}"
        );
        eprintln!("native introducer shutdown: {role} exited normally");
    }
    fs::remove_dir_all(root)?;
    println!(
        "native introducer effects: {}",
        serde_json::json!({
            "configured_peer_reported_requested_trust": true,
            "skip_introduction_removals": keep,
            "direct_data_from_introduced_peer_without_introducer_folder": direct_data_observed,
            "fresh_persisted_session_and_new_file_after_withdrawal": fresh_session_observed,
            "untrusted_device_origin_folder_association": before,
            "trusted_device_origin_folder_association": after,
            "after_withdrawal_device_origin_folder_association": withdrawal,
            "real_converged_shared_data_and_three_normal_exits": true,
        })
    );
    Ok(())
}
