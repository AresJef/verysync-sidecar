//! Native logical-node relay evidence; this is not a WAN bandwidth benchmark.
#[path = "common/introducer_cases.rs"]
mod introducer_cases;
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
#[path = "common/private_redial.rs"]
mod private_redial;
#[path = "common/three_node_diagnostic.rs"]
mod three_node_diagnostic;
use managed_fixture::{options, TestResult};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use verysync_sidecar::{
    Client, CreateDeviceOptions, DeviceId, DevicePatch, DeviceTransport, Error, FolderId,
    JoinFolderOptions, ManagedInstance, NetworkPatch, PeerConnection, PeerConnectionType,
    SharePermission, TargetPath,
};

async fn private_tcp(client: &Client) -> TestResult<String> {
    let network = client.network_configuration().await?;
    let transport = client.transport_configuration().await?;
    assert!(!network.global_announce_enabled && !network.local_announce_enabled);
    assert!(
        !transport.tracker_enabled
            && !transport.udp_enabled
            && !transport.nat_enabled
            && !transport.relays_enabled
            && !transport.tcp_punch_enabled
    );
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for status in client.listener_status().await?.into_values() {
                for address in status.lan_addresses {
                    if address
                        .strip_prefix("tcp://")
                        .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
                        .is_some_and(|s| s.ip().is_loopback() && s.port() != 0 && s.port() != 18886)
                    {
                        return Ok::<_, Error>(address);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??)
}

async fn associate(
    client: &Client,
    folder: &FolderId,
    peer: &DeviceId,
    address: &str,
    paused: bool,
) -> TestResult {
    let update = client
        .create_device(
            &CreateDeviceOptions::new(peer.clone()).settings(
                DevicePatch::default()
                    .addresses(vec![address.to_owned()])
                    .allowed_transports(vec![DeviceTransport::Tcp])
                    .paused(paused),
            ),
        )
        .await?;
    assert!(update.requested_fields_match);
    client.share_folder_with(folder, peer).await?;
    Ok(())
}

async fn connected(client: &Client, peer: &DeviceId) -> TestResult<PeerConnection> {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(connection) = client.connections().await?.connections.remove(peer) {
                if connection.connected {
                    assert!(matches!(
                        connection.connection_type,
                        Some(PeerConnectionType::TcpClient | PeerConnectionType::TcpServer)
                    ));
                    let address = connection
                        .address
                        .as_deref()
                        .ok_or("actual connected address missing")?
                        .parse::<std::net::SocketAddr>()?;
                    assert!(address.ip().is_loopback() && address.port() != 18886);
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(connection);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?
}

fn out(connection: &PeerConnection) -> TestResult<u64> {
    Ok(connection
        .out_bytes_total
        .ok_or("actual outgoing byte counter missing")?)
}

async fn received(
    stage: &'static str,
    client: &Client,
    folder: &FolderId,
    path: &Path,
    samples: &[(PathBuf, Vec<u8>)],
) -> TestResult {
    let mut matched_files = 0;
    let mut last_status = None;
    tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            matched_files = 0;
            let bytes_match = samples.iter().all(|(name, bytes)| {
                let matches = std::fs::read(path.join(name)).is_ok_and(|v| v == *bytes);
                if matches {
                    matched_files += 1;
                }
                matches
            });
            if bytes_match {
                let status = client.folder_status(folder).await?;
                last_status = Some((status.need_bytes, status.local_files));
                if status.need_bytes == Some(0) && status.local_files == Some(samples.len() as u64)
                {
                    return Ok::<_, Error>(());
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .inspect_err(|_| eprintln!("three-node receive deadline: {}",json!({"stage":stage,
        "matching_prefix_files":matched_files,"expected_files":samples.len(),"last_need_and_local_files":last_status,
        "original_timeout_seconds":40})))??;
    Ok(())
}

#[tokio::test]
async fn actual_delivery_batch_waits_for_the_late_receiver_and_checks_bytes() -> TestResult {
    use std::time::SystemTime;
    use verysync_sidecar::{
        DeliveryBatch, DeliveryEvidenceSource, DeliveryFile, DeliveryFileOutcome, DeliveryReceipt,
        DeliveryVerification, OperationCompletion, OperationOptions, OperationPhase,
        ResourceFileState,
    };
    let root = tempfile::Builder::new().prefix("vbd-").tempdir()?;
    let mut a = ManagedInstance::start(options(&root.path().join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.path().join("b"))?).await?;
    let mut c = ManagedInstance::start(options(&root.path().join("c"))?).await?;
    let since = SystemTime::now();
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    let c_id = c.client().instance().device_id.clone();
    let source = a.state_directory().join("profile").join("delivery-source");
    let first = b.state_directory().join("profile").join("delivery-first");
    let late = c.state_directory().join("profile").join("delivery-late");
    std::fs::create_dir(&source)?;
    let samples = vec![
        (
            PathBuf::from("sample.bin"),
            b"transfer from original sender".to_vec(),
        ),
        (PathBuf::from("empty.bin"), Vec::new()),
    ];
    for (name, contents) in &samples {
        std::fs::write(source.join(name), contents)?;
    }
    let keys = a.client().generate_share().await?;
    let af = a
        .client()
        .join_folder(
            &JoinFolderOptions::new(
                a.client().validate_share_key(&keys.read_write_key).await?,
                TargetPath::local(&source),
            )
            .paused(true),
        )
        .await?
        .configuration
        .id;
    let bf = b
        .client()
        .join_folder(
            &JoinFolderOptions::new(
                b.client().validate_share_key(&keys.read_only_key).await?,
                TargetPath::local(&first),
            )
            .paused(true),
        )
        .await?
        .configuration
        .id;
    let cf = c
        .client()
        .join_folder(
            &JoinFolderOptions::new(
                c.client().validate_share_key(&keys.read_only_key).await?,
                TargetPath::local(&late),
            )
            .paused(true),
        )
        .await?
        .configuration
        .id;
    let a_address = private_tcp(a.client()).await?;
    associate(
        a.client(),
        &af,
        &b_id,
        &private_tcp(b.client()).await?,
        false,
    )
    .await?;
    associate(
        a.client(),
        &af,
        &c_id,
        &private_tcp(c.client()).await?,
        false,
    )
    .await?;
    associate(b.client(), &bf, &a_id, &a_address, false).await?;
    associate(c.client(), &cf, &a_id, &a_address, false).await?;
    a.client().resume_folder(&af).await?;
    b.client().resume_folder(&bf).await?;
    a.client().request_scan(&af).await?;
    received(
        "first selected recipient",
        b.client(),
        &bf,
        &first,
        &samples,
    )
    .await?;
    assert!(!late.join("sample.bin").exists());
    let files = samples
        .iter()
        .map(|(name, contents)| {
            DeliveryFile::new(
                name.to_str().unwrap(),
                contents.len() as u64,
                Sha256::digest(contents).into(),
            )
        })
        .collect::<verysync_sidecar::Result<Vec<_>>>()?;
    let batch = DeliveryBatch::new(
        a_id,
        af.clone(),
        files,
        [(b_id.clone(), bf.clone()), (c_id.clone(), cf.clone())],
    )?;
    let limit = || OperationOptions::new(Duration::from_secs(15));
    let first_only = a
        .client()
        .observe_delivery_batch(&batch, &[b.client(), c.client()], &[], since, limit())
        .await?;
    assert_eq!(
        first_only.completion(),
        OperationCompletion::PartiallyCompleted,
        "{first_only:#?}"
    );
    assert!(first_only.recipients[&b_id]
        .files
        .iter()
        .all(|file| file.outcome == DeliveryFileOutcome::Matched));
    assert!(first_only.recipients[&c_id]
        .files
        .iter()
        .all(|file| file.outcome != DeliveryFileOutcome::Matched));

    let without_receivers = a
        .client()
        .observe_delivery_batch(&batch, &[], &[], since, limit())
        .await?;
    assert_eq!(
        without_receivers.completion(),
        OperationCompletion::Unconfirmed
    );
    assert!(without_receivers
        .recipients
        .values()
        .flat_map(|peer| &peer.files)
        .all(|file| file.outcome == DeliveryFileOutcome::Unobserved));

    let strict_refusal = a
        .client()
        .scan_delivery_batch_and_verify(
            &batch,
            &[b.client()],
            &[],
            since,
            DeliveryVerification::RequireReceiverReads,
            limit(),
        )
        .await?;
    assert!(!strict_refusal.write.dispatched && strict_refusal.original.is_err());
    let best_effort = a
        .client()
        .scan_delivery_batch_and_verify(
            &batch,
            &[],
            &[],
            since,
            DeliveryVerification::BestEffort,
            limit(),
        )
        .await?;
    assert!(
        best_effort.write.dispatched && best_effort.write.response_complete,
        "{best_effort:#?}"
    );
    assert_eq!(best_effort.completion(), OperationCompletion::Unconfirmed);
    assert!(!late.join("sample.bin").exists());

    let (events, mut progress) = tokio::sync::mpsc::channel(16);
    let resume = async {
        while let Some(phase) = progress.recv().await {
            if phase == OperationPhase::Submitting {
                c.client().resume_folder(&cf).await?;
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
        }
        Err("strict verification finished before dispatch".into())
    };
    let recipients = [b.client(), c.client()];
    let (strict, resumed) = tokio::join!(
        a.client().scan_delivery_batch_and_verify(
            &batch,
            &recipients,
            &[],
            since,
            DeliveryVerification::RequireReceiverReads,
            limit().report_progress_to(events),
        ),
        resume,
    );
    let strict = strict?;
    assert!(
        strict.write.dispatched && strict.write.response_complete,
        "{strict:#?}"
    );
    resumed?;
    assert_eq!(
        strict.completion(),
        OperationCompletion::Completed,
        "{strict:#?}"
    );
    received("late selected recipient", c.client(), &cf, &late, &samples).await?;
    let complete = a
        .client()
        .observe_delivery_batch(&batch, &[b.client(), c.client()], &[], since, limit())
        .await?;
    assert_eq!(
        complete.completion(),
        OperationCompletion::Completed,
        "{complete:#?}"
    );
    let matched = a
        .client()
        .scan_delivery_batch_and_verify(
            &batch,
            &[b.client(), c.client()],
            &[],
            since,
            DeliveryVerification::RequireReceiverReads,
            limit(),
        )
        .await?;
    assert!(!matched.write.dispatched && matches!(matched.original, Ok(None)));
    assert_eq!(matched.completion(), OperationCompletion::Completed);
    assert!(complete
        .recipients
        .values()
        .flat_map(|peer| &peer.files)
        .all(|file| {
            file.evidence.len() == 1
                && file.evidence[0].source == DeliveryEvidenceSource::RecipientRead
        }));
    let at = SystemTime::now();
    let measured = ResourceFileState::Present {
        bytes: samples[0].1.len() as u64,
        sha256: Sha256::digest(std::fs::read(first.join("sample.bin"))?).into(),
    };
    let actual = DeliveryReceipt::witnessed(&batch, b_id.clone(), 0, at, at, measured)?;
    let actual = DeliveryReceipt::decode(&batch, &actual.encode()?)?;
    let disputed = DeliveryReceipt::witnessed(
        &batch,
        b_id.clone(),
        0,
        at,
        at,
        ResourceFileState::Present {
            bytes: samples[0].1.len() as u64,
            sha256: [0x99; 32],
        },
    )?;
    let conflicts = a
        .client()
        .observe_delivery_batch(&batch, &[], &[actual, disputed], since, limit())
        .await?;
    let conflict = &conflicts.recipients[&b_id].files[0];
    assert_eq!(conflict.outcome, DeliveryFileOutcome::Conflicting);
    assert_eq!(conflict.evidence.len(), 2);
    assert!(conflict
        .evidence
        .iter()
        .all(|item| item.source == DeliveryEvidenceSource::CallerWitness));
    for core in [&mut c, &mut b, &mut a] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    println!(
        "native delivery batch evidence: {}",
        json!({
            "owned_nodes":3, "selected_files":2, "selected_receivers":2,
            "one_late_receiver_before_ready":true, "actual_full_digest_both_receivers":true,
            "model_progress_alone_did_not_complete_batch":true, "conflicting_simultaneous_witnesses_retained":true,
            "external_witness_conflict_fixture_is_synthetic":true, "all_owned_trees_exited_cleanly":true,
        "strict_unqualified_zero_scan":true,"best_effort_with_no_observer_kept_result_unknown":true,
        "qualified_strict_scan_followed_by_native_delivery":true,"already_matched_zero_scan":true,
        })
    );
    Ok(())
}

#[tokio::test]
async fn actual_readonly_node_serves_blank_readonly_peer_after_source_exits() -> TestResult {
    let root = tempfile::Builder::new().prefix("vs3-").tempdir()?.keep();
    let phase = three_node_diagnostic::Phase::new(root.clone());
    phase.set("start-source");
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    phase.set("start-first-readonly");
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    assert_ne!(a_id, b_id);
    phase.set("source-listener");
    let a_address = private_tcp(a.client()).await?;
    phase.set("first-readonly-listener");
    let b_address = private_tcp(b.client()).await?;
    phase.set("prepare-keys-and-source-samples");
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    assert_eq!(rw.permission(), &SharePermission::ReadWrite);
    assert_eq!(ro.permission(), &SharePermission::ReadOnly);
    assert!(ro.read_write_key().is_none());
    let source = root.join("source");
    let retained = root.join("readonly-b");
    std::fs::create_dir_all(source.join("sub"))?;
    let names = [
        PathBuf::from("first.bin"),
        Path::new("sub").join("nested.bin"),
        PathBuf::from("二 空格 %.bin"),
        PathBuf::from("last.bin"),
    ];
    let mut seed = 0x34abcdef12345678u64;
    let samples: Vec<_> = names
        .into_iter()
        .map(|name| {
            let bytes: Vec<u8> = (0..524288)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    seed as u8
                })
                .collect();
            (name, bytes)
        })
        .collect();
    for (name, bytes) in &samples {
        std::fs::write(source.join(name), bytes)?;
    }
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&source)).paused(true))
        .await?;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(&retained)).paused(true))
        .await?;
    assert_ne!(af.configuration.id, bf.configuration.id);
    assert!(bf.submitted_key_matches && bf.read_only_key_matches && bf.read_write_key_matches);
    assert_eq!(bf.configuration.extra["type"], "receiveonly");
    assert!(bf.configuration.extra["readWriteSecret"] == "");
    associate(a.client(), &af.configuration.id, &b_id, &b_address, false).await?;
    associate(b.client(), &bf.configuration.id, &a_id, &a_address, false).await?;
    phase.set("source-to-first-readonly-connection");
    let a_before = out(&connected(a.client(), &b_id).await?)?;
    phase.set("first-readonly-to-source-connection");
    let b_to_a_before = out(&connected(b.client(), &a_id).await?)?;
    phase.set("receive-first-readonly");
    a.client().resume_folder(&af.configuration.id).await?;
    b.client().resume_folder(&bf.configuration.id).await?;
    a.client().request_scan(&af.configuration.id).await?;
    received(
        "source-to-first-readonly",
        b.client(),
        &bf.configuration.id,
        &retained,
        &samples,
    )
    .await?;
    phase.set("source-transfer-counter-readback");
    let a_after = out(&connected(a.client(), &b_id).await?)?;
    let b_to_a_after = out(&connected(b.client(), &a_id).await?)?;
    assert!(a_after > a_before && b_to_a_after >= b_to_a_before);
    phase.set("source-normal-exit");
    let a_exit = a.shutdown(Duration::from_secs(10)).await?;
    assert!(a_exit.tree_stopped && !a_exit.forced && a_exit.code == Some(0));

    // C has no state, files, identity or peer relationship while A is alive.
    phase.set("start-blank-readonly-after-source-exit");
    let mut c = ManagedInstance::start(options(&root.join("c"))?).await?;
    let c_id = c.client().instance().device_id.clone();
    assert!(c_id != a_id && c_id != b_id);
    phase.set("blank-readonly-listener");
    let c_address = private_tcp(c.client()).await?;
    let blank = root.join("blank-c");
    assert!(!blank.exists());
    let c_ro = c.client().validate_share_key(&keys.read_only_key).await?;
    assert_eq!(c_ro.permission(), &SharePermission::ReadOnly);
    assert!(c_ro.read_write_key().is_none());
    let cf = c
        .client()
        .join_folder(&JoinFolderOptions::new(c_ro, TargetPath::local(&blank)).paused(true))
        .await?;
    assert!(cf.submitted_key_matches && cf.read_only_key_matches && cf.read_write_key_matches);
    assert_eq!(cf.configuration.extra["type"], "receiveonly");
    assert!(cf.configuration.extra["readWriteSecret"] == "");
    assert!(samples.iter().all(|(name, _)| !blank.join(name).exists()));

    phase.set("prepare-wrong-address-negative");
    let rejector = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let rejected_address = format!("tcp://{}", rejector.local_addr()?);
    associate(b.client(), &bf.configuration.id, &c_id, &c_address, true).await?;
    associate(
        c.client(),
        &cf.configuration.id,
        &b_id,
        &rejected_address,
        false,
    )
    .await?;
    c.client()
        .update_network_configuration(&NetworkPatch::default().reconnection_interval_seconds(1))
        .await?;
    c.client().resume_folder(&cf.configuration.id).await?;
    phase.set("observe-wrong-address-on-owned-rejector");
    let (rejected_stream, rejected_peer) =
        tokio::time::timeout(Duration::from_secs(15), rejector.accept()).await??;
    assert!(rejected_peer.ip().is_loopback());
    drop(rejected_stream);
    drop(rejector);
    assert!(!c
        .client()
        .connections()
        .await?
        .connections
        .get(&b_id)
        .is_some_and(|p| p.connected));
    assert!(samples.iter().all(|(name, _)| !blank.join(name).exists()));
    assert!(c
        .client()
        .devices()
        .await?
        .iter()
        .all(|d| d.device_id != a_id));
    c.client().pause_folder(&cf.configuration.id).await?;
    c.client()
        .update_device(&b_id, &DevicePatch::default().addresses(vec![b_address]))
        .await?;
    b.client().resume_device(&c_id).await?;
    phase.set("retained-to-blank-readonly-connection");
    let b_before = out(&connected(b.client(), &c_id).await?)?;
    phase.set("blank-to-retained-readonly-connection");
    let c_before = out(&connected(c.client(), &b_id).await?)?;
    phase.set("receive-blank-readonly-with-source-stopped");
    c.client().resume_folder(&cf.configuration.id).await?;
    received(
        "retained-to-blank-readonly",
        c.client(),
        &cf.configuration.id,
        &blank,
        &samples,
    )
    .await?;
    phase.set("relay-transfer-counter-readback");
    let b_after = out(&connected(b.client(), &c_id).await?)?;
    let c_after = out(&connected(c.client(), &b_id).await?)?;
    assert!(b_after > b_before && c_after >= c_before);
    let payload_bytes: usize = samples.iter().map(|(_, bytes)| bytes.len()).sum();
    assert!(b_after - b_before >= payload_bytes as u64);
    let mut hashes = Vec::new();
    for (name, bytes) in &samples {
        let hash = Sha256::digest(bytes);
        for path in [&source, &retained, &blank] {
            let actual = std::fs::read(path.join(name))?;
            assert_eq!(actual, *bytes);
            assert_eq!(Sha256::digest(&actual), hash);
        }
        hashes.push(format!("{hash:x}"));
    }
    assert!(b.client().folder(&bf.configuration.id).await?.extra["readWriteSecret"] == "");
    assert!(c.client().folder(&cf.configuration.id).await?.extra["readWriteSecret"] == "");
    b.client().pause_device(&c_id).await?;
    c.client().pause_device(&b_id).await?;
    for (stage, core) in [
        ("blank-readonly-normal-exit", &mut c),
        ("retained-readonly-normal-exit", &mut b),
    ] {
        phase.set(stage);
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    println!(
        "public three-node byte observations: {}",
        json!({
            "payload_bytes":payload_bytes,"payload_sha256":hashes,
            "a_to_b_out_before":a_before,"a_to_b_out_after":a_after,
            "b_to_a_out_before":b_to_a_before,"b_to_a_out_after":b_to_a_after,
            "b_to_c_out_before":b_before,"b_to_c_out_after":b_after,
            "c_to_b_out_before":c_before,"c_to_b_out_after":c_after,
            "scope":"logical loopback peers; protocol byte counters, not WAN savings"
        })
    );
    phase.set("all-data-and-counter-checks-complete");
    std::fs::remove_dir_all(root)?;
    phase.complete();
    println!(
        "public readonly three-node evidence: {}",
        json!({
            "three_independent_actual_identities":true,"all_private_tcp_and_unrelated_transports_disabled":true,
            "actual_engine_generated_rw_and_ro_key_permissions":true,"engine_proposed_local_ids_not_manually_aligned":true,
            "actual_first_readonly_node_received_complete_data":true,"actual_source_normal_tree_exit_before_c_exists":true,
            "actual_c_blank_path_and_no_rw_material":true,"actual_c_has_no_source_peer_configuration":true,
            "wrong_target_reached_owned_rejector":true,"wrong_target_not_connection_or_file_success":true,
            "actual_readonly_b_serves_c_with_a_stopped":true,"actual_c_received_all_bytes_and_zero_need":true,
            "actual_a_b_c_outgoing_counters_observed":true,"actual_b_to_c_delta_covers_unique_payload":true,
            "all_three_complete_file_hashes_and_bytes_match":true,"readonly_permissions_retained_after_transfer":true,
            "all_three_actual_normal_tree_exits":true
        })
    );
    Ok(())
}
