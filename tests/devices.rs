//! Actual private device controls and their independent connection/file effects.
#[path = "common/device_removal_diagnostic.rs"]
mod device_removal_diagnostic;
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
#[path = "common/private_redial.rs"]
mod private_redial;
use managed_fixture::{options, TestResult};
use serde_json::json;
use std::time::Duration;
use verysync_sidecar::{
    Client, CreateDeviceOptions, DeviceCompression, DeviceId, DevicePatch, Error,
    JoinFolderOptions, ManagedInstance, RawMethod, RawRequest, RequestEffect, TargetPath,
};

async fn raw(
    client: &Client,
    method: RawMethod,
    parts: &[&str],
    body: Option<serde_json::Value>,
) -> TestResult<serde_json::Value> {
    let request = RawRequest::new(
        method,
        parts.iter().copied(),
        if method == RawMethod::Get {
            RequestEffect::ReadOnly
        } else {
            RequestEffect::MayModify
        },
    )?;
    let request = if let Some(body) = body {
        request.json_body(&body)?
    } else {
        request
    };
    let response = client.raw_request(&request).await?;
    assert!((200..300).contains(&response.status()));
    Ok(if response.body_bytes().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(response.body_bytes())?
    })
}

fn loopback_address(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => s
            .strip_prefix("tcp://")
            .and_then(|v| v.parse::<std::net::SocketAddr>().ok())
            .filter(|a| {
                a.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) && a.port() != 0
            })
            .map(|_| s.clone()),
        serde_json::Value::Array(a) => a.iter().find_map(loopback_address),
        serde_json::Value::Object(o) => o.values().find_map(loopback_address),
        _ => None,
    }
}
async fn address(client: &Client) -> TestResult<String> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(address) = client
                .system_status()
                .await?
                .extra
                .get("connectionServiceStatus")
                .and_then(loopback_address)
            {
                return Ok::<_, Error>(address);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??)
}
async fn connected(
    client: &Client,
    id: &DeviceId,
    expected: bool,
) -> TestResult<serde_json::Value> {
    let observed = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let snapshot = raw(
                client,
                RawMethod::Get,
                &["rest", "system", "connections"],
                None,
            )
            .await?;
            let peers = snapshot["connections"]
                .as_object()
                .ok_or("connection map missing")?;
            let actual = match peers.get(id.as_str()) {
                None => false,
                Some(peer) => peer["connected"]
                    .as_bool()
                    .ok_or("peer connection state missing")?,
            };
            if actual == expected {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(snapshot);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    Ok(observed)
}

async fn removal_events(client: &Client, since: u64) -> TestResult<Vec<serde_json::Value>> {
    let response = client
        .raw_request(
            &RawRequest::new(RawMethod::Get, ["rest", "events"], RequestEffect::ReadOnly)?
                // Match the event adapter's verified head-snapshot strategy:
                // requesting at the current head can break this fixed core.
                .query("since", "0")
                .query("timeout", "0")
                .query("limit", "256"),
        )
        .await?;
    if response.status() != 200 {
        return Err("private removal event snapshot failed".into());
    }
    let events: Vec<serde_json::Value> = serde_json::from_slice(response.body_bytes())?;
    Ok(events
        .into_iter()
        .filter(|event| event["id"].as_u64().is_some_and(|id| id > since))
        .collect())
}

async fn removal_disconnect(
    client: &Client,
    peer: &DeviceId,
    since: u64,
    removal_started: std::time::SystemTime,
) -> TestResult<&'static str> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let snapshot = raw(
                client,
                RawMethod::Get,
                &["rest", "system", "connections"],
                None,
            )
            .await?;
            let peers = snapshot["connections"]
                .as_object()
                .ok_or("connection map missing")?;
            let connected = match peers.get(peer.as_str()) {
                None => false,
                Some(value) => value["connected"]
                    .as_bool()
                    .ok_or("peer connection state missing")?,
            };
            if !connected {
                return TestResult::Ok("remote_connection_snapshot");
            }
            let events = removal_events(client, since).await?;
            if device_removal_diagnostic::has_disconnect_event(
                &events,
                peer.as_str(),
                since,
                removal_started,
                std::time::SystemTime::now(),
            ) {
                return TestResult::Ok("remote_native_disconnect_event");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?
}

async fn removal_state_diagnostic(
    role: &'static str,
    client: &Client,
    peer: &DeviceId,
    before_started: Option<&str>,
    since: u64,
    removal_started: std::time::SystemTime,
) -> TestResult<serde_json::Value> {
    println!("synthetic removal diagnostic stage: {role} connections");
    let connections = raw(
        client,
        RawMethod::Get,
        &["rest", "system", "connections"],
        None,
    )
    .await?;
    let row = connections["connections"].get(peer.as_str());
    let connected = row.and_then(|value| value["connected"].as_bool());
    let started_changed = before_started
        .zip(row.and_then(|value| value["startedAt"].as_str()))
        .map(|(before, after)| before != after);
    println!(
        "synthetic removal diagnostic connection: {}",
        json!({"role":role,"row_present":row.is_some(),"connected":connected,"connection_start_changed":started_changed})
    );
    println!("synthetic removal diagnostic stage: {role} configuration");
    let configuration = raw(client, RawMethod::Get, &["rest", "config"], None).await?;
    let configured = configuration["devices"]
        .as_array()
        .ok_or("diagnostic device array missing")?
        .iter()
        .any(|value| value["deviceID"] == peer.as_str());
    let references = configuration["folders"]
        .as_array()
        .ok_or("diagnostic folder array missing")?
        .iter()
        .filter(|folder| {
            folder["devices"].as_array().is_some_and(|values| {
                values
                    .iter()
                    .any(|value| value["deviceID"] == peer.as_str())
            })
        })
        .count();
    println!(
        "synthetic removal diagnostic config: {}",
        json!({"role":role,"device_configured":configured,"folder_reference_count":references})
    );
    println!("synthetic removal diagnostic stage: {role} events");
    let events = removal_events(client, since).await?;
    let count = |kind| events.iter().filter(|event| event["type"] == kind).count();
    let timeline =
        device_removal_diagnostic::removal_timeline(&events, peer.as_str(), removal_started);
    Ok(
        json!({"role":role,"event_scope":"since_fixture_initialization","device_configured":configured,"folder_reference_count":references,"peer_row_present":row.is_some(),"connected":connected,"connection_start_changed":started_changed,"events_returned":events.len(),"device_connected_events":count("DeviceConnected"),"device_disconnected_events":count("DeviceDisconnected"),"device_rejected_events":count("DeviceRejected"),"event_tail_gap":events.first().and_then(|event|event["id"].as_u64()).map(|first|first>since.saturating_add(1)),"timeline_clock":"owned_runner_wall_clock","timeline":timeline}),
    )
}

#[tokio::test]
async fn actual_peer_defaults_creation_patch_conflicts_and_self_protection() -> TestResult {
    let root = tempfile::Builder::new().prefix("vsd-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let own = a.client().instance().device_id.clone();
    let peer = b.client().instance().device_id.clone();
    let defaults = a.client().device_defaults().await?;
    let before = serde_json::to_value(&defaults)?;
    assert_eq!(a.client().devices().await?.len(), 1);
    assert_eq!(a.client().device(&own).await?.device_id, own);
    let patch = DevicePatch::default()
        .name("Synthetic peer")
        .addresses(vec![address(b.client()).await?])
        .compression(DeviceCompression::Never)
        .paused(true);
    let create = CreateDeviceOptions::new(peer.clone()).settings(patch);
    let cloned = a.client().clone();
    let (first, second) = tokio::join!(
        a.client().create_device(&create),
        cloned.create_device(&create)
    );
    assert!(matches!(
        (&first, &second),
        (Ok(_), Err(Error::DeviceAlreadyExists { .. }))
            | (Err(Error::DeviceAlreadyExists { .. }), Ok(_))
    ));
    let created = first.or(second)?;
    assert!(created.requested_fields_match && created.configuration.paused);
    assert_eq!(created.configuration.device_id, peer);
    assert_eq!(
        created.configuration.allowed_transports,
        defaults.allowed_transports
    );
    for (key, value) in &defaults.extra {
        if key != "deviceID" {
            assert_eq!(created.configuration.extra.get(key), Some(value));
        }
    }
    assert_eq!(b.client().devices().await?.len(), 1);
    for compression in [DeviceCompression::Always, DeviceCompression::Metadata] {
        let updated = a
            .client()
            .update_device(
                &peer,
                &DevicePatch::default()
                    .name("Changed synthetic peer")
                    .compression(compression.clone()),
            )
            .await?;
        assert!(updated.requested_fields_match);
        assert_eq!(updated.configuration.compression, compression);
        assert_eq!(
            updated.configuration.addresses,
            created.configuration.addresses
        );
        assert_eq!(updated.configuration.extra, created.configuration.extra);
    }
    // Keep this configuration case independent of an unapproved inbound peer.
    // The separate two-sided case below proves actual disconnect/reconnect.
    let changed_address = a
        .client()
        .update_device(
            &peer,
            &DevicePatch::default().addresses(vec!["dynamic".into()]),
        )
        .await?;
    assert!(changed_address.requested_fields_match);
    assert_eq!(changed_address.configuration.addresses, ["dynamic"]);
    assert!(!a.client().resume_device(&peer).await?.configuration.paused);
    assert!(a.client().pause_device(&peer).await?.configuration.paused);
    assert!(matches!(
        a.client()
            .create_device(&CreateDeviceOptions::new(own.clone()))
            .await,
        Err(Error::LocalDeviceProtected)
    ));
    assert!(matches!(
        a.client().pause_device(&own).await,
        Err(Error::LocalDeviceProtected)
    ));
    assert!(matches!(
        a.client().remove_device(&own).await,
        Err(Error::LocalDeviceProtected)
    ));
    assert!(matches!(
        a.client()
            .update_device(&peer, &DevicePatch::default())
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        a.client()
            .update_device(
                &peer,
                &DevicePatch::default()
                    .compression(DeviceCompression::Unknown("synthetic-future".into()))
            )
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        a.client()
            .update_device(
                &peer,
                &DevicePatch::default().addresses(vec!["bad\naddress".into()])
            )
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    let removed = a.client().remove_device(&peer).await?;
    assert!(removed.configuration_absent && removed.remaining_folder_associations.is_empty());
    assert!(matches!(
        a.client().device(&peer).await,
        Err(Error::DeviceNotFound { .. })
    ));
    assert!(matches!(
        a.client().remove_device(&peer).await,
        Err(Error::DeviceNotFound { .. })
    ));
    assert_eq!(
        serde_json::to_value(a.client().device_defaults().await?)?,
        before
    );
    assert_eq!(a.client().devices().await?.len(), 1);
    for instance in [&mut b, &mut a] {
        let exit = instance.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!(
        "public device configuration evidence: {}",
        json!({"actual_self_and_device_index":true,"actual_defaults_retained":true,"real_remote_identity_created":true,"clone_duplicate_creation_rejected":true,"one_peer_registered":true,"unrelated_engine_defaults_preserved":true,"remote_instance_not_modified":true,"actual_name_and_all_known_compression_patches":true,"unspecified_addresses_and_fields_preserved":true,"pause_resume_configuration_readback":true,"local_identity_protected":true,"empty_unknown_and_control_inputs_rejected":true,"actual_removal_and_not_found":true,"creation_defaults_unchanged":true,"both_actual_normal_tree_exits":true})
    );
    Ok(())
}

#[tokio::test]
async fn actual_device_pause_disconnects_resume_reconnects_and_removal_preserves_files(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vsdp-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    // Explicit fixture scheduling, with every original observation deadline
    // and data assertion retained. This does not change SDK/native defaults.
    private_redial::configure(a.client()).await?;
    private_redial::configure(b.client()).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    // Establish diagnostics before the original lifecycle sequence, so no
    // additional read is inserted between reconnect observation and DELETE.
    let a_events = removal_events(a.client(), 0).await?;
    let b_events = removal_events(b.client(), 0).await?;
    let a_since = a_events
        .last()
        .and_then(|event| event["id"].as_u64())
        .unwrap_or(0);
    let b_since = b_events
        .last()
        .and_then(|event| event["id"].as_u64())
        .unwrap_or(0);
    let a_path = root.join("source files");
    let b_path = root.join("received files");
    std::fs::create_dir(&a_path)?;
    let sample: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
    std::fs::write(a_path.join("sample.bin"), &sample)?;
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(a_path.clone())).paused(true))
        .await?
        .configuration;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(b_path.clone())).paused(true))
        .await?
        .configuration;
    println!("synthetic device effect stage: discover owned listeners");
    let a_addr = address(a.client()).await?;
    let b_addr = address(b.client()).await?;
    for (client, folder, peer, address) in [
        (a.client(), &af, &b_id, b_addr),
        (b.client(), &bf, &a_id, a_addr),
    ] {
        assert!(
            client
                .create_device(
                    &CreateDeviceOptions::new(peer.clone()).settings(
                        DevicePatch::default()
                            .addresses(vec![address])
                            .paused(false)
                    )
                )
                .await?
                .requested_fields_match
        );
        let mut associations = folder.extra["devices"]
            .as_array()
            .ok_or("missing folder device associations")?
            .clone();
        associations.push(json!({"deviceID":peer.as_str()}));
        // Independent fixture setup; not acceptance of typed folder-association controls.
        raw(
            client,
            RawMethod::Patch,
            &["rest", "config", "folders", folder.id.as_str()],
            Some(json!({"devices":associations})),
        )
        .await?;
        client.resume_folder(&folder.id).await?;
    }
    println!("synthetic device effect stage: scan and establish both initial connections");
    a.client().request_scan(&af.id).await?;
    connected(a.client(), &b_id, true).await?;
    connected(b.client(), &a_id, true).await?;
    println!("synthetic device effect stage: receive exact initial payload within original 40s");
    tokio::time::timeout(Duration::from_secs(40), async {
        while std::fs::read(b_path.join("sample.bin")).ok().as_deref() != Some(sample.as_slice()) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    println!("synthetic device effect stage: pause device and disconnect both sides");
    assert!(a.client().pause_device(&b_id).await?.requested_fields_match);
    connected(a.client(), &b_id, false).await?;
    connected(b.client(), &a_id, false).await?;
    println!("synthetic device effect stage: resume device and reconnect both sides");
    assert!(!a.client().folder(&af.id).await?.paused);
    assert!(
        a.client()
            .resume_device(&b_id)
            .await?
            .requested_fields_match
    );
    let a_before = connected(a.client(), &b_id, true).await?;
    let b_before = connected(b.client(), &a_id, true).await?;
    println!("synthetic device effect stage: remove registration and observe remote disconnect");
    let removal_started = std::time::SystemTime::now();
    let removed = a.client().remove_device(&b_id).await?;
    assert!(removed.configuration_absent && removed.remaining_folder_associations.is_empty());
    let disconnect = removal_disconnect(b.client(), &a_id, b_since, removal_started).await;
    // Diagnose native lifecycle state without extending the original 20s
    // deadline, retrying removal, or exposing IDs/addresses. A reconnect cannot
    // erase the exact remote peer's native disconnect event after this DELETE.
    let source_diagnostic = async {
        match tokio::time::timeout(
            Duration::from_secs(3),
            removal_state_diagnostic(
                "source",
                a.client(),
                &b_id,
                a_before["connections"]
                    .get(b_id.as_str())
                    .and_then(|value| value["startedAt"].as_str()),
                a_since,
                removal_started,
            ),
        )
        .await
        {
            Ok(Ok(observed)) => println!("synthetic device removal diagnostic: {observed}"),
            Ok(Err(_)) => {
                println!("synthetic device removal diagnostic: role=source observation_error=true")
            }
            Err(_) => println!(
                "synthetic device removal diagnostic: role=source observation_timed_out=true"
            ),
        }
    };
    let receiver_diagnostic = async {
        match tokio::time::timeout(
            Duration::from_secs(3),
            removal_state_diagnostic(
                "receiver",
                b.client(),
                &a_id,
                b_before["connections"]
                    .get(a_id.as_str())
                    .and_then(|value| value["startedAt"].as_str()),
                b_since,
                removal_started,
            ),
        )
        .await
        {
            Ok(Ok(observed)) => println!("synthetic device removal diagnostic: {observed}"),
            Ok(Err(_)) => println!(
                "synthetic device removal diagnostic: role=receiver observation_error=true"
            ),
            Err(_) => println!(
                "synthetic device removal diagnostic: role=receiver observation_timed_out=true"
            ),
        }
    };
    tokio::join!(source_diagnostic, receiver_diagnostic);
    println!(
        "synthetic original removal disconnect condition passed={}",
        disconnect.is_ok()
    );
    println!("synthetic removal disconnect evidence: {}", disconnect?);
    assert_eq!(std::fs::read(a_path.join("sample.bin"))?, sample);
    assert_eq!(std::fs::read(b_path.join("sample.bin"))?, sample);
    assert_eq!(a.client().folder(&af.id).await?.id, af.id);
    assert_eq!(b.client().folder(&bf.id).await?.id, bf.id);
    assert!(b.client().device(&a_id).await.is_ok());
    for instance in [&mut b, &mut a] {
        let exit = instance.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!(
        "public device live effect evidence: {}",
        json!({"both_real_private_peers_connected":true,"actual_synthetic_file_transferred":true,"device_pause_disconnected_both_sides":true,"folder_pause_layer_unchanged":true,"device_resume_reconnected_both_sides":true,"device_removal_observed_absent":true,"actual_folder_association_detached":true,"removal_disconnected_remote":true,"source_bytes_preserved":true,"received_bytes_preserved":true,"folder_registrations_preserved":true,"remote_device_configuration_preserved":true,"both_actual_normal_tree_exits":true})
    );
    Ok(())
}
