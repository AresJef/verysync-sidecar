//! Actual private device controls and their independent connection/file effects.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
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
async fn connected(client: &Client, id: &DeviceId, expected: bool) -> TestResult {
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
            let actual = match peers.get(id.as_str()) {
                None => false,
                Some(peer) => peer["connected"]
                    .as_bool()
                    .ok_or("peer connection state missing")?,
            };
            if actual == expected {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    Ok(())
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
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
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
    a.client().request_scan(&af.id).await?;
    connected(a.client(), &b_id, true).await?;
    connected(b.client(), &a_id, true).await?;
    tokio::time::timeout(Duration::from_secs(40), async {
        while std::fs::read(b_path.join("sample.bin")).ok().as_deref() != Some(sample.as_slice()) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    assert!(a.client().pause_device(&b_id).await?.requested_fields_match);
    connected(a.client(), &b_id, false).await?;
    connected(b.client(), &a_id, false).await?;
    assert!(!a.client().folder(&af.id).await?.paused);
    assert!(
        a.client()
            .resume_device(&b_id)
            .await?
            .requested_fields_match
    );
    connected(a.client(), &b_id, true).await?;
    connected(b.client(), &a_id, true).await?;
    let removed = a.client().remove_device(&b_id).await?;
    assert!(removed.configuration_absent && removed.remaining_folder_associations.is_empty());
    connected(b.client(), &a_id, false).await?;
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
