//! Real key preparation and registration; peer/transfer verdicts are separate.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use serde_json::json;
use std::time::Duration;
use verysync_sidecar::{
    Error, JoinFolderOptions, JoinPeerObservation, ManagedInstance, ShareKey, SharePermission,
    TargetPath,
};

#[tokio::test]
async fn actual_engine_keys_register_distinct_local_ids_and_preserve_permissions() -> TestResult {
    let root = tempfile::Builder::new().prefix("vsk-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("first"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("second"))?).await?;
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    assert_eq!(rw.permission(), &SharePermission::ReadWrite);
    assert_eq!(ro.permission(), &SharePermission::ReadOnly);
    assert_eq!(rw.read_only_key(), &keys.read_only_key);
    assert_eq!(rw.read_write_key(), Some(&keys.read_write_key));
    assert!(ro.read_write_key().is_none());
    assert_eq!(ro.read_only_key(), &keys.read_only_key);
    assert_ne!(rw.registration_id(), ro.registration_id());
    for debug in [format!("{keys:?}"), format!("{rw:?}"), format!("{ro:?}")] {
        assert!(!debug.contains(keys.read_only_key.expose_secret()));
        assert!(!debug.contains(keys.read_write_key.expose_secret()));
    }
    let rw_id = rw.registration_id().clone();
    let ro_id = ro.registration_id().clone();
    let first = a
        .client()
        .join_folder(
            &JoinFolderOptions::new(rw, TargetPath::local(root.join("original files")))
                .paused(true),
        )
        .await?;
    let second = b
        .client()
        .join_folder(
            &JoinFolderOptions::new(ro, TargetPath::local(root.join("joined files"))).paused(true),
        )
        .await?;
    for result in [&first, &second] {
        assert!(
            result.submitted_key_matches
                && result.read_only_key_matches
                && result.read_write_key_matches
        );
        assert_eq!(result.peer_observation, JoinPeerObservation::Unobserved);
        assert!(result.configuration.paused);
    }
    assert_eq!(first.configuration.id, rw_id);
    assert_eq!(second.configuration.id, ro_id);
    assert!(first.configuration.extra["readWriteSecret"] == keys.read_write_key.expose_secret());
    assert!(second.configuration.extra["readWriteSecret"] == "");
    let exit = b.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced);
    let exit = a.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced);
    std::fs::remove_dir_all(root)?;
    println!(
        "public share registration evidence: {}",
        json!({"engine_generated_key_pair":true,"actual_rw_permission_validated":true,"actual_ro_permission_validated":true,"ro_validation_has_no_rw_material":true,"distinct_engine_proposed_local_ids":true,"no_manual_id_alignment":true,"rw_material_actual_readback":true,"ro_material_actual_readback":true,"actual_submitted_keys_retained":true,"registration_does_not_claim_peer_connection":true,"ordinary_debug_hides_all_keys":true,"both_actual_normal_tree_exits":true})
    );
    Ok(())
}

#[tokio::test]
async fn rejected_keys_wrong_target_and_duplicate_groups_do_not_register() -> TestResult {
    let root = tempfile::Builder::new().prefix("vkr-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("first"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("second"))?).await?;
    let invalid = ShareKey::new("synthetic-invalid-sharing-key")?;
    let error = a
        .client()
        .validate_share_key(&invalid)
        .await
        .err()
        .ok_or("invalid key accepted")?;
    assert!(matches!(error, Error::ShareKeyRejected { .. }));
    assert!(!format!("{error:?} {error}").contains(invalid.expose_secret()));
    assert!(a.client().folders().await?.is_empty());
    let keys = a.client().generate_share().await?;
    let prepared = a.client().validate_share_key(&keys.read_write_key).await?;
    let options =
        JoinFolderOptions::new(prepared, TargetPath::local(root.join("kept sample"))).paused(true);
    let wrong = b.client().join_folder(&options).await;
    assert!(matches!(wrong, Err(Error::IdentityMismatch { .. })));
    assert!(b.client().folders().await?.is_empty());
    let saved = a.client().join_folder(&options).await?;
    assert!(
        saved.submitted_key_matches && saved.read_only_key_matches && saved.read_write_key_matches
    );
    let fresh = a.client().validate_share_key(&keys.read_only_key).await?;
    let duplicate =
        JoinFolderOptions::new(fresh, TargetPath::local(root.join("not-created"))).paused(true);
    assert!(matches!(
        a.client().join_folder(&duplicate).await,
        Err(Error::ShareAlreadyConfigured { .. })
    ));
    assert!(matches!(
        a.client().join_folder(&options).await,
        Err(Error::FolderAlreadyExists { .. })
    ));
    assert_eq!(a.client().folders().await?.len(), 1);
    assert_eq!(
        a.client().folder(options.folder_id()).await?.id,
        saved.configuration.id
    );
    assert!(!root.join("not-created").exists());
    let exit = b.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced);
    let exit = a.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced);
    std::fs::remove_dir_all(root)?;
    println!(
        "public share rejection evidence: {}",
        json!({"http_200_invalid_key_is_typed_rejection":true,"rejection_hides_submitted_key":true,"invalid_key_did_not_register":true,"wrong_target_rejected":true,"wrong_target_configuration_empty":true,"duplicate_group_rejected":true,"same_local_id_rejected":true,"only_original_registration_remains":true,"duplicate_path_not_created":true,"both_actual_normal_tree_exits":true})
    );
    Ok(())
}

#[tokio::test]
async fn key_registered_folders_receive_real_data_over_private_loopback() -> TestResult {
    use verysync_sidecar::{Client, RawMethod, RawRequest, RequestEffect};
    async fn raw(
        client: &Client,
        method: RawMethod,
        parts: &[&str],
        body: Option<serde_json::Value>,
    ) -> TestResult<serde_json::Value> {
        let request = RawRequest::new(
            method,
            parts.iter().copied(),
            if matches!(method, RawMethod::Get) {
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
        assert_eq!(response.status(), 200);
        if response.body_bytes().is_empty() {
            Ok(serde_json::Value::Null)
        } else {
            Ok(serde_json::from_slice(response.body_bytes())?)
        }
    }
    fn address(value: &serde_json::Value) -> Option<String> {
        match value {
            serde_json::Value::String(s) => s
                .strip_prefix("tcp://")
                .and_then(|v| v.parse::<std::net::SocketAddr>().ok())
                .filter(|a| {
                    a.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) && a.port() != 0
                })
                .map(|_| s.clone()),
            serde_json::Value::Array(a) => a.iter().find_map(address),
            serde_json::Value::Object(o) => o.values().find_map(address),
            _ => None,
        }
    }
    async fn loopback(client: &Client) -> TestResult<String> {
        raw(client,RawMethod::Patch,&["rest","config","options"],Some(json!({"listenAddresses":["tcp://127.0.0.1:0"],"globalAnnounceEnabled":false,"localAnnounceEnabled":false,"relaysEnabled":false,"natEnabled":false}))).await?;
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let status = client.system_status().await?;
                if let Some(a) = status
                    .extra
                    .get("connectionServiceStatus")
                    .and_then(address)
                {
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(a);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await?
    }
    let root = tempfile::Builder::new().prefix("vkp-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("first"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("second"))?).await?;
    let (a_addr, b_addr) = tokio::try_join!(loopback(a.client()), loopback(b.client()))?;
    eprintln!("private share join probe: both actual loopback listeners observed");
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    let a_path = root.join("origin files");
    let b_path = root.join("joined files");
    std::fs::create_dir(&a_path)?;
    let sample = b"synthetic private key join data; no user files";
    std::fs::write(a_path.join("sample.bin"), sample)?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(a_path.clone())).paused(true))
        .await?;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(b_path.clone())).paused(true))
        .await?;
    for (client, folder, peer_id, peer_address) in [
        (a.client(), &af.configuration, &b_id, &b_addr),
        (b.client(), &bf.configuration, &a_id, &a_addr),
    ] {
        let mut device = raw(
            client,
            RawMethod::Get,
            &["rest", "config", "defaults", "device"],
            None,
        )
        .await?;
        device["deviceID"] = json!(peer_id.as_str());
        device["addresses"] = json!([peer_address]);
        raw(
            client,
            RawMethod::Post,
            &["rest", "config", "devices"],
            Some(device),
        )
        .await?;
        let mut devices = folder.extra["devices"]
            .as_array()
            .ok_or("folder devices missing")?
            .clone();
        devices.push(json!({"deviceID":peer_id.as_str()}));
        raw(
            client,
            RawMethod::Patch,
            &["rest", "config", "folders", folder.id.as_str()],
            Some(json!({"devices":devices})),
        )
        .await?;
        client.resume_folder(&folder.id).await?;
        assert!(client.folder(&folder.id).await?.extra["devices"]
            .as_array()
            .ok_or("association readback missing")?
            .iter()
            .any(|entry| entry["deviceID"] == peer_id.as_str()));
    }
    a.client().request_scan(&af.configuration.id).await?;
    eprintln!("private share join probe: direct peer and actual key registrations configured");
    let observed = tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            if std::fs::read(b_path.join("sample.bin")).ok().as_deref() == Some(sample.as_slice()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    let a_connections = raw(
        a.client(),
        RawMethod::Get,
        &["rest", "system", "connections"],
        None,
    )
    .await?;
    let b_connections = raw(
        b.client(),
        RawMethod::Get,
        &["rest", "system", "connections"],
        None,
    )
    .await?;
    let connected_a = a_connections["connections"][b_id.as_str()]["connected"] == true;
    let connected_b = b_connections["connections"][a_id.as_str()]["connected"] == true;
    println!(
        "private key join probe effects: {}",
        json!({"actual_loopback_listeners":true,"distinct_local_ids":af.configuration.id!=bf.configuration.id,"origin_connected":connected_a,"receiver_connected":connected_b,"actual_received_sample_matches":observed.is_ok()})
    );
    let exit = b.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced);
    let exit = a.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced);
    observed?;
    assert!(connected_a && connected_b);
    assert_eq!(std::fs::read(a_path.join("sample.bin"))?, sample);
    println!(
        "public share peer evidence: {}",
        json!({"actual_loopback_listeners":true,"distinct_engine_local_ids":true,
        "actual_origin_peer_connected":true,"actual_receiver_peer_connected":true,"actual_device_associations":true,
        "actual_received_sample_matches":true,"source_sample_retained":true,"both_actual_normal_tree_exits":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
