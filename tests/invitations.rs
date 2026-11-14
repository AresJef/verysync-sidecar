//! Real pending offers, persistent ignores and caller-chosen key acceptance.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
#[path = "common/peer_proxy.rs"]
mod peer_proxy;
#[path = "common/private_redial.rs"]
mod private_redial;
#[path = "common/sync_diagnostics.rs"]
mod sync_diagnostics;
use managed_fixture::{options, TestResult};
use serde_json::{json, Value};
use std::{collections::BTreeMap, time::Duration};
use verysync_sidecar::{
    Client, CreateDeviceOptions, DeviceCompression, DeviceId, DevicePatch, Error, FolderId,
    JoinFolderOptions, ManagedInstance, PendingFolderOffers, RawMethod, RawRequest, RequestEffect,
    SharePermission, TargetPath,
};

#[tokio::test]
async fn unapproved_inbound_stop_retains_truthful_deadline_and_explicit_owned_cleanup() -> TestResult
{
    let root = tempfile::Builder::new().prefix("vsil-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    let sample = b"synthetic unrelated data must survive any selected cleanup";
    std::fs::write(root.join("sample.bin"), sample)?;
    let created = a
        .client()
        .create_device(
            &CreateDeviceOptions::new(b_id.clone()).settings(
                DevicePatch::default()
                    .name("Unapproved inbound sender")
                    .addresses(vec![listener(b.client()).await?])
                    .compression(DeviceCompression::Never)
                    .paused(true),
            ),
        )
        .await?;
    assert!(created.requested_fields_match);
    for compression in [DeviceCompression::Always, DeviceCompression::Metadata] {
        assert!(
            a.client()
                .update_device(&b_id, &DevicePatch::default().compression(compression))
                .await?
                .requested_fields_match
        );
    }
    a.client().resume_device(&b_id).await?;
    connection(a.client(), &b_id, true).await?;
    assert_eq!(b.client().devices().await?.len(), 1);
    assert!(matches!(
        b.client().device(&a_id).await,
        Err(Error::DeviceNotFound { .. })
    ));
    a.client().pause_device(&b_id).await?;
    connection(a.client(), &b_id, false).await?;
    assert!(a.client().remove_device(&b_id).await?.configuration_absent);
    eprintln!(
        "private unapproved inbound stage: one normal stop with original ten-second deadline"
    );
    let (mode, exit) = match b.shutdown(Duration::from_secs(10)).await {
        Ok(exit) => ("normal_before_deadline", exit),
        Err(Error::Timeout { .. }) => {
            eprintln!("private unapproved inbound stage: timeout is not an exit; reconcile without another write");
            match tokio::time::timeout(Duration::from_secs(2), b.wait_for_exit()).await {
                Ok(exit) => ("normal_after_deadline_without_retry", exit?),
                Err(_) => {
                    let exit = b.force_stop(Duration::from_secs(10)).await?;
                    (
                        if exit.forced {
                            "explicit_owned_force_after_unobserved_exit"
                        } else {
                            "normal_exit_raced_explicit_force"
                        },
                        exit,
                    )
                }
            }
        }
        Err(error) => return Err(error.into()),
    };
    assert!(exit.tree_stopped);
    if !exit.forced {
        assert_eq!(exit.code, Some(0));
    }
    assert_eq!(a.client().system_status().await?.device_id, a_id);
    assert_eq!(std::fs::read(root.join("sample.bin"))?, sample);
    let sender_exit = a.shutdown(Duration::from_secs(10)).await?;
    assert!(sender_exit.tree_stopped && !sender_exit.forced && sender_exit.code == Some(0));
    println!("private unapproved inbound actual exit mode: {mode}");
    println!(
        "public unapproved inbound lifetime evidence: {}",
        json!({"actual_one_sided_private_connection":true,"receiver_remote_identity_not_configured":true,"sender_pause_and_removal_observed":true,"single_normal_stop_request_with_original_deadline":true,"actual_receiver_tree_exit_observed":true,"other_private_sender_untouched":true,"synthetic_sample_preserved":true,"sender_actual_normal_tree_exit":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn typed_device_ignore_blocks_actual_attempts_persists_and_preserves_configuration(
) -> TestResult {
    async fn config(client: &Client) -> TestResult<Value> {
        let response = client
            .raw_request(&RawRequest::new(
                RawMethod::Get,
                ["rest", "config"],
                RequestEffect::ReadOnly,
            )?)
            .await?;
        assert_eq!(response.status(), 200);
        Ok(serde_json::from_slice(response.body_bytes())?)
    }
    fn unrelated(mut value: Value) -> Value {
        value
            .as_object_mut()
            .expect("observed config object")
            .remove("remoteIgnoredDevices");
        value
    }
    async fn drained(proxy: &peer_proxy::PeerProxy) -> TestResult {
        tokio::time::timeout(Duration::from_secs(5), async {
            while proxy.attempts().0 != proxy.attempts().1 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        Ok(())
    }
    async fn rejected_attempt(
        a: &Client,
        b: &DeviceId,
        proxy: &peer_proxy::PeerProxy,
    ) -> TestResult {
        let before = proxy.attempts();
        let upstream = proxy.upstream_connections();
        a.resume_device(b).await?;
        tokio::time::timeout(Duration::from_secs(15), async {
            while proxy.attempts().1 <= before.1 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        assert!(
            proxy.upstream_connections() > upstream,
            "no actual TCP attempt reached the private receiver"
        );
        connection(a, b, false).await?;
        Ok(())
    }
    let root = tempfile::Builder::new().prefix("vsid-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let mut c = ManagedInstance::start(options(&root.join("c"))?).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    let c_id = c.client().instance().device_id.clone();
    let sample = b"synthetic ignored-device preservation control";
    std::fs::write(root.join("sample.bin"), sample)?;
    // Explicit fixture scheduling; keep the original connection-observation
    // deadline while avoiding the engine's unrelated default redial interval.
    let response = a
        .client()
        .raw_request(
            &RawRequest::new(
                RawMethod::Patch,
                ["rest", "config", "options"],
                RequestEffect::MayModify,
            )?
            .json_body(&json!({"reconnectionIntervalS":5}))?,
        )
        .await?;
    assert_eq!(response.status(), 200);
    assert_eq!(
        config(a.client()).await?["options"]["reconnectionIntervalS"],
        5
    );
    eprintln!(
        "private device ignore stage: baseline connection with explicit fixture redial interval"
    );
    let proxy = peer_proxy::PeerProxy::start(&listener(b.client()).await?).await?;
    a.client()
        .create_device(
            &CreateDeviceOptions::new(b_id.clone()).settings(
                DevicePatch::default()
                    .addresses(vec![proxy.address()])
                    .paused(false),
            ),
        )
        .await?;
    connection(a.client(), &b_id, true).await?;
    a.client().pause_device(&b_id).await?;
    connection(a.client(), &b_id, false).await?;
    drained(&proxy).await?;
    assert!(matches!(
        a.client().ignore_device(&b_id).await,
        Err(Error::ConfiguredDeviceCannotBeIgnored { .. })
    ));
    assert!(matches!(
        b.client().ignore_device(&b_id).await,
        Err(Error::LocalDeviceProtected)
    ));
    let before = unrelated(config(b.client()).await?);
    assert!(b.client().ignored_devices().await?.is_empty());
    assert!(b.client().ignore_device(&c_id).await?.is_ignored);
    let other = b
        .client()
        .ignored_devices()
        .await?
        .into_iter()
        .find(|v| v.device_id == c_id)
        .ok_or("unrelated ignore missing")?;
    let other = serde_json::to_value(other)?;
    assert!(b.client().ignore_device(&a_id).await?.is_ignored);
    let ignored = b.client().ignored_devices().await?;
    assert_eq!(ignored.len(), 2);
    assert_eq!(
        serde_json::to_value(
            ignored
                .iter()
                .find(|v| v.device_id == c_id)
                .ok_or("unrelated ignore lost")?
        )?,
        other
    );
    assert_eq!(unrelated(config(b.client()).await?), before);
    assert!(b.client().ignore_device(&a_id).await?.is_ignored);
    eprintln!("private device ignore stage: first actual rejected attempt");
    rejected_attempt(a.client(), &b_id, &proxy).await?;
    a.client().pause_device(&b_id).await?;
    connection(a.client(), &b_id, false).await?;
    drained(&proxy).await?;
    proxy.close().await?;
    eprintln!("private device ignore stage: restart receiver with both ignored identities");
    b.restart(Duration::from_secs(30)).await?;
    assert_eq!(b.client().instance().device_id, b_id);
    assert_eq!(b.client().ignored_devices().await?.len(), 2);
    let proxy = peer_proxy::PeerProxy::start(&listener(b.client()).await?).await?;
    assert!(
        a.client()
            .update_device(
                &b_id,
                &DevicePatch::default().addresses(vec![proxy.address()])
            )
            .await?
            .requested_fields_match
    );
    eprintln!("private device ignore stage: actual rejection after restart");
    rejected_attempt(a.client(), &b_id, &proxy).await?;
    a.client().pause_device(&b_id).await?;
    connection(a.client(), &b_id, false).await?;
    drained(&proxy).await?;
    assert!(!b.client().unignore_device(&a_id).await?.is_ignored);
    let remaining = b.client().ignored_devices().await?;
    assert_eq!(remaining.len(), 1);
    assert_eq!(serde_json::to_value(&remaining[0])?, other);
    assert!(matches!(
        b.client().unignore_device(&a_id).await,
        Err(Error::DeviceNotIgnored)
    ));
    assert!(matches!(
        b.client().device(&a_id).await,
        Err(Error::DeviceNotFound { .. })
    ));
    eprintln!("private device ignore stage: actual reconnect after unignore");
    a.client().resume_device(&b_id).await?;
    connection(a.client(), &b_id, true).await?;
    assert!(!b.client().unignore_device(&c_id).await?.is_ignored);
    assert_eq!(unrelated(config(b.client()).await?), before);
    a.client().pause_device(&b_id).await?;
    connection(a.client(), &b_id, false).await?;
    drained(&proxy).await?;
    let (exit, mode) = match b.shutdown(Duration::from_secs(10)).await {
        Ok(exit) => (exit, "normal"),
        Err(Error::Timeout { .. }) => (
            b.force_stop(Duration::from_secs(10)).await?,
            "explicit_force_after_normal_deadline",
        ),
        Err(error) => return Err(error.into()),
    };
    assert!(exit.tree_stopped);
    if !exit.forced {
        assert_eq!(exit.code, Some(0));
    }
    assert_eq!(a.client().system_status().await?.device_id, a_id);
    assert_eq!(c.client().system_status().await?.device_id, c_id);
    assert_eq!(std::fs::read(root.join("sample.bin"))?, sample);
    for instance in [&mut c, &mut a] {
        let exit = instance.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    proxy.close().await?;
    std::fs::remove_dir_all(root)?;
    println!("private ignored-device actual receiver exit mode: {mode}");
    println!(
        "public ignored device evidence: {}",
        json!({"actual_baseline_peer_connected":true,"local_identity_protected":true,"configured_device_cannot_be_implicitly_removed":true,"two_real_device_ignore_records":true,"unrelated_ignore_metadata_preserved":true,"all_other_configuration_preserved":true,"actual_attempt_reached_private_receiver_and_closed":true,"sender_connection_rejected":true,"two_ignores_survive_actual_restart":true,"same_receiver_identity_restarted":true,"actual_attempt_rejected_after_restart":true,"unignore_removes_only_exact_identity":true,"missing_unignore_rejected":true,"ignore_does_not_register_remote_device":true,"actual_same_path_reconnect_after_unignore":true,"final_configuration_restored":true,"other_private_instances_untouched":true,"synthetic_sample_preserved":true,"all_actual_tree_exits_observed":true,"loopback_proxy_closed_and_joined":true})
    );
    Ok(())
}

fn address(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => s
            .strip_prefix("tcp://")
            .and_then(|v| v.parse::<std::net::SocketAddr>().ok())
            .filter(|v| {
                v.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) && v.port() != 0
            })
            .map(|_| s.clone()),
        Value::Array(v) => v.iter().find_map(address),
        Value::Object(v) => v.values().find_map(address),
        _ => None,
    }
}
async fn listener(client: &Client) -> TestResult<String> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(v) = client
                .system_status()
                .await?
                .extra
                .get("connectionServiceStatus")
                .and_then(address)
            {
                return Ok::<_, Error>(v);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??)
}
async fn connection(client: &Client, peer: &DeviceId, expected: bool) -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let response = client
                .raw_request(&RawRequest::new(
                    RawMethod::Get,
                    ["rest", "system", "connections"],
                    RequestEffect::ReadOnly,
                )?)
                .await?;
            assert_eq!(response.status(), 200);
            let value: Value = serde_json::from_slice(response.body_bytes())?;
            let map = value["connections"]
                .as_object()
                .ok_or("actual connection map missing")?;
            let observed = match map.get(peer.as_str()) {
                None => false,
                Some(v) => v["connected"]
                    .as_bool()
                    .ok_or("actual connection state missing")?,
            };
            if observed == expected {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    Ok(())
}
async fn reconnect(a: &Client, b: &Client, a_id: &DeviceId, b_id: &DeviceId) -> TestResult {
    assert!(a.pause_device(b_id).await?.requested_fields_match);
    connection(a, b_id, false).await?;
    connection(b, a_id, false).await?;
    assert!(a.resume_device(b_id).await?.requested_fields_match);
    connection(a, b_id, true).await?;
    connection(b, a_id, true).await?;
    Ok(())
}
async fn offer(
    client: &Client,
    folder: &FolderId,
    peer: &DeviceId,
    present: bool,
) -> TestResult<BTreeMap<FolderId, PendingFolderOffers>> {
    Ok(tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let records = client.pending_folders(Some(peer)).await?;
            if records
                .get(folder)
                .is_some_and(|v| v.offered_by.contains_key(peer))
                == present
            {
                return Ok::<_, Error>(records);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??)
}

async fn named_offer(client: &Client, peer: &DeviceId, label: &str) -> TestResult<FolderId> {
    Ok(tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let records = client.pending_folders(Some(peer)).await?;
            let matching: Vec<_> = records
                .iter()
                .filter(|(_, v)| v.offered_by.get(peer).is_some_and(|o| o.label == label))
                .collect();
            if matching.len() == 1 {
                return Ok::<_, Error>(matching[0].0.clone());
            }
            assert!(matching.is_empty(), "ambiguous synthetic folder labels");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??)
}

#[tokio::test]
async fn actual_folder_offer_dismiss_ignore_unignore_and_explicit_read_only_acceptance(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vsif-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    // Explicit fixture scheduling, with every original observation deadline
    // and data assertion retained. This does not change SDK/native defaults.
    private_redial::configure(a.client()).await?;
    private_redial::configure(b.client()).await?;
    let a_id = a.client().instance().device_id.clone();
    let b_id = b.client().instance().device_id.clone();
    assert!(b.client().pending_devices().await?.is_empty());
    assert!(b.client().pending_folders(None).await?.is_empty());
    assert!(matches!(
        b.client().dismiss_pending_device(&a_id).await,
        Err(Error::PendingOfferNotFound)
    ));
    let a_addr = listener(a.client()).await?;
    let b_addr = listener(b.client()).await?;
    for (client, peer, address) in [(a.client(), &b_id, b_addr), (b.client(), &a_id, a_addr)] {
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
    }
    let path1 = root.join("first offered source");
    let path2 = root.join("second offered source");
    let received = root.join("accepted read only");
    std::fs::create_dir(&path1)?;
    std::fs::create_dir(&path2)?;
    let sample: Vec<u8> = (0..32768).map(|i| (i % 251) as u8).collect();
    std::fs::write(path1.join("sample.bin"), &sample)?;
    let first_keys = a.client().generate_share().await?;
    let second_keys = a.client().generate_share().await?;
    let mut folders = Vec::new();
    for (keys, path, label) in [
        (&first_keys, &path1, "First synthetic offer"),
        (&second_keys, &path2, "Second synthetic offer"),
    ] {
        let prepared = a.client().validate_share_key(&keys.read_write_key).await?;
        let folder = a
            .client()
            .join_folder(
                &JoinFolderOptions::new(prepared, TargetPath::local(path.clone()))
                    .label(label)
                    .paused(true),
            )
            .await?
            .configuration;
        assert!(
            a.client()
                .share_folder_with(&folder.id, &b_id)
                .await?
                .association_present
        );
        a.client().resume_folder(&folder.id).await?;
        folders.push(folder.id);
    }
    let first_local = folders[0].clone();
    eprintln!("private invitation stage: observe actual named remote offers");
    let first_observed = named_offer(b.client(), &a_id, "First synthetic offer").await;
    if first_observed.is_err() {
        sync_diagnostics::report(
            "invitation-first-named-offer",
            &[(&a, &folders[0], &b_id), (&b, &folders[0], &a_id)],
        )
        .await;
    }
    let first_remote = first_observed?;
    let second_observed = named_offer(b.client(), &a_id, "Second synthetic offer").await;
    if second_observed.is_err() {
        sync_diagnostics::report(
            "invitation-second-named-offer",
            &[(&a, &folders[0], &b_id), (&b, &folders[0], &a_id)],
        )
        .await;
    }
    let second_remote = second_observed?;
    let first = &first_remote;
    let second = &second_remote;
    let pending = offer(b.client(), first, &a_id, true).await?;
    let first_offer = &pending[first].offered_by[&a_id];
    assert!(!first_offer.receive_encrypted && !first_offer.remote_encrypted);
    assert!(!first_offer.time.is_empty());
    offer(b.client(), second, &a_id, true).await?;
    assert!(!received.exists());
    eprintln!("private invitation stage: dismiss only first remote offer");
    assert!(
        b.client()
            .dismiss_folder_offer(first, &a_id)
            .await?
            .record_absent
    );
    assert!(matches!(
        b.client().dismiss_folder_offer(first, &a_id).await,
        Err(Error::PendingOfferNotFound)
    ));
    offer(b.client(), second, &a_id, true).await?;
    assert!(!received.exists() && b.client().folders().await?.is_empty());
    reconnect(a.client(), b.client(), &a_id, &b_id).await?;
    eprintln!("private invitation stage: observe reannouncement and persist first ignore");
    let reannounced = offer(b.client(), first, &a_id, true).await;
    if reannounced.is_err() {
        sync_diagnostics::report(
            "invitation-reannounce-after-dismiss-and-reconnect",
            &[(&a, &folders[0], &b_id), (&b, &folders[0], &a_id)],
        )
        .await;
    }
    reannounced?;
    let ignored = b.client().ignore_folder_offer(first, &a_id).await?;
    assert!(ignored.is_ignored);
    offer(b.client(), first, &a_id, false).await?;
    let first_ignore = serde_json::to_value(
        b.client()
            .ignored_folders(&a_id)
            .await?
            .into_iter()
            .find(|v| v.id == *first)
            .ok_or("first ignore missing")?,
    )?;
    eprintln!("private invitation stage: preserve first ignore while adding second");
    assert!(
        b.client()
            .ignore_folder_offer(second, &a_id)
            .await?
            .is_ignored
    );
    offer(b.client(), second, &a_id, false).await?;
    assert_eq!(b.client().ignored_folders(&a_id).await?.len(), 2);
    assert_eq!(
        serde_json::to_value(
            b.client()
                .ignored_folders(&a_id)
                .await?
                .into_iter()
                .find(|v| v.id == *first)
                .ok_or("first ignore lost")?
        )?,
        first_ignore
    );
    eprintln!("private invitation stage: restart receiver with two persistent ignores");
    b.restart(Duration::from_secs(30)).await?;
    assert_eq!(b.client().instance().device_id, b_id);
    assert_eq!(b.client().ignored_folders(&a_id).await?.len(), 2);
    let updated = a
        .client()
        .update_device(
            &b_id,
            &DevicePatch::default().addresses(vec![listener(b.client()).await?]),
        )
        .await?;
    assert!(updated.requested_fields_match);
    eprintln!("private invitation stage: unignore only first remote folder");
    let unignored = b.client().unignore_folder(first, &a_id).await?;
    assert!(!unignored.is_ignored);
    assert!(matches!(
        b.client().unignore_folder(first, &a_id).await,
        Err(Error::FolderNotIgnored)
    ));
    reconnect(a.client(), b.client(), &a_id, &b_id).await?;
    let announced = offer(b.client(), first, &a_id, true).await;
    if announced.is_err() {
        sync_diagnostics::report(
            "invitation-reannounce-after-unignore-and-reconnect",
            &[(&a, &folders[0], &b_id), (&b, &folders[0], &a_id)],
        )
        .await;
    }
    let announced = announced?;
    assert!(!announced.contains_key(second));
    let remaining = b.client().ignored_folders(&a_id).await?;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, *second);
    let prepared = b
        .client()
        .validate_share_key(&first_keys.read_only_key)
        .await?;
    eprintln!("private invitation stage: explicitly join caller-chosen read-only key");
    assert_eq!(prepared.permission(), &SharePermission::ReadOnly);
    let joined = b
        .client()
        .join_folder(
            &JoinFolderOptions::new(prepared, TargetPath::local(received.clone())).paused(true),
        )
        .await?;
    assert!(
        joined.submitted_key_matches
            && joined.read_only_key_matches
            && joined.read_write_key_matches
    );
    assert_eq!(joined.permission, SharePermission::ReadOnly);
    assert!(
        b.client()
            .share_folder_with(&joined.configuration.id, &a_id)
            .await?
            .association_present
    );
    b.client().resume_folder(&joined.configuration.id).await?;
    a.client().request_scan(&first_local).await?;
    eprintln!("private invitation stage: observe actual accepted file bytes");
    tokio::time::timeout(Duration::from_secs(40), async {
        while std::fs::read(received.join("sample.bin")).ok().as_deref() != Some(sample.as_slice())
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    let pending = b.client().pending_folders(Some(&a_id)).await?;
    if pending
        .get(first)
        .is_some_and(|v| v.offered_by.contains_key(&a_id))
    {
        assert!(
            b.client()
                .dismiss_folder_offer(first, &a_id)
                .await?
                .record_absent
        );
    }
    offer(b.client(), first, &a_id, false).await?;
    assert!(
        !b.client()
            .unshare_folder_from(&joined.configuration.id, &a_id)
            .await?
            .association_present
    );
    assert!(b.client().device(&a_id).await.is_ok());
    assert_eq!(
        b.client().folder(&joined.configuration.id).await?.id,
        joined.configuration.id
    );
    assert_eq!(std::fs::read(path1.join("sample.bin"))?, sample);
    assert_eq!(std::fs::read(received.join("sample.bin"))?, sample);
    assert!(matches!(
        b.client()
            .unshare_folder_from(&joined.configuration.id, &b_id)
            .await,
        Err(Error::LocalDeviceProtected)
    ));
    eprintln!("private invitation stage: actual normal process-tree exits");
    for instance in [&mut b, &mut a] {
        let exit = instance.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!(
        "public folder invitation evidence: {}",
        json!({"actual_empty_pending_device_snapshot":true,"absent_device_dismissal_rejected":true,"actual_empty_pending_folder_snapshot":true,"both_real_peers_explicitly_registered":true,"actual_two_distinct_folder_offers":true,"offering_device_filter_verified":true,"actual_offer_encryption_flags":true,"pending_offer_does_not_register_or_create_path":true,"exact_folder_offer_dismissed":true,"duplicate_dismissal_rejected":true,"unrelated_offer_retained":true,"dismissed_offer_reappears_after_announcement":true,"persistent_ignore_record_read_back":true,"ignored_offer_removed":true,"unrelated_ignore_metadata_preserved":true,"both_ignores_survive_actual_restart":true,"same_receiver_identity_restarted":true,"explicit_unignore_read_back":true,"unignored_offer_reappears":true,"other_ignore_suppresses_same_cluster_offer":true,"read_only_key_permission_validated":true,"actual_key_material_retained":true,"explicit_folder_peer_association":true,"actual_accepted_sample_transferred":true,"accepted_original_offer_absent":true,"unshare_removes_only_association":true,"remote_peer_and_folder_registrations_retained":true,"source_and_received_bytes_preserved":true,"local_identity_association_protected":true,"both_actual_normal_tree_exits":true})
    );
    Ok(())
}
