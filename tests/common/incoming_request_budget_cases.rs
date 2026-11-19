//! Native signed selections and real transfer, without a memory-cap inference.
use super::managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::*;

#[tokio::test]
async fn native_signed_incoming_request_budgets_survive_restart_and_real_transfers() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vsincoming-")
        .tempdir()?
        .keep();
    let sentinel = root.join("caller-sentinel");
    std::fs::write(&sentinel, b"signed request budget caller data")?;
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    // Freeze names before connecting; native adoption must not mutate the
    // unrelated-device protection baseline during these budget checks.
    for core in [&a, &b] {
        assert!(
            core.client()
                .update_general_options(
                    &GeneralOptionsPatch::default().overwrite_remote_device_names_on_connect(false),
                )
                .await?
                .requested_fields_match
        );
    }
    let aid = a.client().instance().device_id.clone();
    let bid = b.client().instance().device_id.clone();
    let protected = ["key.pem", "cert.pem"];
    let original_a = protected
        .iter()
        .map(|n| std::fs::read(a.state_directory().join(n)))
        .collect::<std::io::Result<Vec<_>>>()?;
    let original_b = protected
        .iter()
        .map(|n| std::fs::read(b.state_directory().join(n)))
        .collect::<std::io::Result<Vec<_>>>()?;
    let address = super::configuration_policy_listener(&b).await?;
    for (client, peer, addresses) in [
        (a.client(), &bid, vec![format!("tcp://{address}")]),
        (b.client(), &aid, vec!["dynamic".into()]),
    ] {
        client
            .create_device(
                &CreateDeviceOptions::new(peer.clone()).settings(
                    DevicePatch::default()
                        .name("controlled incoming-budget peer")
                        .addresses(addresses)
                        .allowed_transports(vec![DeviceTransport::Tcp]),
                ),
            )
            .await?;
    }
    let source = root.join("source");
    let received = root.join("received");
    std::fs::create_dir(&source)?;
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_only_key).await?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(&source)))
        .await?;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(&received)))
        .await?;
    a.client()
        .share_folder_with(&af.configuration.id, &bid)
        .await?;
    b.client()
        .share_folder_with(&bf.configuration.id, &aid)
        .await?;
    let before = a.client().configuration().await?;
    let mut payloads = Vec::new();
    for (phase, selected) in [-1_i64, 0, 32768].into_iter().enumerate() {
        let patch = GeneralOptionsPatch::default().max_concurrent_incoming_request_kib(selected);
        if phase == 1 {
            let mut snapshot = a.client().configuration().await?;
            snapshot.set_general_options(&patch)?;
            assert!(
                a.client()
                    .replace_configuration(&snapshot)
                    .await?
                    .requested_fields_match
            );
        } else {
            assert!(
                a.client()
                    .update_general_options(&patch)
                    .await?
                    .requested_fields_match
            );
        }
        assert_eq!(
            a.client()
                .general_options()
                .await?
                .max_concurrent_incoming_request_kib,
            selected
        );
        a.restart(Duration::from_secs(30)).await?;
        assert_eq!(
            a.client()
                .general_options()
                .await?
                .max_concurrent_incoming_request_kib,
            selected
        );
        super::name_policy_connection_pair(&a, &b, true).await?;
        let name = format!("signed-budget-{phase}-二 %.bin");
        let bytes: Vec<u8> = (0..32768).map(|i| ((i + phase) % 251) as u8).collect();
        std::fs::write(source.join(&name), &bytes)?;
        a.client().request_scan(&af.configuration.id).await?;
        tokio::time::timeout(Duration::from_secs(30), async {
            while !std::fs::read(received.join(&name)).is_ok_and(|x| x == bytes) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await?;
        payloads.push((name, bytes));
        println!(
            "native signed incoming budget evidence: {}",
            serde_json::json!({
                "selected":selected,"actual_signed_patch_or_complete_save_and_readback":true,
                "actual_normal_restart_retained_signed_selection":true,
                "actual_authenticated_owned_peer_and_new_file_transfer":true,
                "complete_snapshot_save_used":phase==1,"actual_transferred_bytes":32768,
                "concurrent_request_memory_cap_measured":false,"throughput_improvement_claimed":false
            })
        );
    }
    let after = a.client().configuration().await?;
    for section in ["folders", "devices", "gui", "defaults", "ldap"] {
        assert!(
            before.native_document()[section] == after.native_document()[section],
            "unrelated native section changed: {section}"
        );
    }
    for (core, id, original) in [(&a, &aid, &original_a), (&b, &bid, &original_b)] {
        assert_eq!(&core.client().system_status().await?.device_id, id);
        for (file, bytes) in protected.iter().zip(original) {
            assert!(
                std::fs::read(core.state_directory().join(file))? == *bytes,
                "owned credential bytes changed"
            );
        }
    }
    for (name, bytes) in payloads {
        assert_eq!(std::fs::read(source.join(&name))?, bytes);
        assert_eq!(std::fs::read(received.join(name))?, bytes);
    }
    assert_eq!(
        std::fs::read(sentinel)?,
        b"signed request budget caller data"
    );
    for core in [&mut a, &mut b] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    }
    std::fs::remove_dir_all(root)?;
    println!("native signed incoming budget cleanup evidence: actual_three_source_receiver_payloads_identity_keys_certificates_sentinel_retained=true actual_unrelated_configuration_retained=true actual_both_normal_owned_tree_and_state_exit=true no_limiter_memory_or_performance_inference=true");
    Ok(())
}
