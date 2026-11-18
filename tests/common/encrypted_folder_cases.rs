//! Verify the initial receive-encrypted settings and peer-side secret contract.
use super::{configuration_policy_listener, options, TestResult};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, time::Duration};
use verysync_sidecar::*;

fn receive_payloads(path: &Path, sample: &[u8]) -> TestResult<(Vec<[u8; 32]>, bool)> {
    let mut pending = vec![path.to_path_buf()];
    let mut digests = Vec::new();
    let mut saw_plaintext = false;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir()
                && !matches!(entry.file_name().to_str(), Some(".verysync" | ".stfolder"))
            {
                pending.push(entry.path());
            } else if kind.is_file() {
                let body = fs::read(entry.path())?;
                if !body.is_empty() {
                    digests.push(Sha256::digest(&body).into());
                }
                saw_plaintext |= body.windows(sample.len()).any(|bytes| bytes == sample);
            }
        }
    }
    digests.sort_unstable();
    Ok((digests, saw_plaintext))
}

#[tokio::test]
async fn native_receive_encrypted_group_keeps_registration_and_peer_setting() -> TestResult {
    let root = tempfile::Builder::new().prefix("vs-enc-").tempdir()?.keep();
    let source = root.join("source");
    let stored = root.join("stored");
    fs::create_dir(&source)?;
    fs::create_dir(&stored)?;
    let sentinel = root.join("caller-sentinel");
    fs::write(&sentinel, b"unrelated caller data")?;
    let mut sender = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut receiver = ManagedInstance::start(options(&root.join("b"))?).await?;
    let sender_id = sender.client().instance().device_id.clone();
    let receiver_id = receiver.client().instance().device_id.clone();
    assert_ne!(sender_id, receiver_id);
    let folder_id = FolderId::parse("903369745331104675")?;
    let send = sender
        .client()
        .create_folder(
            &CreateFolderOptions::new(folder_id.clone(), TargetPath::local(&source)).paused(true),
        )
        .await?;
    let receive = receiver
        .client()
        .create_folder(
            &CreateFolderOptions::new(folder_id, TargetPath::local(&stored))
                .paused(true)
                .advanced_configuration(
                    FolderAdvancedPatch::default().folder_type(FolderType::ReceiveEncrypted),
                )?,
        )
        .await?;
    let receive_type = receive.advanced_configuration()?.folder_type;
    let address = configuration_policy_listener(&receiver).await?;
    for (client, peer, endpoint, directory) in [
        (
            sender.client(),
            &receiver_id,
            format!("tcp://{address}"),
            &send.id,
        ),
        (receiver.client(), &sender_id, "dynamic".into(), &receive.id),
    ] {
        let peer_options = DevicePatch::default()
            .addresses(vec![endpoint])
            .allowed_transports(vec![DeviceTransport::Tcp])
            .paused(true);
        assert!(
            client
                .create_device(&CreateDeviceOptions::new(peer.clone()).settings(peer_options))
                .await?
                .requested_fields_match
        );
        assert!(
            client
                .share_folder_with(directory, peer)
                .await?
                .association_present
        );
    }
    let synthetic_password = "private isolated receive-encrypted fixture password";
    let encryption = sender
        .client()
        .set_folder_peer_encryption_password(&send.id, &receiver_id, Some(synthetic_password))
        .await?;
    let retained =
        encryption.requested_password_matches && encryption.password_is_set == Some(true);
    let sample = b"isolated source cleartext sample";
    let fixture = sample.repeat(4096);
    let name = "contains-plain-source.bin";
    let mut payload_observation = None;
    if receive_type == Some(FolderType::ReceiveEncrypted) && retained {
        let mark_untrusted = DevicePatch::default()
            .advanced_configuration(DeviceAdvancedPatch::default().untrusted(true))?;
        assert!(
            sender
                .client()
                .update_device(&receiver_id, &mark_untrusted)
                .await?
                .requested_fields_match
        );
        fs::write(source.join(name), &fixture)?;
        sender.client().resume_folder(&send.id).await?;
        receiver.client().resume_folder(&receive.id).await?;
        sender.client().resume_device(&receiver_id).await?;
        receiver.client().resume_device(&sender_id).await?;
        let result = tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                let status = receiver.client().folder_status(&receive.id).await?;
                let (files, plaintext) = receive_payloads(&stored, sample)?;
                if status.local_files == Some(1)
                    && status.global_files == Some(1)
                    && status.need_bytes == Some(0)
                    && status.state == Some(FolderState::Idle)
                    && !files.is_empty()
                {
                    return TestResult::Ok((files.len(), plaintext, stored.join(name).exists()));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        if let Ok(observed) = result {
            payload_observation = Some(observed?);
        }
        assert_eq!(fs::read(source.join(name))?, fixture);
    }
    assert_eq!(fs::read(sentinel)?, b"unrelated caller data");
    let stop = sender.shutdown(Duration::from_secs(10)).await?;
    assert!(stop.code == Some(0) && stop.tree_stopped && stop.state_released && !stop.forced);
    let mut exact_recovery_after_source_exit = false;
    let mut third_normal_exit = false;
    let mut password_clear_matches = false;
    let mut wrong_password_rejected = false;
    let mut wrong_password_no_file = false;
    let mut ciphertext_preserved = false;
    let mut restarter_retained_identity = false;
    if payload_observation == Some((1, false, false)) {
        let original_replica = receive_payloads(&stored, sample)?;
        assert_eq!(original_replica.0.len(), 1);
        assert!(!original_replica.1);
        eprintln!("native encrypted phase: recover from only the remaining encrypted peer");
        let recovered = root.join("recovered");
        fs::create_dir(&recovered)?;
        let mut restore = ManagedInstance::start(options(&root.join("c"))?).await?;
        let restorer_id = restore.client().instance().device_id.clone();
        assert_ne!(restorer_id, sender_id);
        assert_ne!(restorer_id, receiver_id);
        let local = restore
            .client()
            .create_folder(
                &CreateFolderOptions::new(receive.id.clone(), TargetPath::local(&recovered))
                    .paused(true),
            )
            .await?;
        let remote = DevicePatch::default()
            .addresses(vec![format!("tcp://{address}")])
            .allowed_transports(vec![DeviceTransport::Tcp])
            .paused(true);
        assert!(
            restore
                .client()
                .create_device(&CreateDeviceOptions::new(receiver_id.clone()).settings(remote))
                .await?
                .requested_fields_match
        );
        assert!(
            restore
                .client()
                .share_folder_with(&local.id, &receiver_id)
                .await?
                .association_present
        );
        let reciprocal = DevicePatch::default()
            .addresses(vec!["dynamic".into()])
            .allowed_transports(vec![DeviceTransport::Tcp])
            .paused(true);
        assert!(
            receiver
                .client()
                .create_device(&CreateDeviceOptions::new(restorer_id.clone()).settings(reciprocal))
                .await?
                .requested_fields_match
        );
        assert!(
            receiver
                .client()
                .share_folder_with(&receive.id, &restorer_id)
                .await?
                .association_present
        );
        let wrong_password = "independent incorrect fixture password";
        let configured = restore
            .client()
            .set_folder_peer_encryption_password(&local.id, &receiver_id, Some(wrong_password))
            .await?;
        assert!(configured.requested_password_matches);
        assert_eq!(configured.password_is_set, Some(true));
        let mark_untrusted = DevicePatch::default()
            .advanced_configuration(DeviceAdvancedPatch::default().untrusted(true))?;
        assert!(
            restore
                .client()
                .update_device(&receiver_id, &mark_untrusted)
                .await?
                .requested_fields_match
        );

        assert!(!recovered.join(name).exists());
        restore.client().resume_folder(&local.id).await?;
        receiver.client().resume_device(&restorer_id).await?;
        restore.client().resume_device(&receiver_id).await?;
        eprintln!("native encrypted phase: wrong password on the fresh restorer");
        if let Ok(result) = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let log = restore.client().core_log(None).await?;
                for entry in log.messages.into_iter().flatten() {
                    let lower = entry.message.to_ascii_lowercase();
                    if lower.contains("encrypt")
                        && lower.contains("password")
                        && [
                            "mismatch",
                            "does not match",
                            "doesn't match",
                            "different",
                            "incorrect",
                            "verification failed",
                        ]
                        .iter()
                        .any(|fragment| lower.contains(fragment))
                    {
                        let words = entry
                            .message
                            .replace(&*root.to_string_lossy(), "<fixture>")
                            .replace(synthetic_password, "<synthetic password>")
                            .replace(wrong_password, "<incorrect synthetic password>")
                            .replace(restorer_id.as_str(), "<restorer>")
                            .replace(receiver_id.as_str(), "<replica>");
                        eprintln!("native encrypted rejection: {words}");
                        return TestResult::Ok(true);
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        {
            wrong_password_rejected = result?;
        }
        if !wrong_password_rejected {
            let log = restore.client().core_log(None).await?;
            for entry in log
                .messages
                .into_iter()
                .flatten()
                .filter(|entry| {
                    let lower = entry.message.to_ascii_lowercase();
                    lower.contains("encrypt") || lower.contains("password")
                })
                .take(4)
            {
                eprintln!(
                    "native encrypted owned-peer diagnostic: {}",
                    entry
                        .message
                        .replace(&*root.to_string_lossy(), "<fixture>")
                        .replace(synthetic_password, "<synthetic password>")
                        .replace(wrong_password, "<incorrect synthetic password>")
                        .replace(restorer_id.as_str(), "<restorer>")
                        .replace(receiver_id.as_str(), "<replica>")
                );
            }
        }
        wrong_password_no_file =
            !recovered.join(name).exists() && receive_payloads(&recovered, sample)?.0.is_empty();
        assert_eq!(receive_payloads(&stored, sample)?, original_replica);

        restore.client().pause_folder(&local.id).await?;
        assert!(
            restore
                .client()
                .pause_device(&receiver_id)
                .await?
                .configuration
                .paused
        );
        assert!(
            receiver
                .client()
                .pause_device(&restorer_id)
                .await?
                .configuration
                .paused
        );
        let corrected = restore
            .client()
            .set_folder_peer_encryption_password(&local.id, &receiver_id, Some(synthetic_password))
            .await?;
        assert!(corrected.requested_password_matches && corrected.password_is_set == Some(true));
        eprintln!("native encrypted phase: restart with the corrected password");
        restore.restart(Duration::from_secs(20)).await?;
        restarter_retained_identity = restore.client().instance().device_id == restorer_id;
        assert!(restarter_retained_identity);
        restore.client().resume_folder(&local.id).await?;
        receiver.client().resume_device(&restorer_id).await?;
        restore.client().resume_device(&receiver_id).await?;
        if let Ok(checked) = tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                if recovered.join(name).is_file()
                    && fs::read(recovered.join(name))? == fixture
                    && restore.client().folder_status(&local.id).await?.need_bytes == Some(0)
                {
                    return TestResult::Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        {
            checked?;
            exact_recovery_after_source_exit = true;
        }
        ciphertext_preserved = receive_payloads(&stored, sample)? == original_replica;
        restore.client().pause_folder(&local.id).await?;
        assert!(
            restore
                .client()
                .pause_device(&receiver_id)
                .await?
                .configuration
                .paused
        );
        let clear_untrusted = DevicePatch::default()
            .advanced_configuration(DeviceAdvancedPatch::default().untrusted(false))?;
        assert!(
            restore
                .client()
                .update_device(&receiver_id, &clear_untrusted)
                .await?
                .requested_fields_match
        );
        let cleared = restore
            .client()
            .set_folder_peer_encryption_password(&local.id, &receiver_id, None)
            .await?;
        password_clear_matches =
            cleared.requested_password_matches && cleared.password_is_set == Some(false);
        assert_eq!(
            restore
                .client()
                .folder_peer_encryption_password_is_set(&local.id, &receiver_id)
                .await?,
            cleared.password_is_set
        );
        assert_eq!(fs::read(recovered.join(name))?, fixture);
        let stop = restore.shutdown(Duration::from_secs(10)).await?;
        assert!(stop.code == Some(0) && stop.tree_stopped && stop.state_released && !stop.forced);
        third_normal_exit = true;
    }
    let stop = receiver.shutdown(Duration::from_secs(10)).await?;
    assert!(stop.code == Some(0) && stop.tree_stopped && stop.state_released && !stop.forced);
    fs::remove_dir_all(root)?;
    println!(
        "native encrypted registration effects: {}",
        serde_json::json!({
                "created_receive_encrypted": receive_type == Some(FolderType::ReceiveEncrypted),
        "registered_identical_explicit_folder_ids": send.id == receive.id,
            "typed_password_clear_matches": password_clear_matches,
            "owned_peer_exact_password_retained": retained,
        "received_nonempty_files_plaintext_fragment_plaintext_path": payload_observation,
            "exact_recovery_after_source_exit": exact_recovery_after_source_exit,
            "wrong_password_native_rejection": wrong_password_rejected,
            "wrong_password_left_empty_restore_target": wrong_password_no_file,
            "ciphertext_preserved_across_failed_and_successful_restore": ciphertext_preserved,
            "restarter_retained_identity": restarter_retained_identity,
            "three_normal_owned_exits": third_normal_exit,
        })
    );
    assert_eq!(receive_type, Some(FolderType::ReceiveEncrypted));
    assert!(
        retained,
        "owned peer encryption field did not survive actual readback"
    );
    assert_eq!(
        payload_observation,
        Some((1, false, false)),
        "no exact encrypted native file effect"
    );
    assert!(
        exact_recovery_after_source_exit,
        "trusted receiver did not restore exact bytes from the encrypted replica"
    );
    assert!(
        password_clear_matches,
        "native password clear did not have exact readback"
    );
    assert!(
        wrong_password_rejected,
        "native rejection evidence for wrong password is absent"
    );
    assert!(wrong_password_no_file, "incorrect password produced a file");
    assert!(
        ciphertext_preserved,
        "replica bytes changed during recovery"
    );
    Ok(())
}
