//! Actual version retention and restoration through public Rust APIs.
#[path = "common/storage_service.rs"]
mod archive_storage_service;
#[path = "common/ftp_archive_scope.rs"]
mod ftp_archive_scope;
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::{path::Path, time::Duration};
use verysync_sidecar::{
    CreateDeviceOptions, DevicePatch, DeviceTransport, FileVersionRestore, FolderVersioningPolicy,
    JoinFolderOptions, ManagedInstance, OperationCompletion, OperationOptions,
    RestoreFileExpectation, TargetPath, VerifiedRestoreSelection,
};

#[tokio::test]
async fn public_remote_sftp_archive_location_retains_and_restores_versions() -> TestResult {
    remote_archive_case(verysync_sidecar::StorageProtocol::Sftp, false).await
}
#[tokio::test]
async fn public_remote_sftp_key_file_archive_authenticates_without_password_fallback() -> TestResult
{
    remote_archive_case(verysync_sidecar::StorageProtocol::Sftp, true).await
}
#[tokio::test]
async fn public_remote_ftp_archive_location_checks_first_generation_boundary() -> TestResult {
    remote_archive_case(verysync_sidecar::StorageProtocol::Ftp, false).await
}
fn ftp_peer_events(peer: &archive_storage_service::Service) -> TestResult<(bool, Vec<String>)> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(&peer.observation_log)?
        .take(65537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("owned FTP observation exceeds its byte bound".into());
    }
    let text = std::str::from_utf8(&bytes)?;
    for field in ["user", "password"] {
        let credential = peer
            .endpoint
            .extra()
            .get(field)
            .and_then(|value| value.as_str())
            .ok_or("explicit synthetic FTP credential missing")?;
        if text.contains(credential) {
            return Err("owned FTP observation disclosed a credential".into());
        }
    }
    let mut authenticated = false;
    let mut commands = Vec::new();
    for line in text.lines() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            if value["owned_ftp_event"] == "authenticated" {
                authenticated = true;
            } else if value["owned_ftp_event"] == "command" {
                if let Some(command) = value["command"].as_str() {
                    commands.push(command.to_owned());
                }
            }
        }
    }
    Ok((authenticated, commands))
}

fn sftp_peer_auth(
    peer: &archive_storage_service::Service,
) -> TestResult<(usize, usize, std::collections::BTreeSet<u64>)> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(&peer.observation_log)?
        .take(65537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("owned SFTP observation exceeds bound".into());
    }
    let text = std::str::from_utf8(&bytes)?;
    for field in ["user", "password"] {
        let credential = peer.endpoint.extra()[field]
            .as_str()
            .ok_or("synthetic SFTP credential")?;
        assert!(
            !text.contains(credential),
            "peer observation must omit credentials"
        );
    }
    assert!(!text.contains("PRIVATE KEY"));
    let mut accepted = 0;
    let mut rejected = 0;
    let mut sessions = std::collections::BTreeSet::new();
    for line in text.lines() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            if value["owned_sftp_auth"] == "publickey" {
                if value["accepted"] == true {
                    accepted += 1;
                } else if value["accepted"] == false {
                    rejected += 1;
                }
            } else if value["owned_sftp_auth"] == "password" {
                assert_eq!(
                    value["accepted"], false,
                    "key-only peer cannot accept password fallback"
                );
            } else if value["owned_sftp_session"] == true {
                sessions.insert(
                    value["connection_id"]
                        .as_u64()
                        .ok_or("bounded peer connection identity")?,
                );
            }
        }
    }
    Ok((accepted, rejected, sessions))
}

async fn remote_archive_case(
    protocol: verysync_sidecar::StorageProtocol,
    key_auth: bool,
) -> TestResult {
    use verysync_sidecar::VersionArchiveLocation;
    let root = tempfile::Builder::new().prefix("varc-").tempdir()?.keep();
    let mut peer = if key_auth {
        archive_storage_service::Service::start_key_only_sftp(&root.join("peer"))?
    } else if protocol == verysync_sidecar::StorageProtocol::Ftp {
        archive_storage_service::Service::start_observed_ftp(&root.join("peer"))?
    } else {
        archive_storage_service::Service::start(protocol, &root.join("peer"), Duration::ZERO)?
    };
    let archive = peer.share.join("archive");
    let key_file = root.join("peer").join("key 路径 %.pem");
    let mut key_bytes = None;
    if key_auth {
        std::fs::copy(
            root.join("peer").join("synthetic-client-key.pem"),
            &key_file,
        )?;
        key_bytes = Some(std::fs::read(&key_file)?);
    }
    std::fs::create_dir(&archive)?;
    assert_eq!(std::fs::read_dir(&archive)?.count(), 0);
    let mut uri = url::Url::parse(peer.endpoint.uri())?;
    uri.set_username(peer.endpoint.extra()["user"].as_str().ok_or("peer user")?)
        .map_err(|_| "synthetic URI user")?;
    uri.set_password(if key_auth {
        None
    } else {
        peer.endpoint.extra()["password"].as_str()
    })
    .map_err(|_| "synthetic URI password")?;
    uri.set_path("/archive");
    if key_auth {
        uri.query_pairs_mut().append_pair(
            "privateKey",
            key_file.to_str().ok_or("synthetic UTF-8 key path")?,
        );
        uri.query_pairs_mut()
            .append_pair("parallelConnections", "1")
            .append_pair("sftpChannels", "2")
            .append_pair("connectTimeout", "6");
    }
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let source = root.join("source");
    let receive = root.join("receive");
    std::fs::create_dir(&source)?;
    let name = if protocol == verysync_sidecar::StorageProtocol::Ftp {
        "archive-ascii.txt"
    } else {
        "archive 二 %.txt"
    };
    let old = b"retained original archive bytes";
    let new = b"new remote content with a different length";
    std::fs::write(source.join(name), old)?;
    let (af, bf) = register(&a, &b, &source, &receive).await?;
    b.client()
        .set_folder_versioning(
            &bf.id,
            FolderVersioningPolicy::Simple {
                keep: 3,
                cleanout_days: 0,
                cleanup_interval_seconds: 3600,
            },
        )
        .await?;
    let prior = b.client().folder_versioning(&bf.id).await?;
    if key_auth {
        let mut wrong = uri.clone();
        wrong.set_query(None);
        wrong.query_pairs_mut().append_pair(
            "privateKey",
            root.join("peer")
                .join("synthetic-host-key.pem")
                .to_str()
                .ok_or("synthetic UTF-8 wrong key path")?,
        );
        let update = b
            .client()
            .set_version_archive_location(
                &bf.id,
                &VersionArchiveLocation::remote_uri(wrong.as_str())?,
            )
            .await?;
        assert!(update.requested_fields_match);
        let error = b.client().folder_versions(&bf.id, None).await.unwrap_err();
        assert!(
            matches!(
                error,
                verysync_sidecar::Error::Http { .. }
                    | verysync_sidecar::Error::Api { .. }
                    | verysync_sidecar::Error::AccessDenied { .. }
            ),
            "wrong key requires an actual native response, not a timeout"
        );
        let (accepted, rejected, sessions) = sftp_peer_auth(&peer)?;
        assert_eq!(accepted, 0);
        assert!(sessions.is_empty());
        assert!(
            rejected > 0,
            "peer must observe actual wrong public key rejection"
        );
        assert_eq!(std::fs::read_dir(&archive)?.count(), 0);
        assert_eq!(std::fs::read(source.join(name))?, old);
        eprintln!("private remote archive stage: wrong key rejected by actual key-only peer");
    }
    let location = VersionArchiveLocation::remote_uri(uri.as_str())?;
    assert!(!format!("{location:?}").contains(uri.as_str()));
    let changed = b
        .client()
        .set_version_archive_location(&bf.id, &location)
        .await?;
    assert!(changed.requested_fields_match);
    let observed = b.client().folder_versioning(&bf.id).await?;
    if key_auth {
        let debug = format!("{location:?} {observed:?}");
        for secret in [
            peer.endpoint.extra()["user"].as_str().ok_or("peer user")?,
            key_file.to_str().ok_or("synthetic UTF-8 key path")?,
        ] {
            assert!(!debug.contains(secret));
        }
    }
    assert_eq!(observed.filesystem_type, peer.endpoint.filesystem_type());
    assert_eq!(observed.filesystem_path, uri.as_str());
    assert_eq!(observed.params, prior.params);
    assert_eq!(
        observed.cleanup_interval_seconds,
        prior.cleanup_interval_seconds
    );
    eprintln!("private remote archive stage: configured");
    if key_auth {
        assert!(b.client().folder_versions(&bf.id, None).await?.0.is_empty());
        let (_, _, one_connection) = sftp_peer_auth(&peer)?;
        assert_eq!(
            one_connection.len(),
            1,
            "explicit one-connection pool must be observed at peer"
        );
        uri.query_pairs_mut()
            .clear()
            .append_pair(
                "privateKey",
                key_file.to_str().ok_or("synthetic UTF-8 key path")?,
            )
            .append_pair("parallelConnections", "2")
            .append_pair("sftpChannels", "2")
            .append_pair("connectTimeout", "6");
        let update = b
            .client()
            .set_version_archive_location(
                &bf.id,
                &VersionArchiveLocation::remote_uri(uri.as_str())?,
            )
            .await?;
        assert!(update.requested_fields_match);
        assert!(b.client().folder_versions(&bf.id, None).await?.0.is_empty());
        let (_, _, two_connections) = sftp_peer_auth(&peer)?;
        assert_eq!(
            two_connections.difference(&one_connection).count(),
            2,
            "explicit two-connection pool must create two real authenticated peer sessions"
        );
    }
    a.client().resume_folder(&af.id).await?;
    b.client().resume_folder(&bf.id).await?;
    a.client().request_scan(&af.id).await?;
    data(&receive.join(name), old).await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    std::fs::write(source.join(name), new)?;
    a.client().request_scan(&af.id).await?;
    // The refusal check requires both exact artifacts and their observed scope.
    let refusal_profile = if protocol == verysync_sidecar::StorageProtocol::Ftp {
        match (
            ftp_archive_scope::observed_refusal_profile(&a),
            ftp_archive_scope::observed_refusal_profile(&b),
        ) {
            (Some(first), Some(second)) if first == second => Some(first),
            _ => None,
        }
    } else {
        None
    };
    if let Some(profile) = refusal_profile {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let errors = b
                    .client()
                    .folder_errors(&bf.id, verysync_sidecar::ListPage::new(1, 10)?)
                    .await?;
                if errors.errors.as_ref().is_some_and(|rows| {
                    rows.iter().any(|e| {
                        e.path == name
                            && e.error
                                .contains("simple versioner: archive: file does not exist")
                    })
                }) {
                    return Ok::<_, verysync_sidecar::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        assert!(b
            .client()
            .folder_status(&bf.id)
            .await?
            .pull_errors
            .is_some_and(|n| n > 0));
        assert_eq!(std::fs::read(receive.join(name))?, old);
        assert_eq!(std::fs::read(source.join(name))?, new);
        assert_eq!(std::fs::read_dir(&archive)?.count(), 0);
        let (authenticated, commands) = ftp_peer_events(&peer)?;
        assert!(
            authenticated,
            "owned FTP peer did not record accepted authentication"
        );
        assert!(!commands
            .iter()
            .any(|command| command == "STOR" || command == "APPE"));
        assert!(commands.iter().any(|command| command == "USER"));
        assert!(commands.iter().any(|command| command == "PASS"));
        let exit = a.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
        let exit = b.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
        peer.stop()?;
        std::fs::remove_dir_all(root)?;
        println!(
            "public native FTP archive refusal evidence: {}",
            serde_json::json!({
            "actual_owned_ftp_authentication_accepted":true,
            "actual_user_and_pass_commands_observed":true,
            "actual_no_upload_command_in_observed_window":true,
            "actual_peer_observation_credentials_redacted":true,
            "native_target_os":std::env::consts::OS,"native_target_arch":std::env::consts::ARCH,
            "verified_standard_package":profile.hosted_runner.is_none().then_some(profile.package.as_str()),
            "verified_additional_package":profile.hosted_runner.is_some().then_some(profile.package.as_str()),
            "verified_hosted_runner":profile.hosted_runner,
            "actual_fixed_archive_and_binary_fingerprints_matched":true,
            "observed_command_names":commands,
            "actual_typed_location_readback":true,"actual_native_archive_not_found_error":true,
            "actual_nonzero_pull_error_counter":true,"actual_receiver_old_bytes_retained":true,
            "actual_source_new_bytes_retained":true,"actual_no_remote_archive_invented":true,
            "actual_both_normal_owned_tree_exits":true,"positive_ftp_archival":false,
            "scope":"fixed v2.33.2 first generation on dedicated standard FTP peer; documented reproduced targets only"})
        );
        return Ok(());
    }
    if let Err(error) = data(&receive.join(name), new).await {
        let errors = b
            .client()
            .folder_errors(&bf.id, verysync_sidecar::ListPage::new(1, 10)?)
            .await;
        eprintln!(
            "private remote archive failure snapshot: {}",
            serde_json::json!({
            "protocol":peer.endpoint.filesystem_type(),
            "actual_receiver_old":std::fs::read(receive.join(name)).is_ok_and(|v|v==old),
            "actual_source_new":std::fs::read(source.join(name)).is_ok_and(|v|v==new),
            "native_archive_not_found":errors.ok().and_then(|p|p.errors).is_some_and(|rows|
                rows.iter().any(|e|e.path==name && e.error.contains("simple versioner: archive: file does not exist"))),
            "remote_archive_entries":std::fs::read_dir(&archive).ok().map(|v|v.count()),
            "original_data_deadline_retained":true,
            "ftp_authentication_observed":if protocol == verysync_sidecar::StorageProtocol::Ftp {
                ftp_peer_events(&peer).ok().map(|value| value.0)
            } else { None }})
        );
        return Err(error);
    }

    let files = std::fs::read_dir(&archive)?
        .map(|x| x.map(|v| v.path()))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(files
        .iter()
        .any(|p| std::fs::read(p).ok().as_deref() == Some(old.as_slice())));
    let history = b.client().folder_versions(&bf.id, None).await?;
    let stamp = history
        .0
        .get(name)
        .and_then(|v| v.first())
        .ok_or("native SFTP archive not listed")?
        .version_time
        .clone();
    eprintln!("private remote archive stage: real bytes archived and listed");
    let exit = a.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    past_archive_generation(&b, &stamp).await?;
    let report = b
        .client()
        .restore_file_versions(
            &bf.id,
            &[FileVersionRestore::new(
                TargetPath::local(Path::new(name)),
                stamp,
            )?],
        )
        .await?;
    assert_eq!(report.error_count(), 0);
    data(&receive.join(name), old).await?;
    assert_eq!(std::fs::read(source.join(name))?, new);
    if key_auth {
        let (accepted, rejected, _) = sftp_peer_auth(&peer)?;
        assert!(accepted > 0 && rejected > 0);
    }
    let exit = b.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    b.restart(Duration::from_secs(30)).await?;
    assert_eq!(
        b.client().folder_versioning(&bf.id).await?.filesystem_path,
        uri.as_str()
    );
    assert!(!b.client().folder_versions(&bf.id, None).await?.0.is_empty());
    data(&receive.join(name), old).await?;
    let retained = std::fs::read_dir(&archive)?
        .map(|x| x.and_then(|v| std::fs::read(v.path()).map(|bytes| (v.file_name(), bytes))))
        .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?;
    let changed = b
        .client()
        .set_version_archive_location(&bf.id, &VersionArchiveLocation::FolderDefault)
        .await?;
    assert!(changed.requested_fields_match);
    let unchanged = std::fs::read_dir(&archive)?
        .map(|x| x.and_then(|v| std::fs::read(v.path()).map(|bytes| (v.file_name(), bytes))))
        .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?;
    assert_eq!(retained, unchanged);
    let exit = b.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    if let Some(bytes) = key_bytes {
        assert_eq!(std::fs::read(&key_file)?, bytes);
    }
    peer.stop()?;
    std::fs::remove_dir_all(root)?;
    println!(
        "public remote version archive evidence: {}",
        serde_json::json!({
        "actual_typed_remote_archive_location":true,"actual_original_policy_preserved":true,
        "actual_old_bytes_archived_on_remote_peer":true,"actual_native_version_browse":true,
        "actual_restored_old_bytes":true,"actual_source_new_bytes_retained":true,
        "actual_selected_filename_restored":true,"protocol":peer.endpoint.filesystem_type(),
        "filename_kind":if protocol == verysync_sidecar::StorageProtocol::Sftp { "unicode-percent" } else { "ascii" },"actual_normal_restart_keeps_remote_location":true,
        "actual_reset_default_preserves_remote_archives":true,"actual_both_normal_owned_tree_exits":true,
        "actual_key_only_peer":key_auth,"actual_target_key_file_consumed":key_auth,
        "actual_wrong_key_native_response_and_peer_rejection":key_auth,"actual_no_password_fallback":key_auth,
        "actual_private_peer_auth_observation":key_auth,
        "actual_unicode_percent_target_key_path":key_auth,"actual_key_file_bytes_retained":key_auth,
        "actual_one_then_two_authenticated_connections":key_auth,"actual_private_uri_debug":key_auth,
        "explicit_sftp_request_concurrency_selection":if key_auth { Some(2) } else { None },
        "explicit_connect_timeout_seconds":if key_auth { Some(6) } else { None },
        "request_concurrency_or_timeout_bound_measured":false,"server_host_identity_verified":false})
    );
    Ok(())
}

fn history_result<T>(
    stage: &'static str,
    started: std::time::Instant,
    result: verysync_sidecar::Result<T>,
) -> verysync_sidecar::Result<T> {
    if let Err(error) = &result {
        let mut cause = error;
        for depth in 0..4 {
            eprintln!(
                "private history failure: stage={stage} elapsed_ms={} depth={depth} error={cause:?}",
                started.elapsed().as_millis()
            );
            match cause {
                verysync_sidecar::Error::MutationOutcomeUnknown { source, .. } => cause = source,
                verysync_sidecar::Error::Http { response }
                | verysync_sidecar::Error::Api { response, .. }
                | verysync_sidecar::Error::AccessDenied { response }
                | verysync_sidecar::Error::InvalidResponse { response, .. } => {
                    eprintln!(
                        "private history response: status={} bytes={} body_omitted=true",
                        response.status(),
                        response.body_bytes().len()
                    );
                    break;
                }
                _ => break,
            }
        }
    }
    result
}

async fn past_archive_generation(core: &ManagedInstance, stamp: &str) -> TestResult {
    let selected = stamp
        .parse::<jiff::Timestamp>()?
        .as_nanosecond()
        .div_euclid(1_000_000_000);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let status = core.client().system_status().await?;
            let now = status
                .now_time
                .as_deref()
                .ok_or("native current clock absent")?
                .parse::<jiff::Timestamp>()?
                .as_nanosecond()
                .div_euclid(1_000_000_000);
            if now > selected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn public_same_second_restore_refusal_preserves_selected_old_archive_and_current_bytes(
) -> TestResult {
    use sha2::{Digest, Sha256};
    use verysync_sidecar::{DirectoryVersionOrder, Error, VersionedDirectory};
    let root = tempfile::Builder::new().prefix("vguard-").tempdir()?.keep();
    let data_dir = root.join("data");
    std::fs::create_dir(&data_dir)?;
    let old = b"selected old archive bytes";
    let side = b"separate earlier archive sentinel";
    let new = b"current synthetic contents of another size";
    for name in ["same.txt", "older.txt"] {
        std::fs::write(data_dir.join(name), new)?;
    }
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let share = core.client().generate_share().await?;
    let key = core
        .client()
        .validate_share_key(&share.read_write_key)
        .await?;
    let folder = core
        .client()
        .join_folder(&JoinFolderOptions::new(key, TargetPath::local(&data_dir)))
        .await?
        .configuration;
    core.client()
        .set_folder_versioning(
            &folder.id,
            FolderVersioningPolicy::Simple {
                keep: 3,
                cleanout_days: 0,
                cleanup_interval_seconds: 3600,
            },
        )
        .await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let state = core.client().folder_status(&folder.id).await?;
            if state.local_files == Some(2)
                && state.state == Some(verysync_sidecar::FolderState::Idle)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, verysync_sidecar::Error>(())
    })
    .await??;
    let first = core
        .client()
        .system_status()
        .await?
        .now_time
        .ok_or("native clock absent")?;
    let stamp = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let next = core
                .client()
                .system_status()
                .await?
                .now_time
                .ok_or("native clock absent")?;
            if next != first {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(next);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    assert!(stamp.is_ascii() && stamp.len() >= 19);
    let tag = format!(
        "{}{}{}-{}{}{}",
        &stamp[0..4],
        &stamp[5..7],
        &stamp[8..10],
        &stamp[11..13],
        &stamp[14..16],
        &stamp[17..19]
    );
    let archive = data_dir.join(".verysync").join("Archive");
    std::fs::create_dir_all(&archive)?;
    let same_archive = archive.join(format!("same~{tag}.txt"));
    std::fs::write(&same_archive, old)?;
    let side_path = archive.join("older~20000101-000000.txt");
    std::fs::write(&side_path, side)?;
    let listed = core.client().folder_versions(&folder.id, None).await?;
    let same_stamp = listed.0["same.txt"][0].version_time.clone();
    let same = FileVersionRestore::new(TargetPath::local(Path::new("same.txt")), same_stamp)?;
    assert!(matches!(
        core.client()
            .restore_file_versions(&folder.id, &[same])
            .await,
        Err(Error::ArchiveRestorePrecondition { .. })
    ));
    assert!(matches!(
        core.client()
            .restore_directory_versions(
                &folder.id,
                &VersionedDirectory::FolderRoot,
                DirectoryVersionOrder::Oldest
            )
            .await,
        Err(Error::ArchiveRestorePrecondition { .. })
    ));
    let now = core
        .client()
        .system_status()
        .await?
        .now_time
        .ok_or("native clock absent")?;
    assert_eq!(
        &stamp[..19],
        &now[..19],
        "same-second fixture crossed a target clock boundary"
    );
    assert_eq!(std::fs::read(&same_archive)?, old);
    assert_eq!(std::fs::read(data_dir.join("same.txt"))?, new);
    assert_eq!(
        Sha256::digest(std::fs::read(&same_archive)?),
        Sha256::digest(old)
    );
    assert_eq!(
        Sha256::digest(std::fs::read(data_dir.join("same.txt"))?),
        Sha256::digest(new)
    );
    for (label, path, expected) in [
        ("current", data_dir.join("same.txt"), new.as_slice()),
        ("same-second archive", same_archive.clone(), old.as_slice()),
        ("strictly older archive", side_path.clone(), side.as_slice()),
    ] {
        let received = std::fs::read(&path)?;
        assert_eq!(received.as_slice(), expected);
        assert_eq!(Sha256::digest(&received), Sha256::digest(expected));
        println!(
            "after both refusals: {label} bytes={} SHA256={:x}",
            received.len(),
            Sha256::digest(&received)
        );
    }
    let older = FileVersionRestore::new(
        TargetPath::local(Path::new("older.txt")),
        listed.0["older.txt"][0].version_time.clone(),
    )?;
    assert_eq!(
        core.client()
            .restore_file_versions(&folder.id, &[older])
            .await?
            .error_count(),
        0
    );
    data(&data_dir.join("older.txt"), side).await?;
    let restored = std::fs::read(data_dir.join("older.txt"))?;
    assert_eq!(Sha256::digest(&restored), Sha256::digest(side));
    println!(
        "after explicit older restore: bytes={} SHA256={:x}",
        restored.len(),
        Sha256::digest(&restored)
    );
    assert_eq!(std::fs::read(&same_archive)?, old);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    eprintln!(
        "public archive collision guard evidence: {}",
        serde_json::json!({"actual_same_native_second":true,"actual_file_restore_refused":true,"actual_directory_restore_refused":true,"actual_old_archive_bytes_and_sha_preserved":true,"actual_current_bytes_and_sha_preserved":true,"actual_explicit_older_restore_works":true,"actual_unselected_archive_preserved":true,"actual_normal_owned_tree_exit":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
async fn listener(core: &ManagedInstance) -> TestResult<String> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            for status in core.client().listener_status().await?.into_values() {
                for address in status.lan_addresses {
                    if address
                        .strip_prefix("tcp://")
                        .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
                        .is_some_and(|a| a.ip().is_loopback() && a.port() != 0 && a.port() != 18886)
                    {
                        return Ok::<_, verysync_sidecar::Error>(address);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??)
}
async fn data(path: &Path, expected: &[u8]) -> TestResult {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if std::fs::read(path).ok().as_deref() == Some(expected) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    Ok(())
}
async fn register(
    a: &ManagedInstance,
    b: &ManagedInstance,
    source: &Path,
    receive: &Path,
) -> TestResult<(
    verysync_sidecar::FolderConfig,
    verysync_sidecar::FolderConfig,
)> {
    let keys = a.client().generate_share().await?;
    let rw = a.client().validate_share_key(&keys.read_write_key).await?;
    let ro = b.client().validate_share_key(&keys.read_write_key).await?;
    let af = a
        .client()
        .join_folder(&JoinFolderOptions::new(rw, TargetPath::local(source)).paused(true))
        .await?
        .configuration;
    let bf = b
        .client()
        .join_folder(&JoinFolderOptions::new(ro, TargetPath::local(receive)).paused(true))
        .await?
        .configuration;
    let aid = a.client().instance().device_id.clone();
    let bid = b.client().instance().device_id.clone();
    let aa = listener(a).await?;
    let ba = listener(b).await?;
    for (core, folder, peer, address) in [(a, &af.id, &bid, ba), (b, &bf.id, &aid, aa)] {
        core.client()
            .create_device(
                &CreateDeviceOptions::new(peer.clone()).settings(
                    DevicePatch::default()
                        .addresses(vec![address])
                        .allowed_transports(vec![DeviceTransport::Tcp]),
                ),
            )
            .await?;
        core.client().share_folder_with(folder, peer).await?;
    }
    Ok((af, bf))
}
#[tokio::test]
async fn public_version_policy_archives_remote_changes_and_restores_old_bytes() -> TestResult {
    let root = tempfile::Builder::new().prefix("vfh-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let source = root.join("source");
    let receive = root.join("receive");
    std::fs::create_dir(&source)?;
    let initial_bytes = b"first synthetic version payload";
    let old = b"second retained archived payload with unique size";
    let middle = b"third retained archived version bytes";
    let new = b"second distinct synthetic replacement version bytes";
    std::fs::write(source.join("version-sample.bin"), initial_bytes)?;
    let (af, bf) = register(&a, &b, &source, &receive).await?;
    assert!(matches!(
        b.client().folder_version_inventory(&bf.id).await,
        Err(verysync_sidecar::Error::Http { response }) if response.status()==500
    ));
    let initial = b.client().folder_versioning(&bf.id).await?;
    assert_eq!(initial.kind, "");
    let policy = FolderVersioningPolicy::Simple {
        keep: 2,
        cleanout_days: 0,
        cleanup_interval_seconds: 3600,
    };
    let configured = b
        .client()
        .change_versioning_and_verify(
            verysync_sidecar::VersioningTarget::Folder(&bf.id),
            Some(&policy),
            None,
            OperationOptions::new(Duration::from_secs(15)),
        )
        .await?;
    assert_eq!(
        configured.completion(),
        OperationCompletion::Completed,
        "{configured:?}"
    );
    assert!(configured.write.dispatched && configured.write.response_complete);
    let actual = configured
        .current
        .ok_or("versioning configuration not observed")?;
    assert_eq!(actual.filesystem_path, initial.filesystem_path);
    assert_eq!(actual.filesystem_type, initial.filesystem_type);
    // Establish the separate lazy native disk buffer before real peer changes.
    match b
        .client()
        .subscribe_disk_events(verysync_sidecar::EventOptions::default())
        .await
    {
        Ok(stream) => stream.close().await?,
        Err(verysync_sidecar::Error::Transport { .. }) => (),
        Err(error) => return Err(error.into()),
    }
    a.client().resume_folder(&af.id).await?;
    b.client().resume_folder(&bf.id).await?;
    a.client().request_scan(&af.id).await?;
    eprintln!("private version stage: initial-transfer");
    data(&receive.join("version-sample.bin"), initial_bytes).await?;
    assert!(b.client().folder_versions(&bf.id, None).await?.0.is_empty());
    assert!(b
        .client()
        .folder_version_inventory(&bf.id)
        .await?
        .0
        .is_empty());
    for bytes in [old.as_slice(), middle.as_slice(), new.as_slice()] {
        // Archive names use one-second timestamps; create distinct revisions.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        std::fs::write(source.join("version-sample.bin"), bytes)?;
        a.client().request_scan(&af.id).await?;
        eprintln!("private version stage: remote-update");
        data(&receive.join("version-sample.bin"), bytes).await?;
    }
    let remote_cursor = verysync_sidecar::EventCursor {
        source: verysync_sidecar::EventSource::Disk,
        device_id: b.client().instance().device_id.clone(),
        engine_started_at: b.client().system_status().await?.start_time,
        last_id: 0,
    };
    let mut disk = b
        .client()
        .subscribe_disk_events(
            verysync_sidecar::EventOptions::default().resume_from(remote_cursor)?,
        )
        .await?;
    let remote_changes = tokio::time::timeout(Duration::from_secs(15), async {
        let mut count = 0;
        while count < 4 {
            let item = disk.next().await.ok_or("remote disk stream ended")??;
            if let verysync_sidecar::EventStreamItem::Event(event) = item {
                assert_eq!(event.cursor.source, verysync_sidecar::EventSource::Disk);
                assert!(!format!("{event:?}").contains("version-sample.bin"));
                if event.kind == verysync_sidecar::EventKind::RemoteChangeDetected
                    && event.data()["folderID"] == bf.id.as_str()
                    && event.data()["path"] == "version-sample.bin"
                {
                    assert_eq!(event.data()["action"], "modified");
                    assert_eq!(event.data()["type"], "file");
                    count += 1;
                }
            }
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(count)
    })
    .await??;
    assert_eq!(remote_changes, 4);
    disk.close().await?;
    let history = b.client().folder_versions(&bf.id, None).await?;
    let observed = b
        .client()
        .change_versioning_and_verify(
            verysync_sidecar::VersioningTarget::Folder(&bf.id),
            Some(&policy),
            None,
            OperationOptions::new(Duration::from_secs(15)),
        )
        .await?;
    assert!(!observed.write.dispatched && observed.original?.is_none());
    let inventory = observed
        .archive
        .ok_or("versioning workflow did not read the archive")??;
    assert_eq!(inventory.0.len(), history.0.len());
    println!("native_versioner_folder original_and_exact_readback=true repeat_zero=true verified_inventory=true");
    for (name, versions) in &history.0 {
        let all = inventory
            .0
            .get(name)
            .ok_or("whole inventory omitted a known native archive")?;
        let records = |items: &[verysync_sidecar::ArchivedFileVersion]| {
            items
                .iter()
                .map(|v| (v.version_time.clone(), v.mod_time.clone(), v.size))
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(records(all), records(versions));
    }
    assert!(!format!("{inventory:?}").contains("version-sample.bin"));
    assert_eq!(std::fs::read(receive.join("version-sample.bin"))?, new);

    let versions = history
        .0
        .get("version-sample.bin")
        .ok_or("actual old version missing")?;
    assert_eq!(versions.len(), 2);
    let sizes: std::collections::BTreeSet<_> = versions.iter().map(|v| v.size).collect();
    assert_eq!(
        sizes,
        std::collections::BTreeSet::from([old.len() as u64, middle.len() as u64])
    );
    let stamp = versions
        .iter()
        .find(|v| v.size == old.len() as u64)
        .ok_or("retained archive missing")?
        .version_time
        .clone();
    let prefixed = b
        .client()
        .folder_versions(
            &bf.id,
            Some(&TargetPath::local(Path::new("version-sample.bin"))),
        )
        .await?;
    assert!(prefixed.0.is_empty());
    assert_eq!(std::fs::read(source.join("version-sample.bin"))?, new);
    let exit = a.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    let restore = [FileVersionRestore::new(
        TargetPath::local("version-sample.bin"),
        stamp,
    )?];
    let expected = [RestoreFileExpectation {
        path: TargetPath::local("version-sample.bin"),
        bytes: old.len() as u64,
        sha256: Sha256::digest(old).into(),
    }];
    let request = || VerifiedRestoreSelection::Files {
        versions: &restore,
        expected: &expected,
    };
    let report = b
        .client()
        .restore_versions_and_verify(
            &bf.id,
            request(),
            OperationOptions::new(Duration::from_secs(15)),
        )
        .await?;
    assert!(
        report.write.dispatched && report.write.response_complete,
        "{report:?}"
    );
    assert!(!report.files[0].already_matched);
    assert_eq!(
        report.completion(),
        OperationCompletion::Completed,
        "{report:?}"
    );
    assert_eq!(
        report
            .original?
            .expect("native restore reply")
            .error_count(),
        0
    );
    let already = b
        .client()
        .restore_versions_and_verify(
            &bf.id,
            request(),
            OperationOptions::new(Duration::from_secs(15)),
        )
        .await?;
    assert_eq!(
        already.completion(),
        OperationCompletion::Completed,
        "{already:?}"
    );
    assert!(!already.write.dispatched && already.files[0].already_matched);
    eprintln!("private version stage: restore");
    data(&receive.join("version-sample.bin"), old).await?;
    assert_eq!(std::fs::read(source.join("version-sample.bin"))?, new);
    use sha2::{Digest, Sha256};
    assert_eq!(
        Sha256::digest(std::fs::read(receive.join("version-sample.bin"))?),
        Sha256::digest(old)
    );
    let disabled = b
        .client()
        .set_folder_versioning(&bf.id, FolderVersioningPolicy::Disabled)
        .await?;
    assert!(disabled.requested_fields_match && disabled.configuration.kind.is_empty());
    let reenabled = b
        .client()
        .set_folder_versioning(
            &bf.id,
            FolderVersioningPolicy::Simple {
                keep: 2,
                cleanout_days: 0,
                cleanup_interval_seconds: 3600,
            },
        )
        .await?;
    assert!(reenabled.requested_fields_match);
    assert!(!b.client().folder_versions(&bf.id, None).await?.0.is_empty());
    let exit = b.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public version history evidence: {}",
        serde_json::json!({"actual_remote_disk_change_events":4,"actual_default_disabled":true,"whole_version_inventory_empty_and_actual_two_archives":true,"whole_inventory_retains_exact_browse_records":true,"paused_versioner_error_not_empty":true,"actual_simple_configuration":true,"actual_archive_location_preserved":true,"actual_remote_old_to_new_update":true,"actual_keep_two_after_three_remote_updates":true,"actual_file_prefix_observes_empty_descendants":true,"actual_nonempty_versions_and_original_size":true,"actual_source_stopped_before_restore":true,"actual_exact_old_bytes_restored":true,"typed_restore_verified_bytes":true,"already_matching_zero_write":true,"actual_restored_sha256":true,"actual_stopped_source_new_bytes_preserved":true,"actual_disable_preserves_archives":true,"actual_normal_both_owned_tree_exits":true})
    );
    Ok(())
}

#[tokio::test]
async fn public_trashcan_restores_the_last_remotely_deleted_file() -> TestResult {
    let root = tempfile::Builder::new().prefix("vfht-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let source = root.join("source");
    let receive = root.join("receive");
    std::fs::create_dir(&source)?;
    let relative = Path::new("recycle 二 %.txt");
    let old = b"old before actual remote replacement";
    let new = b"last synthetic bytes before deletion";
    std::fs::write(source.join(relative), old)?;
    let (af, bf) = register(&a, &b, &source, &receive).await?;
    let update = b
        .client()
        .set_folder_versioning(
            &bf.id,
            FolderVersioningPolicy::Trashcan {
                cleanout_days: 0,
                cleanup_interval_seconds: 3600,
            },
        )
        .await?;
    assert!(update.requested_fields_match && update.configuration.kind == "trashcan");
    a.client().resume_folder(&af.id).await?;
    b.client().resume_folder(&bf.id).await?;
    a.client().request_scan(&af.id).await?;
    data(&receive.join(relative), old).await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    std::fs::write(source.join(relative), new)?;
    a.client().request_scan(&af.id).await?;
    data(&receive.join(relative), new).await?;
    let history = b.client().folder_versions(&bf.id, None).await?;
    let key = relative.to_str().ok_or("synthetic name encoding")?;
    assert_eq!(history.0[key].len(), 1);
    assert_eq!(history.0[key][0].size, old.len() as u64);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    std::fs::remove_file(source.join(relative))?;
    a.client().request_scan(&af.id).await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        while receive.join(relative).exists() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    let history = b.client().folder_versions(&bf.id, None).await?;
    assert_eq!(history.0[key].len(), 1);
    assert_eq!(history.0[key][0].size, new.len() as u64);
    let exit = a.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    past_archive_generation(&b, &history.0[key][0].version_time).await?;
    let report = b
        .client()
        .restore_file_versions(
            &bf.id,
            &[FileVersionRestore::new(
                TargetPath::local(relative),
                history.0[key][0].version_time.clone(),
            )?],
        )
        .await?;
    assert_eq!(report.error_count(), 0);
    data(&receive.join(relative), new).await?;
    use sha2::{Digest, Sha256};
    assert_eq!(
        Sha256::digest(std::fs::read(receive.join(relative))?),
        Sha256::digest(new)
    );
    assert!(!source.join(relative).exists());
    let exit = b.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public trashcan version evidence: {}",
        serde_json::json!({
        "actual_trashcan_policy":true,"actual_remote_overwrite_archive":true,"actual_remote_file_delete":true,
        "actual_latest_deleted_bytes_retained":true,"actual_single_recycle_version":true,
        "actual_deleted_file_restored":true,"actual_restored_sha256":true,"actual_stopped_source_stays_deleted":true,
        "actual_unicode_literal_percent_path":true,"actual_both_normal_owned_tree_exits":true})
    );
    Ok(())
}

#[tokio::test]
async fn public_free_audit_settings_report_unretained_enable_and_empty_pages() -> TestResult {
    use verysync_sidecar::AuditHistorySettings;
    let root = tempfile::Builder::new().prefix("vfha-").tempdir()?.keep();
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let initial = core.client().audit_history_settings().await?;
    assert!(!initial.enabled);
    let update = core
        .client()
        .set_audit_history_settings(AuditHistorySettings {
            enabled: true,
            maximum_records: initial.maximum_records,
        })
        .await?;
    assert!(!update.requested_fields_match && !update.configuration.enabled);
    for page in [1, 2] {
        let result = core.client().audit_history(page, 10).await?;
        assert_eq!(result.total, 0);
        assert!(result.records.is_none() && result.error.is_none());
    }
    let started = std::time::Instant::now();
    history_result(
        "empty-audit-reset",
        started,
        core.client().reset_audit_history().await,
    )?;
    assert_eq!(core.client().audit_history(1, 10).await?.total, 0);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public free audit history evidence: {}",
        serde_json::json!({"actual_default_recording_disabled":true,"actual_enable_not_retained_in_readback":true,"actual_two_explicit_empty_pages":true,"actual_empty_reset_acknowledgement":true,"actual_empty_total_after_reset":true,"actual_normal_owned_tree_exit":true,"scope":"free-instance settings/readback/empty response only; no licensed recording or nonempty history removal claim"})
    );
    Ok(())
}

#[tokio::test]
async fn public_directory_restore_selects_nested_and_explicit_root_versions() -> TestResult {
    use verysync_sidecar::{DirectoryVersionOrder, VersionedDirectory};
    let root = tempfile::Builder::new().prefix("vfhd-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let source = root.join("source");
    let receive = root.join("receive");
    let relative = [
        std::path::PathBuf::from("a.txt"),
        Path::new("nested").join("b 二 %.txt"),
        Path::new("nested").join("deeper").join("c.txt"),
    ];
    let old = b"original archived directory bytes";
    let new = b"distinct newer directory content with another size";
    for p in &relative {
        std::fs::create_dir_all(source.join(p).parent().ok_or("synthetic file parent")?)?;
        std::fs::write(source.join(p), old)?;
    }
    let (af, bf) = register(&a, &b, &source, &receive).await?;
    assert!(
        b.client()
            .set_folder_versioning(
                &bf.id,
                FolderVersioningPolicy::Simple {
                    keep: 3,
                    cleanout_days: 0,
                    cleanup_interval_seconds: 3600
                }
            )
            .await?
            .requested_fields_match
    );
    a.client().resume_folder(&af.id).await?;
    b.client().resume_folder(&bf.id).await?;
    a.client().request_scan(&af.id).await?;
    for p in &relative {
        data(&receive.join(p), old).await?;
    }
    tokio::time::sleep(Duration::from_millis(1100)).await;
    for p in &relative {
        std::fs::write(source.join(p), new)?;
    }
    a.client().request_scan(&af.id).await?;
    for p in &relative {
        data(&receive.join(p), new).await?;
    }
    let root_catalog = b.client().folder_versions(&bf.id, None).await?;
    let nested_catalog = b
        .client()
        .folder_versions(&bf.id, Some(&TargetPath::local(Path::new("nested"))))
        .await?;
    assert!(root_catalog.0.values().any(|versions| !versions.is_empty()));
    assert!(nested_catalog
        .0
        .values()
        .any(|versions| !versions.is_empty()));
    let exit = a.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    // Native archive names have one-second precision. Restoring a selected
    // archive while archiving the current file in that same second can replace
    // the selected archive before it is restored. Establish distinct archive
    // generations explicitly; keep every 30-second content deadline unchanged.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let scope = VersionedDirectory::Path(TargetPath::local(Path::new("nested")));
    let expected: Vec<_> = relative[1..]
        .iter()
        .map(|path| RestoreFileExpectation {
            path: TargetPath::local(path),
            bytes: old.len() as u64,
            sha256: Sha256::digest(old).into(),
        })
        .collect();
    let restore = |expected| VerifiedRestoreSelection::Directory {
        scope: &scope,
        order: DirectoryVersionOrder::Oldest,
        expected,
    };
    let incomplete = b
        .client()
        .restore_versions_and_verify(
            &bf.id,
            restore(&expected[..1]),
            OperationOptions::new(Duration::from_secs(15)),
        )
        .await?;
    assert!(matches!(
        incomplete.original,
        Err(verysync_sidecar::Error::ArchiveRestorePrecondition { .. })
    ));
    assert!(!incomplete.write.dispatched);
    for path in &relative {
        assert_eq!(std::fs::read(receive.join(path))?, new);
    }
    let result = b
        .client()
        .restore_versions_and_verify(
            &bf.id,
            restore(&expected),
            OperationOptions::new(Duration::from_secs(15)),
        )
        .await?;
    assert_eq!(result.files.len(), expected.len());
    assert!(result
        .files
        .iter()
        .all(|file| !file.already_matched && file.current_matches == Some(true)));
    assert_eq!(
        result.completion(),
        OperationCompletion::Completed,
        "{result:?}"
    );
    assert_eq!(
        result
            .original?
            .expect("native directory restore reply")
            .error_count(),
        0
    );
    for (index, p) in relative[1..].iter().enumerate() {
        let effect = data(&receive.join(p), old).await;
        if effect.is_err() {
            eprintln!(
                "private directory oldest scope diagnostic: {}",
                serde_json::json!({"failed_relative_index":index+1,"old_bytes":relative.iter().map(|p|std::fs::read(receive.join(p)).is_ok_and(|v|v==old)).collect::<Vec<_>>(),"new_bytes":relative.iter().map(|p|std::fs::read(receive.join(p)).is_ok_and(|v|v==new)).collect::<Vec<_>>()})
            );
        }
        effect?;
    }
    assert_eq!(std::fs::read(receive.join(&relative[0]))?, new);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let result = b
        .client()
        .restore_directory_versions(&bf.id, &scope, DirectoryVersionOrder::Newest)
        .await?;
    assert_eq!(result.error_count(), 0);
    for p in &relative {
        data(&receive.join(p), new).await?;
    }
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let result = b
        .client()
        .restore_directory_versions(
            &bf.id,
            &VersionedDirectory::FolderRoot,
            DirectoryVersionOrder::Oldest,
        )
        .await?;
    assert_eq!(result.error_count(), 0);
    use sha2::{Digest, Sha256};
    for p in &relative {
        data(&receive.join(p), old).await?;
        assert_eq!(
            Sha256::digest(std::fs::read(receive.join(p))?),
            Sha256::digest(old)
        );
        assert_eq!(std::fs::read(source.join(p))?, new);
    }
    let exit = b.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public directory version restore evidence: {}",
        serde_json::json!({"actual_three_remote_archived_paths":true,"actual_nested_oldest_restore":true,"typed_restore_verified_whole_inventory":true,"incomplete_inventory_zero_write":true,"actual_deeper_descendant_restored":true,"actual_unselected_root_file_unchanged":true,"actual_nested_newest_restore":true,"actual_explicit_dot_root_oldest_restore":true,"actual_all_restored_sha256":true,"actual_stopped_source_new_bytes_unchanged":true,"actual_unicode_percent_nested_path":true,"actual_both_owned_normal_tree_exits":true})
    );
    Ok(())
}

#[tokio::test]
async fn public_staggered_external_and_archive_locations_preserve_actual_versions() -> TestResult {
    use verysync_sidecar::{ExternalVersioningCommand, VersionArchiveLocation};
    let root = tempfile::Builder::new().prefix("vhu-").tempdir()?.keep();
    let mut a = ManagedInstance::start(options(&root.join("a"))?).await?;
    let mut b = ManagedInstance::start(options(&root.join("b"))?).await?;
    let source = root.join("source");
    let receive = root.join("receive");
    let archive = root.join("explicit archive");
    std::fs::create_dir(&source)?;
    std::fs::create_dir(&archive)?;
    let name = "sample 二 %.txt";
    let old = b"old staggered sample";
    let new = b"new version with distinct length";
    let last = b"final external version data";
    std::fs::write(source.join(name), old)?;
    let (af, bf) = register(&a, &b, &source, &receive).await?;
    let location = VersionArchiveLocation::BasicDirectory(TargetPath::local(&archive));
    let changed = b
        .client()
        .set_version_archive_location(&bf.id, &location)
        .await?;
    assert!(changed.requested_fields_match && changed.configuration.filesystem_type == "basic");
    assert_eq!(
        changed.configuration.filesystem_path,
        archive.to_str().ok_or("test path UTF8")?
    );
    let changed = b
        .client()
        .set_folder_versioning(
            &bf.id,
            FolderVersioningPolicy::Staggered {
                max_age_seconds: 0,
                cleanup_interval_seconds: 1,
            },
        )
        .await?;
    assert!(changed.requested_fields_match && changed.configuration.kind == "staggered");
    assert_eq!(
        changed
            .configuration
            .params
            .get("maxAge")
            .map(String::as_str),
        Some("0")
    );
    assert!(!format!("{location:?}").contains(archive.to_str().ok_or("test path UTF8")?));
    a.client().resume_folder(&af.id).await?;
    b.client().resume_folder(&bf.id).await?;
    a.client().request_scan(&af.id).await?;
    data(&receive.join(name), old).await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    std::fs::write(source.join(name), new)?;
    a.client().request_scan(&af.id).await?;
    data(&receive.join(name), new).await?;
    let history = b.client().folder_versions(&bf.id, None).await?;
    assert!(history.0.get(name).is_some_and(|v| v.len() == 1));
    let files = std::fs::read_dir(&archive)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(files
        .iter()
        .any(|p| std::fs::read(p).ok().as_deref() == Some(old.as_slice())));
    let default_archive = receive.join(".verysync").join("Archive");
    assert!(!default_archive.exists() || std::fs::read_dir(default_archive)?.next().is_none());
    let helper = root.join("external-helper.py");
    let external = root.join("external archive");
    std::fs::create_dir(&external)?;
    std::fs::write(
        &helper,
        r#"import sys,json,shutil
from pathlib import Path
folder=Path(sys.argv[1]).resolve();rel=Path(sys.argv[2]);destination=Path(sys.argv[3]).resolve()
assert not rel.is_absolute() and '..' not in rel.parts
source=(folder/rel).resolve();assert source.is_relative_to(folder)
mode='fail' if len(sys.argv)>4 and sys.argv[4]=='fail' else 'archive'
(destination/('failed-invocation.json' if mode=='fail' else 'invocation.json')).write_text(json.dumps({'folder':str(folder),'file':str(rel)}))
if mode=='fail':sys.exit(7)
shutil.move(str(source),str(destination/'kept.bin'))
"#,
    )?;
    let python = std::env::var("VERYSYNC_TEST_PYTHON")?;
    let command = format!(
        "\"{}\" \"{}\" \"%FOLDER_PATH%\" \"%FILE_PATH%\" \"{}\"",
        python,
        helper.display(),
        external.display()
    );
    let command = ExternalVersioningCommand::new(command)?;
    assert!(!format!("{command:?}").contains(helper.to_str().ok_or("test helper UTF8")?));
    let changed = b
        .client()
        .set_folder_versioning(&bf.id, FolderVersioningPolicy::External { command })
        .await?;
    assert!(changed.requested_fields_match && changed.configuration.kind == "external");
    assert_eq!(
        changed.configuration.filesystem_path,
        archive.to_str().ok_or("test path UTF8")?
    );
    std::fs::write(source.join(name), last)?;
    a.client().request_scan(&af.id).await?;
    data(&receive.join(name), last).await?;
    assert_eq!(std::fs::read(external.join("kept.bin"))?, new);
    let called: serde_json::Value =
        serde_json::from_slice(&std::fs::read(external.join("invocation.json"))?)?;
    assert_eq!(called["file"], name);
    assert_eq!(
        std::fs::canonicalize(Path::new(
            called["folder"].as_str().ok_or("native folder arg")?
        ))?,
        std::fs::canonicalize(&receive)?
    );
    let reset_location = b
        .client()
        .set_version_archive_location(&bf.id, &VersionArchiveLocation::FolderDefault)
        .await?;
    assert!(
        reset_location.requested_fields_match
            && reset_location.configuration.filesystem_path.is_empty()
    );
    let changed = b
        .client()
        .set_folder_versioning(
            &bf.id,
            FolderVersioningPolicy::Staggered {
                max_age_seconds: 0,
                cleanup_interval_seconds: 1,
            },
        )
        .await?;
    assert!(changed.requested_fields_match);
    let final_bytes = b"final default archive generation with unique bytes";
    std::fs::write(source.join(name), final_bytes)?;
    a.client().request_scan(&af.id).await?;
    data(&receive.join(name), final_bytes).await?;
    let default_archive = receive.join(".verysync").join("Archive");
    let default_files = std::fs::read_dir(&default_archive)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(default_files
        .iter()
        .any(|p| std::fs::read(p).ok().as_deref() == Some(last.as_slice())));
    let expiring = b
        .client()
        .set_folder_versioning(
            &bf.id,
            FolderVersioningPolicy::Staggered {
                max_age_seconds: 1,
                cleanup_interval_seconds: 1,
            },
        )
        .await?;
    assert!(expiring.requested_fields_match);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if std::fs::read_dir(&default_archive)?.next().is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok::<_, std::io::Error>(())
    })
    .await??;
    assert!(files
        .iter()
        .any(|p| std::fs::read(p).ok().as_deref() == Some(old.as_slice())));
    assert_eq!(std::fs::read(external.join("kept.bin"))?, new);
    assert_eq!(std::fs::read(receive.join(name))?, final_bytes);
    let failure = ExternalVersioningCommand::new(format!(
        "\"{}\" \"{}\" \"%FOLDER_PATH%\" \"%FILE_PATH%\" \"{}\" fail",
        python,
        helper.display(),
        external.display()
    ))?;
    assert!(
        b.client()
            .set_folder_versioning(
                &bf.id,
                FolderVersioningPolicy::External { command: failure }
            )
            .await?
            .requested_fields_match
    );
    let refused = b"new source bytes deliberately refused by the external archiver";
    std::fs::write(source.join(name), refused)?;
    a.client().request_scan(&af.id).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let started = std::time::Instant::now();
            let status = b.client().folder_status(&bf.id).await;
            if status.is_err() {
                eprintln!(
                    "private failed-archiver state: {}",
                    serde_json::json!({
                        "callback_marker_present":external.join("failed-invocation.json").is_file(),
                        "receiver_previous_bytes_retained":std::fs::read(receive.join(name)).is_ok_and(|bytes|bytes==final_bytes),
                        "source_refused_bytes_retained":std::fs::read(source.join(name)).is_ok_and(|bytes|bytes==refused),
                        "external_archive_bytes_retained":std::fs::read(external.join("kept.bin")).is_ok_and(|bytes|bytes==new),
                        "no_extra_native_request":true
                    })
                );
            }
            let status = history_result("failed-archiver-folder-status", started, status)?;
            if status.pull_errors.is_some_and(|n| n > 0)
                && external.join("failed-invocation.json").is_file()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok::<_, verysync_sidecar::Error>(())
    })
    .await??;
    assert_eq!(std::fs::read(receive.join(name))?, final_bytes);
    assert_eq!(std::fs::read(source.join(name))?, refused);
    assert_eq!(std::fs::read(external.join("kept.bin"))?, new);
    assert!(files
        .iter()
        .any(|p| std::fs::read(p).ok().as_deref() == Some(old.as_slice())));
    for core in [&mut b, &mut a] {
        let exit = core.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    assert_eq!(std::fs::read(source.join(name))?, refused);
    eprintln!(
        "public extended versioner evidence: {}",
        serde_json::json!({"actual_staggered_native_policy_and_zero_age":true,"actual_explicit_basic_archive_location":true,"actual_old_bytes_in_selected_archive":true,"actual_default_archive_initially_empty":true,"actual_native_browse_from_selected_location":true,"actual_external_command_native_readback":true,"actual_external_callback_folder_and_file_arguments":true,"actual_external_callback_archives_old_bytes":true,"actual_explicit_default_location_restored":true,"actual_default_location_archives_next_remote_change":true,"actual_positive_native_age_cleanup_removes_observed_archive":true,"actual_previous_location_archive_not_migrated_or_cleaned":true,"actual_external_archived_bytes_retained":true,"actual_current_source_and_receiver_bytes_retained":true,"actual_private_command_and_location_debug":true,"actual_both_normal_owned_tree_exits":true,"actual_failed_external_callback_invoked":true,"actual_native_pull_error_after_callback_exit_seven":true,"actual_failed_callback_preserves_existing_receiver_bytes":true,"actual_failed_callback_preserves_new_source_bytes":true,"actual_failed_callback_preserves_both_previous_archives":true})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
