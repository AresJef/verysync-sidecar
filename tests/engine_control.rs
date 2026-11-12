//! Public management API tests and explicitly separated fixture contracts.

#[path = "common/engine_fixture.rs"]
mod engine_fixture;

#[path = "common/response_proxy.rs"]
mod response_proxy;

use engine_fixture::{EngineFixture, TestBinary, TestResult};
use reqwest::{Method, StatusCode};
use verysync_sidecar::{ApiKey, Client, ConnectOptions, DeviceId, Error, ManagementEndpoint};

fn endpoint(instance: &EngineFixture) -> verysync_sidecar::Result<ManagementEndpoint> {
    #[cfg(unix)]
    {
        ManagementEndpoint::unix_socket(instance.state_dir().join("gui.sock"))
    }
    #[cfg(windows)]
    {
        ManagementEndpoint::http(&format!("http://{}", instance.management_address()))
    }
}

#[tokio::test]
async fn connect_auth_version_and_identity_through_the_public_api() -> TestResult {
    let mut instance = EngineFixture::start().await?;
    let identity = DeviceId::parse(instance.device_id())?;
    let options = ConnectOptions::new(endpoint(&instance)?, ApiKey::new(instance.api_key())?)
        .expected_device_id(identity.clone());
    let client = Client::connect(options).await?;
    let info = client.instance();
    assert_eq!(info.device_id, identity);
    assert_eq!(
        info.compatibility,
        verysync_sidecar::VersionCompatibility::ValidatedBaseline
    );
    assert_eq!(
        info.version.os,
        if cfg!(target_os = "macos") {
            "darwin"
        } else {
            std::env::consts::OS
        }
    );
    assert_eq!(
        info.version.arch,
        if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "amd64"
        }
    );
    assert_eq!(
        info.version.version,
        verysync_sidecar::BASELINE_ENGINE_VERSION
    );
    assert!(!format!("{client:?}").contains(instance.api_key()));
    drop(client);
    // A management connection does not own the serving process.
    assert_eq!(
        instance.read_json("/rest/system/status").await?["myID"],
        instance.device_id()
    );

    let wrong_key =
        ConnectOptions::new(endpoint(&instance)?, ApiKey::new("synthetic-invalid-key")?);
    assert!(matches!(
        Client::connect(wrong_key).await,
        Err(Error::AccessDenied { response }) if response.status() == 403
    ));

    let wrong_id =
        DeviceId::parse("AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA")?;
    assert_ne!(wrong_id.as_str(), instance.device_id());
    let wrong_identity =
        ConnectOptions::new(endpoint(&instance)?, ApiKey::new(instance.api_key())?)
            .expected_device_id(wrong_id);
    assert!(matches!(
        Client::connect(wrong_identity).await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert_eq!(
        instance.read_json("/rest/system/status").await?["myID"],
        instance.device_id()
    );
    assert!(instance.shutdown().await?.success());
    assert!(instance.has_reaped_process());
    Ok(())
}

#[test]
fn missing_test_program_or_checksum_is_an_error() -> TestResult {
    let path = std::env::current_exe()?;
    for (path, checksum) in [
        (None, None),
        (Some(path), None),
        (None, Some("0".repeat(64))),
    ] {
        assert!(TestBinary::new(path, checksum).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn checksum_mismatch_is_rejected_before_starting_an_engine() -> TestResult {
    let source = TestBinary::from_env()?;
    let invalid = TestBinary::new(Some(source.path().to_owned()), Some("0".repeat(64)))?;
    let result = EngineFixture::start_from(invalid).await;
    assert!(matches!(result, Err(error) if error.to_string().contains("checksum")));
    Ok(())
}

#[tokio::test]
async fn two_private_instances_have_separate_identity_authentication_and_cleanup() -> TestResult {
    let mut first = EngineFixture::start().await?;
    let mut second = EngineFixture::start().await?;

    assert_ne!(first.state_dir(), second.state_dir());
    assert_ne!(first.device_id(), second.device_id());
    assert_ne!(first.management_address(), second.management_address());
    assert!(
        first.api_key() != second.api_key(),
        "fixtures must not share API keys"
    );

    let helper = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("prepare-test-engine.py");
    let python = if cfg!(windows) { "python" } else { "python3" };
    let cleanup_probe = std::process::Command::new(python)
        .arg(helper)
        .arg("check-cleanup")
        .output()?;
    assert!(!cleanup_probe.status.success());
    assert!(String::from_utf8(cleanup_probe.stderr)?
        .contains("task-owned test engine processes remain"));

    let wrong_key = first
        .request_with_key(Method::GET, "/rest/system/version", "invalid-test-key")?
        .send()
        .await?;
    assert_eq!(wrong_key.status(), StatusCode::FORBIDDEN);

    for instance in [&first, &second] {
        let version = instance.read_json("/rest/system/version").await?;
        let expected_os = if cfg!(target_os = "macos") {
            "darwin"
        } else {
            std::env::consts::OS
        };
        let expected_arch = match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "amd64",
            other => {
                return Err(
                    format!("fixture architecture mapping not yet verified: {other}").into(),
                )
            }
        };
        assert_eq!(version["os"], expected_os);
        assert_eq!(version["arch"], expected_arch);
        let config = instance.read_json("/rest/config").await?;
        assert!(config["folders"].as_array().is_some_and(Vec::is_empty));
        for key in [
            "globalAnnounceEnabled",
            "localAnnounceEnabled",
            "relaysEnabled",
            "natEnabled",
            "udpEnabled",
            "startBrowser",
            "systrayEnabled",
            "trackerEnabled",
        ] {
            assert_eq!(
                config["options"][key], false,
                "unsafe fixture option: {key}"
            );
        }
        assert_eq!(config["relayServer"]["enabled"], false);
        assert_eq!(config["options"]["autoUpgradeIntervalH"], 0);
        assert!(config["options"]["globalAnnounceServers"]
            .as_array()
            .is_some_and(Vec::is_empty));
        assert!(instance.private_resources_are_protected()?);
    }

    let first_pid = first.pid();
    assert!(first.shutdown().await?.success());
    assert!(first.has_reaped_process());
    let version = second.read_json("/rest/system/version").await?;
    assert_eq!(
        version["version"],
        verysync_sidecar::BASELINE_ENGINE_VERSION
    );
    assert!(second.shutdown().await?.success());
    assert!(second.has_reaped_process());
    println!(
        "fixture cleanup confirmed for owned PIDs {first_pid} and {}",
        second.pid()
    );
    Ok(())
}

#[tokio::test]
async fn status_queries_report_real_synthetic_folder_counts_through_public_api() -> TestResult {
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::time::{Duration, Instant};
    use verysync_sidecar::{FolderId, FolderState, TargetPath};
    let mut instance = EngineFixture::start().await?;
    let client = Client::connect(
        ConnectOptions::new(endpoint(&instance)?, ApiKey::new(instance.api_key())?)
            .expected_device_id(DeviceId::parse(instance.device_id())?),
    )
    .await?;
    let version = client.version().await?;
    assert_eq!(version.version, verysync_sidecar::BASELINE_ENGINE_VERSION);
    let system = client.system_status().await?;
    assert_eq!(system.device_id.as_str(), instance.device_id());
    assert!(system.uptime_seconds.is_some());
    assert!(system.goroutines.is_some_and(|value| value > 0));
    assert!(system.memory_allocated_bytes.is_some_and(|value| value > 0));

    // This raw fixture operation only arranges an existing configured folder
    // for a read test. It is not acceptance of a public create-folder API.
    let folder_path = instance.state_dir().join("status folder 中文");
    fs::create_dir(&folder_path)?;
    let file = folder_path.join("synthetic.txt");
    let payload = b"synthetic status payload\n";
    fs::write(&file, payload)?;
    let before = Sha256::digest(fs::read(&file)?);
    let id = FolderId::parse("sidecar-status-fixture")?;
    let mut configuration = instance.read_json("/rest/config/defaults/folder").await?;
    let marker = configuration["markerName"]
        .as_str()
        .ok_or("baseline folder marker missing")?;
    if std::path::Path::new(marker)
        .components()
        .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err("fixture marker must be a single native relative component".into());
    }
    fs::create_dir(folder_path.join(marker))?;
    configuration["id"] = serde_json::json!(id.as_str());
    configuration["label"] = serde_json::json!("Synthetic status fixture");
    configuration["path"] =
        serde_json::json!(TargetPath::local(folder_path.clone()).to_protocol()?);
    configuration["paused"] = serde_json::json!(false);
    let created = instance
        .request(Method::POST, "/rest/config/folders")?
        .json(&configuration)
        .send()
        .await?;
    assert!(
        created.status().is_success(),
        "isolated fixture folder setup must succeed"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let folder = loop {
        match client.folder_status(&id).await {
            Ok(status)
                if status.state == Some(FolderState::Idle)
                    && status.local_files == Some(1)
                    && status.local_bytes == Some(payload.len() as u64) =>
            {
                break status
            }
            Ok(status) if Instant::now() >= deadline => {
                return Err(format!(
                    "synthetic folder never reached the expected indexed snapshot: {status:?}"
                )
                .into())
            }
            Err(error) if Instant::now() >= deadline => return Err(error.into()),
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    };
    assert_eq!(folder.global_files, Some(1));
    assert_eq!(folder.global_bytes, Some(payload.len() as u64));
    assert_eq!(folder.need_files, Some(0));
    assert_eq!(folder.need_bytes, Some(0));
    assert_eq!(Sha256::digest(fs::read(&file)?), before);
    let missing = client
        .folder_status(&FolderId::parse("sidecar-no-such-folder")?)
        .await;
    assert!(
        matches!(missing, Err(Error::Http { .. })),
        "missing upstream folder is not fabricated as idle/zero"
    );
    println!("public status evidence: version={}, uptime_known={}, goroutines_known={}, local_files={:?}, local_bytes={:?}, need_files={:?}, state={:?}, synthetic_hash_unchanged=true",version.version,system.uptime_seconds.is_some(),system.goroutines.is_some(),folder.local_files,folder.local_bytes,folder.need_files,folder.state);
    assert!(instance.shutdown().await?.success());
    Ok(())
}

#[tokio::test]
async fn fixture_research_folder_post_conflicts_and_conditions() -> TestResult {
    use sha2::{Digest, Sha256};
    use std::fs;
    use verysync_sidecar::TargetPath;
    let mut instance = EngineFixture::start().await?;
    let observation:TestResult<serde_json::Value>=async {
        let first=instance.state_dir().join("research original folder");
        let second=instance.state_dir().join("research replacement folder");
        let conditional=instance.state_dir().join("research conditional folder");
        fs::create_dir(&first)?;fs::create_dir(&second)?;
        let file=first.join("retained.txt");fs::write(&file,b"synthetic conflict data")?;
        let before=Sha256::digest(fs::read(&file)?);
        let response=instance.request(Method::GET,"/rest/config")?.send().await?;
        let etag_present=response.headers().contains_key("etag");
        let mut defaults=instance.read_json("/rest/config/defaults/folder").await?;
        defaults["id"]=serde_json::json!("sidecar-contract-research");
        defaults["label"]=serde_json::json!("original");
        defaults["path"]=serde_json::json!(TargetPath::local(first.clone()).to_protocol()?);
        defaults["paused"]=serde_json::json!(true);
        let first_http=instance.request(Method::POST,"/rest/config/folders")?.json(&defaults).send().await?.status().as_u16();
        let original=instance.read_json("/rest/config/folders/sidecar-contract-research").await?;
        defaults["label"]=serde_json::json!("replacement");
        defaults["path"]=serde_json::json!(TargetPath::local(second.clone()).to_protocol()?);
        let duplicate_http=instance.request(Method::POST,"/rest/config/folders")?.json(&defaults).send().await?.status().as_u16();
        let replacement=instance.read_json("/rest/config/folders/sidecar-contract-research").await?;
        defaults["id"]=serde_json::json!("sidecar-contract-condition");
        defaults["path"]=serde_json::json!(TargetPath::local(conditional).to_protocol()?);
        let conditional_http=instance.request(Method::POST,"/rest/config/folders")?.header("If-Match","\"synthetic-stale-etag\"").json(&defaults).send().await?.status().as_u16();
        let conditional_lookup=instance.request(Method::GET,"/rest/config/folders/sidecar-contract-condition")?.send().await?.status().as_u16();
        defaults["id"] = serde_json::json!("sidecar-contract-research");
        defaults["label"] = serde_json::json!("if-none-match-replacement");
        let if_none_http = instance.request(Method::POST,"/rest/config/folders")?
            .header("If-None-Match","*").json(&defaults).send().await?.status().as_u16();
        let after_if_none = instance.read_json("/rest/config/folders/sidecar-contract-research").await?;
        Ok(serde_json::json!({"scope":"raw fixture contract research, not public create-folder acceptance","first_http":first_http,"duplicate_http":duplicate_http,"original_label_correct":original["label"]=="original","duplicate_replaced_label":replacement["label"]=="replacement","duplicate_replaced_path":replacement["path"]==TargetPath::local(second).to_protocol()?,"config_etag_present":etag_present,"stale_if_match_http":conditional_http,"conditional_resource_lookup_http":conditional_lookup,"if_none_match_star_http":if_none_http,"if_none_match_replaced_label":after_if_none["label"]=="if-none-match-replacement","original_file_sha_unchanged":Sha256::digest(fs::read(file)?)==before}))
    }.await;
    let stopped = instance.shutdown().await;
    let observation = observation?;
    assert!(stopped?.success());
    if let Some(path) = std::env::var_os("VERYSYNC_FOLDER_CONTRACT_EVIDENCE") {
        let path = std::path::PathBuf::from(path);
        if !path.is_absolute() {
            return Err("absolute research evidence path required".into());
        }
        use std::io::Write;
        writeln!(
            fs::File::options()
                .write(true)
                .create_new(true)
                .open(path)?,
            "{}",
            serde_json::to_string_pretty(&observation)?
        )?;
    }
    println!("folder POST fixture research: {observation}");
    // Fixed-version protocol characterization, separate from public API proof.
    for field in [
        "first_http",
        "duplicate_http",
        "stale_if_match_http",
        "conditional_resource_lookup_http",
        "if_none_match_star_http",
    ] {
        assert_eq!(observation[field], 200, "{field}");
    }
    for field in [
        "original_label_correct",
        "duplicate_replaced_label",
        "duplicate_replaced_path",
        "if_none_match_replaced_label",
        "original_file_sha_unchanged",
    ] {
        assert_eq!(observation[field], true, "{field}");
    }
    assert_eq!(observation["config_etag_present"], false);

    Ok(())
}

#[tokio::test]
async fn folder_create_read_conflicts_and_existing_data_through_public_api() -> TestResult {
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::time::{Duration, Instant};
    use verysync_sidecar::{CreateFolderOptions, FolderId, TargetPath};
    let mut instance = EngineFixture::start().await?;
    let client = Client::connect(
        ConnectOptions::new(endpoint(&instance)?, ApiKey::new(instance.api_key())?)
            .expected_device_id(DeviceId::parse(instance.device_id())?),
    )
    .await?;
    let verified:TestResult<serde_json::Value>=async {
        let fresh=instance.state_dir().join("created by API 中文");
        let absent_before=!fresh.exists();
        let id=FolderId::parse("sidecar-created-folder")?;
        let options=CreateFolderOptions::new(id.clone(),TargetPath::local(fresh.clone())).label("Created folder 中文").paused(false);
        let created=client.create_folder(&options).await?;
        let deadline=Instant::now()+Duration::from_secs(15);
        while !fresh.is_dir() {
            if Instant::now()>=deadline {return Err("official engine did not create the requested directory".into());}
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        let configured=client.folder(&id).await?;
        let duplicate=client.create_folder(&CreateFolderOptions::new(id.clone(),TargetPath::local(fresh.clone())).label("must not overwrite")).await;
        let path_conflict=client.create_folder(&CreateFolderOptions::new(FolderId::parse("sidecar-other-id")?,TargetPath::local(fresh.clone()))).await;
        let after=client.folder(&id).await?;
        let existing=instance.state_dir().join("existing synthetic directory");fs::create_dir(&existing)?;
        let file=existing.join("retained.txt");fs::write(&file,b"retain pre-existing synthetic bytes")?;
        let hash=Sha256::digest(fs::read(&file)?);
        let existing_id=FolderId::parse("sidecar-existing-directory")?;
        let added=client.create_folder(&CreateFolderOptions::new(existing_id.clone(),TargetPath::local(existing.clone())).paused(true)).await?;
        let alias_id = FolderId::parse("sidecar-explicit-shared-path")?;
        let alias = client.create_folder(&CreateFolderOptions::new(alias_id.clone(),TargetPath::local(existing.clone())).paused(true).allow_shared_path(true)).await?;
        let race_id=FolderId::parse("sidecar-concurrent-create")?;
        let first=CreateFolderOptions::new(race_id.clone(),TargetPath::local(instance.state_dir().join("race-first"))).paused(true);
        let second=CreateFolderOptions::new(race_id.clone(),TargetPath::local(instance.state_dir().join("race-second"))).paused(true);
        let cloned=client.clone();let (one,two)=tokio::join!(client.create_folder(&first),cloned.create_folder(&second));
        let successes=usize::from(one.is_ok())+usize::from(two.is_ok());
        let conflicts=usize::from(matches!(one,Err(Error::FolderAlreadyExists{..})))+usize::from(matches!(two,Err(Error::FolderAlreadyExists{..})));
        let list=client.folders().await?;
        Ok(serde_json::json!({"new_directory_absent_before":absent_before,"official_engine_created_directory":fresh.is_dir(),"id_correct":created.id==id,"path_correct":configured.path.to_protocol()?==TargetPath::local(fresh).to_protocol()?,"label_correct":after.label=="Created folder 中文","duplicate_rejected":matches!(duplicate,Err(Error::FolderAlreadyExists{..})),"identical_path_rejected":matches!(path_conflict,Err(Error::FolderPathAlreadyConfigured{..})),"existing_directory_registered":added.id==existing_id && added.paused,"explicit_shared_path_registered":alias.id==alias_id && alias.paused,"original_file_sha_unchanged":Sha256::digest(fs::read(file)?)==hash,"concurrent_successes":successes,"concurrent_conflicts":conflicts,"single_concurrent_id":list.iter().filter(|folder|folder.id==race_id).count()==1,"upstream_defaults_retained":created.extra.contains_key("markerName") && created.extra.contains_key("devices")}))
    }.await;
    let stopped = instance.shutdown().await;
    let report = verified?;
    assert!(stopped?.success());
    for name in [
        "new_directory_absent_before",
        "official_engine_created_directory",
        "id_correct",
        "path_correct",
        "label_correct",
        "duplicate_rejected",
        "identical_path_rejected",
        "existing_directory_registered",
        "explicit_shared_path_registered",
        "original_file_sha_unchanged",
        "single_concurrent_id",
        "upstream_defaults_retained",
    ] {
        assert_eq!(report[name], true, "{name}");
    }
    assert_eq!(report["concurrent_successes"], 1);
    assert_eq!(report["concurrent_conflicts"], 1);
    println!("public folder create evidence: {report}");
    Ok(())
}

#[tokio::test]
async fn folder_update_pause_preserves_fields_and_resumes_actual_indexing() -> TestResult {
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        time::{Duration, Instant},
    };
    use verysync_sidecar::{CreateFolderOptions, FolderId, FolderPatch, FolderState, TargetPath};
    let mut instance = EngineFixture::start().await?;
    let client = Client::connect(
        ConnectOptions::new(endpoint(&instance)?, ApiKey::new(instance.api_key())?)
            .expected_device_id(DeviceId::parse(instance.device_id())?),
    )
    .await?;
    let verified: TestResult<serde_json::Value> = async {
        let path = instance.state_dir().join("update pause 中文");
        fs::create_dir(&path)?;
        let file = path.join("original.txt");
        fs::write(&file, b"synthetic before pause\n")?;
        let before_hash = Sha256::digest(fs::read(&file)?);
        let id = FolderId::parse("sidecar-update 中文?#%")?;
        let original = client.create_folder(&CreateFolderOptions::new(id.clone(),TargetPath::local(path.clone()))
            .label("Before").paused(false)).await?;
        let other_id = FolderId::parse("sidecar-unaffected-folder")?;
        let other = client.create_folder(&CreateFolderOptions::new(other_id.clone(),TargetPath::local(instance.state_dir().join("other folder")))
            .label("Untouched").paused(true)).await?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if client.folder_status(&id).await.is_ok_and(|s|s.local_files == Some(1) && s.state == Some(FolderState::Idle)) {break;}
            if Instant::now() >= deadline { return Err("initial synthetic index did not become ready".into()); }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let config_before = instance.read_json("/rest/config").await?;
        let updated = client.update_folder(&id,&FolderPatch::default().label("After 中文")).await?;
        let label_only = updated.requested_fields_match && updated.configuration.label == "After 中文"
            && updated.configuration.extra == original.extra && updated.configuration.paused == original.paused
            && updated.configuration.path.to_protocol()? == original.path.to_protocol()?;
        let paused = client.pause_folder(&id).await?;
        // An explicit fixture request probes runtime behavior; this does not
        // constitute acceptance of a public scan/task API.
        let deadline = Instant::now() + Duration::from_secs(15);
        let scan_rejected_paused = loop {
            let (fixture_http, request) = instance.request(Method::POST,"/rest/db/scan")?.build_split();
            let mut request = request?;
            request.url_mut().query_pairs_mut().append_pair("folder", id.as_str());
            let response = fixture_http.execute(request).await?;
            let scan_status = response.status().as_u16();
            let scan_body = response.text().await?;
            if !(200..300).contains(&scan_status) && scan_body.to_ascii_lowercase().contains("paused") { break true; }
            if Instant::now() >= deadline { return Err("runtime never rejected scanning as paused".into()); }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let status_while_paused = client.folder_status(&id).await?;
        let added = path.join("added while paused.txt");
        fs::write(&added,b"synthetic while paused\n")?;
        let resumed = client.resume_folder(&id).await?;
        let deadline = Instant::now() + Duration::from_secs(30);
        let indexed = loop {
            match client.folder_status(&id).await {
                Ok(status) if status.state == Some(FolderState::Idle) && status.local_files == Some(2) => break status,
                _ if Instant::now() >= deadline => return Err("resumed folder did not index the added sample".into()),
                _ => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        };
        let final_folder = client.folder(&id).await?;
        let other_after = client.folder(&other_id).await?;
        let config_after = instance.read_json("/rest/config").await?;
        let missing = client.pause_folder(&FolderId::parse("sidecar-missing-update")?).await;
        Ok(serde_json::json!({
            "label_only_fields_preserved":label_only,
            "pause_config_observed":paused.requested_fields_match && paused.configuration.paused,
            "runtime_paused_observed":scan_rejected_paused,
            "paused_status_remains_unknown":status_while_paused.state == Some(FolderState::Unknown(String::new())),
            "scan_rejected_while_paused":scan_rejected_paused,
            "resume_config_observed":resumed.requested_fields_match && !resumed.configuration.paused,
            "resumed_actual_file_count":indexed.local_files,
            "original_file_sha_unchanged":Sha256::digest(fs::read(file)?)==before_hash,
            "added_file_bytes_preserved":fs::read(added)?==b"synthetic while paused\n",
            "unknown_fields_preserved":final_folder.extra==original.extra,
            "unrelated_folder_preserved":other_after.id==other.id && other_after.label==other.label && other_after.paused==other.paused && other_after.extra==other.extra,
            "device_pause_and_options_unchanged":config_before["devices"]==config_after["devices"] && config_before["options"]==config_after["options"],
            "missing_target_rejected":matches!(missing,Err(Error::FolderNotFound{..}))
        }))
    }.await;
    let stopped = instance.shutdown().await;
    let report = verified?;
    println!("public folder update evidence: {report}");
    assert!(stopped?.success());
    for name in [
        "label_only_fields_preserved",
        "pause_config_observed",
        "runtime_paused_observed",
        "paused_status_remains_unknown",
        "scan_rejected_while_paused",
        "resume_config_observed",
        "original_file_sha_unchanged",
        "added_file_bytes_preserved",
        "unknown_fields_preserved",
        "unrelated_folder_preserved",
        "device_pause_and_options_unchanged",
        "missing_target_rejected",
    ] {
        assert_eq!(report[name], true, "{name}");
    }
    assert_eq!(report["resumed_actual_file_count"], 2);
    Ok(())
}

#[tokio::test]
async fn folder_remove_keep_files_preserves_samples_and_unrelated_configuration() -> TestResult {
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        time::{Duration, Instant},
    };
    use verysync_sidecar::{CreateFolderOptions, FolderId, FolderState, TargetPath};
    let mut instance = EngineFixture::start().await?;
    let client = Client::connect(
        ConnectOptions::new(endpoint(&instance)?, ApiKey::new(instance.api_key())?)
            .expected_device_id(DeviceId::parse(instance.device_id())?),
    )
    .await?;
    let verified:TestResult<serde_json::Value>=async {
        let path=instance.state_dir().join("unregister retained 中文");
        let nested=path.join("nested");fs::create_dir_all(&nested)?;
        let file=nested.join("retained.txt");fs::write(&file,b"retain this synthetic file after unregister\n")?;
        let hash=Sha256::digest(fs::read(&file)?);
        let other_path=instance.state_dir().join("unrelated retained folder");fs::create_dir(&other_path)?;
        let other_file=other_path.join("untouched.txt");fs::write(&other_file,b"unrelated synthetic file\n")?;
        let other_hash=Sha256::digest(fs::read(&other_file)?);
        let id=FolderId::parse("sidecar-remove 中文?#%")?;
        client.create_folder(&CreateFolderOptions::new(id.clone(),TargetPath::local(path.clone())).label("Unregister target").paused(false)).await?;
        let other_id=FolderId::parse("sidecar-keep-configured")?;
        let other=client.create_folder(&CreateFolderOptions::new(other_id.clone(),TargetPath::local(other_path.clone())).label("Keep configured").paused(true)).await?;
        let deadline=Instant::now()+Duration::from_secs(30);
        loop {
            if client.folder_status(&id).await.is_ok_and(|s|s.local_files==Some(1) && s.state==Some(FolderState::Idle)){break;}
            if Instant::now()>=deadline{return Err("active removal target did not index its sample".into());}
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let before=instance.read_json("/rest/config").await?;
        let missing_before=client.remove_folder_keep_files(&FolderId::parse("sidecar-no-such-removal")?).await;
        let target_survived_wrong_id=client.folder(&id).await?.id==id;
        let removed=client.remove_folder_keep_files(&id).await?;
        let absent=matches!(client.folder(&id).await,Err(Error::FolderNotFound{..}));
        let missing_after=client.remove_folder_keep_files(&id).await;
        let other_after=client.folder(&other_id).await?;
        let after=instance.read_json("/rest/config").await?;
        Ok(serde_json::json!({
            "absence_readback":removed.configuration_absent && absent,
            "previous_target_correct":removed.previous_configuration.id==id && removed.previous_configuration.path.to_protocol()?==TargetPath::local(path.clone()).to_protocol()?,
            "target_directory_retained":path.is_dir() && nested.is_dir(),
            "sample_sha_unchanged":Sha256::digest(fs::read(file)?)==hash,
            "unrelated_sample_sha_unchanged":Sha256::digest(fs::read(other_file)?)==other_hash,
            "unrelated_configuration_retained":other_after.id==other.id && other_after.label==other.label && other_after.path.to_protocol()?==other.path.to_protocol()? && other_after.paused==other.paused && other_after.extra==other.extra,
            "wrong_id_rejected_before_mutation":matches!(missing_before,Err(Error::FolderNotFound{..})) && target_survived_wrong_id,
            "already_removed_rejected":matches!(missing_after,Err(Error::FolderNotFound{..})),
            "devices_and_options_unchanged":before["devices"]==after["devices"] && before["options"]==after["options"]
        }))
    }.await;
    let stopped = instance.shutdown().await;
    let report = verified?;
    println!("public folder remove evidence: {report}");
    assert!(stopped?.success());
    for (name, value) in report
        .as_object()
        .ok_or("missing removal evidence object")?
    {
        assert_eq!(value, &serde_json::json!(true), "{name}");
    }
    Ok(())
}

#[tokio::test]
async fn error_timeout_native_denial_http_diagnostics_and_connection_reuse() -> TestResult {
    use verysync_sidecar::FolderId;
    let mut instance = EngineFixture::start().await?;
    let verified: TestResult<serde_json::Value> = async {
        let denied = Client::connect(ConnectOptions::new(endpoint(&instance)?,ApiKey::new("dedicated-incorrect-test-key")?)).await;
        let denial_safe = denied.as_ref().is_err_and(|error|!format!("{error:?} {error}").contains(instance.api_key()));
        let access_denied = matches!(denied,Err(Error::AccessDenied { response }) if response.status()==403);
        let client = Client::connect(ConnectOptions::new(endpoint(&instance)?,ApiKey::new(instance.api_key())?)
            .expected_device_id(DeviceId::parse(instance.device_id())?)).await?;
        let missing = client.folder_status(&FolderId::parse("sidecar-error-missing-folder")?).await;
        let (http_error, bounded_diagnostic) = match missing {
            Err(Error::Http { response }) => (response.status()>=400,!response.body_bytes().is_empty() && response.body_bytes().len()<=1024*1024),
            _ => (false,false),
        };
        let after = client.system_status().await?;
        Ok(serde_json::json!({"native_wrong_key_access_denied":access_denied,"denial_debug_safe":denial_safe,"native_missing_folder_http_error":http_error,"bounded_http_diagnostic":bounded_diagnostic,"same_client_read_after_http_failure":after.device_id.as_str()==instance.device_id()}))
    }.await;
    let stopped = instance.shutdown().await;
    let report = verified?;
    println!("public native error evidence: {report}");
    assert!(stopped?.success());
    for (name, value) in report.as_object().ok_or("missing error evidence")? {
        assert_eq!(value, &serde_json::json!(true), "{name}");
    }
    Ok(())
}

#[tokio::test]
async fn error_timeout_and_cancellation_preserve_actual_applied_mutation() -> TestResult {
    use response_proxy::{ResponseFault, ResponseProxy};
    use std::time::Duration;
    use verysync_sidecar::{CreateFolderOptions, FolderId, TargetPath};
    let mut instance = EngineFixture::start().await?;
    let verified:TestResult<serde_json::Value>=async {
        let mut reports=Vec::new();
        for (name,fault) in [("lost-response",ResponseFault::DropAfterApply),("deadline",ResponseFault::HoldAfterApply),("cancelled",ResponseFault::HoldAfterApply)] {
            let proxy=ResponseProxy::start(&instance,fault).await?;
            let timeout=if name=="deadline" {Duration::from_secs(1)} else {Duration::from_secs(10)};
            let client=Client::connect(ConnectOptions::new(proxy.endpoint(),ApiKey::new(instance.api_key())?)
                .expected_device_id(DeviceId::parse(instance.device_id())?).request_timeout(timeout)?).await?;
            let id=FolderId::parse(&format!("sidecar-error-{name}"))?;
            let options=CreateFolderOptions::new(id.clone(),TargetPath::local(instance.state_dir().join(name))).paused(true);
            let mut pending=Box::pin(client.create_folder(&options));
            let failure_correct=if name=="cancelled" {
                tokio::select! {
                    applied=tokio::time::timeout(Duration::from_secs(5),proxy.mutation_applied())=>{applied?;},
                    _=&mut pending=>return Err("modifying future completed before cancellation fault was injected".into()),
                }
                drop(pending);
                true
            } else {
                let error=tokio::time::timeout(Duration::from_secs(5),pending).await?.err().ok_or("faulted mutation unexpectedly returned success")?;
                tokio::time::timeout(Duration::from_secs(5),proxy.mutation_applied()).await?;
                let safe=!format!("{error:?} {error}").contains(instance.api_key());
                safe && if name=="deadline" {
                    matches!(error,Error::MutationOutcomeUnknown { source,.. } if matches!(*source,Error::Timeout {..}))
                } else {matches!(error,Error::MutationOutcomeUnknown {..})}
            };
            proxy.release_response();
            let observed=client.folder(&id).await?;
            let repeated=client.create_folder(&options).await;
            let identity=client.system_status().await?.device_id.as_str()==instance.device_id();
            let posts=proxy.post_count();
            proxy.finish().await?;
            reports.push(serde_json::json!({"case":name,"failure_or_cancellation_correct":failure_correct,"actual_mutation_read_back":observed.id==id && observed.paused,"no_automatic_write_retry":posts==1,"repeated_create_rejected_without_write":matches!(repeated,Err(Error::FolderAlreadyExists {..})) && posts==1,"same_client_remains_usable":identity,"proxy_joined":true}));
        }
        Ok(serde_json::Value::Array(reports))
    }.await;
    let stopped = instance.shutdown().await;
    let report = verified?;
    println!("public mutation uncertainty evidence: {report}");
    assert!(stopped?.success());
    for case in report.as_array().ok_or("missing uncertainty cases")? {
        for (name, value) in case.as_object().ok_or("missing uncertainty result")? {
            if name != "case" {
                assert_eq!(value, &serde_json::json!(true), "{} {name}", case["case"]);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn raw_request_uses_owned_management_connection_and_preserves_actual_results() -> TestResult {
    use verysync_sidecar::{
        CreateFolderOptions, FolderId, RawMethod, RawRequest, RequestEffect, TargetPath,
    };
    let mut instance = EngineFixture::start().await?;
    let client = Client::connect(
        ConnectOptions::new(endpoint(&instance)?, ApiKey::new(instance.api_key())?)
            .expected_device_id(DeviceId::parse(instance.device_id())?),
    )
    .await?;
    let verified:TestResult<serde_json::Value>=async {
        let version=client.raw_request(&RawRequest::new(RawMethod::Get,["rest","system","version"],RequestEffect::ReadOnly)?).await?;
        let decoded:serde_json::Value=serde_json::from_slice(version.body_bytes())?;
        let id=FolderId::parse("sidecar-raw 中文?#%")?;
        client.create_folder(&CreateFolderOptions::new(id.clone(),TargetPath::local(instance.state_dir().join("raw request synthetic folder"))).label("Before raw").paused(true)).await?;
        let updated=client.raw_request(&RawRequest::new(RawMethod::Patch,["rest","config","folders",id.as_str()],RequestEffect::MayModify)?
            .json_body(&serde_json::json!({"label":"Updated through raw"}))?).await?;
        let after=client.folder(&id).await?;
        let missing=client.raw_request(&RawRequest::new(RawMethod::Get,["rest","sidecar-no-such-route"],RequestEffect::ReadOnly)?).await?;
        let status=client.system_status().await?;
        Ok(serde_json::json!({"raw_version_status":version.status()==200,"raw_version_body":decoded["version"]==verysync_sidecar::BASELINE_ENGINE_VERSION,"raw_headers_retained":version.headers().any(|(name,_)|name=="content-type"),"explicit_raw_mutation_ack":(200..300).contains(&updated.status()),"actual_label_read_back":after.label=="Updated through raw" && after.paused,"unknown_route_status_retained":missing.status()==404,"unknown_route_body_retained":!missing.body_bytes().is_empty(),"same_selected_identity":status.device_id.as_str()==instance.device_id(),"debug_omits_key":!format!("{version:?} {updated:?} {missing:?}").contains(instance.api_key())}))
    }.await;
    let stopped = instance.shutdown().await;
    let report = verified?;
    println!("public raw request evidence: {report}");
    assert!(stopped?.success());
    for (name, value) in report.as_object().ok_or("missing raw evidence")? {
        assert_eq!(value, &serde_json::json!(true), "{name}");
    }
    Ok(())
}

#[tokio::test]
async fn capabilities_report_matches_native_coordinates_without_inventing_authorization(
) -> TestResult {
    use verysync_sidecar::{
        Capability, ImplementationStatus, InstanceObservation, TargetValidation, VerificationStatus,
    };
    let mut instance = EngineFixture::start().await?;
    let verified:TestResult<serde_json::Value>=async {
        let client=Client::connect(ConnectOptions::new(endpoint(&instance)?,ApiKey::new(instance.api_key())?)
            .expected_device_id(DeviceId::parse(instance.device_id())?)).await?;
        let report=client.capabilities();
        let runtime=report.library.iter().find(|entry|entry.capability==Capability::ManagedRuntime).ok_or("runtime scope missing")?;
        let raw=report.library.iter().find(|entry|entry.capability==Capability::RawManagement).ok_or("raw scope missing")?;
        Ok(serde_json::json!({"baseline_snapshot_correct":report.target.engine_version==verysync_sidecar::BASELINE_ENGINE_VERSION,"native_coordinates_match":report.target_validation==TargetValidation::MatchesRecordedCoordinates,"authenticated_at_handshake_only":report.instance.authentication==InstanceObservation::ObservedAtHandshake,"unprobed_license_unknown":report.instance.commercial_license==InstanceObservation::Unknown,"unprobed_permissions_unknown":report.instance.operation_authorization==InstanceObservation::Unknown,"runtime_not_implemented_not_promoted":runtime.implementation==ImplementationStatus::NotImplemented && runtime.verification==VerificationStatus::NotRun,"raw_is_transport_only":raw.implementation==ImplementationStatus::RawTransport,"raw_evidence_explicit":matches!(raw.verification,VerificationStatus::NativeEvidence {engine_version,..} if engine_version==verysync_sidecar::BASELINE_ENGINE_VERSION),"debug_key_safe":!format!("{report:?}").contains(instance.api_key())}))
    }.await;
    let stopped = instance.shutdown().await;
    let report = verified?;
    println!("public capability evidence: {report}");
    assert!(stopped?.success());
    for (name, value) in report.as_object().ok_or("missing capability evidence")? {
        assert_eq!(value, &serde_json::json!(true), "{name}");
    }
    Ok(())
}
