use super::*;
use sha2::{Digest, Sha256};
use std::path::Path;
use verysync_sidecar::{
    Client, CreateFolderOptions, FolderId, FolderPatch, RawMethod, RawRequest, RequestEffect,
};

#[tokio::test]
async fn existing_dot_registration_is_readable_and_ordinary_lifecycles_keep_owned_files(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vfid-").tempdir()?;
    let mut core = ManagedInstance::start(options(&root.path().join("c"))?).await?;
    let path = root.path().to_path_buf();
    let client = core.client().clone();
    let result = tokio::spawn(async move { verify_registrations(&client, &path).await }).await;
    let exit = core.shutdown(Duration::from_secs(15)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    root.close()?;
    println!("native registration cleanup: normal_exit=true state_removed=true");
    result?
}

async fn verify_registrations(client: &Client, root: &Path) -> TestResult {
    let legacy = root.join("legacy");
    let created = root.join("created");
    let joined = root.join("joined");
    let samples = [
        (&legacy, b"legacy registration bytes".as_slice()),
        (&created, b"ordinary creation bytes".as_slice()),
        (&joined, b"ordinary shared registration bytes".as_slice()),
    ];
    for (path, data) in samples {
        std::fs::create_dir(path)?;
        std::fs::write(path.join("sentinel.bin"), data)?;
    }
    for id in [".", ".."] {
        let create =
            CreateFolderOptions::new(FolderId::parse(id)?, TargetPath::local(&legacy)).paused(true);
        assert!(matches!(
            client.create_folder(&create).await,
            Err(Error::InvalidConfiguration { .. })
        ));
        assert!(client.folders().await?.is_empty());
    }

    // Seed an existing native registration through the explicit raw collection
    // route. The guard is for new typed registrations and leaves this readable.
    let defaults = client
        .raw_request(&RawRequest::new(
            RawMethod::Get,
            ["rest", "config", "defaults", "folder"],
            RequestEffect::ReadOnly,
        )?)
        .await?;
    assert_eq!(defaults.status(), 200);
    let mut item: serde_json::Value = serde_json::from_slice(defaults.body_bytes())?;
    item["id"] = json!(".");
    item["path"] = json!(legacy.to_str().ok_or("non-UTF8 private fixture path")?);
    item["label"] = json!("historic");
    item["paused"] = json!(true);
    let seeded = client
        .raw_request(
            &RawRequest::new(
                RawMethod::Post,
                ["rest", "config", "folders"],
                RequestEffect::MayModify,
            )?
            .json_body(&item)?,
        )
        .await?;
    assert!(matches!(seeded.status(), 200 | 204));
    let dot = FolderId::parse(".")?;
    assert_eq!(
        client
            .folders()
            .await?
            .iter()
            .filter(|folder| folder.id == dot)
            .count(),
        1
    );
    assert_eq!(client.folder(&dot).await?.label, "historic");
    let patch = FolderPatch::default().label("updated");
    assert!(matches!(
        client.update_folder(&dot, &patch).await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        client.remove_folder_keep_files(&dot).await,
        Err(Error::InvalidConfiguration { .. })
    ));

    let ordinary = FolderId::parse("ordinary-created")?;
    let create =
        CreateFolderOptions::new(ordinary.clone(), TargetPath::local(&created)).paused(true);
    assert_eq!(client.create_folder(&create).await?.id, ordinary);
    let keys = client.generate_share().await?;
    let share = client.validate_share_key(&keys.read_write_key).await?;
    let share_id = share.registration_id().clone();
    assert_ne!(share_id, ordinary);
    let join = JoinFolderOptions::new(share, TargetPath::local(&joined)).paused(true);
    let actual = client.join_folder(&join).await?;
    assert_eq!(actual.configuration.id, share_id);
    assert!(
        actual.submitted_key_matches
            && actual.read_only_key_matches
            && actual.read_write_key_matches
    );
    for (target, other) in [(&ordinary, &share_id), (&share_id, &dot)] {
        let updated = client.update_folder(target, &patch).await?;
        assert!(updated.requested_fields_match);
        assert_eq!(&updated.configuration.id, target);
        assert_eq!(client.folder(target).await?.label, "updated");
        assert!(
            client
                .remove_folder_keep_files(target)
                .await?
                .configuration_absent
        );
        assert!(matches!(
            client.folder(target).await,
            Err(Error::FolderNotFound { .. })
        ));
        assert_eq!(&client.folder(other).await?.id, other);
    }
    assert_eq!(client.folders().await?.len(), 1);
    assert_eq!(client.folder(&dot).await?.label, "historic");
    for (path, data) in samples {
        let actual = std::fs::read(path.join("sentinel.bin"))?;
        assert_eq!(actual, data);
        assert_eq!(Sha256::digest(actual), Sha256::digest(data));
    }
    println!("native registration evidence: historical_dot_read=true typed_dot_writes_refused=true ordinary_create_and_join=true precise_update_and_unregister=true three_file_hashes_match=true");
    Ok(())
}
