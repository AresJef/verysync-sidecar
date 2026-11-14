//! Actual typed native policy selection; platform data effects are separate.
use super::*;

#[tokio::test]
async fn typed_folder_policies_and_initial_encrypted_registration_preserve_files() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-folder-policies-")
        .tempdir()?
        .keep();
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let id = FolderId::parse("synthetic-policies")?;
    let data = root.join("data");
    std::fs::create_dir(&data)?;
    std::fs::write(data.join("sentinel.bin"), b"retained native policy data")?;
    core.client()
        .create_folder(
            &CreateFolderOptions::new(id.clone(), TargetPath::local(data.clone())).paused(true),
        )
        .await?;
    for kind in [
        FolderType::SendOnly,
        FolderType::ReceiveOnly,
        FolderType::SendReceive,
    ] {
        let update = core
            .client()
            .update_folder_advanced_configuration(
                &id,
                &FolderAdvancedPatch::default().folder_type(kind.clone()),
            )
            .await?;
        assert!(update.requested_fields_match);
        assert_eq!(update.configuration.folder_type, Some(kind));
    }
    for order in [
        BlockPullOrder::Standard,
        BlockPullOrder::Random,
        BlockPullOrder::InOrder,
    ] {
        let update = core
            .client()
            .update_folder_advanced_configuration(
                &id,
                &FolderAdvancedPatch::default().block_pull_order(order.clone()),
            )
            .await?;
        assert!(update.requested_fields_match);
        assert_eq!(update.configuration.block_pull_order, Some(order));
    }
    for method in [
        CopyRangeMethod::Standard,
        CopyRangeMethod::CopyFileRange,
        CopyRangeMethod::Ioctl,
        CopyRangeMethod::Sendfile,
        CopyRangeMethod::DuplicateExtents,
        CopyRangeMethod::All,
    ] {
        let update = core
            .client()
            .update_folder_advanced_configuration(
                &id,
                &FolderAdvancedPatch::default().copy_range_method(method.clone()),
            )
            .await?;
        assert!(update.requested_fields_match);
        assert_eq!(update.configuration.copy_range_method, Some(method));
    }
    let filter = ExtendedAttributeFilter::new(
        vec![
            ExtendedAttributeRule::new("user.verysync*", true)?,
            ExtendedAttributeRule::new("*", false)?,
        ],
        2048,
        8192,
    )?;
    let patch = FolderAdvancedPatch::default()
        .folder_type(FolderType::SendOnly)
        .block_pull_order(BlockPullOrder::InOrder)
        .copy_range_method(CopyRangeMethod::All)
        .extended_attribute_filter(filter.clone());
    assert!(
        core.client()
            .update_folder_defaults(&FolderDefaultsPatch::default().advanced_configuration(patch)?)
            .await?
            .requested_fields_match
    );
    assert_eq!(
        core.client()
            .folder_advanced_configuration(&id)
            .await?
            .folder_type,
        Some(FolderType::SendReceive)
    );
    let future = FolderId::parse("synthetic-policy-inherited")?;
    let future_path = root.join("future");
    std::fs::create_dir(&future_path)?;
    let created = core
        .client()
        .create_folder(
            &CreateFolderOptions::new(future.clone(), TargetPath::local(future_path)).paused(true),
        )
        .await?;
    let inherited = created.advanced_configuration()?;
    assert_eq!(inherited.folder_type, Some(FolderType::SendOnly));
    assert_eq!(inherited.extended_attribute_filter, Some(filter.clone()));
    let encrypted = FolderId::parse("synthetic-policy-encrypted")?;
    let encrypted_path = root.join("encrypted");
    std::fs::create_dir(&encrypted_path)?;
    let before = core.client().folder_defaults().await?;
    let initial = core
        .client()
        .create_folder(
            &CreateFolderOptions::new(encrypted.clone(), TargetPath::local(encrypted_path))
                .paused(true)
                .advanced_configuration(
                    FolderAdvancedPatch::default().folder_type(FolderType::ReceiveEncrypted),
                )?,
        )
        .await?;
    assert_eq!(
        initial.advanced_configuration()?.folder_type,
        Some(FolderType::ReceiveEncrypted)
    );
    assert_eq!(
        serde_json::to_value(&core.client().folder_defaults().await?)?,
        serde_json::to_value(before)?
    );
    assert!(
        core.client()
            .update_folder_advanced_configuration(
                &encrypted,
                &FolderAdvancedPatch::default().folder_type(FolderType::ReceiveEncrypted)
            )
            .await?
            .requested_fields_match
    );
    for (folder, kind) in [
        (&id, FolderType::ReceiveEncrypted),
        (&encrypted, FolderType::SendReceive),
    ] {
        assert!(matches!(
            core.client()
                .update_folder_advanced_configuration(
                    folder,
                    &FolderAdvancedPatch::default().folder_type(kind)
                )
                .await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(core.client().instance().device_id, identity);
    assert_eq!(
        core.client()
            .folder_advanced_configuration(&encrypted)
            .await?
            .folder_type,
        Some(FolderType::ReceiveEncrypted)
    );
    let persisted = core.client().folder_advanced_configuration(&future).await?;
    assert_eq!(persisted.folder_type, Some(FolderType::SendOnly));
    assert_eq!(persisted.extended_attribute_filter, Some(filter));
    for folder in [&id, &future, &encrypted] {
        assert!(
            core.client()
                .remove_folder_keep_files(folder)
                .await?
                .configuration_absent
        );
    }
    assert_eq!(
        std::fs::read(data.join("sentinel.bin"))?,
        b"retained native policy data"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    println!("native_folder_policy_effects=20 initial_encrypted_registration=true metadata_copy_path_encrypted_transfer_not_claimed=true");
    Ok(())
}
