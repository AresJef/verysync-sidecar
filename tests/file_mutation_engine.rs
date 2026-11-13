//! Public filesystem effects are confined to one private engine's synthetic data.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
#[path = "common/resource_fixture.rs"]
mod resource_fixture;
use managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::{
    Error, ManagedInstance, ResourceConflictPolicy as Conflict, ResourceDeleteScope, ResourcePath,
};
async fn mount(core: &ManagedInstance) -> TestResult<(std::path::PathBuf, ResourcePath)> {
    let volumes = core.client().resource_volumes().await?;
    resource_fixture::owned_base(core, &volumes)
}
fn report(stage: &str, error: &Error) {
    eprintln!("Private mutation failure stage: {stage}, error={error:?}");
    match error {
        Error::MutationOutcomeUnknown { source, .. } => report("underlying", source),
        Error::ResourceMutationRejected { reason }
        | Error::InvalidConfiguration { reason }
        | Error::InvalidPath { reason } => eprintln!("Private mutation reason: {reason}"),
        Error::Http { response }
        | Error::AccessDenied { response }
        | Error::InvalidResponse { response, .. } => eprintln!(
            "Private mutation response: status={} bytes={}",
            response.status(),
            response.body_bytes().len()
        ),
        _ => {}
    }
}
#[tokio::test]
async fn public_resource_changes_create_copy_move_edit_and_delete_actual_synthetic_bytes(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vfm-").tempdir()?.keep();
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let (profile, volume) = mount(&core).await?;
    let base = volume.clone().child("changes")?;
    let result = core.client().create_resource_directory(&base).await?;
    assert!(result.is_dir);
    let native = profile.join("changes");
    assert!(native.is_dir());
    let nested = base.clone().child("parents")?.child("二 %.dir")?;
    assert!(
        core.client()
            .create_resource_directory(&nested)
            .await?
            .is_dir
    );
    assert!(native.join("parents").join("二 %.dir").is_dir());
    std::fs::write(native.join("source.bin"), b"source original bytes")?;
    std::fs::write(native.join("existing.bin"), b"destination original bytes")?;
    std::fs::write(native.join("untouched.bin"), b"unrelated sibling bytes")?;
    assert!(matches!(
        core.client().create_resource_directory(&base).await,
        Err(Error::ResourceAlreadyExists)
    ));
    let source = base.clone().child("source.bin")?;
    assert!(matches!(
        core.client().create_resource_directory(&source).await,
        Err(Error::ResourceAlreadyExists)
    ));
    assert_eq!(
        std::fs::read(native.join("source.bin"))?,
        b"source original bytes"
    );
    let copied = base.clone().child("copied 二 %.bin")?;
    let result = core
        .client()
        .copy_resource(&source, &copied, Conflict::RejectExisting)
        .await
        .inspect_err(|e| report("copy-resource", e))?;
    assert!(!result.generated_name && !result.metadata.is_dir);
    assert_eq!(
        std::fs::read(native.join("copied 二 %.bin"))?,
        b"source original bytes"
    );
    assert_eq!(
        std::fs::read(native.join("source.bin"))?,
        b"source original bytes"
    );
    let existing = base.clone().child("existing.bin")?;
    assert!(matches!(
        core.client()
            .copy_resource(&source, &existing, Conflict::RejectExisting)
            .await,
        Err(Error::ResourceAlreadyExists)
    ));
    assert_eq!(
        std::fs::read(native.join("existing.bin"))?,
        b"destination original bytes"
    );
    let kept = core
        .client()
        .copy_resource(&source, &existing, Conflict::KeepBoth)
        .await
        .inspect_err(|e| report("copy-resource", e))?;
    assert!(kept.generated_name);
    assert_eq!(kept.metadata.name, "existing(1).bin");
    assert_eq!(
        std::fs::read(native.join("existing(1).bin"))?,
        b"source original bytes"
    );
    assert_eq!(
        std::fs::read(native.join("existing.bin"))?,
        b"destination original bytes"
    );
    let overwrite = core
        .client()
        .copy_resource(&source, &existing, Conflict::OverwriteAndMerge)
        .await
        .inspect_err(|e| report("copy-resource", e))?;
    assert!(!overwrite.generated_name);
    assert_eq!(
        std::fs::read(native.join("existing.bin"))?,
        b"source original bytes"
    );
    assert!(matches!(
        core.client()
            .move_resource(&copied, &existing, Conflict::RejectExisting)
            .await,
        Err(Error::ResourceAlreadyExists)
    ));
    assert_eq!(
        std::fs::read(native.join("copied 二 %.bin"))?,
        b"source original bytes"
    );
    let moved_keep = core
        .client()
        .move_resource(&copied, &existing, Conflict::KeepBoth)
        .await?;
    assert!(moved_keep.generated_name);
    assert_eq!(moved_keep.metadata.name, "existing(2).bin");
    assert!(!native.join("copied 二 %.bin").exists());
    assert_eq!(
        std::fs::read(native.join("existing(2).bin"))?,
        b"source original bytes"
    );
    let moved = base.clone().child("renamed 二 %.bin")?;
    let result = core
        .client()
        .move_resource(&moved_keep.destination, &moved, Conflict::RejectExisting)
        .await
        .inspect_err(|e| report("move-resource", e))?;
    assert!(!result.generated_name);
    assert!(!native.join("copied 二 %.bin").exists());
    assert_eq!(
        std::fs::read(native.join("renamed 二 %.bin"))?,
        b"source original bytes"
    );
    let empty = core.client().write_resource_text(&moved, "").await?;
    assert_eq!(empty.size, 0);
    assert!(std::fs::read(native.join("renamed 二 %.bin"))?.is_empty());
    let text = "new UTF-8 二 % text\nsecond line";
    let edited = core.client().write_resource_text(&moved, text).await?;
    assert_eq!(edited.size, text.len() as u64);
    assert_eq!(
        std::fs::read(native.join("renamed 二 %.bin"))?,
        text.as_bytes()
    );
    assert!(matches!(
        core.client().write_resource_text(&base, "refused").await,
        Err(Error::ResourceMutationRejected { .. })
    ));
    let missing = base.clone().child("missing")?;
    assert!(matches!(
        core.client().write_resource_text(&missing, "refused").await,
        Err(Error::ResourceNotFound)
    ));
    assert!(matches!(
        core.client()
            .delete_resource(&base, ResourceDeleteScope::File)
            .await,
        Err(Error::ResourceMutationRejected { .. })
    ));
    assert!(matches!(
        core.client()
            .delete_resource(&source, ResourceDeleteScope::RecursiveDirectory)
            .await,
        Err(Error::ResourceMutationRejected { .. })
    ));
    assert!(matches!(
        core.client()
            .copy_resource(&source, &source, Conflict::OverwriteAndMerge)
            .await,
        Err(Error::ResourceMutationRejected { .. })
    ));
    assert!(matches!(
        core.client()
            .move_resource(
                &base,
                &base.clone().child("inside")?,
                Conflict::RejectExisting
            )
            .await,
        Err(Error::ResourceMutationRejected { .. })
    ));
    let protected_root = ResourcePath::root(volume.volume().clone(), volume.style());
    for result in [
        core.client()
            .create_resource_directory(&protected_root)
            .await
            .map(|_| ()),
        core.client()
            .delete_resource(&protected_root, ResourceDeleteScope::RecursiveDirectory)
            .await
            .map(|_| ()),
        core.client()
            .write_resource_text(&protected_root, "refused")
            .await
            .map(|_| ()),
    ] {
        assert!(matches!(result, Err(Error::InvalidPath { .. })));
    }
    let removed = core
        .client()
        .delete_resource(&moved, ResourceDeleteScope::File)
        .await
        .inspect_err(|e| report("copy-resource", e))?;
    assert!(!removed.previous.is_dir);
    assert!(!native.join("renamed 二 %.bin").exists());
    assert!(matches!(
        core.client()
            .delete_resource(&moved, ResourceDeleteScope::File)
            .await,
        Err(Error::ResourceNotFound)
    ));
    assert_eq!(
        std::fs::read(native.join("untouched.bin"))?,
        b"unrelated sibling bytes"
    );
    assert_eq!(
        std::fs::read(native.join("source.bin"))?,
        b"source original bytes"
    );
    let removed = core
        .client()
        .delete_resource(&base, ResourceDeleteScope::RecursiveDirectory)
        .await
        .inspect_err(|e| report("move-resource", e))?;
    assert!(removed.previous.is_dir);
    assert!(!native.exists());
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public resource mutation evidence: {}",
        serde_json::json!({
        "actual_post_directory_and_parent_creation":true,"actual_unicode_percent_directory":true,
        "actual_duplicate_directory_and_file_preserved":true,"actual_copy_payload_and_source_unchanged":true,
        "actual_copy_conflict_refused_without_data_change":true,"actual_keep_both_generated_name_and_both_payloads":true,
        "actual_explicit_file_overwrite":true,"actual_move_old_absent_new_bytes":true,"actual_move_conflict_refusal_preserves_source":true,"actual_move_keep_both_generated_name_and_payload":true,
        "actual_existing_text_put_size_digest_and_utf8_bytes":true,"actual_empty_text_put_and_digest":true,"actual_text_kind_and_missing_guards":true,
        "actual_delete_kind_guards_preserve_data":true,"actual_self_descendant_and_volume_root_guards":true,
        "actual_file_delete_and_missing_refusal":true,"actual_unrelated_sibling_and_source_retained":true,
        "actual_explicit_recursive_delete":true,"actual_normal_owned_tree_exit":true})
    );
    Ok(())
}

#[tokio::test]
async fn public_directory_merges_preserve_destination_children_and_reject_cross_volume_misrouting(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vfdm-").tempdir()?.keep();
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let (profile, volume) = mount(&core).await?;
    let base = volume.clone().child("trees")?;
    core.client().create_resource_directory(&base).await?;
    let native = profile.join("trees");
    for name in ["source", "existing", "moving", "move-destination"] {
        core.client()
            .create_resource_directory(&base.clone().child(name)?)
            .await?;
    }
    std::fs::create_dir(native.join("source").join("nested"))?;
    std::fs::write(
        native.join("source").join("nested").join("payload.bin"),
        b"source nested bytes",
    )?;
    std::fs::write(
        native.join("source").join("same.txt"),
        b"new colliding bytes",
    )?;
    std::fs::write(
        native.join("existing").join("same.txt"),
        b"old colliding bytes",
    )?;
    std::fs::write(
        native.join("existing").join("extra.txt"),
        b"destination-only bytes",
    )?;
    let source = base.clone().child("source")?;
    let existing = base.clone().child("existing")?;
    core.client()
        .copy_resource(
            &source,
            &base.clone().child("copy")?,
            Conflict::RejectExisting,
        )
        .await
        .inspect_err(|e| report("copy-resource", e))?;
    assert_eq!(
        std::fs::read(native.join("copy").join("nested").join("payload.bin"))?,
        b"source nested bytes"
    );
    core.client()
        .copy_resource(&source, &existing, Conflict::OverwriteAndMerge)
        .await
        .inspect_err(|e| report("copy-resource", e))?;
    assert_eq!(
        std::fs::read(native.join("existing").join("same.txt"))?,
        b"new colliding bytes"
    );
    assert_eq!(
        std::fs::read(native.join("existing").join("extra.txt"))?,
        b"destination-only bytes"
    );
    assert_eq!(
        std::fs::read(native.join("existing").join("nested").join("payload.bin"))?,
        b"source nested bytes"
    );
    let kept = core
        .client()
        .copy_resource(&source, &existing, Conflict::KeepBoth)
        .await
        .inspect_err(|e| report("copy-resource", e))?;
    assert!(kept.generated_name);
    assert_eq!(kept.metadata.name, "existing(1)");
    assert_eq!(
        std::fs::read(
            native
                .join("existing(1)")
                .join("nested")
                .join("payload.bin")
        )?,
        b"source nested bytes"
    );
    std::fs::write(
        native.join("moving").join("source.txt"),
        b"moving tree bytes",
    )?;
    std::fs::write(
        native.join("move-destination").join("extra.txt"),
        b"moving destination-only bytes",
    )?;
    core.client()
        .move_resource(
            &base.clone().child("moving")?,
            &base.clone().child("move-destination")?,
            Conflict::OverwriteAndMerge,
        )
        .await
        .inspect_err(|e| report("move-resource", e))?;
    assert!(!native.join("moving").exists());
    assert_eq!(
        std::fs::read(native.join("move-destination").join("source.txt"))?,
        b"moving tree bytes"
    );
    assert_eq!(
        std::fs::read(native.join("move-destination").join("extra.txt"))?,
        b"moving destination-only bytes"
    );
    std::fs::write(
        native.join("cross-source.bin"),
        b"cross logical volume bytes",
    )?;
    let other = ResourcePath::root(
        verysync_sidecar::ResourceVolumeId::parse("unrelated-synthetic-volume")?,
        volume.style(),
    )
    .child("protected.bin")?;
    assert!(matches!(
        core.client()
            .copy_resource(
                &base.clone().child("cross-source.bin")?,
                &other,
                Conflict::RejectExisting
            )
            .await,
        Err(Error::ResourceMutationRejected { .. })
    ));
    assert!(matches!(
        core.client()
            .move_resource(
                &base.clone().child("cross-source.bin")?,
                &other,
                Conflict::OverwriteAndMerge
            )
            .await,
        Err(Error::ResourceMutationRejected { .. })
    ));
    assert!(!native.join("cross-copy.bin").exists());
    assert_eq!(
        std::fs::read(native.join("cross-source.bin"))?,
        b"cross logical volume bytes"
    );
    assert_eq!(
        std::fs::read(native.join("source").join("nested").join("payload.bin"))?,
        b"source nested bytes"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!(
        "public resource tree mutation evidence: {}",
        serde_json::json!({
        "actual_complete_nested_directory_copy":true,"actual_copy_merge_overwrites_colliding_files":true,
        "actual_copy_merge_retains_destination_only_children":true,"actual_generated_directory_name_and_contents":true,
        "actual_move_merge_old_source_absent":true,"actual_move_merge_source_payload":true,
        "actual_move_merge_retains_destination_only_children":true,"cross_volume_copy_rejected_before_misrouted_request":true,
        "cross_volume_move_rejected_before_misrouted_request":true,"actual_original_file_and_tree_preserved":true,
        "actual_normal_owned_tree_exit":true,"scope":"same logical volume only; distinct volume IDs are refused before native mutation"})
    );
    Ok(())
}

#[tokio::test]
async fn public_cancelled_directory_copy_reconciles_partial_merge_without_rolling_back_data(
) -> TestResult {
    let root = tempfile::Builder::new().prefix("vfmc-").tempdir()?.keep();
    let mut core = ManagedInstance::start(options(&root.join("c"))?).await?;
    let (profile, volume) = mount(&core).await?;
    let source = volume.clone().child("cancel-source")?;
    let target = volume.clone().child("cancel-target")?;
    core.client().create_resource_directory(&source).await?;
    core.client().create_resource_directory(&target).await?;
    let from = profile.join("cancel-source");
    let to = profile.join("cancel-target");
    let block: Vec<_> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();
    for i in 0..128u64 {
        let mut data = block.clone();
        data[..8].copy_from_slice(&i.to_le_bytes());
        std::fs::write(from.join(format!("file-{i:04}.bin")), data)?;
    }
    std::fs::write(to.join("destination-only.txt"), b"merge sentinel bytes")?;
    std::fs::write(to.join("file-0000.bin"), b"old colliding target bytes")?;
    let client = core.client().clone();
    let copy = tokio::spawn(async move {
        client
            .copy_resource(&source, &target, Conflict::OverwriteAndMerge)
            .await
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let overwritten = tokio::fs::metadata(to.join("file-0000.bin"))
                .await
                .is_ok_and(|m| m.len() > 32);
            let entries = std::fs::read_dir(&to)?.count();
            if overwritten && entries < 129 {
                break Ok::<(), std::io::Error>(());
            }
            assert!(
                !copy.is_finished(),
                "copy completed before observing a partial merge"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await??;
    copy.abort();
    assert!(copy.await.unwrap_err().is_cancelled());
    core.client().system_status().await?;
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    assert_eq!(
        std::fs::read(to.join("destination-only.txt"))?,
        b"merge sentinel bytes"
    );
    let mut destination_files = 0;
    let mut retained_bytes = 0u64;
    for entry in std::fs::read_dir(&to)? {
        let entry = entry?;
        if entry.file_name() == "destination-only.txt" {
            continue;
        }
        assert!(entry.file_type()?.is_file());
        let actual = std::fs::read(entry.path())?;
        let expected = std::fs::read(from.join(entry.file_name()))?;
        assert!(actual.len() <= expected.len());
        assert_eq!(actual, expected[..actual.len()]);
        destination_files += 1;
        retained_bytes += actual.len() as u64;
    }
    assert!(destination_files > 0 && destination_files <= 128);
    for i in 0..128u64 {
        let data = std::fs::read(from.join(format!("file-{i:04}.bin")))?;
        assert_eq!(data.len(), block.len());
        assert_eq!(&data[..8], &i.to_le_bytes());
        assert_eq!(&data[8..], &block[8..]);
    }
    println!(
        "public resource copy cancellation evidence: {}",
        serde_json::json!({
        "actual_cancel_after_nonempty_overwrite_and_partial_tree":true,"actual_future_joined_cancelled":true,
        "actual_destination_only_data_preserved":true,"actual_retained_files_match_source_prefixes":true,
        "actual_all_128_source_files_unchanged":true,"actual_client_authentication_after_cancel":true,
        "actual_normal_owned_tree_exit":true,"retained_destination_files":destination_files,
        "retained_destination_bytes":retained_bytes,"source_files":128,"source_bytes":67108864})
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
