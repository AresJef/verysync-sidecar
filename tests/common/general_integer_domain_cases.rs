//! Native signed configuration domain; negative runtime effects remain separate.
use super::managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::*;

#[tokio::test]
async fn native_general_signed_integer_domains_survive_partial_full_saves_and_restart() -> TestResult
{
    let root = tempfile::Builder::new()
        .prefix("vsgsigned-")
        .tempdir()?
        .keep();
    std::fs::write(
        root.join("caller-sentinel"),
        b"signed general option caller data",
    )?;
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let before = core.client().configuration().await?;
    let original = core.client().general_options().await?;
    let protected = ["key.pem", "cert.pem"];
    let original_credentials = protected
        .iter()
        .map(|p| std::fs::read(core.state_directory().join(p)))
        .collect::<std::io::Result<Vec<_>>>()?;
    let fields = [
        "keepTemporariesH",
        "maxFolderConcurrency",
        "maxDialConcurrent",
        "tempIndexMinBlocks",
        "trafficClass",
    ];
    for (phase, selected) in [-1_i64, -2, 0].into_iter().enumerate() {
        let patch = GeneralOptionsPatch::default()
            .keep_temporaries_hours(selected)
            .max_folder_concurrency(selected)
            .max_dial_concurrent(selected)
            .temp_index_min_blocks(selected)
            .traffic_class(selected);
        if phase == 1 {
            let mut snapshot = core.client().configuration().await?;
            snapshot.set_general_options(&patch)?;
            assert!(
                core.client()
                    .replace_configuration(&snapshot)
                    .await?
                    .requested_fields_match
            );
        } else {
            let receipt = core.client().update_general_options(&patch).await?;
            println!(
                "native general domain save diagnostic: {}",
                serde_json::json!({
                    "requested":selected,"requested_fields_match":receipt.requested_fields_match,
                    "keepTemporariesH":receipt.configuration.keep_temporaries_hours,
                    "maxFolderConcurrency":receipt.configuration.max_folder_concurrency,
                    "maxDialConcurrent":receipt.configuration.max_dial_concurrent,
                    "tempIndexMinBlocks":receipt.configuration.temp_index_min_blocks,
                    "trafficClass":receipt.configuration.traffic_class
                })
            );
            // The fixed native configuration normalizes tempIndexMinBlocks=0
            // to 2 immediately; retain its exact mismatch instead of hiding it.
            assert_eq!(receipt.requested_fields_match, selected != 0);
        }
        core.restart(Duration::from_secs(30)).await?;
        let read = core.client().general_options().await?;
        assert_eq!(
            (
                read.keep_temporaries_hours,
                read.max_folder_concurrency,
                read.max_dial_concurrent,
                read.temp_index_min_blocks,
                read.traffic_class
            ),
            (
                selected,
                selected,
                selected,
                Some(if selected == 0 { 2 } else { selected }),
                Some(selected)
            )
        );
        let actual = core.client().configuration().await?;
        for (section, value) in before
            .native_document()
            .as_object()
            .ok_or("original configuration not object")?
        {
            if section != "options" {
                assert!(
                    actual.native_document()[section] == *value,
                    "unrelated configuration section changed"
                );
            }
        }
        for (name, value) in before.native_document()["options"]
            .as_object()
            .ok_or("original options not object")?
        {
            if !fields.contains(&name.as_str()) {
                assert!(
                    actual.native_document()["options"][name] == *value,
                    "unselected native option changed"
                );
            }
        }
        assert_eq!(core.client().system_status().await?.device_id, identity);
        println!(
            "native general signed-domain evidence: {}",
            serde_json::json!({
                "selected":selected,"actual_five_fields_and_native_zero_normalization_observed":true,
                "actual_temp_index_min_blocks":read.temp_index_min_blocks,
                "actual_complete_save_used":phase==1,"actual_unselected_options_and_sections_retained":true,
                "negative_scheduling_retention_or_index_effect_claimed":false
            })
        );
    }
    let restore = GeneralOptionsPatch::default()
        .keep_temporaries_hours(original.keep_temporaries_hours)
        .max_folder_concurrency(original.max_folder_concurrency)
        .max_dial_concurrent(original.max_dial_concurrent)
        .temp_index_min_blocks(
            original
                .temp_index_min_blocks
                .ok_or("fixed baseline temporary-index selection absent")?,
        )
        .traffic_class(
            original
                .traffic_class
                .ok_or("fixed baseline traffic-class selection absent")?,
        );
    assert!(
        core.client()
            .update_general_options(&restore)
            .await?
            .requested_fields_match
    );
    core.restart(Duration::from_secs(30)).await?;
    assert!(
        before.native_document() == core.client().configuration().await?.native_document(),
        "original configuration not restored"
    );
    for (path, bytes) in protected.iter().zip(original_credentials) {
        assert!(
            std::fs::read(core.state_directory().join(path))? == bytes,
            "owned credential changed"
        );
    }
    assert_eq!(
        std::fs::read(root.join("caller-sentinel"))?,
        b"signed general option caller data"
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && exit.state_released && !exit.forced && exit.code == Some(0));
    std::fs::remove_dir_all(root)?;
    println!("native general signed-domain cleanup evidence: actual_original_configuration_identity_credentials_sentinel_retained=true actual_normal_owned_tree_and_state_exit=true negative_runtime_effects_not_inferred=true");
    Ok(())
}
