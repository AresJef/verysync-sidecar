//! Actual core-side logs and diagnostic metadata through public Rust APIs.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::{collections::BTreeMap, time::Duration};
use verysync_sidecar::{CoreLogLevel, ManagedInstance};

#[tokio::test]
async fn public_core_errors_logs_levels_and_owned_diagnostics() -> TestResult {
    let root = tempfile::Builder::new().prefix("vmt-").tempdir()?.keep();
    let state = root.join("c");
    let mut core = ManagedInstance::start(options(&state)?).await?;
    assert!(core.client().core_errors().await?.is_empty());
    let before = core.client().core_log(None).await?;
    let old_entries = before.messages.as_ref().ok_or("startup log absent")?;
    assert!(!old_entries.is_empty());
    let stamp = old_entries
        .last()
        .ok_or("last log entry absent")?
        .when
        .clone();
    let message = "verysync-sidecar synthetic error: 二 %";
    let native_message = format!("External error report (error=\"{message}\" log.pkg=api)");
    let recorded = core.client().record_core_error(message).await?;
    let errors = recorded.errors.as_ref().ok_or("registered error absent")?;
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].message, native_message);
    assert_eq!(errors[0].level, "ERR");
    assert!(!errors[0].when.is_empty());
    assert!(!format!("{recorded:?} {:?}", errors[0]).contains(message));
    let log = core.client().core_log(Some(&stamp)).await?;
    let messages = log.messages.as_ref().ok_or("log snapshot absent")?;
    assert!(messages.iter().any(|entry| entry.message.contains(message)));
    assert!(messages.iter().all(|entry| entry.when >= stamp));
    assert!(old_entries.iter().any(|entry| entry.when < stamp));
    assert!(!format!("{log:?}").contains(message));
    let second = "second synthetic registered error";
    let recorded = core.client().record_core_error(second).await?;
    assert_eq!(recorded.errors.as_ref().map(Vec::len), Some(2));
    assert!(recorded.errors.as_ref().is_some_and(|entries| entries
        .iter()
        .any(|e| e.message == native_message)
        && entries.iter().any(|e| e.message.contains(second))));
    assert!(core.client().clear_core_errors().await?.is_empty());
    assert!(core.client().core_errors().await?.is_empty());

    let initial = core.client().core_log_levels().await?;
    assert_eq!(initial.levels.get("main"), Some(&CoreLogLevel::Info));
    assert!(initial.packages.contains_key("main"));
    for level in [
        CoreLogLevel::Debug,
        CoreLogLevel::Warn,
        CoreLogLevel::Error,
        CoreLogLevel::Info,
    ] {
        let changed = core
            .client()
            .set_core_log_levels(&BTreeMap::from([("main".to_owned(), level.clone())]))
            .await?;
        assert!(changed.requested_levels_match);
        assert_eq!(changed.configuration.levels.get("main"), Some(&level));
        assert_eq!(changed.configuration.packages, initial.packages);
        assert_eq!(changed.configuration.levels.len(), initial.levels.len());
        assert!(initial
            .levels
            .iter()
            .filter(|(k, _)| k.as_str() != "main")
            .all(|(name, old)| changed.configuration.levels.get(name) == Some(old)));
    }
    let restored = core.client().core_log_levels().await?;
    assert_eq!(restored.levels, initial.levels);
    let diagnostics = core.client().core_diagnostics().await?;
    let actual_state = std::fs::canonicalize(&state)?;
    for name in ["confdir", "datadir"] {
        let path = diagnostics
            .locations
            .get(name)
            .ok_or("owned location missing")?;
        assert!(path.local_path().is_none());
        assert_eq!(
            path.style(),
            verysync_sidecar::TargetPath::local(&state).style()
        );
        assert_eq!(std::fs::canonicalize(path.to_protocol()?)?, actual_state);
    }
    assert!(diagnostics.database_size > 0);
    assert!(!format!("{diagnostics:?}").contains(root.to_str().ok_or("UTF-8 test root")?));
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    eprintln!(
        "public core maintenance evidence: {}",
        serde_json::json!({
            "actual_initial_empty_error_log":true,"actual_exact_unicode_error_registered":true,
            "actual_error_severity_and_timestamp":true,"actual_second_error_preserves_first":true,
            "actual_errors_cleared_and_observed_empty":true,"actual_log_contains_explicit_message":true,
            "actual_since_filter_excludes_older_entries":true,"actual_four_package_levels":true,
            "actual_unselected_package_levels_preserved":true,"actual_package_descriptions_preserved":true,
            "actual_original_levels_restored":true,"actual_owned_config_and_data_locations":true,
            "actual_target_path_syntax_without_host_open_in_sdk":true,"actual_positive_native_database_size_metadata":true,
            "actual_private_debug_redaction":true,"actual_normal_owned_tree_exit":true
        })
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}
