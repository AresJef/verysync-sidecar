//! Actual core-side logs and diagnostic metadata through public Rust APIs.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::{collections::BTreeMap, time::Duration};
use verysync_sidecar::{CoreLogLevel, ManagedInstance};

fn decode_profile(profile: &verysync_sidecar::CoreProfile) -> TestResult<Vec<u8>> {
    use std::io::Read;
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(profile.body_bytes())
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut decoded)?;
    assert!(!decoded.is_empty() && decoded.len() <= 32 * 1024 * 1024);
    Ok(decoded)
}

#[tokio::test]
async fn public_profiles_metrics_and_clone_serialization_preserve_the_owned_core() -> TestResult {
    use verysync_sidecar::{CoreProfileRequest, RawMethod, RawRequest, RequestEffect};
    let root = tempfile::Builder::new().prefix("vpr-").tempdir()?.keep();
    let options = options(&root.join("c"))?;
    let endpoint = options.management_endpoint().clone();
    let mut core = ManagedInstance::start(options).await?;
    let identity = core.client().instance().device_id.clone();
    let before = core.client().core_metrics().await?;
    assert!(before.native_text().contains("# TYPE go_goroutines gauge"));
    let gc_count = |text: &str| -> TestResult<f64> {
        Ok(text
            .lines()
            .find_map(|line| line.strip_prefix("go_gc_duration_seconds_count "))
            .ok_or("native GC count absent")?
            .parse::<f64>()?)
    };
    let gc_before = gc_count(before.native_text())?;
    let heap = core
        .client()
        .collect_core_profile(CoreProfileRequest::Heap)
        .await?;
    assert_eq!(heap.request, CoreProfileRequest::Heap);
    let heap_decoded = decode_profile(&heap)?;
    let after = core.client().core_metrics().await?;
    assert!(gc_count(after.native_text())? > gc_before);
    let start = std::time::Instant::now();
    let a = core.client().clone();
    let b = core.client().clone();
    let cpu = CoreProfileRequest::Cpu {
        duration_seconds: 1,
    };
    let (one, two) = tokio::join!(a.collect_core_profile(cpu), b.collect_core_profile(cpu));
    let one = one?;
    let two = two?;
    assert!(start.elapsed() >= Duration::from_secs(2));
    assert_eq!(one.request, cpu);
    assert_eq!(two.request, cpu);
    let cpu_decoded = decode_profile(&one)?;
    decode_profile(&two)?;
    assert!(format!("{heap:?} {one:?} {before:?}").len() < 512);
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let gui = core
        .client()
        .raw_request(&RawRequest::new(
            RawMethod::Get,
            ["rest", "config", "gui"],
            RequestEffect::ReadOnly,
        )?)
        .await?;
    let gui: serde_json::Value = serde_json::from_slice(gui.body_bytes())?;
    assert_eq!(gui["metricsWithoutAuth"], false);
    let builder = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3));
    #[cfg(unix)]
    let builder = if let Some(socket) = endpoint.socket_path() {
        builder.unix_socket(socket)
    } else {
        builder
    };
    let url = if let Some(base) = endpoint.http_url() {
        base.join("metrics")?
    } else {
        "http://localhost/metrics".parse()?
    };
    let unauthenticated = builder.build()?.get(url).send().await?;
    assert!(matches!(unauthenticated.status().as_u16(), 401 | 403));
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    eprintln!(
        "public core profile and metrics evidence: {}",
        serde_json::json!({
            "actual_nonempty_native_metrics":true,"actual_native_goroutine_descriptor":true,
            "actual_native_gc_count_increased":true,"actual_heap_profile_gzip_crc":true,
            "actual_two_cpu_profiles_gzip_crc":true,"actual_clone_profile_serialization":true,
            "actual_selected_request_kinds_preserved":true,"actual_authenticated_metrics":true,
            "actual_unauthenticated_metrics_denied":true,"actual_metrics_without_auth_remains_disabled":true,
            "actual_owned_identity_retained":true,"actual_normal_owned_tree_exit":true,
            "heap_decoded_bytes":heap_decoded.len(),"cpu_decoded_bytes":cpu_decoded.len()
        })
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

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
