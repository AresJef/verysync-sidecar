//! Actual stored template, observed native initial rules and explicit application.
use super::*;

#[tokio::test]
async fn native_default_ignore_template_and_explicit_application_preserve_rules_files_and_restart(
) -> TestResult {
    use verysync_sidecar::{IgnoreChange, IgnoreReadback, OperationCompletion, OperationOptions};
    let root = tempfile::Builder::new()
        .prefix("vs-ignore-defaults-")
        .tempdir()?
        .keep();
    let old = root.join("old");
    let new = root.join("new");
    for path in [&old, &new] {
        std::fs::create_dir(path)?;
        std::fs::write(path.join("visible.txt"), b"retained visible bytes")?;
        std::fs::write(path.join("hidden.new-default"), b"retained ignored bytes")?;
    }
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let original = core.client().default_ignore_patterns().await?;
    let old_id = FolderId::parse("existing-ignore-defaults")?;
    let new_id = FolderId::parse("new-ignore-defaults")?;
    core.client()
        .create_folder(&CreateFolderOptions::new(
            old_id.clone(),
            TargetPath::local(&old),
        ))
        .await?;
    let built_in = core.client().ignore_patterns(&old_id).await?;
    let old_rules = IgnorePatterns::new(vec!["*.old-pattern".into()])?;
    core.client()
        .set_ignore_patterns(&old_id, &old_rules)
        .await?;
    let old_file = std::fs::read(old.join(".verysync").join("ignoreList"))?;
    let before = core.client().configuration().await?;
    let rules = IgnorePatterns::new(vec![
        "// synthetic global default".into(),
        "*.new-default".into(),
    ])?;
    let limits = || OperationOptions::new(Duration::from_secs(12));
    let update = core
        .client()
        .change_ignore_patterns_and_verify(IgnoreChange::DefaultTemplate(&rules), limits())
        .await?;
    assert_eq!(
        update.completion(),
        OperationCompletion::Completed,
        "{update:?}"
    );
    let Some(IgnoreReadback::DefaultTemplate(configuration)) = update.current else {
        return Err("the actual template was not read back".into());
    };
    assert_eq!(configuration.lines, rules.patterns());
    assert!(configuration.extra == original.extra);
    let same = core
        .client()
        .change_ignore_patterns_and_verify(IgnoreChange::DefaultTemplate(&rules), limits())
        .await?;
    assert!(!same.write.dispatched && matches!(same.original, Ok(None)));
    let mut expected = before.native_document().clone();
    expected["defaults"]["ignores"]["lines"] = serde_json::json!(rules.patterns());
    let after = core.client().configuration().await?;
    assert!(after.native_document() == &expected);
    assert_eq!(after.default_ignore_patterns()?.lines, rules.patterns());
    core.client()
        .create_folder(&CreateFolderOptions::new(
            new_id.clone(),
            TargetPath::local(&new),
        ))
        .await?;
    core.client().request_scan(&new_id).await?;
    let inherited = core.client().ignore_patterns(&new_id).await?;
    eprintln!("default_ignore_inheritance_observation lines_match={} parser_error={} old_file_unchanged={}",inherited.patterns.as_deref()==Some(rules.patterns()),inherited.parse_error.is_some(),std::fs::read(old.join(".verysync").join("ignoreList"))?==old_file);
    let native_auto_inherited = inherited.patterns.as_deref() == Some(rules.patterns());
    if !native_auto_inherited {
        assert_eq!(
            inherited.patterns, built_in.patterns,
            "unrecognized native initial rules"
        );
    }
    assert!(inherited.parse_error.is_none());
    let applied = core.client().set_ignore_patterns(&new_id, &rules).await?;
    assert!(applied.requested_patterns_match && applied.snapshot.parse_error.is_none());
    let applied_file = std::fs::read(new.join(".verysync").join("ignoreList"))?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if core.client().folder_status(&new_id).await?.local_files == Some(1) {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    assert_eq!(
        std::fs::read(old.join(".verysync").join("ignoreList"))?,
        old_file
    );
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(
        core.client().default_ignore_patterns().await?.lines,
        rules.patterns()
    );
    assert_eq!(
        core.client()
            .ignore_patterns(&new_id)
            .await?
            .patterns
            .as_deref(),
        Some(rules.patterns())
    );
    let invalid_template =
        IgnorePatterns::new(vec!["#include synthetic-missing-ignore-file".into()])?;
    assert!(
        core.client()
            .set_default_ignore_patterns(&invalid_template)
            .await?
            .requested_fields_match
    );
    assert_eq!(
        core.client()
            .ignore_patterns(&new_id)
            .await?
            .patterns
            .as_deref(),
        Some(rules.patterns())
    );
    let mut snapshot = core.client().configuration().await?;
    snapshot.set_default_ignore_patterns(&IgnorePatterns::new(vec![])?)?;
    assert!(
        core.client()
            .replace_configuration(&snapshot)
            .await?
            .requested_fields_match
    );
    assert!(core
        .client()
        .default_ignore_patterns()
        .await?
        .lines
        .is_empty());
    assert_eq!(
        std::fs::read(old.join(".verysync").join("ignoreList"))?,
        old_file
    );
    assert_eq!(
        core.client()
            .ignore_patterns(&new_id)
            .await?
            .patterns
            .as_deref(),
        Some(rules.patterns())
    );
    assert_eq!(
        std::fs::read(new.join(".verysync").join("ignoreList"))?,
        applied_file
    );
    for path in [&old, &new] {
        assert_eq!(
            std::fs::read(path.join("visible.txt"))?,
            b"retained visible bytes"
        );
        assert_eq!(
            std::fs::read(path.join("hidden.new-default"))?,
            b"retained ignored bytes"
        );
    }
    assert_eq!(core.client().system_status().await?.device_id, identity);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.code == Some(0) && exit.tree_stopped && exit.state_released && !exit.forced);
    println!("native_default_ignore_template=true native_auto_inherited={native_auto_inherited} explicit_rule_application=true actual_index_exclusion=true invalid_template_stored_without_parsing=true existing_ignore_bytes_retained=true full_snapshot_template_edit=true normal_restart_persistence=true caller_bytes_and_identity_retained=true normal_owned_tree_exit=true");
    Ok(())
}
