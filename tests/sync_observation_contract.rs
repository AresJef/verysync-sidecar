//! Snapshot schema and privacy controls; native effects have a separate target.
use serde_json::json;
use verysync_sidecar::{CompletionSnapshot, FolderErrorPage, ListPage, NeedPage, SyncFilePage};

#[test]
fn completion_percentage_does_not_replace_unknown_remote_or_missing_counters() {
    let snapshot:CompletionSnapshot=serde_json::from_value(json!({"completion":100,"remoteState":"future-private-state","privateField":"private-value"})).unwrap();
    assert_eq!(snapshot.completion_percent, 100.0);
    assert_eq!(
        snapshot.remote_state.as_deref(),
        Some("future-private-state")
    );
    assert_eq!(snapshot.need_bytes, None);
    assert_eq!(snapshot.extra["privateField"], "private-value");
    assert!(!format!("{snapshot:?}").contains("private"));
    for invalid in [
        json!({}),
        json!({"completion":-1}),
        json!({"completion":101}),
        json!({"completion":"100"}),
    ] {
        assert!(serde_json::from_value::<CompletionSnapshot>(invalid).is_err());
    }
}

#[test]
fn lists_preserve_null_errors_unknown_file_types_and_untrusted_names_without_exposure() {
    let null: FolderErrorPage =
        serde_json::from_value(json!({"folder":"opaque","errors":null})).unwrap();
    let empty: FolderErrorPage =
        serde_json::from_value(json!({"folder":"opaque","errors":[]})).unwrap();
    assert!(null.errors.is_none());
    assert!(empty.errors.as_ref().unwrap().is_empty());
    let files:SyncFilePage=serde_json::from_value(json!({"files":[{"name":"../private-name","type":"future-private-kind","future":"private-metadata"}],"page":2,"perpage":1})).unwrap();
    assert_eq!(files.files[0].name, "../private-name");
    assert_eq!(files.files[0].size, None);
    assert_eq!(files.files[0].extra["future"], "private-metadata");
    assert!(!format!("{files:?} {:?}", files.files[0]).contains("private"));
    assert!(serde_json::from_value::<SyncFilePage>(json!({"files":null})).is_err());
    assert!(serde_json::from_value::<NeedPage>(json!({"progress":[],"queued":[]})).is_err());
}

#[test]
fn explicit_pages_reject_zero_excessive_or_overflowing_requests() {
    assert_eq!(ListPage::new(2, 5).unwrap().number(), 2);
    assert_eq!(ListPage::new(2, 5).unwrap().per_page(), 5);
    for (page, limit) in [(0, 1), (1, 0), (1, 1001), (u32::MAX, 1000)] {
        assert!(ListPage::new(page, limit).is_err());
    }
}

#[test]
fn scan_settings_preserve_fractional_seconds_and_patch_only_explicit_fields() {
    use verysync_sidecar::{FolderScanConfig, FolderScanPatch};
    let config: FolderScanConfig = serde_json::from_value(json!({
        "rescanIntervalS":0,"fsWatcherEnabled":false,"fsWatcherDelayS":1.5,
        "fsWatcherTimeoutS":2,"scanProgressIntervalS":-1,"disableInitialScan":false,
        "future":"private-value"
    }))
    .unwrap();
    assert_eq!(config.watcher_delay_seconds, 1.5);
    assert_eq!(config.rescan_interval_seconds, 0);
    assert_eq!(config.extra["future"], "private-value");
    assert!(!format!("{config:?}").contains("private-value"));
    let patch = FolderScanPatch::default()
        .rescan_interval_seconds(0)
        .watcher(false)
        .watcher_delay_seconds(1.5);
    assert_eq!(
        serde_json::to_value(patch).unwrap(),
        json!({"rescanIntervalS":0,"fsWatcherEnabled":false,"fsWatcherDelayS":1.5})
    );
}

#[test]
fn ignore_snapshots_preserve_null_patterns_parse_errors_and_private_directives() {
    use verysync_sidecar::{IgnorePatterns, IgnoreSnapshot};
    let empty: IgnoreSnapshot =
        serde_json::from_value(json!({"ignore":null,"expanded":[],"error":null})).unwrap();
    assert!(empty.patterns.is_none());
    let bad: IgnoreSnapshot = serde_json::from_value(json!({"ignore":["private-pattern"],"expanded":[],"error":"private-parse-error","future":"private-value"})).unwrap();
    assert_eq!(bad.parse_error.as_deref(), Some("private-parse-error"));
    assert!(!format!("{bad:?}").contains("private"));
    let lines = vec![
        r"#escape=\".into(),
        "// private comment".into(),
        "!keep.tmp".into(),
        "*.tmp".into(),
    ];
    let rules = IgnorePatterns::new(lines.clone()).unwrap();
    assert_eq!(rules.patterns(), lines);
    assert!(!format!("{rules:?}").contains("private"));
    for lines in [
        vec!["a\nb".into()],
        vec!["a\rb".into()],
        vec!["\0".into()],
        vec!["x".repeat(262145)],
        vec![String::new(); 4097],
    ] {
        assert!(IgnorePatterns::new(lines).is_err());
    }
    for malformed in [
        json!({"expanded":[],"error":null}),
        json!({"ignore":[],"error":null}),
        json!({"ignore":[],"expanded":[]}),
    ] {
        assert!(serde_json::from_value::<IgnoreSnapshot>(malformed).is_err());
    }
}
