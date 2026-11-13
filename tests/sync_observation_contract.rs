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
