//! Candidate evolution and privacy contracts, separate from native effects.
use verysync_sidecar::{PendingDeviceInfo, PendingFolderOffers};

#[test]
fn pending_folder_schema_retains_future_fields_without_logging_offer_data() {
    let value: PendingFolderOffers = serde_json::from_value(serde_json::json!({
        "offeredBy": {"AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA": {
            "time":"2026-01-01T00:00:00Z","label":"private-offer-label",
            "receiveEncrypted":false,"remoteEncrypted":true,"futureSecret":"private-offer-extra"
        }},"futureSecret":"private-folder-extra"
    }))
    .unwrap();
    let offer = value.offered_by.values().next().unwrap();
    assert!(offer.remote_encrypted && !offer.receive_encrypted);
    assert_eq!(offer.extra["futureSecret"], "private-offer-extra");
    assert_eq!(value.extra["futureSecret"], "private-folder-extra");
    let text = format!("{value:?}");
    for token in [
        "private-offer-label",
        "private-offer-extra",
        "private-folder-extra",
    ] {
        assert!(!text.contains(token));
    }
}

#[test]
fn candidate_pending_device_debug_hides_remote_values_and_unknown_fields() {
    let value:PendingDeviceInfo=serde_json::from_value(serde_json::json!({"time":"private-time","name":"private-name","address":"private-address","futureSecret":"private-extra"})).unwrap();
    assert_eq!(value.extra["futureSecret"], "private-extra");
    let text = format!("{value:?}");
    for token in [
        "private-time",
        "private-name",
        "private-address",
        "private-extra",
    ] {
        assert!(!text.contains(token));
    }
}
