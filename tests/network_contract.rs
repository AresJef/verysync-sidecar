//! Forward-compatible network snapshots, separate from native effects.
use verysync_sidecar::{ConnectionSnapshot, DiscoveryRecord, PeerConnectionType};

#[test]
fn disabled_relay_and_unknown_probe_keep_missing_state_and_private_values() {
    use verysync_sidecar::{RelayProbe, RelayProbeResult, RelayServerPatch, RelayServerStatus};
    let disabled: RelayServerStatus =
        serde_json::from_value(serde_json::json!({"enabled":false})).unwrap();
    assert!(
        disabled.options.is_none()
            && disabled.bytes_proxied.is_none()
            && disabled.num_active_sessions.is_none()
            && disabled.relay_url.is_none()
    );
    let probe:RelayProbe=serde_json::from_value(serde_json::json!({"result":"future-private-result","error":"private-error","future":"private-extra"})).unwrap();
    assert_eq!(
        probe.result,
        RelayProbeResult::Unknown("future-private-result".into())
    );
    assert_eq!(probe.extra["future"], "private-extra");
    let patch = RelayServerPatch::default()
        .token("private-token")
        .listen("private-listener")
        .provided_by("private-provider");
    let debug = format!("{probe:?} {patch:?}");
    for value in [
        "future-private-result",
        "private-error",
        "private-extra",
        "private-token",
        "private-listener",
        "private-provider",
    ] {
        assert!(!debug.contains(value));
    }
}

#[test]
fn discovery_record_preserves_metadata_without_exposing_address_or_inventing_fields() {
    let record: DiscoveryRecord = serde_json::from_value(serde_json::json!({
        "addresses":["tcp://private-example.invalid:12345"], "future":"private-metadata"
    }))
    .unwrap();
    assert_eq!(record.addresses, ["tcp://private-example.invalid:12345"]);
    assert_eq!(record.extra["future"], "private-metadata");
    let debug = format!("{record:?}");
    assert!(!debug.contains("private-example"));
    assert!(!debug.contains("private-metadata"));
    assert!(serde_json::from_value::<DiscoveryRecord>(serde_json::json!({})).is_err());
}

#[test]
fn connection_snapshot_preserves_unknown_types_and_does_not_invent_counters() {
    let snapshot:ConnectionSnapshot=serde_json::from_value(serde_json::json!({"connections":{"AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA":{"connected":true,"type":"future-private-type","address":"private-address","futureSecret":"private-extra"}},"total":null})).unwrap();
    let peer = snapshot.connections.values().next().unwrap();
    assert_eq!(
        peer.connection_type,
        Some(PeerConnectionType::Unknown("future-private-type".into()))
    );
    assert_eq!(peer.in_bytes_total, None);
    assert_eq!(peer.out_bytes_total, None);
    assert_eq!(peer.extra["futureSecret"], "private-extra");
    let debug = format!("{snapshot:?}");
    for value in ["future-private-type", "private-address", "private-extra"] {
        assert!(!debug.contains(value));
    }
}
