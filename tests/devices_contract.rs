//! Schema evolution and diagnostic privacy, not native engine acceptance.
use verysync_sidecar::{DeviceCompression, DeviceConfig, DevicePatch};

#[test]
fn future_device_fields_and_compression_are_preserved_without_debug_exposure() {
    let config: DeviceConfig = serde_json::from_value(serde_json::json!({
        "deviceID":"AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA",
        "name":"synthetic-private-name", "addresses":["tcp://synthetic-private.invalid:1234"],
        "compression":"future-private-compression", "paused":false,
        "futureSecret":"synthetic-private-extra"
    }))
    .unwrap();
    assert_eq!(
        config.compression,
        DeviceCompression::Unknown("future-private-compression".into())
    );
    assert_eq!(config.extra["futureSecret"], "synthetic-private-extra");
    let patch = DevicePatch::default()
        .name("synthetic-private-name")
        .addresses(vec!["tcp://synthetic-private.invalid:1234".into()])
        .compression(DeviceCompression::Unknown(
            "future-private-compression".into(),
        ));
    let debug = format!("{config:?} {patch:?}");
    for value in [
        "synthetic-private-name",
        "synthetic-private.invalid",
        "future-private-compression",
        "synthetic-private-extra",
    ] {
        assert!(!debug.contains(value));
    }
}
