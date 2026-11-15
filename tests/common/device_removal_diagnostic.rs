//! Bounded, value-redacted event ordering after the original removal condition.
use serde_json::{json, Value};
use std::time::SystemTime;

pub(super) fn removal_timeline(
    events: &[Value],
    peer: &str,
    removal_started: SystemTime,
) -> Vec<Value> {
    let started: chrono::DateTime<chrono::Utc> = removal_started.into();
    let includes_peer = |devices: &[Value]| {
        devices.iter().try_fold(false, |found, device| {
            let id = device["deviceID"].as_str()?;
            Some(found || id == peer)
        })
    };
    let mut rows: Vec<_> = events
        .iter()
        .rev()
        .filter_map(|event| {
            let kind = match event["type"].as_str()? {
                kind @ ("ConfigSaved"
                | "DeviceConnected"
                | "DeviceDisconnected"
                | "DevicePaused"
                | "DeviceResumed"
                | "DeviceRejected"
                | "FolderPaused"
                | "FolderResumed"
                | "PendingDevicesChanged") => kind,
                _ => return None,
            };
            let time = event["time"]
                .as_str()
                .filter(|time| time.len() <= 128)
                .and_then(|time| chrono::DateTime::parse_from_rfc3339(time).ok())
                .filter(|time| time.timestamp_subsec_nanos() < 1_000_000_000);
            let relation = match time {
                Some(time) if time < started => "before_removal_start",
                Some(_) => "at_or_after_removal_start",
                None => "unverified",
            };
            let data = &event["data"];
            let configured = (kind == "ConfigSaved")
                .then(|| data["devices"].as_array())
                .flatten()
                .and_then(|devices| includes_peer(devices));
            let references = (kind == "ConfigSaved")
                .then(|| data["folders"].as_array())
                .flatten()
                .and_then(|folders| {
                    folders.iter().try_fold(0, |count, folder| {
                        let devices = folder["devices"].as_array()?;
                        let present = includes_peer(devices)?;
                        Some(count + usize::from(present))
                    })
                });
            let peer_matches = data
                .get("id")
                .or_else(|| data.get("deviceID"))
                .or_else(|| data.get("device"))
                .and_then(Value::as_str)
                .map(|value| value == peer);
            Some(json!({"sequence":event["id"].as_u64(),"kind":kind,
                "clock_relation":relation,"peer_matches":peer_matches,
                "device_configured":configured,"folder_reference_count":references}))
        })
        .take(32)
        .collect();
    rows.reverse();
    rows
}

#[cfg(test)]
mod removal_timeline_contracts {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn retains_configuration_transitions_without_private_values() {
        let peer = "synthetic-peer";
        let events = vec![
            json!({"id":1,"type":"ConfigSaved","time":"2026-01-01T00:00:00Z","data":{"devices":[{"deviceID":peer}],"folders":[{"devices":[{"deviceID":peer}]}],"gui":{"apiKey":"private-canary"}}}),
            json!({"id":2,"type":"ConfigSaved","time":"2026-01-01T00:00:02Z","data":{"devices":[],"folders":[]}}),
            json!({"id":3,"type":"ConfigSaved","time":"2026-01-01T00:00:03Z","data":{"devices":[{"deviceID":peer}],"folders":[{"devices":[{"deviceID":peer}]}]}}),
        ];
        let rows = removal_timeline(&events, peer, UNIX_EPOCH + Duration::from_secs(1767225601));
        assert_eq!(
            rows.iter()
                .map(|row| row["device_configured"].as_bool())
                .collect::<Vec<_>>(),
            [Some(true), Some(false), Some(true)]
        );
        assert_eq!(
            rows.iter()
                .map(|row| row["folder_reference_count"].as_u64())
                .collect::<Vec<_>>(),
            [Some(1), Some(0), Some(1)]
        );
        assert_eq!(rows[0]["clock_relation"], "before_removal_start");
        assert_eq!(rows[1]["clock_relation"], "at_or_after_removal_start");
        let output = serde_json::to_string(&rows).unwrap();
        assert!(
            !output.contains(peer)
                && !output.contains("private-canary")
                && !output.contains("apiKey")
        );
    }

    #[test]
    fn absent_fields_and_invalid_times_stay_unverified() {
        let rows = removal_timeline(
            &[
                json!({"id":1,"type":"ConfigSaved","time":"invalid","data":{}}),
                json!({"id":2,"type":"ConfigSaved","time":"invalid","data":{"devices":[{}],"folders":[{}]}}),
            ],
            "synthetic-peer",
            UNIX_EPOCH,
        );
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row["clock_relation"] == "unverified"));
        assert!(rows.iter().all(|row| row["device_configured"].is_null()));
        assert!(rows
            .iter()
            .all(|row| row["folder_reference_count"].is_null()));
    }

    #[test]
    fn retains_only_bounded_known_event_names_in_native_order() {
        let mut events: Vec<_> = (0..40).map(|id| json!({"id":id,"type":"DeviceConnected","time":"2026-01-01T00:00:00Z","data":{"id":"synthetic-peer"}})).collect();
        events.push(json!({"id":40,"type":"private-unknown-kind","data":"private-canary"}));
        let rows = removal_timeline(&events, "synthetic-peer", UNIX_EPOCH);
        assert_eq!(rows.len(), 32);
        assert_eq!(rows[0]["sequence"], 8);
        assert_eq!(rows[31]["sequence"], 39);
        assert!(rows.iter().all(|row| row["peer_matches"] == true));
    }
}
