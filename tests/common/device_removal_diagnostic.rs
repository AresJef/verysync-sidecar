//! Exact disconnect observations and bounded, value-redacted native event ordering.
use serde_json::{json, Value};
use std::time::SystemTime;

fn event_time(event: &Value) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    event["time"]
        .as_str()
        .filter(|time| time.len() <= 128)
        .and_then(|time| chrono::DateTime::parse_from_rfc3339(time).ok())
        .filter(|time| time.timestamp_subsec_nanos() < 1_000_000_000)
}

pub(super) fn has_disconnect_event(
    events: &[Value],
    peer: &str,
    since: u64,
    removal_started: SystemTime,
    observed_at: SystemTime,
) -> bool {
    let started: chrono::DateTime<chrono::Utc> = removal_started.into();
    let observed: chrono::DateTime<chrono::Utc> = observed_at.into();
    events.iter().any(|event| {
        let data = &event["data"];
        event["type"] == "DeviceDisconnected"
            && event["id"].as_u64().is_some_and(|id| id > since)
            && data
                .get("id")
                .or_else(|| data.get("deviceID"))
                .or_else(|| data.get("device"))
                .and_then(Value::as_str)
                == Some(peer)
            && event_time(event).is_some_and(|time| time >= started && time <= observed)
    })
}

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
            let relation = match event_time(event) {
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
    fn a_real_disconnect_remains_observable_after_an_immediate_reconnection() {
        let events = [
            json!({"id":31,"type":"DeviceDisconnected","time":"2026-01-01T00:00:02Z","data":{"id":"synthetic-peer"}}),
            json!({"id":32,"type":"DeviceConnected","time":"2026-01-01T00:00:03Z","data":{"id":"synthetic-peer"}}),
        ];
        let start = UNIX_EPOCH + Duration::from_secs(1767225601);
        let end = start + Duration::from_secs(3);
        assert!(has_disconnect_event(
            &events,
            "synthetic-peer",
            30,
            start,
            end
        ));
        // Native event times with a different offset represent the same instant.
        let mut offset = events[0].clone();
        offset["time"] = json!("2026-01-01T08:00:02+08:00");
        assert!(has_disconnect_event(
            &[offset],
            "synthetic-peer",
            30,
            start,
            end
        ));
    }

    #[test]
    fn earlier_pause_other_peers_invalid_times_and_future_events_cannot_pass_removal() {
        let event = json!({"id":31,"type":"DeviceDisconnected","time":"2026-01-01T00:00:02Z","data":{"id":"synthetic-peer"}});
        let start = UNIX_EPOCH + Duration::from_secs(1767225601);
        let end = start + Duration::from_secs(3);
        for (field, invalid) in [
            ("id", json!(30)),
            ("id", json!("31")),
            ("type", json!("DeviceConnected")),
            ("data", json!({"id":"another-peer"})),
            ("data", json!({})),
            ("time", json!("2026-01-01T00:00:00Z")),
            ("time", json!("2026-01-01T00:00:05Z")),
            ("time", json!("2025-12-31T23:59:60Z")),
            ("time", json!("invalid")),
            ("time", Value::Null),
        ] {
            let mut invalid_event = event.clone();
            invalid_event[field] = invalid;
            assert!(
                !has_disconnect_event(&[invalid_event], "synthetic-peer", 30, start, end),
                "{field}"
            );
        }
        assert!(!has_disconnect_event(
            &[event],
            "synthetic-peer",
            30,
            end,
            start
        ));
    }

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
