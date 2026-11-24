use crate::Stage;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use verysync_sidecar::{AuditHistoryPage, Client};

const PAGE_SIZE: u16 = 2;
const MAX_RECORDS: u64 = 16;

pub(crate) fn scope_matches(row: &Value, folder: &str, cases: &[&str]) -> Stage<Value> {
    if !row.is_object() {
        return Err("audit-native-row-is-not-an-object");
    }
    let mut has_folder = false;
    let mut known = BTreeSet::new();
    let mut stack = vec![(row, 0)];
    let mut visited = 0;
    while let Some((value, depth)) = stack.pop() {
        visited += 1;
        if visited > 4096 || depth > 16 {
            return Err("audit-native-row-too-complex-to-confirm");
        }
        match value {
            Value::String(item) => {
                has_folder |= item == folder;
                for &label in cases {
                    if item == label {
                        let _ = known.insert(label);
                    }
                }
            }
            Value::Array(items) => stack.extend(items.iter().map(|item| (item, depth + 1))),
            Value::Object(fields) => stack.extend(fields.values().map(|value| (value, depth + 1))),
            _ => (),
        }
    }
    let Some(event) = known.first() else {
        return Err("audit-native-row-has-no-registered-file");
    };
    if !has_folder || known.len() != 1 {
        return Err("audit-native-row-cannot-be-tied-to-one-owned-file");
    }
    let encoded = serde_json::to_vec(row).map_err(|_| "audit-native-row-not-fingerprintable")?;
    let fingerprint = format!("{:x}", Sha256::digest(encoded));
    Ok(json!({"event":event,"fingerprint":fingerprint}))
}

fn usable(page: &AuditHistoryPage) -> Stage<()> {
    if page.error.as_ref().is_some_and(|detail| !detail.is_empty()) {
        return Err("audit-native-page-reports-error");
    }
    Ok(())
}

pub(crate) async fn empty_view(client: &Client) -> Stage<Value> {
    let native = client
        .audit_history(1, PAGE_SIZE)
        .await
        .map_err(|_| "audit-native-empty-read-failed")?;
    usable(&native)?;
    let shape = match &native.records {
        None => "null",
        Some(records) if records.is_empty() => "empty",
        _ => return Err("audit-native-baseline-not-empty"),
    };
    if native.total != 0 {
        return Err("audit-native-baseline-not-empty");
    }
    Ok(json!({"page":1,"per_page":PAGE_SIZE,"total":native.total,
              "shape":shape,"records":native.records}))
}

pub(crate) async fn owned_pages(
    client: &Client,
    folder: &str,
    cases: &[&str],
) -> Stage<Vec<Value>> {
    let mut observed = Vec::new();
    let mut fingerprints = BTreeSet::new();
    let mut markers = BTreeSet::new();
    let mut expected_total = None;
    for index in 1..=MAX_RECORDS.div_ceil(u64::from(PAGE_SIZE)) {
        let page = client
            .audit_history(index as u32, PAGE_SIZE)
            .await
            .map_err(|_| "audit-native-page-read-failed")?;
        usable(&page)?;
        let total = *expected_total.get_or_insert(page.total);
        if total != page.total || total > MAX_RECORDS {
            return Err("audit-native-page-total-changed-or-exceeded-fixture");
        }
        if total <= u64::from(PAGE_SIZE) {
            return Err("audit-native-more-than-one-page-unverified");
        }
        let actual = page
            .records
            .ok_or("audit-native-page-records-unavailable")?;
        let expected = (total - (index - 1) * u64::from(PAGE_SIZE)).min(u64::from(PAGE_SIZE));
        if expected != actual.len() as u64 {
            return Err("audit-native-page-record-count-mismatch");
        }
        let mut registered = Vec::new();
        for raw in &actual {
            let redacted = scope_matches(raw, folder, cases)?;
            let signature = redacted["fingerprint"]
                .as_str()
                .ok_or("audit-row-fingerprint-missing")?;
            let file = redacted["event"]
                .as_str()
                .ok_or("audit-row-event-missing")?;
            if !fingerprints.insert(signature.to_string()) || !markers.insert(file.to_string()) {
                return Err("audit-native-duplicate-row-or-registered-event");
            }
            registered.push(redacted);
        }
        observed.push(json!({"page":index,"per_page":PAGE_SIZE,"total":total,
                             "shape":"array","records":registered}));
        if index * u64::from(PAGE_SIZE) >= total {
            break;
        }
    }
    if markers.iter().map(String::as_str).collect::<BTreeSet<_>>()
        != cases.iter().copied().collect()
    {
        return Err("audit-native-owned-events-incomplete");
    }
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use super::scope_matches;
    use serde_json::json;

    #[test]
    fn exact_registered_event_keeps_only_label_and_hash() {
        let row =
            json!({"data":{"folder":"fixture-only","path":"registered.txt","private-note":"omit"}});
        let effect = scope_matches(&row, "fixture-only", &["registered.txt"]).unwrap();
        assert_eq!(effect["event"], "registered.txt");
        assert_eq!(effect["fingerprint"].as_str().unwrap().len(), 64);
        assert!(!effect.to_string().contains("private-note"));
        assert!(!effect.to_string().contains("fixture-only"));
    }

    #[test]
    fn unowned_rows_and_ambiguous_sample_values_are_rejected() {
        let mismatch = json!({"folder":"other","path":"registered.txt"});
        assert!(scope_matches(&mismatch, "fixture-only", &["registered.txt"]).is_err());
        let ambiguous =
            json!({"folder":"fixture-only","before":"registered.txt","after":"second.txt"});
        assert!(scope_matches(
            &ambiguous,
            "fixture-only",
            &["registered.txt", "second.txt"]
        )
        .is_err());
        let path_prefix = json!({"folder":"fixture-only","path":"unregistered.txt"});
        assert!(scope_matches(&path_prefix, "fixture-only", &["registered.txt"]).is_err());
    }
}
