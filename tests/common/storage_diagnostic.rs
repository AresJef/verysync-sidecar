//! Bounded diagnostics for owned synthetic protocol effects only.
use verysync_sidecar::StorageEndpoint;
pub fn native_rejection(
    error: &verysync_sidecar::Error,
    endpoint: &StorageEndpoint,
    root: &std::path::Path,
) {
    let mut cause = error;
    while let verysync_sidecar::Error::MutationOutcomeUnknown { source, .. } = cause {
        cause = source;
    }
    let response = match cause {
        verysync_sidecar::Error::Api { response, .. }
        | verysync_sidecar::Error::Http { response }
        | verysync_sidecar::Error::InvalidResponse { response, .. } => response,
        _ => {
            eprintln!("synthetic protocol failure category: {cause:?}");
            return;
        }
    };
    let decoded: serde_json::Value =
        serde_json::from_slice(response.body_bytes()).unwrap_or(serde_json::Value::Null);
    if let Some(message) = decoded.get("error").and_then(serde_json::Value::as_str) {
        let mut redacted = message.to_owned();
        for key in ["user", "password"] {
            if let Some(secret) = endpoint
                .extra()
                .get(key)
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
            {
                redacted = redacted.replace(secret, "[SYNTHETIC_CREDENTIAL]");
            }
        }
        let path = root.to_string_lossy();
        redacted = redacted
            .replace(path.as_ref(), "[SYNTHETIC_ROOT]")
            .replace(&path.replace('\\', "/"), "[SYNTHETIC_ROOT]");
        let bounded = redacted
            .chars()
            .filter(|c| !c.is_control())
            .take(512)
            .collect::<String>();
        eprintln!(
            "synthetic native protocol rejection: status={} message={bounded}",
            response.status()
        );
    } else {
        // Shape only: preserve enough evidence to distinguish a malformed run
        // receipt from a JSON/API envelope without printing paths, credentials,
        // native error details or unknown metadata values in public CI logs.
        let shape = |value: Option<&serde_json::Value>| match value {
            None => "absent",
            Some(serde_json::Value::Null) => "null",
            Some(serde_json::Value::Bool(_)) => "bool",
            Some(serde_json::Value::Number(_)) => "number",
            Some(serde_json::Value::String(_)) => "string",
            Some(serde_json::Value::Array(_)) => "array",
            Some(serde_json::Value::Object(_)) => "object",
        };
        let fields: std::collections::BTreeMap<_, _> = [
            "id",
            "jobId",
            "started",
            "finished",
            "count",
            "summary",
            "cancelled",
            "error",
        ]
        .map(|key| (key, shape(decoded.get(key))))
        .into_iter()
        .collect();
        eprintln!(
            "synthetic native protocol rejection: status={} body_bytes={} run_field_shapes={}",
            response.status(),
            response.body_bytes().len(),
            serde_json::json!(fields)
        );
    }
}
