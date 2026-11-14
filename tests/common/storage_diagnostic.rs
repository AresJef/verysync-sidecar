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
        eprintln!(
            "synthetic native protocol rejection: status={} body_bytes={}",
            response.status(),
            response.body_bytes().len()
        );
    }
}
