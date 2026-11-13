# Core logs and diagnostic metadata

These unreleased APIs operate on the authenticated official core selected by a
`Client`. They do not install a logger, change global tracing, handle application
signals, exit the caller, or automatically collect private diagnostic files.

`core_errors()` returns the actual native error log. A native `null` is retained
as `None`; missing or malformed containers are errors. `record_core_error(text)`
submits one explicit nonempty, NUL-free UTF-8 report of at most 8 KiB. The core
wraps external reports in its own message format. The SDK preserves the observed
message, timestamp and severity instead of replacing them with the input.
`clear_core_errors()` explicitly clears the current target error log and reads
it back. Another writer or the core itself can add new errors concurrently.

`core_log(since)` reads one bounded snapshot. `since` can use an exact native
timestamp from an earlier entry. The SDK preserves its offset and precision and
encodes it as a query value. It performs no automatic polling, deduplication,
pagination, or conversion to the controller's timezone. Native log rotation and
concurrent writes can create gaps; this is not a durable logging subscription.

`core_log_levels()` returns active native package identifiers, their levels and
descriptions. `set_core_log_levels()` updates only 1–128 explicitly selected
existing packages. `Debug`, `Info`, `Warn` and `Error` map to the verified native
configuration strings. Unknown response values remain `Other(String)` and cannot
be submitted as verified settings. Unselected packages remain under native or
external-writer control. Inspect `requested_levels_match` and the actual returned
configuration; an acknowledgement alone does not prove a level changed. Runtime
readback does not promise persistence across a program restart.

```rust,no_run
# async fn inspect(client: &verysync_sidecar::Client) -> verysync_sidecar::Result<()> {
use std::collections::BTreeMap;
use verysync_sidecar::CoreLogLevel;

let before = client.core_log_levels().await?;
let changed = client.set_core_log_levels(&BTreeMap::from([
    ("main".to_owned(), CoreLogLevel::Debug),
])).await?;
assert!(changed.requested_levels_match);
// Explicitly restore a verified value when your diagnostic work is finished.
if let Some(level) = before.levels.get("main") {
    client.set_core_log_levels(&BTreeMap::from([
        ("main".to_owned(), level.clone()),
    ])).await?;
}
# Ok(()) }
```

`core_diagnostics()` exposes the exact native `databaseSize` metadata and
locations such as `confdir` and `datadir`. No undocumented size-unit conversion
occurs. Locations are `TargetPath` values in the connected target's syntax,
including when the controller runs on another OS. The SDK opens no such path on
the controller and does not infer access permissions or directory ownership.
Returned text, locations and unknown fields are untrusted private target data.
Default `Debug` output omits messages, package descriptions and paths; explicit
field access remains available to callers responsible for handling them.

Every call uses a fresh identity check. Mutations serialize between clones of one
connection and are never retried. A write followed by failed or malformed
acknowledgement/readback reports `MutationOutcomeUnknown`; the native action may
already have occurred. External writers still require application coordination.

Local macOS arm64 isolated public-API effects have been observed with fixed
VerySync v2.33.2 and no commercial entitlement. Final same-source native Windows,
Linux and macOS gates remain pending for this slice. No destructive database
reset, profile collection, conflict resolution, licensed behavior, remote
filesystem access, or OS-wide isolation claim follows from these log APIs.
