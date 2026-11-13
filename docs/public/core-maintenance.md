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
reset, conflict resolution, licensed behavior, remote
filesystem access, or OS-wide isolation claim follows from these log APIs.

## Explicit native profiles and metrics

`collect_core_profile(CoreProfileRequest::Heap)` explicitly triggers the official
core's garbage collection and returns its gzip-compressed heap pprof data.
`CoreProfileRequest::Cpu { duration_seconds }` collects 1–30 whole seconds of
native CPU activity. Both GET endpoints are treated as mutations, use a fresh
identity check, serialize between clones of one connection and never retry.
They do not profile the controller application, install a global profiler,
change logging, store files or restart either process.

The selected connection's response-size limit and request deadline remain in
force. Choose a longer connection deadline explicitly when collecting a longer
CPU profile. A timeout, cancelled future or failed response does not prove that
native sampling stopped. Coordinate subsequent profiling and external writers
after an unknown outcome; there is no invented native cancellation endpoint.

`CoreProfile::body_bytes()` borrows the unchanged compressed response;
`into_body_bytes()` transfers ownership for explicit caller handling. The SDK
checks the gzip signature and minimum length, rather than decoding the CRC,
protobuf records or symbols. Decode and validate the data with your profiling
tool before use. Native test evidence independently decompresses complete gzip
members and checks CRCs; an HTTP-success JSON or HTML response is not a profile.
Profiles can contain private target paths, addresses and symbols. `Debug` shows
only the requested kind/duration and compressed size.

`core_metrics()` reads one authenticated, bounded UTF-8 Prometheus exposition
snapshot from `/metrics` under the selected management base path. The fixed
program's `/rest/metrics` route returns 404. `CoreMetricsSnapshot::native_text()`
preserves native families, values, labels and comments; callers can use their
chosen metrics parser. The SDK recognizes the observed HELP/TYPE text envelope,
rejects HTML or invalid UTF-8, and invents no missing sample, unit, timestamp,
rate or aggregation. Default `Debug` omits the text and labels.

This API attaches the connection's API key normally. It does not enable
`metricsWithoutAuth`, expose another listener, start an exporter or change the
caller's telemetry configuration. The isolated local native case verifies both
authenticated collection and denied unauthenticated collection while that flag
remains false. It also checks native GC count observation, complete heap/CPU
gzip data, clone serialization, unchanged instance identity and normal owned
process exit. Same-source six-native acceptance for profiles and metrics remains
pending; these observations are functional evidence, not a performance score.

## Explicit synchronization-index reset

`request_index_reset(&IndexResetScope::Folder(id))` requests the native reset for
one configured folder. `IndexResetScope::AllFolders` is a separate explicit
choice. An absent folder never falls back to a global reset. Paused configured
folders can be selected. The SDK verifies the exact native acknowledgement and
returns `IndexResetAcknowledgement`; malformed or different action messages
remain unknown mutation outcomes and are not retried.

The native action schedules a program restart. On the fixed isolated baseline,
the owned generation exits normally with native code **3**. This acknowledgement
does not prove an index was removed, an old tree exited or a new generation is
ready. An owner can explicitly await `ManagedInstance::wait_for_exit()` and then
call `restart()`; remote callers must coordinate the actual program owner. The
SDK does not start a replacement, pause peers, restore a backup or roll back.

Keep an independent state backup and coordinate active writers/peers before
destructive index maintenance. Resetting an index does not itself unregister
the folder or remove the controlled synthetic files, but later scanning and
synchronization can apply changes. The isolated public-API case verifies
selected-index removal, exact retention of the other paused folder's index,
removal of both indexes for the explicit global choice, unchanged complete
configuration/identity/key/certificate and original file hashes. A separate
stopped-program CLI oracle checks the actual database; the paused HTTP status
already reports zero before reset and is not used as removal evidence.

Those oracle commands are independent test instrumentation. Final same-source
native acceptance for the reset API remains pending.

## Explicit stopped-owner database commands

`ManagedInstance::run_database_command(command, timeout)` runs only the selected,
hash-verified official executable against its private state after a confirmed
owned-tree exit. It rejects an active generation and never stops or starts one
implicitly. `DatabaseCommand` admits `Statistics`, `Counts(folder)`,
`File { folder, path }` and the separate destructive choice `ResetAll`.
Arguments use structured argv with an option terminator before folder/file
selectors. File selectors must be bounded relative paths in the local program's
native syntax. No shell is invoked.

`DatabaseCommandExit` retains the actual code, contained-tree completion and
bounded private output. `Success` means native exit zero. Counts decode only the
verified six-column table; unknown device/kind/flag/deletion labels remain exact.
Opaque text preceding a recognized table or exact missing-folder error is
retained separately in `native_preamble`, as well as unchanged in the complete
private diagnostic. It is not interpreted as a row or silently discarded.
Every row after the header must still match the schema; malformed, overflowing,
duplicate-header and unknown-trailer responses remain unrecognized.
Malformed successful tables return `UnrecognizedCounts`, never an invented empty
index. Only the known exact exit-one diagnostic maps to `FolderNotIndexed`.
Statistics and file metadata remain explicit native text; the SDK invents no
units or undocumented metadata schema. Default `Debug` omits selectors and output.

Each call holds the existing private-state lease through process cleanup and
uses the caller's positive deadline for admission, program hashing and native
execution. Output is limited to 64 KiB. Before a database command, a bounded
metadata walk rejects symbolic links, reparse points and special entries in the stopped state without
following them or traversing registered data roots: at most 65,536 entries and
64 directory levels; only the selected retained management socket is allowed. Coordinate
external state writers; this check is not a filesystem transaction.

Dropping the future requests cooperative cancellation and exact CLI containment
cleanup; lease release can follow asynchronously. The SDK does not retry or roll
back. After an interrupted reset, inspect the actual state before another action.
A modifying command's execution failure can be `MutationOutcomeUnknown`.
These commands invalidate the prior clean-state backup eligibility, including
reads that can open native database files; explicitly restart and normally stop
the owned core before taking a managed backup again.

`ResetAll` resets native indexes, not the registered synchronization source
files. Keep a separate state backup and coordinate peers and later scans.
The isolated local case observes nonempty typed counts and actual file metadata,
reset removal, missing-index classification, retained original hashes and
identity, explicit restart and normal final exit. Same-source six-native gates
remain pending; no general database repair or licensed feature is implied.

```rust,no_run
# async fn counts(core: &mut verysync_sidecar::ManagedInstance, folder: verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
use std::time::Duration;
use verysync_sidecar::{DatabaseCommand, DatabaseCommandOutcome};

// The caller has already confirmed this owned generation is stopped.
let result = core.run_database_command(
    DatabaseCommand::Counts(folder), Duration::from_secs(10),
).await?;
if result.outcome == DatabaseCommandOutcome::Success {
    if let Some(rows) = result.counts {
        for row in rows {
            println!("count={} native_size={}", row.count, row.size);
        }
    }
}
# Ok(()) }
```
