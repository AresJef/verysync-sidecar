# Native Local-API

A read of a full configuration must return the folder that was requested.
If a write first checks folder A and receives folder B, the request to change
A stops before the write. If a request for A was already sent and the reply to
the verification read belongs to B, the error reports an unknown outcome.
Read A on the selected instance before deciding whether to try again. A
license refusal is a separate typed result.

`LocalApiClient` connects to an explicitly selected, already enabled native
Local-API endpoint. It is separate from the GUI API-key `Client` and from
`ManagedInstance` process ownership. Connecting never changes configuration,
activates a trial, acquires a license, downloads a program or discovers a port.

```rust,no_run
use verysync_sidecar::{LocalApiClient, LocalApiConnectOptions, ManagementEndpoint};
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let endpoint = ManagementEndpoint::http("http://127.0.0.1:12345/")?;
let local = LocalApiClient::connect(LocalApiConnectOptions::new(endpoint)?).await?;
let status = local.system_status().await?;
println!("{}", status.device_id);
# Ok(())
# }
```

Use the address of a dedicated instance. No default endpoint is assumed. Supply
`expected_device_id` when an out-of-band identity is available. A changed
identity rejects a fresh status read or a potentially modifying raw request.
The connection follows the fixed v2.33.2 version policy, explicit transport trust,
bounded response size and complete-request deadline. It does not send a GUI API
key, reuse a GUI login session or automatically retry a request.

`version()` and `system_status()` return typed snapshots. Absent metrics remain
`None`, distinct from a reported zero. Unknown fields remain explicitly available
and are omitted from ordinary debug output. `raw()` encodes structured components
beneath `rest/localapi/` on the selected endpoint, preserving any proxy prefix.
Components exclude that fixed prefix. Raw status, headers and body are preserved;
HTTP success alone does not establish a native operation's effect or entitlement.
Declare `RequestEffect::MayModify` for state-changing routes, including GET routes
whose native behavior changes state. Those calls serialize across client clones
and check identity before sending.

`folders()` and `folder()` return the native `LocalApiFolder` projection. It
contains target-native paths, pause and optional scan/selective settings, plus
identity/name peer projections. The native Local-API projection has no GUI label.
Unmodeled fields, including share material, remain private explicit `extra` data.
`devices()` returns the native identity/name projection, rather than full GUI
device settings or a live connection report. Private peer names are omitted from
ordinary debug output. Returned target paths are never treated as local paths.

`request_scan(folder, scope)` accepts a folder root or a strictly relative path
in the target's syntax. It checks the configured folder and pause setting, sends
one POST and requires the fixed native `ok: scanning` acknowledgement. It does
not retry or claim correlated scan completion. Changed/malformed acknowledgements
are unknown mutation outcomes. A native macOS ARM64 case independently observed
a newly written synthetic file in the index after this Local-API subpath request
with automatic rescan/watching disabled, then verified root-scan acknowledgement,
identity/private-share preservation, unchanged bytes and normal owned-tree exit.

`browse_folder()` uses the native wrapper's fixed level-zero selective tree;
`folder_need()` reads one explicit `ListPage`; `request_selection()` sends the
explicit select/deselect/remove-from-all flags. The SDK validates target-relative
scopes and sends no selection body. These methods preserve the Local-API license
rejection observed as HTTP200 with native code3001 and a nonempty error string:
`Error::LicenseRequired { code: 3001, .. }`. Raw requests retain that original
status/body. Generic HTTP403 or future error codes do not invent this entitlement
classification. A selection acknowledgement does not prove removal, download or
all-peer completion. Licensed success/effects remain pending native acceptance.

`folder_summaries()`, `folder_statistics()`, `connections()`,
`folder_download_progress()` and `folder_completions()` return typed native
maps/snapshots behind their individual Local-API license gates. The summary
handler omits folders whose model lookup fails. Completion maps contain peer
device IDs and exclude this instance; omitted/error peers are not fabricated.
Download progress names remain untrusted index names. No read initiates peer
discovery or establishes WAN reachability, file durability or batch completion.

`folder_history(page, filter)` sends one explicit bounded page and a JSON-encoded
`LocalApiHistoryFilter`. Name/folder/action fields remain native selections;
start/end must be bounded RFC3339 with a valid ordering; leap seconds and
precision finer than nanoseconds are rejected. Original spelling is preserved. The core itself ignores malformed
filter JSON, so the SDK validates/encodes it before making a request. Native
backend errors remain `Error::Api`; missing page containers are response errors.
An explicit null record collection is preserved separately from an empty array.
Known omitempty record fields remain optional. Signed native modified/event-time
integers are retained without guessing their unit or converting them to a clock.
An empty free-instance page does not verify licensed recording or populated
history effects. It does not enable auditing, reset history or follow pages.

`hardware()` decodes the three nested CPU/memory/network objects. An embedded
native section error returns bounded `Error::Api` diagnostics, preserving partial
data for explicit inspection; missing/malformed sections are response errors.
No controller inventory or synthetic zero inventory is substituted. The local
macOS ARM64 common-control case observed this native error path, so it establishes
error preservation rather than a positive complete hardware inventory.

`generate_share()` and `validate_share_key()` reuse the existing `GeneratedShare`
and `ValidatedShare` types through the native licensed Local-API handlers. Both
consume native randomness and use the conservative modifying-request path.
Neither registers or joins a folder. Suggested registration IDs can differ on
each call and are not stable key fingerprints or cross-node group IDs. Native
invalid-key errors can be JSON objects and remain private bounded
`Error::ShareKeyRejected` diagnostics; the SDK never coerces them to text. A
read-only validation cannot acquire a read/write credential. Real licensed
generation/validation effects remain pending authorized acceptance.

The licensed configuration item routes use the native management configuration
schema, rather than the Local-API projection. `folder_configuration()` reads one
full `FolderConfig`. `create_folder(template, options)` requires an explicitly
supplied complete `FolderDefaults` template; the Local-API router registers no
defaults-reading route, and this method never fetches through another channel or
invents a native template. Explicit ID/path/label/pause selections override that
template, retaining its other native fields. Template origin/version and sharing
material remain the caller's explicit responsibility.

`update_folder()` sends only selected label/pause fields.
`replace_folder_configuration()` sends the caller's complete snapshot.
`replace_folder_configurations()` explicitly replaces the entire collection and
can remove omitted IDs. The latter reads full items in the observed projection
order; matching flags compare exact IDs and complete per-ID bodies. A successful
acknowledgement with different native readback remains a mismatch.
`remove_folder_keep_files()` sends a single configuration DELETE without file
flags/body and reports actual subsequent configuration absence. File retention,
runtime application and peer effects retain their separate real acceptance gates.

Writes retain the clone-shared mutation lock through preflight, request and
readback. Create refuses an already configured ID and, unless explicitly allowed,
an identical target path string. Independent controllers still need coordination:
the native POST is an upsert and these separate requests are not an atomic
transaction. No aliases are resolved on the controller's filesystem. A full item
response must carry the exact requested ID. `FolderIdentityMismatch` exposes
the two identifiers through explicit inspection and omits the unrelated
configuration. A preflight mismatch or native license refusal prevents that
write. A failed readback, including an ID mismatch, leaves the outcome
unknown. The SDK never retries the write.
Licensed actual write effects remain pending; synthetic readbacks do not replace
authorized native acceptance.

`request_restart()` and `request_shutdown()` send one explicit native action and
require their distinct text acknowledgements. The native handler flushes its
response before a nonblocking exit request; an acknowledgement proves neither
process exit nor automatic relaunch. For an owned instance, await
`ManagedInstance::wait_for_exit()` with an explicit caller deadline, then choose
whether to start another generation. A local macOS ARM64 native case observed
actual restart exit3, a separately requested new generation with retained
identity/shares/files, and actual shutdown exit0 with the owned tree stopped and
state released. These are distinct observations from the HTTP acknowledgements.

`request_server_selected_upgrade()` explicitly invokes the core's release
provider and installer, which can replace its executable. Use a dedicated mutable
program and backups. The SDK downloads/selects nothing itself and does not retry,
relaunch or roll back. `restart_acknowledged: false` preserves the core's empty
successful reply, distinct from its `restarting` marker. Neither is an installed
version or executable hash receipt.

An isolated macOS ARM64 test used this Local-API action without a configured
license. With explicit manual upgrade checks enabled, the official release
provider selected v2.33.2 for an owned v2.33.1 instance. The test supplied a
verified local copy of the official archive. It observed the old process exit,
matched the installed executable with the fixed v2.33.2 digest, and started a new
generation explicitly. The device identity, share keys, existing index and sample
bytes were preserved, and the new generation shut down normally.

`request_folder_temporary_cleanup(folder)` is an explicit destructive operation
on a configured folder's `.verysync/*.tmp` and `*.sess` entries, including matching
directories. The clone-shared mutation guard covers folder preflight and dispatch.
The core can acknowledge success while logging an individual removal failure;
verify required file effects independently. The local native case observed both
a matching file and a matching directory removed, with ordinary bytes retained.
It does not sweep other folders, retry removal or automatically request a scan.

`subscribe_index_events(options)` and
`subscribe_filtered_index_events(filter, options)` use the native licensed
Local-API event buffer and the existing bounded event-stream behavior: consumed
cursors, backpressure, explicit gaps, finite read recovery and explicit close.
`EventSource::LocalIndex` binds each cursor to this source and its canonical
filter; GUI, disk and other filter cursors are rejected before a request. Initial
failure starts no background worker and is not retried. Native per-filter buffers
are finite; a native limit can select the latest tail, so the stream does not
promise durable history or gap-free replay. Local free-instance default and
filtered subscription attempts both returned native license code3001. Licensed
positive index events and final current-source platform coverage remain pending.

For a library-owned instance, `ManagedOptions::local_api_enabled(true)` explicitly
sets the native startup flag. It requires an HTTP(S) management endpoint and
grants no commercial entitlement. The default preserves Local-API settings.
Only known library-generated `appconf.yaml` forms may be replaced, including the
earlier exact SDK startup file. Other settings are rejected without replacement.
The generated settings use the native `verysync:` root and disable automatic
startup. This is a startup option, not an assertion that a live reconfiguration
has taken effect. Caller-owned instances must be enabled by their owner.

On v2.33.2, controlled macOS ARM64 native observations distinguish disabled HTTP
404, enabled loopback HTTP reads and Unix-socket HTTP 400. The Unix-socket wrapper
fails while parsing its peer address, before its enable check; this client rejects
that transport. A disabled endpoint is not classified as a missing license.
Some native Local-API routes have separate commercial checks. A successful basic
status read does not prove licensed folder browsing, selective sync or remote
access. Those positive paths still need authorized native acceptance. Cross-platform
runtime coverage is tracked separately from these local observations.


## Registered route coverage

All 28 method/path entries in the fixed v2.33.2 Local-API router have typed
interfaces. The capability catalog lists five canonical symbol-derived routes
and 23 canonical Local-API rows; these are distinct entries, not extra aliases.
The APIs cover connection/status, projections, configuration changes, scans,
selection and listing, progress/statistics, history, share-key operations,
system actions, temporary cleanup and index events.

The first stable release defers the positive cases that require an official
entitlement on an isolated test instance. Resume those cases with the fixed
program and corresponding authorization, including licensed selection,
populated history and events, and actual licensed configuration writes.
Applicable ordinary native effects and observed native license refusals remain
part of candidate validation. Empty pages, partial hardware errors and
acknowledgement-only observations keep their stated limits. The Local-API
router does not establish an independent enterprise-control contract or another
feature's commercial entitlement.
