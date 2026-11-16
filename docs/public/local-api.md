# Native Local-API

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
start/end must be RFC3339 with a valid ordering. The core itself ignores malformed
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
