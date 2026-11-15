# Explicit native helpers

`native_health()` reads the program's native HTTP health snapshot through the
selected authenticated connection, with a fresh target-identity check. The native
route `/rest/noauth/health` itself does not require authentication; this `Client`
method is intended for an already connected instance. `NativeHealthStatus::Ok`
represents the exact `OK` token. Other nonempty tokens and additional fields are
retained, while missing, empty or wrongly typed status fields are invalid
responses. Unknown values are omitted from ordinary Debug output. Native body
errors remain typed API errors even if the HTTP status is 200. The snapshot does
not establish folder completion, task success or commercial authorization.

`native_migration_progress()` reads the global native migration snapshot from
`/rest/migrate/progress`, after a fresh target-identity check. It preserves the
native task label, signed total/completed counters, percentage, finished flag,
task error text and unknown fields. Counter units and sentinel values are not
inferred; the percentage is neither clamped nor recomputed from the counters.
All known fields must be present with the expected types. A full progress
snapshot with nonempty task error text remains data; a native request-error
envelope remains a typed API error, and unsuccessful HTTP responses retain their
typed transport/authentication or HTTP errors.

Reading progress does not start or cancel a migration. This global snapshot has
no caller job ID and may already report a finished migration on a fresh instance.
Inspect `error_message` separately from `finished`; neither flag nor percentage
alone proves the success of work initiated by your application. The native test
checks the existing completed baseline without starting migration work. Active
and failed snapshots have synthetic transport coverage. Names, task errors,
counters and additional values are omitted from ordinary Debug output.

`normalize_device_id(text)` asks the selected engine to validate and normalize
device text. Native lowercase and ungrouped forms can return the same canonical
`DeviceId`. This differs from `DeviceId::parse`, which checks the local canonical
character layout. The native test separately checks a changed checksum that
passes the local layout check and is rejected by the engine. Neither operation
proves possession of a peer certificate or registers a device.

`lookup_target_ip(ip)` asks that engine for its IP-location data. It accepts an
explicit `std::net::IpAddr`, checks the returned address, and preserves empty or
localized native location strings. The target may consult its own services or
network. The native test uses IPv4 and IPv6 loopback only; geographically accurate
public-IP results have separate environment requirements.

`native_random_number()` explicitly requests the native decimal number and
decodes it as `u64`. This makes no cryptographic, uniqueness or distribution
claim. Use `ApiKey::generate()` for secure management credentials. The native GET
uses mutation semantics and is never automatically retried, since random state
can advance even if a response is lost or malformed.

`native_random_string(length)` explicitly generates one native ASCII
alphanumeric string. `None` omits the query and `Some(0)` selects the native
32-character default. Positive `u16` lengths request the exact byte count,
including 65535. The result retains unknown fields and excludes the value and
unknown data from ordinary Debug. Inspect `value` explicitly and redact it
before logging. Wrong lengths, malformed values and native body errors remain
errors, with unknown mutation outcomes after a request may have advanced state.
There is no retry, cryptographic-strength or uniqueness guarantee; use
`ApiKey::generate()` for secure management credentials. The SDK bound describes
the verified typed interface, not an inferred native maximum; raw requests remain
available for separately validated inputs.

`collect_native_usage_report()` explicitly collects the engine's report snapshot,
including its version, platform, device count and additional native fields. The
SDK neither enables reporting nor uploads the returned report. Native background
reporting remains a separate configuration concern; collection is not evidence
of system-wide network isolation or delivery. Native benchmark-like fields are
retained data, not SDK performance measurements. Collection uses mutation
semantics because native diagnostic state can change. The native test separately
checks that usage/crash preferences remain unchanged by collection.

`pending_native_link()` retrieves one native GUI-link snapshot. An empty native
string becomes `None`. Nonempty text is private, untrusted data and can contain
sharing credentials. The SDK never opens/follows it, accepts a key, or registers
a folder automatically. Delivery can consume native state, so the method uses
conservative mutation semantics, with no retry on uncertain results. The native
test currently verifies the empty-link case; nonempty transport and redaction
have synthetic contract coverage, with actual native nonempty delivery still
requiring its own effect evidence.

```no_run
# async fn example(client: &verysync_sidecar::Client) -> verysync_sidecar::Result<()> {
let health = client.native_health().await?;
let migration = client.native_migration_progress().await?;
let generated = client.native_random_string(Some(16)).await?;
assert_eq!(generated.value.len(), 16);
let canonical = client.normalize_device_id("caller-provided device text").await?;
let report = client.collect_native_usage_report().await?;
let pending = client.pending_native_link().await?;
// Handle untrusted pending text explicitly, without automatically opening it.
# let _ = (health, migration, generated, canonical, report, pending);
# Ok(()) }
```

All methods check the authenticated instance identity before their native request.
Mutating helpers serialize with other mutations through cloned clients. Response
size limits, deadlines and transport authentication remain in force. Ordinary
Debug output omits private report, location and link values; inspect fields
explicitly when needed and redact them before logging.

## Interpreting the surface index

The capability CSV also records internal native symbols found during surface
research. Rows classified as `internal` identify verified listener/bootstrap or
route-construction implementation, without a separate HTTP or CLI call. They
are not extra SDK methods, aliases of an entire module, support claims or
completion credit. Registered operations keep their individual implementation
and acceptance records even when one constructor wires many routes.

In particular, the native `getListener` constructor builds the GUI socket/TLS
listener during startup; public listener settings and managed lifecycle remain
separate controls. `patchVerysyncHandler` constructs the custom router and
file-resource dispatcher; its name does not describe a PATCH request. The
independent native `/rest/folder/downloadprogress` and `/rest/fs/path/writeable`
endpoints retain separate pending implementation/effect records until their
actual contracts are verified. The latter's native `attempt` input is not
silently treated as a filesystem-selector parameter.

## Native path-writeability snapshots

Call `probe_target_path_writeability(&path, check_ancestors)` for the distinct
native `/rest/fs/path/writeable` endpoint. Use `TargetPath::local(PathBuf)` for
a local target and explicit target syntax for a remote one. The SDK does no
controller filesystem I/O, traversal or permission substitution. The native
`path`, `lastPath`, `attempt`, `writeable` and required `error` value are retained
in `NativePathWriteability`, along with unknown fields. Ordinary Debug omits
paths, tokens, errors and extension values.

`false` omits `attempt`; `true` sends its nonempty token `true`, allowing the
native bounded search of at most ten parents after a missing-path error.
The fixed handler tests nonempty text, so raw literal `attempt=false` does not
disable that branch. The typed method never sends that string.

**Fixed-baseline limitation:** on the tested v2.33.2 macOS ARM64 core, a
caller-verified writable directory, existing file and missing descendants all
returned HTTP 200 with `writeable: false` and `error: {}`. Ancestor selection
did not change these observations. The native call passes an empty filesystem
type into its factory lookup. These results do not establish a reliable
writable/unwritable distinction. The empty error object is preserved without
an invented explanation. Do not use this snapshot as a permission precondition
or a guarantee of later write success. Positive native permission detection
and current-source platform acceptance remain open.

The native writable-directory helper contains permission adjustment and
restoration code. Despite using GET, this operation conservatively serializes
with mutations, verifies identity first and retains uncertain outcomes after
a lost, malformed, failed or oversized response. No retries, implicit directory
creation, controller chmod or native repair occur. An interrupted request
can still have native effects.

```no_run
# async fn example(client: &verysync_sidecar::Client) -> verysync_sidecar::Result<()> {
let path = verysync_sidecar::TargetPath::local(std::path::PathBuf::from("/owned/target"));
let snapshot = client.probe_target_path_writeability(&path, false).await?;
// Inspect writeable AND native_error; the fixed-baseline limitation still applies.
# let _ = snapshot;
# Ok(()) }
```

## Explicit target-side folder open requests

`request_native_folder_open(&folder, NativeFolderOpenLocation::Folder)` asks the
connected target to open a registered folder. `Trash` selects the fixed native
trash/archive category. The target derives the location from its registration;
the SDK accepts no arbitrary opener path, joins no filesystem strings and
opens no application on the controller.

**The receipt does not prove a window opened.** The fixed native handler returns
an empty HTTP 200 after calling its desktop opener, ignores opener-start errors
and can silently ignore requests that fail its locality check. The SDK does not
override that check, retry a request, change the target's environment, repair
the opener or fall back to a controller application.

The state-changing GET is explicit, serialized with other mutations and
preceded by fresh identity and configured-folder checks. The typed interface
accepts the verified exact empty-200 acknowledgement. Native body failures,
unexpected content/status and lost/oversized responses retain typed failures
and uncertain mutation outcomes. Missing registrations fail before dispatch.
`NativeFolderOpenReceipt` preserves the selected registration and location;
ordinary Debug omits the registration ID.

Native tests substitute a short-lived owned capture executable through the
test child's environment, then verify the official core's exact normal/trash
arguments. This proves native dispatch without opening desktop applications.
It does not prove that a real graphical shell or chosen file manager is
available. Current-source target execution remains separate from local evidence.

```no_run
# async fn example(client: &verysync_sidecar::Client, folder: &verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
let receipt = client.request_native_folder_open(
    folder, verysync_sidecar::NativeFolderOpenLocation::Folder,
).await?;
// An acknowledgement alone does not establish graphical UI success.
# let _ = receipt;
# Ok(()) }
```

## Native wallpaper resources

`native_wallpaper(if_none_match)` retrieves `/verysync/wallpaper` from the
authenticated target after a fresh identity check. The fixed program fetches
its Bing metadata and image upstream. The SDK contacts only the management
endpoint; it does not fetch a provider URL, save or decode image data, persist
a cache, set a system wallpaper or open a desktop application.

`NativeWallpaperResponse` reports `Image` for a nonempty HTTP 200 advertised as
image media, or `NotModified` for HTTP 304 with no returned bytes. Media headers
do not prove that a decoder will accept the opaque bytes. Exact headers remain
available, including unknown and duplicate values; ordinary Debug omits their
contents and the resource data.

Pass an explicit opaque ETag string to send `If-None-Match` unchanged. Tags must
be nonempty, at most 1024 UTF-8 bytes and control-free; this is an SDK input
bound. The native handler uses exact string comparison and still performs
upstream requests before deciding to return 304. The SDK neither implements a
cache nor creates bytes for a not-modified response. Native cache headers are
observations, not a local persistence or freshness guarantee.

Unavailable/blocked upstream services, authentication failures, native body
errors, invalid responses, size bounds and deadlines remain typed failures.
No automatic request retry occurs. Source availability is independent of the
management connection. The native tests require both source-denied behavior
and a separately explicit live-source image/304 observation, with unchanged
configuration, identity, synthetic sample and normal owned-process exit.
Images stay in memory; no third-party picture is published in test evidence.

```no_run
# async fn example(client: &verysync_sidecar::Client) -> verysync_sidecar::Result<()> {
let resource = client.native_wallpaper(None).await?;
match resource.status() {
    verysync_sidecar::NativeWallpaperStatus::Image => {
        let untrusted_bytes = resource.body_bytes();
        let _ = untrusted_bytes;
    }
    verysync_sidecar::NativeWallpaperStatus::NotModified => {}
}
# Ok(()) }
```
