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
endpoints have distinct typed contracts and independent acceptance records.
The latter's native `attempt` input is not
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

**Fixed-baseline limitation:** tested v2.33.2 macOS, Linux AMD64 and Windows
AMD64/ARM64 cores returned `writeable: false` and `error: {}` even for independently
verified writable directories. The macOS observations also cover an existing file
and missing descendants, with and without ancestor selection. Static inspection
of the macOS and Linux implementations finds an empty filesystem type passed to
the factory lookup. These results do not establish a reliable
writable/unwritable distinction. The empty error object is preserved without
an invented explanation. Do not use this snapshot as a permission precondition
or a guarantee of later write success. For this fixed baseline, acceptance
preserves complete native snapshots and their documented limitation on macOS,
Linux and Windows. Actual file writes and all other path operations require their
own evidence. Other architectures and complete current-source platform coverage
remain separately recorded; this condition grants no unrelated capability.

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

For the fixed macOS baseline, support here means faithful native-result
preservation with this limitation, rather than a reliable permission oracle.
Other platforms retain their own independent validation requirements.

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
The Windows fixture selects the socket provider for the actual compiled opener's
PE architecture, including x86 under WOW64. Its runtime preflight executes that
same owned target executable and requires a successful loopback bind with the
matching architecture and pointer width. A host Python socket check cannot
establish that a different target architecture can initialize Winsock.
The WOW64 directory query uses a bounded writable buffer, one permitted resize,
and the actual copied UTF-16 length. A positive native count with empty or
incomplete output is an error; it cannot become a current-directory DLL lookup.
This follows [Microsoft's return-value contract](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-getsystemwow64directoryw).

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

## Native CLI storage locations

After explicitly stopping an owned instance, call
`inspect_native_storage_paths(timeout)` to run the exact last-ready executable's
`paths --home <owned-state>` command. This is separate from the REST
`native_system_paths()` request. It uses the dedicated native profile, retains
the state lease through contained child cleanup, verifies the executable hash,
and bounds captured private output to 64 KiB. It never starts a serving core,
connects to an existing instance, retries, downloads, or changes caller environment.
Native helper initialization may create directories inside that owned state.

`NativeStoragePathsExit` preserves the actual exit and private native output.
Only exit zero with all seven recognized groups produces the nine typed local
`PathBuf` fields. Failure and unrecognized output are distinct; unknown text is
retained instead of inventing an empty successful result. Ordinary Debug hides
path values. Newline/control-containing paths and changed native report schemas
remain unrecognized rather than being guessed or normalized.
Native text preceding the first complete report is retained separately in
`native_preamble`, as well as in the complete private diagnostic. The fixed
Windows program emits console initialization messages before this report.
Their presence does not remove any required group or accept a partial report.

A reported path does not prove existence, writeability, active configuration,
registered synchronization folders, or an active HTTPS listener. In particular,
the default sync directory and HTTPS files may be absent. This inspection
can report a native account home outside the dedicated environment profile,
including on Windows; the SDK never opens that reported default location. It
invalidates the prior clean-generation backup eligibility like other stopped
CLI commands; explicitly start and normally stop again before a fresh backup.
Running owners and invalid deadlines are rejected. Cancellation requests exact
helper cleanup; the worker holds its state locks until cleanup ends.

```no_run
# async fn example(core: &mut verysync_sidecar::ManagedInstance) -> verysync_sidecar::Result<()> {
use std::time::Duration;
use verysync_sidecar::NativeStoragePathsOutcome;
core.shutdown(Duration::from_secs(10)).await?;
let exit = core.inspect_native_storage_paths(Duration::from_secs(10)).await?;
if exit.outcome == NativeStoragePathsOutcome::Success {
    if let Some(paths) = &exit.paths {
        let database_directory = &paths.database_directory;
        let _ = database_directory;
    }
}
# Ok(()) }
```

## Native shell completion instructions

The fixed program discovers the account's login shell rather than using a
caller-supplied SHELL selector. Its pinned kongplete implementation prints
templates for bash, zsh and fish. On Windows, its login-shell dependency selects
COMSPEC (normally cmd.exe), for which no template exists. That native nonzero
unsupported-shell response remains `NativeCompletionOutcome::Failure`, with
private diagnostic bytes and no instruction text. It is not successful shell
integration. The API neither selects a replacement shell nor evaluates a script.
See the pinned [completion implementation](https://github.com/WillAbides/kongplete/blob/v0.4.0/completion_install.go)
and [Windows shell discovery](https://github.com/riywo/loginshell/blob/7d26008be1ab/loginshell.go).

`native_completion_instructions(action, timeout)` explicitly invokes the native
`install-completions` command, optionally with `--uninstall`, on a confirmed
stopped owned instance. `NativeCompletionAction` selects the exact native flag.
The method retains the executable hash check, private state lease/profile,
bounded 64 KiB capture, alias rejection, cancellation and contained cleanup.
Running owners and invalid deadlines are rejected. The private state traversal
does not inspect registered synchronization roots.

`NativeCompletionExit` preserves the actual native code, exact private output
and action. `InstructionText` means exit zero and nonempty UTF-8 text without
NUL; `instruction_text()` borrows those exact bytes as text. It does not certify
valid shell syntax, the correct shell, installation, removal, or effective
completion. Empty/malformed text and nonzero exits remain separate outcomes.
Debug hides the output. The SDK never evaluates, quotes, rewrites or executes
the returned instructions, and never changes the caller's environment.

The fixed macOS v2.33.2 program printed the same two zsh instruction lines for
both actions and for the tested `SHELL` environment values. It preserved the
synthetic shell customization and all protected state/identity material.
Executable paths containing spaces and Unicode remain literal in the native
text, including its original shell quoting choices. Other platforms retain
their own native results and require corresponding execution evidence.

Native helper initialization or another platform's native action can affect
its explicit owned profile. Post-dispatch errors or deadlines therefore remain
uncertain mutations without automatic retry. State aliases/reparse points are
refused before invocation. Like other stopped CLI commands, this invalidates
the previous clean-generation backup eligibility.

```no_run
# async fn example(core: &mut verysync_sidecar::ManagedInstance) -> verysync_sidecar::Result<()> {
use std::time::Duration;
use verysync_sidecar::{NativeCompletionAction, NativeCompletionOutcome};
core.shutdown(Duration::from_secs(10)).await?;
let exit = core.native_completion_instructions(
    NativeCompletionAction::Install, Duration::from_secs(10),
).await?;
if exit.outcome == NativeCompletionOutcome::InstructionText {
    let exact_native_text = exit.instruction_text();
    let _ = exact_native_text; // Present or review it under caller policy.
}
# Ok(()) }
```

## Explicit native host watch limits

`ManagedInstance::request_native_file_watch_limit(minimum, timeout)` explicitly
runs `configure-host --watch-files N` on a confirmed stopped owned instance.
This is a host-wide Linux kernel action. The SDK never elevates privileges,
starts a serving core, installs a service or persists a sysctl setting. The
fixed Linux implementation only raises an insufficient current value; zero
requests no increase, and it cannot lower the value. The minimum must fit the
local signed native integer range.

The native CLI discards its internal read/parse/write errors and can return zero
without changing the setting. The SDK independently reads at most 33 bytes from
the Linux inotify watch-limit procfs file before and after the command.
`NativeWatchLimitExit` preserves the actual code, bounded private diagnostic,
requested minimum and both `NativeWatchLimitObservation` snapshots.
`MinimumObserved` means a post-command value was at least the request;
`MinimumNotObserved` means a known value stayed below it. `Unobservable` and
`NativeFailure` remain explicit. Observation failures preserve I/O category
and OS code; missing, malformed or timed-out observations never become zero.
Other hosts have no Linux observation; their actual native exit is retained.

These are snapshots, not exclusive host administration or proof that this caller
caused a change. Other administrators can race the request, and a host restart
can reset the value. One total deadline covers observations and CLI work;
necessary contained cleanup can finish afterward. Cancellation or failure can
leave a changed host limit. No retry or rollback is implicit. State leases,
executable hashes, alias rejection and private profile protection remain in force;
clean-backup eligibility is invalidated like other stopped CLI commands.

```no_run
# async fn example(core: &mut verysync_sidecar::ManagedInstance) -> verysync_sidecar::Result<()> {
use std::time::Duration;
use verysync_sidecar::NativeWatchLimitOutcome;
core.shutdown(Duration::from_secs(10)).await?;
let receipt = core.request_native_file_watch_limit(524_288, Duration::from_secs(10)).await?;
if receipt.outcome == NativeWatchLimitOutcome::MinimumObserved {
    let observed = receipt.after;
    let _ = observed;
}
# Ok(()) }
```

## Explicit native browser dispatch

`ManagedInstance::request_native_browser(helper_state, verify, timeout)` invokes
the exact last-ready local program's `browser` command for its explicitly
configured HTTP(S) management URL. The pinned CLI first tries its Chrome-style
application mode with a profile under the helper state, then its platform opener
fallback. `BROWSER` does not override that first mode on macOS. The SDK preserves
the native choice; it does not choose or install a browser for the caller.
Unix-socket-only owners have no browser URL and are rejected.

Provide a separate persistent helper directory. It must be new/empty or already
marked specifically for this browser helper. Primary-state overlap (including
parent/child relationships and resolved aliases), ordinary application profiles
and other managed-core state are rejected. Fresh helpers generate their own
private keys and configuration; primary credentials, registrations and files are
not copied. The helper does not serve, listen, synchronize or install a service.
The directory persists for explicit inspection and reuse, including after failure.

With `verify=true`, the SDK first authenticates the owned target identity within
the total deadline and passes native `--verify`. The native HTTP probe itself
does not certify authentication or status; its HTTPS trust is separate from SDK
TLS options. With false, the last configured URL can be dispatched after the
owned core has stopped, without either probe. Neither choice proves a window
opened or that a web application is usable.

`NativeBrowserExit` preserves the actual root code, program fingerprint and
verification/release observations. `CommandSucceeded` means the exact root
exited zero and its desktop descendants' lifetime guard was released.
`NativeFailure` preserves a nonzero or abnormal native exit. Root standard
streams are discarded so a desktop child cannot retain an output capture;
preparation errors keep the existing private metadata diagnostics. Ordinary
Debug excludes the helper path. Explicit path access is available through
`helper_state_directory()`.

Only the root is awaited. A dispatched desktop request may outlive native
failure, timeout or caller cancellation; the SDK does not promise graphical
rollback. Cancellation retains worker ownership until root cleanup finishes,
and an immediate reuse can still encounter the helper-state lease. No request
retry, core stop/restart or change to ordinary owned-core cleanup is implicit.

The macOS native integration case denies every pinned Chrome executable
candidate in a temporary test-only execution policy and captures the native
fallback through an owned opener. It verifies two successful exact URL requests,
live authenticated verification, dispatch after normal shutdown with verification
disabled, independent helper identities, unchanged primary configuration/keys/data,
and an actor that continues executing after each root result. The outer wrapper
must observe every actor's actual exit before deleting its capture. A separate
owned invalid opener produces the real native code-1 `NativeFailure`, with no
successful descendant release. Cancellation is exercised while the native CLI
is actually awaiting an owned opener and an actor has received a third exact
URL. The worker's state lease must release, and the outer observer requires the
exact native root and cancellation actor to have exited before sending any
cleanup stop markers. Primary and both helper profiles retain their bytes.
These tests prove
native request/lifetime behavior through that fallback; they do not establish a
visible application window, Chrome-mode runtime behavior or other platforms.
The library installs no execution policy or desktop hook. The Linux CI fixture
masks the five fixed Chrome candidates inside a private mount namespace and
exercises the owned `xdg-open` fallback as the original runner user. Focused
AMD64 and ARM64 runs have exercised successful dispatch and native opener
failure. The cancellation case additionally requires actual native-root exit
before any outer cleanup. Because the native Linux opener can create a separate
process group, the outer observer separately records whether its exact owned
opener and actor survive that root, then explicitly stops those test fixtures.
Survival is not reported as library cleanup or graphical rollback. A run with
no cancellation journals reports unknown cancellation observations. Native
execution of the new Linux cancellation case and the complete current-source
platform gate remain pending.
Windows native browser integration remains pending; its fallback uses
`ShellExecute`, which the directory-opener fixture does not intercept.
A standalone Windows CI protocol pilot first checks whether a temporary owned
HTTP/HTTPS command can be selected and independently observed through the Shell.
It preserves `UserChoice`, refuses delegated or unverifiable handlers before
dispatch, and requires exact original registry values and effective handlers
after restoration, including a pre-dispatch interruption. This pilot invokes
only the owned capture executable; it does not execute VerySync or establish
acceptance of the browser API.

```no_run
# async fn example(core: &verysync_sidecar::ManagedInstance, helper: std::path::PathBuf) -> verysync_sidecar::Result<()> {
use std::time::Duration;
use verysync_sidecar::NativeBrowserOutcome;
let receipt = core.request_native_browser(helper, true, Duration::from_secs(30)).await?;
if receipt.outcome == NativeBrowserOutcome::CommandSucceeded {
    assert!(receipt.helper_state_released);
    // Command success does not establish a visible browser window.
}
# Ok(()) }
```

## Windows protocol research pilot

The opt-in isolated-CI pilot can query the current Windows ProgID and temporarily
shadow its per-user class command with an exact owned capture program. Protected
UserChoice values remain read-only and are checked unchanged after restoration.
Merged COM-delegated or DDE handlers are refused before dispatch. The pilot also
verifies restoration after an injected pre-dispatch failure, then exact native
HTTP/HTTPS arguments and process exit. This is test infrastructure, with actual
Windows results tracked separately from SDK browser acceptance.

A separate opt-in Windows SDK runner reuses the loopback-only proxy, exact owned
opener and restored ProgID transaction. Its native case checks verified and
unverified dispatch, exact URL/actor exit, primary/helper key separation and
caller bytes. Cancellation must first observe a new live process with the exact
owned program image after preparation completed, hold that native process handle,
and then independently observe its exit and helper lease release. Desktop
rollback is not inferred. Windows runtime acceptance remains pending these actual
SDK results; compiling the case does not establish them.
