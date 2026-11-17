# Native Local Sync and storage endpoints

The unreleased Local Sync API controls the official core's storage jobs. These
registrations are distinct from P2P synchronization folders and file-manager
volumes. Every method uses the selected authenticated connection. The SDK does
not implement a copy engine, open target files on the controller or install a
background helper. Dependency resolution and compilation run no storage job.

`StorageEndpoint::local(TargetPath)` selects a basic filesystem path on the
target. Use native `Path`/`PathBuf` operations before `TargetPath::local()` for a
locally described path, or `TargetPath::remote(style, value)` for an explicitly
specified target system. The client checks the supplied syntax against the
connected core. It does not infer that the controller and target share files,
expand home directories or reinterpret a remote path with host filesystem APIs.
Endpoint URIs and native extra settings can contain private credentials; default
`Debug` omits them. Explicit getters and serialization expose private values.

`StorageEndpoint::remote(protocol, uri)` explicitly selects FTP, SFTP, SMB or
HTTP(S) WebDAV. The URI must match the selected protocol, identify a host and
contain no userinfo, query or fragment. Supply credentials with
`.credentials(user, password)`; they remain private native fields and are never
added to the URI. The SDK connects only to the management target: the official
core establishes the storage connection. Explicitly serializing an endpoint can
expose its secrets.

`connection_timeout_seconds()` configures the target's native connection limit;
it does not extend the management request deadline. The fixed core's SFTP
backend can retry failed SSH authentication internally through its native pacer.
A management timeout does not prove a completed credential refusal; choose an
explicit bounded management deadline when that final native result is required.
The protocol fixture uses thirty seconds for this SFTP observation and ten for
the other peers, recording the selected limit separately from actual duration.
The SDK adds no retry. SFTP private-key paths use
`private_key_file(TargetPath)` and the target's path syntax; the controller opens
no key file. `insecure_tls(true)` explicitly disables native peer verification
for SFTP/WebDAV and should be limited to deliberately trusted test endpoints.
`smb_domain()` and `smb_guest()` select the native SMB authentication settings;
positive domain/guest effects retain separate acceptance requirements.

`local_sync_health()` returns actual target-reported availability. That flag is
separate from protocol, platform and entitlement acceptance.
`local_sync_configuration()`, `local_sync_jobs()` and `local_sync_job()` retain
native fields and unknown settings. `CreateLocalSyncJob::new(label, side_a, side_b, mode)` requires an explicit nonempty
name before a request can be sent. `create_local_sync_job()` selects both endpoints
and a direction, then reads back the actual registration. An ungrouped job
retains `group: None`; native omission is preserved by scoped full-object
updates. An explicitly empty patch group clears it. Defaults
enable neither startup execution, watch, schedules nor mirror removal of
destination-only data. `delete_extraneous(true)` is a separately explicit
destructive mirror choice, with no SDK backup or rollback. Bidirectional mode
refuses that mirror-only flag.

`update_local_sync_job()` freshly reads a full native object, changes only the
selected label/group/enabled fields and preserves unselected credentials and
unknown settings. Readback reports whether those fields match. Client clones
serialize changes; other management writers must be coordinated separately.
`delete_local_sync_job()` verifies the registration is absent after its known
acknowledgement. It does not mean target data were removed, an active run rolled
back or all native work stopped.

`probe_storage_endpoint()` exposes the core's actual permission/time/move/replace
capability flags. A probe can create and remove a temporary target object, so it
is treated as a mutation. Those flags alone do not verify every data operation.
`browse_storage_endpoint()` and `create_storage_directory()` use logical,
slash-separated relative components. Empty browse/parent paths select the
endpoint root. Dot/parent, absolute, empty intermediate and backslash components
are refused; directory names must be one nonempty component. Creating a directory
requires independent native listing readback. None of these operations provide a
controller filesystem fallback. `StorageEntry::size` is signed: FTP directories
can report `-1` for unknown size. This value is preserved, separate from actual
transferred byte counters.

## Analysis, execution and observation

Start analysis explicitly with `start_local_sync_preview()`. Its operation ID
acknowledges analysis; it is not a preview ID or a completed-data receipt.
`local_sync_status()` exposes the actual state and optional operation identity.
Compare the identity with that start receipt, inspect native errors and apply
your own bounded observation deadline. Unknown states remain exact strings.
An absent native operation identity is `None`, not successful completion.

Read `local_sync_preview()` after the exact analysis finishes. It contains its
own preview ID, producing operation ID, action count, native expiry text and scan
issue count. `local_sync_preview_actions()` pages the exact preview's actions;
numeric action ID zero is valid. Reading or starting analysis does not execute
those actions.

`run_local_sync_preview_all()` explicitly requests every action in one exact
preview. It refuses a changed preview ID or unresolved scan issues before POST.
The target still decides expiry, active-operation and conflict conditions;
preflights cannot lock external writers. Inspect the job's direction, deletion
and permission settings and the preview's actual actions before requesting a
run. `run_local_sync_preview()` accepts an explicit `LocalSyncSelection` of inclusive
native action-ID ranges. `including()` and `all_except()` accept at most 10000
ascending, disjoint ranges; action zero is valid. Ranges are never silently
sorted, merged, expanded or clipped. Fresh preview count/identity checks reject
out-of-range or empty execution before native POST. Native dependency and expiry
rules still apply. `local_sync_selection_summary()` reads exact predicted action
counts and copy bytes without execution; predicted bytes are separate from
actual run results. An empty include selection can be summarized as zero.

Two-way jobs accept `LocalSyncConflictPolicy::{Newer, Larger, Manual}`. A manual
conflict can be resolved with `resolve_local_sync_conflict()` and an explicit
winning `LocalSyncConflictSide` at one path or subtree. The returned replacement
preview is independently read back; resolving it does not execute its actions.
Choosing a missing side can plan deletion. Review the replacement actions and
explicitly execute that exact new preview. No old data backup or rollback is
provided by the SDK.

The initial `LocalSyncRun` is a receipt. Observe `local_sync_run()` and compare
its exact run ID before interpreting finish time, counters and result pages.
The native zero finish timestamp means unfinished. Even a finished run can have
failed or skipped actions. `local_sync_run_results()` returns per-action details
for the exact run. `local_sync_history()` returns native action history with
explicit page limits; it is separate from file-version archives. Verify actual
target bytes and source retention when those effects matter.

HTTP success is not native business success: the SDK rejects known error
envelopes, malformed success schemas and wrong job identities. A failure after a
possible write returns an unknown mutation outcome rather than retrying. Dropping
a request future does not prove native work stopped. No automatic mutation retry, rollback, target restart or archive migration occurs.

## In-flight control and Local Sync events

A native `paused` state does not cancel an already opened file transfer. In one
macOS ARM native run, an existing temporary payload committed more than one
second after the pause readback. The SDK reports actual state and makes no
immediate filesystem-quiescence promise. The dedicated per-protocol tests retain their initial one-second settling period, then
waits up to five additional seconds for an already-open native temporary payload
to commit. It then
asserts one unchanged 500ms full-directory hash window while paused; it does not
ignore temporary files, retry a failed stability window or change the workload.

Separate FTP, SFTP, SMB and WebDAV native cases have each observed actual
in-flight progress, paused file stability, resumed progress, cancellation of the
exact run, stopped file stability, source/sentinel retention and native events.
Each uses sixteen 256 KiB files and an explicit 40 ms delay at the private peer's
real data-write boundary. This delay creates observable work; it is not an SDK
throttle or a throughput measurement. Local macOS observations do not complete
the final same-source platform gate or protocol-specific disconnect recovery.


`control_local_sync_operation()` requires the reviewed job and operation IDs and
an explicit pause, resume or stop choice. Client clones serialize the identity
preflight, known acknowledgement and fresh status readback. Another management
writer can still race them. The receipt contains actual observed status; it does
not promise that current I/O stopped, earlier writes were undone or a target state
will persist. Observe the exact run, `cancelled` and actual destination effects.
Native progress counters are optional observations and may include cancelled
work; they are separate from durable destination-byte proof.

A complete `LocalSyncRun` can have a nonempty `error` together with its actual
finish time, failure counts and cancellation flag. This describes native
execution, rather than an API-error envelope or successful work. The SDK retains
that private text and still rejects malformed records, native API errors and
mismatched job identities. Ordinary Debug omits the text.

Run-result pages use native current-run storage. After another run replaces it,
the old exact run ID can return HTTP 409. Read and retain needed results before
starting the next run; the SDK does not synthesize historical results, substitute
another run or retry a stale identity. A newly created job's configuration
readback is also not a durable-storage acknowledgement; verify persisted state
when interruption recovery depends on it.

### Disconnected peers and explicit owned recovery

A broken peer can leave native work running or `canceling` beyond a bounded
observation. A stop acknowledgement does not prove I/O ended. Isolated SFTP and
SMB runs remained in that state after a twenty-second stop observation. The
internal wait's cause is not established. The SDK does not extend deadlines,
retry work, roll back files or force an existing instance automatically.

For a library-owned core, callers can separately choose `force_stop()`, await
confirmed exact-tree exit, then explicitly restart retained state. This can
interrupt writes; it is not normal shutdown or proof of the old run's completion.
Reconcile actual partial files/status, explicitly update a changed endpoint,
review a fresh preview, then choose a separate run. An ordinary Client does not
acquire process ownership over an existing instance.

An endpoint can also disappear after a run has completed and the job is idle.
Failed probes or browsing do not roll back that run or remove its files. The
controlled backend case preserves the saved run and exact destination snapshot
across completed native refusals, then explicitly updates the endpoint and
reviews a new preview before copying additional bytes. This is separate from
interrupting active work. Native retries can outlast the default request timeout;
choose a request bound explicitly when observing their final response. A deadline
still leaves an uncertain outcome and never counts as a completed refusal.

Private recovery cases distinguish FTP's failed run and saved action errors from
deliberately chosen owned termination for the other protocols. A peer failure can
finish before a separate stop request arrives, so the optional native `cancelled`
flag is preserved as observed; an acknowledged stop never fabricates cancellation.
The last operation ID can remain in status after its failed run has finished.
For the fixed native FTP case, a later Stop then returns HTTP 404 with
`job not found`, although the registered job still exists. The SDK retains its
mutation-uncertainty error and performs no retry or automatic recovery. A caller
must separately reconcile the exact existing job, operation, finished failed run
and actual partial files before deciding to update an endpoint, review a new
preview and start a different run. A generic 404, timeout or unrelated error is
not a successful Stop or evidence that recovery is safe. The controlled terminal
case checks this specific refusal and all data effects separately from successful
in-flight pause/resume/stop controls.
Each still requires unchanged source/sentinel, retained partial files, a fresh
preview without copying, separate execution and sixteen exact completed payloads.
An interrupted old run is never relabelled successful. Local effects and the
complete final-source platform gate remain separate.

`local_sync_events(after, wait_seconds)` returns the native Local Sync event log,
which uses `sequence`, `cursor`, `reset` and `missed`. These positions are distinct
from P2P event IDs. Events identify a job and sequence, not an exact run or
operation; correlate a run-finished event with fresh status and the reviewed
run/result identity before treating that operation as completed. Global configuration events can report an empty job ID, kept
as `None`; action zero is retained even when the native event uses it as a
non-action placeholder. Unknown event categories and private payloads remain
available without being printed by `Debug`.

`subscribe_local_sync_events()` creates a bounded, pull-driven subscription.
No network read starts until `next()` is polled, and no background task or global
handler is installed. Without a resume cursor it requests the retained history
from zero. The default batch bound is 1024 events, selectable up to 4096; native
response-byte limits also apply. Oversized or malformed batches fail instead of
being silently truncated. Event/gap buffering is bounded by twice the selected
event limit plus two error notifications.

The cursor advances only when an event or gap is consumed. Resumption always
warns that continuity is unverified; an upstream start-time string is not a
durable generation token. Changed before/after generations discard the batch.
Reported resets, missing events and interior sequence holes produce explicit
gaps. Refresh affected state after a gap. A transport/protocol error produces a
gap and terminal error, with no automatic retry. Explicitly create a new
subscription to resume. An independent cancellation handle aborts a pending read
without sending a job or engine command. Native waits range from zero to 55
seconds; the caller's management deadline remains independently enforced.

## Verification scope

Local macOS effects have been observed through these public methods with
independent synthetic paths, identities and credentials: actual endpoint probing,
browsing and nested Unicode/percent directory creation; preview without writes;
explicit execution and exact bytes; source and destination-only retention;
result/history readback; scoped configuration preservation; registration deletion
while retaining data; and normal owned-tree shutdown. Final same-source native
acceptance on the other modern profiles remains pending.

Separate local native FTP/SFTP/SMB/WebDAV cases have also observed incorrect
password refusal, actual remote probe/browse/mkdir, explicit preview execution,
exact remote payload/source retention and registration removal preserving data.
These are bounded modern macOS observations, with independent loopback peers,
not full protocol/platform acceptance. The SMB test peer corrects two known
Impacket 0.13.1 wire details: it retains session identity in LOGOFF responses and
returns a named-object absence error for a missing CREATE/OPEN name. On Windows its
share-file handles also grant native delete sharing, so server-side rename can
commit an open request FileId. A real fd read/write/rename check runs before peer
readiness; the global Python `os` module and SDK behavior are unchanged. Real
credential validation, logout and filesystem effects remain in the peer; no
native error is converted into success.

Selected/excluded actions, reverse mirror and two-way newer/larger/manual
conflicts have separate local native cases. Their final same-source platform
gates remain pending. In-flight controls and Local Sync events have separate local native data,
cancellation, reset and actual restart observations; final platform acceptance
remains pending. Licensed watch/schedule execution, marker/baseline recovery and each of
FTP/SFTP/SMB/WebDAV require separate native effects and verification. Their GUI
presence, enum values, stored configuration or a basic endpoint success are not
support claims. Licensed conditions, old architectures and final cross-network
acceptance retain their independent project gates.

## Test peer environments

Protocol tests require an explicitly prepared private Python environment and
`VERYSYNC_STORAGE_TEST_PYTHON`. The test-only preparation script installs fixed
versions into a fresh virtual environment; neither Cargo builds nor library
calls invoke it. Servers bind ephemeral loopback ports, use random synthetic
credentials and independent directories, and remain owned by their exact test
child until cleanup. They create no system account, service or SSH configuration.

CI records the Rust test architecture, the core's reported architecture and the
peer interpreter platform separately. On Windows ARM64 only the protocol peer
uses a dedicated x64 Python because a fixed cryptographic dependency has no
ARM64 wheel. The Rust executable and VerySync core retain their separate native
ARM64 requirements. An emulated peer is never reported as native SDK execution.

## Native automatic triggers

Automatic startup, watching, and schedules default off. Explicitly enabling them
can cause unattended file changes, including immediately when a job is enabled.
`CreateLocalSyncJob::enabled(false)` allows registration before execution is enabled.
`sync_on_startup(true)` requests a full native analysis and synchronization when
an enabled job starts or resumes at core startup. The SDK installs no timer,
watcher, service, or background executor.

`watch_changes(true, check_minutes)` selects native local change watching and
periodic full checks. The bounded minute interval is 0 through 525600; zero
disables only periodic checks. `LocalSyncSchedule::interval(seconds)` requires a
positive interval. `LocalSyncSchedule::calendar(rules, timezone)` takes 1 through
64 rules. `LocalSyncCalendarRule::new` requires nonempty unique ISO weekday
numbers (Monday 1 through Sunday 7) and unique canonical `HH:MM` times. An empty
timezone selects the target's local timezone; named timezone validation happens
on the core. No controller timezone conversion is performed. Turning a schedule
off does not also turn off watching/startup or cancel existing work.

These options are also available through `LocalSyncJobPatch`. A scoped update
retains endpoint credentials and unselected native settings and reports
`requested_fields_match` against the independent readback. Native normalization
can make that flag false. If creation normalizes a requested option, creation
returns `MutationOutcomeUnknown`; reconcile the actual job list before taking
further action. The registration may exist, and automatic retries can duplicate it.

On fresh unlicensed v2.33.2 instances, watch, interval and calendar requests are
normalized to false/off. That observation does not establish licensed automatic
execution. Licensed positive watch/schedule acceptance remains pending. Native
startup synchronization has separately copied real synthetic data on enablement
and after a core restart through the public Rust API. Optional observed schedule
fields retain missing values as unknown; unknown native modes are preserved.

## Explicit marker and baseline recovery

`rebuild_local_sync_markers(&reviewed_job)` and
`recover_local_sync_baseline(&reviewed_job)` take a complete job snapshot obtained
from `local_sync_job`. Verify the endpoint paths, mounts and ownership before
choosing either operation. The client compares a fresh full configuration with
the reviewed snapshot and refuses stale settings. Scanning, running, paused,
canceling and unknown states are refused; known idle/error states are eligible.
The clone mutation lock does not exclude external writers or make these checks
an atomic transaction.

Marker rebuilding deliberately recreates native safety markers. Its receipt is
a known empty acknowledgement plus separately observed status, not proof of a
remote filesystem effect. The SDK creates no endpoint directories itself and
performs no copy fallback or automatic synchronization.

Baseline recovery deliberately discards incompatible two-way comparison state
and returns a readback-verified native recovery preview. This can change how
future deletions and conflicts are interpreted. It is not file backup restoration.
Review the replacement preview and select a separate explicit run. Recovery can
remove the old baseline before execution; it does not provide rollback. A
successful explicit run can establish the new baseline. An incompatible setting
change such as `LocalSyncJobPatch::ignore_permissions` requires this separate
recovery choice; the SDK does not recover implicitly.

The public native test creates a real missing marker and a comparison-rule
mismatch, observes both native guards, rebuilds the actual marker directory,
retains original files and test backups, reviews recovery without file execution,
then explicitly runs and verifies the new baseline and clean analysis after a
core restart. Local success and the complete six-profile source gate are separate.
Missing baseline files alone do not necessarily produce a native failure; the
comparison mismatch is the tested recovery trigger. Per-backend recovery and
fault conditions remain independently required.

## Explicit anonymous FTP

An FTP endpoint can explicitly select `.credentials("anonymous", "contact@example.invalid")`.
The server must already allow that identity; the SDK does not configure server
accounts or permissions. The test peer registers only an anonymous identity,
refuses an ordinary named user and records the actual accepted anonymous login
without printing credentials.

All six standard macOS/Linux/Windows AMD64/ARM64 v2.33.2 cases verified native
probe/browse, two distinct
explicit preview/run cycles across a same-identity restart, exact 131072-byte and
65536-byte payloads, retained source and target-only data, unregister without
deletion, and normal owned core/state/peer cleanup in
[run 44118836327](https://github.com/AresJef/verysync-sidecar/actions/runs/44118836327).
The Mac ARM job's original cancellation had no runner or executed steps; its
single scheduling retry supplied that profile's actual native result. Other
profiles retain their original results. Independent password-authentication
cases also verify actual incorrect-credential refusal and real native data
effects. These are authentication subcases; the complete release candidate and
remaining backend, fault and authorization gates are separate. This is plain FTP
authentication and data evidence;
it does not establish FTPS or a verified server identity.

## SFTP key validation boundary

`private_key_pem(pem)` explicitly supplies private-key text for the fixed native
Local Sync backend. The SDK encodes it for that consumer and opens no key file on
the controller. Explicit serialization exposes this credential; ordinary Debug
omits it. Supply a username and an empty password to select key authentication
without password fallback. Empty-password omission in native readback is accepted
only for an SFTP endpoint with an explicitly supplied nonempty private key;
changed keys, nonempty passwords and explicit nulls remain mismatches.

```rust,no_run
use verysync_sidecar::{StorageEndpoint, StorageProtocol};
# fn example(pem: String) -> verysync_sidecar::Result<()> {
let endpoint = StorageEndpoint::remote(StorageProtocol::Sftp, "sftp://127.0.0.1:12345/")?
    .credentials("explicit-user", "")?
    .private_key_pem(pem)?;
# let _ = endpoint;
# Ok(())
# }
```

A fixed v2.33.2 public-API case observed actual wrong-key rejection,
key-authenticated browsing, exact preview/run identities, complete transferred
bytes, source/destination-only retention, unregister-without-deletion and normal
owned-tree exit on all six standard macOS, Windows and Linux AMD64/ARM64 profiles
in [native run 44082376849](https://github.com/AresJef/verysync-sidecar/actions/runs/44082376849).
The producer was `329e6680abd7dc5424e263ad2f41642112700642`, tree
`5ab134ee957f7208391c2d99e8930c317049e5ac`. These selected cases passed inside a
full run with other failures; they do not establish a complete final-source pass.
Earlier escaped-key creation attempts were unknown outcomes because the SDK
misclassified native omission of the empty password; those failed records remain
historical evidence and are not rewritten as successful earlier tests.

On those same six profiles, the native limits probe rejects this valid backend encoding with HTTP500
and its `SSH private key: ssh: no key found` error. The SDK preserves that actual
failure; it does not invent capability flags, substitute a password probe or
claim that a successful listing validates the limits interface. Static inspection
shows that the backend applies Go string unquoting before key parsing, whereas
the limits probe parses the same field directly. No encoding accepted by both
consumers has been verified. This limitation is separate from actual key-based
backend operations and verified host identity.

`private_key_file(TargetPath)` retains the bundled GUI's native path-field
selection. It opens no controller key file. The fixed macOS ARM64 Local Sync
backend rejected a valid synthetic RSA key-file path before authentication; this
path selection has no positive key-file acceptance. Inline private-key support
adds neither implicit key-file upload nor SSH-agent/password fallback. Other
platforms and later native versions require their own evidence.

## Per-protocol directional and selection evidence

The dedicated advanced native cases separately exercise FTP, SFTP, SMB and
WebDAV: actual remote-to-local mirror copying, two-way initial changes in both
directions, simultaneous newer/larger/manual conflicts, manual replacement
preview without immediate file changes, and a separately explicit selected-only
run with native predicted counts/bytes. The unselected target file remains
absent and its source bytes remain intact. Registration removal retains files.
These effects remain separate from licensed scheduling, in-flight control and
additional authentication/identity modes. Separate source-bound native recovery
cases on all six standard profiles verified each protocol after an actual peer
disconnection: partial files and source/sentinel bytes remained intact, an
explicit new endpoint/preview/run completed all sixteen payloads, stale result
identities were refused, and owned teardown completed normally. Some backends
required an explicitly chosen owned force-stop/restart; this is not a normal
Stop acknowledgement or proof that the old native operation was cancelled.
The [recorded run](https://github.com/AresJef/verysync-sidecar/actions/runs/43999174938)
retains unrelated whole-fixture failures. Final current-candidate six-profile
acceptance is still required.

The Impacket 0.13.1 synthetic SMB peer also needs a correctly structured EOF
error response for actual remote reads. Its stock READ handler returns a READ
body with `STATUS_END_OF_FILE`; the test peer preserves that status and supplies
an SMB2 ERROR body as required by [MS-SMB2 section 2.2.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d4da8b67-c180-47e3-ba7a-d24214ac4aaa).
This is a peer-fixture protocol correction, not an SDK read fallback, successful
empty read or retry policy.

## Complete scoped configuration

Endpoint `parallel_transfers` accepts 1 through 32. SFTP `sftp_channels` accepts
1 through 256; `sftp_compression` requests the native compression preference.
These settings are distinct from observed concurrency or negotiated wire
compression. On the fixed macOS ARM baseline, enabling compression was saved but
native analysis returned an unsupported-operation error before file effects.
The test explicitly observes that refusal, then selects compression off before
separately verifying data effects. It does not report compression as supported.

Creation and `LocalSyncJobPatch` expose bounded native `ignore_lines` and
`parallel_file_operations` (1 through 32). Rules are preserved as supplied, with
at most 1024 lines, 4096 UTF-8 bytes per line and 64 KiB total including separators.
Embedded NUL/newlines and include-file directives are refused; the SDK opens no
ignore file. Empty rules explicitly clear the list. The native readback represents
that known empty list as JSON null, which is preserved in the returned job;
`requested_fields_match` recognizes this verified clear operation. It does not
treat an unknown missing list as empty.

`side_a` and `side_b` replace only the selected endpoint. Their path syntax is
checked against the core before a modifying request; credentials/options of an
unselected endpoint remain intact. Native extra defaults do not make an otherwise
matching selected endpoint fail readback. Disabled SFTP compression is natively
omitted; only that verified false default is treated as equivalent, without
normalizing unknown missing credentials or other response fields.

A patch can select `mode`, `delete_extraneous` and `conflict_policy`. The client
checks the combined fresh configuration before PUT: mirror deletion is refused
for two-way/unknown modes, and selected conflict preferences require two-way mode.
Changing endpoints or comparison rules can require separately explicit marker or
baseline recovery. No file migration, metadata repair, retry, backup or rollback
happens implicitly. Explicit mirror deletion can remove destination-only files;
review both endpoint ownership and the native preview before execution.

The public synthetic native case verifies endpoint/direction changes, actual
ignore and clear behavior, explicit deletion, old endpoint and source retention,
and a subsequent reverse copy into a new endpoint. Full source/platform acceptance
and protocol-specific remaining conditions are independent of this local case.

SFTP `insecure_tls(false)` preserves the native option; it is not evidence that
the target consults a particular trust store. An isolated v2.33.2 macOS ARM core
accepted a probe despite a conflicting synthetic host key in its private-profile
`known_hosts`. That attempted profile trust mechanism is unverified. The test
failed before positive identity/copy acceptance, and no system or controller SSH
configuration was changed. Do not infer verified host identity from a successful
probe or this flag alone. Static inspection of the same fixed core confirms that
its SFTP limits probe installs an unconditional accept host-key callback. The
Local Sync backend does not supply a `known_hosts_file` setting to its SFTP
constructor. These observations do not establish a supported way to configure
verified SSH host identity through this API. Verified identity remains pending;
the SDK adds no trust-policy bypass, SSH tunnel or controller trust-store edits. A
separate actual native test selected `RCLONE_SFTP_KNOWN_HOSTS_FILE` only in fresh
test-process environments and supplied explicit wrong and matching synthetic
public keys. Both new core generations accepted browsing and limits probes with
`insecureTls: false`. This environment candidate therefore does not establish
verified host identity in the inspected build, even though upstream rclone
supports a known-hosts configuration. No system SSH files or trust stores changed.

The portable native server-policy case also checks actual data effects in two
fresh core generations. It writes conflicting and matching synthetic public
keys to both owned trust candidates, records probe and browse outcomes, and
copies an entire Unicode-named payload whenever browsing succeeds. The matching
policy must allow the real copy. Each completed copy must preserve the source,
destination-only sentinel and files after registration removal, and both cores
must exit normally. On the inspected macOS ARM build, both policies allowed
the probe, browse and copy. This confirms the native identity limitation for
that build; it does not verify the server's identity. Other native profiles
must pass their own observations before extending this conclusion to them.

The native job serializer can omit `insecureTls` when it is false. For SFTP and
WebDAV, creation and endpoint-update verification recognize that known false
default while preserving the omitted field in returned snapshots. An explicit
true, null, malformed value or unrelated missing option still fails matching.
This reconciliation neither enables a verification bypass nor establishes SSH
server identity. The native strict HTTPS case separately requires a trusted
chain and hostname, rejection of a wrong hostname and credentials, actual
payloads across restart, and normal owned cleanup. These effects passed on the
six standard macOS, Windows and Linux AMD64/ARM64 native profiles described below.


## HTTPS WebDAV certificate boundary

A separate private HTTPS case has observed the fixed core reject an untrusted
self-signed server certificate with verification selected. Explicitly selecting
`insecure_tls(true)` then allowed the probe and exact file copy; wrong credentials
still produced an actual native refusal. Source data, target-only data and copied
bytes remained intact, and owned teardown completed normally.

This deliberately insecure synthetic endpoint does not establish positive
trusted-CA/server-identity acceptance. A separate strict HTTPS native case now
uses the existing fingerprint-pinned public-CA loopback development fixture,
with explicit private preparation and cleanup. It requires a correct hostname,
rejects the same certificate through the loopback IP, retains credential
validation, and verifies exact data before and after restart without TLS bypass.
The dedicated case passed on all six standard macOS, Windows and Linux
AMD64/ARM64 native profiles against v2.33.2 in
[native run 44095566343](https://github.com/AresJef/verysync-sidecar/actions/runs/44095566343).
The producer was `2097a64dc636c77ff215ee1e46f76574fbe9f258` (tree
`10b859956ebe164c8af3fe9456c145c134854ae8`). Each profile verified the same
fingerprint-pinned certificate, correct chain and hostname, native rejection of
an incorrect hostname and credentials, and exact 262144-byte and 131072-byte
payloads across restart. Registration removal retained the files and sentinel;
owned processes, state locks and private peer files were released normally.

Six separate cases also verified strict-flag creation, true-to-false updates,
native false-default omission and same-identity restart for SFTP and WebDAV.
WebDAV continued to reject an untrusted certificate after restart. These flag
observations do not establish SFTP server identity.

The SDK installs no CA, changes no system trust store and makes no universal
trust-configuration promise for the target kernel. These observations apply to
the pinned test endpoint and the selected modern hosted runners. Other platform,
minimum-system and full final-source acceptance retain their separate gates;
configuration flags alone are not certificate verification proof.


## SMB domain and guest boundary

The independent Impacket 0.13.1 test peer coordinates directory enumeration with
CREATE, SET_INFO and CLOSE metadata requests. Its stock enumeration can otherwise
stat a temporary filename after another request removes it, raise an unhandled
`FileNotFoundError` and close the connection. Payload READ/WRITE handlers retain
their actual concurrency and test-only delays. Native data hashes, zero failed
actions, operation identities and process-exit requirements are checked in full.

The dedicated native cases observe the selected domain in the actual NTLM
exchange at a private standalone peer. A different domain is rejected; a wrong
password with the correct domain is also rejected by the peer's real NTLMv2
verification. The correct combination probes and copies exact file contents.

A separately selected credential-free guest endpoint produces an actual guest
session flag and copies real bytes. The peer refuses a non-guest authentication
attempt under that explicit policy. Source and target-only files remain intact
and owned processes exit normally. The observations contain only policy match,
username-presence, status and session flags, never NTLM hashes or passwords.
These cases establish the selected native parameters and standalone protocol
behavior. They do not claim Active Directory, Kerberos or arbitrary server guest
permissions. The domain and guest arms passed on all six standard macOS, Windows
and Linux AMD64/ARM64 profiles in
[native run 44082376849](https://github.com/AresJef/verysync-sidecar/actions/runs/44082376849),
producer `329e6680abd7dc5424e263ad2f41642112700642`, tree
`5ab134ee957f7208391c2d99e8930c317049e5ac`. Other cases in that full run failed;
these selected authentication effects retain their original producer and do not
establish full final-source or minimum-system acceptance.
