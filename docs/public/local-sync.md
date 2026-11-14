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

`control_local_sync_operation()` requires the reviewed job and operation IDs and
an explicit pause, resume or stop choice. Client clones serialize the identity
preflight, known acknowledgement and fresh status readback. Another management
writer can still race them. The receipt contains actual observed status; it does
not promise that current I/O stopped, earlier writes were undone or a target state
will persist. Observe the exact run, `cancelled` and actual destination effects.
Native progress counters are optional observations and may include cancelled
work; they are separate from durable destination-byte proof.

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
