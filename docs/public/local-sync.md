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

`local_sync_health()` returns actual target-reported availability. That flag is
separate from protocol, platform and entitlement acceptance.
`local_sync_configuration()`, `local_sync_jobs()` and `local_sync_job()` retain
native fields and unknown settings. `create_local_sync_job()` selects both
endpoints and a direction, then reads back the actual registration. Defaults
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
controller filesystem fallback.

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
run. This API currently exposes all-action execution; selected-action execution
remains a separate pending capability.

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
a request future does not prove native work stopped. No implicit retry, polling,
rollback, target restart or archive migration occurs.

## Verification scope

Local macOS effects have been observed through these public methods with
independent synthetic paths, identities and credentials: actual endpoint probing,
browsing and nested Unicode/percent directory creation; preview without writes;
explicit execution and exact bytes; source and destination-only retention;
result/history readback; scoped configuration preservation; registration deletion
while retaining data; and normal owned-tree shutdown. Final same-source native
acceptance on the other modern profiles remains pending.

Reverse mirror, bidirectional conflicts, selected execution, inflight controls,
Local Sync events, watch/schedules, marker/baseline recovery and each of
FTP/SFTP/SMB/WebDAV require separate native effects and verification. Their GUI
presence, enum values, stored configuration or a basic endpoint success are not
support claims. Licensed conditions, old architectures and final cross-network
acceptance retain their independent project gates.
