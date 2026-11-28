# File versions and restoration

Choose the version and destination before restoring. A restore can replace
the current file. VerySync orders old and current files by its own clock. The
library reads that clock again immediately before asking VerySync to restore.
If the selected archive is in the current second, the library refuses the
write. Choose a strictly older version and verify the destination and the
archive you selected after the request.

Versioning belongs to a configured synchronization folder, independently from
file-manager mounts and the global Pro history log. It archives remote changes;
it is not a backup of arbitrary controller edits or a snapshot of every local
operation. Existing data can be overwritten by a restore.

```rust,no_run
# async fn restore(client: &verysync_sidecar::Client,
# folder: &verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
use verysync_sidecar::{FileVersionRestore, FolderVersioningPolicy, TargetPath};
let update = client.set_folder_versioning(folder, FolderVersioningPolicy::Simple {
    keep: 2, cleanout_days: 0, cleanup_interval_seconds: 3600,
}).await?;
if !update.requested_fields_match {
    return Ok(()); // Inspect the actual configuration before proceeding.
}
let history = client.folder_versions(folder, None).await?;
if let Some(versions) = history.0.get("report.txt") {
    if let Some(version) = versions.first() {
        let selection = FileVersionRestore::new(
            TargetPath::local(std::path::Path::new("report.txt")),
            version.version_time.clone(),
        )?;
        let report = client.restore_file_versions(folder, &[selection]).await?;
        // Inspect report.0 for native per-path errors, then verify actual bytes.
        assert_eq!(report.error_count(), 0);
    }
}
# Ok(())
# }
```

`Disabled`, `Simple`, `Trashcan`, `Staggered` and `External` select explicit policies. Simple keeps a
positive number of versions. Trashcan keeps the last archived version. A zero
cleanout age disables age-based expiry. Positive cleanup intervals are whole
seconds. These settings describe native retention; the SDK runs no cleanup job.
The archive filesystem/location, unknown fields and inactive policy parameters
are preserved. Native PATCH merges parameter maps, so disabling a policy retains
its unused values. Check `requested_fields_match` and the actual configuration.
Disabling versioning does not delete existing archives; re-enabling can expose
them again. Access while disabled is subject to the kernel's versioner state.

`Staggered { max_age_seconds, cleanup_interval_seconds }` selects native
staggered retention. Maximum age uses seconds, not the days shown by some native
interfaces; zero disables age-based expiry. The target owns the age tiers and
cleanup schedule. Positive bounded cleanup intervals do not guarantee an exact
deletion time. The isolated native case observes a retained old archive first,
then explicit age-based removal while current source/receiver bytes stay intact.

`External { command: ExternalVersioningCommand }` is an explicit caller choice
to run a program with the target core's permissions during archival. The SDK
retains 1–8192 bytes of command text without controls; it does not parse, quote,
expand or execute it on the controller. Native `%FOLDER_PATH%` and `%FILE_PATH%`
placeholders are target arguments. Choose and verify the executable, quoting and
retention behavior for that target. `native_command()` explicitly exposes the
private text, while `Debug` redacts it. The external program owns archival and
failure behavior; configuring it is not proof it ran or created a usable backup.
The isolated test verifies an actual native invocation and exact old bytes moved
by a short-lived controlled test callback. The library installs no callback,
service or daemon. Native built-in browsing/restoration need not apply to an
external program's own storage format.
An actual exit-seven callback case produces native pull errors and preserves the
existing receiver, newer source and both earlier archives. Native synchronization
can retry independently; a configuration readback is not a callback-completion
or cancellation receipt.

`set_version_archive_location(folder, &VersionArchiveLocation)` selects either
`FolderDefault`, `BasicDirectory(TargetPath)`, or an explicit `RemoteUri(Url)`.
`VersionArchiveLocation::remote_uri(text)` parses a bounded native FTP/SFTP URI
without performing I/O. It rejects other schemes, missing hosts, fragments and
control-containing text. The selected URI supplies the native backend and is
independent of the management target's Windows/Unix path style. Basic selects the native basic
filesystem backend. Native relative paths and tilde expansion are interpreted on
the target; remote syntax must match that target. The SDK opens no controller
path and never joins target paths with host strings. Logical path text is bounded
to 32 KiB.

Remote URIs can contain credentials and native query selectors. They are sent
explicitly to the core and omitted from ordinary Debug; protect serialized
configuration and private diagnostics. Local Sync endpoint options are a
different interface and are not translated here. URI configuration does not
establish authentication, server identity or successful archival.

For this fixed version's archive SFTP backend, the native `privateKey` query
value is a **key-file path on the target machine**, not inline PEM text. Encode
it as a URI query value; the SDK neither reads the key nor copies it to the
target. This differs from the Local Sync endpoint's inline-key interface.
Native tests on all six standard macOS/Linux/Windows AMD64/ARM64 profiles reject
a different valid private key at a dedicated key-only peer, then authenticate the
selected key without password fallback and verify real archival, browsing,
restoration, restart and retained remote archives. They also use a target key
path containing Unicode, spaces and a literal percent. These results belong to
[run 44082376849](https://github.com/AresJef/verysync-sidecar/actions/runs/44082376849),
whose unrelated failures remain recorded; they do not establish a passing full
release candidate.

The fixed native parser accepts `parallelConnections` (default 1, maximum 32)
and `sftpChannels` (default 5, maximum 256). Missing, invalid or nonpositive
values use the native defaults; larger values are capped. Despite its name,
`sftpChannels` is passed to the SFTP client's per-file concurrent-request limit.
`connectTimeout` is parsed as positive integer seconds, with a native default
of 30 seconds. These details come from the selected executable's parser and
consumer; they are independent of management-request timeouts. The isolated
key-only test observes one and then two actual authenticated SSH connections
when changing `parallelConnections` from 1 to 2, and performs the data effects
with `sftpChannels=2` and `connectTimeout=6`. It does not measure a concurrency
or network-timeout bound, throughput improvement or verified server identity.

Separate password and key-file SFTP cases in the six standard profiles verify
real remote old bytes, native version browsing, restoration of a Unicode/percent
filename, unchanged source data, normal restart with the remote location retained,
resetting to the default location without deleting remote archives, and normal
owned-tree/state release. Each profile's complete file-history target passed all
11 tests in the linked run. These archive results do not establish verified
server host identity or a concurrency or network-timeout bound.

FTP URI readback succeeds. The first remote generation fails with the exact
native `simple versioner: archive: file does not exist` error on all six standard
macOS/Linux/Windows AMD64/ARM64 profiles using the dedicated pyftpdlib2.2.0
peer. Original positive-case failures retain old receiver bytes, new source bytes
and an empty remote archive. The initial Mac protocol trace confirms authentication,
existing-directory listing and deletion of an absent destination without upload.
The regression for these reproduced targets now requires accepted peer
authentication, observed USER/PASS commands, no upload command in that observation
window, the exact native error and a nonzero pull-error counter, retained files,
an empty archive, and normal owned-tree/state release. The observer is opt-in,
records command names without arguments or credentials, and preserves the original
server command handler. All six standard profiles passed this strict observed
refusal case in the linked run, independently of their positive SFTP archive cases.

The original FTP positive case reached the same first-generation error on
fifteen additional fixed-package profiles. This includes two x86 compatibility
profiles, eleven Linux user-mode QEMU profiles, and both Windows legacy ABIs
on Server 2022. All fifteen recorded accepted peer authentication, USER/PASS,
zero upload commands in the observation window, retained source and receiver
files, an empty remote archive, and normal exit and cleanup. Password and
key-file SFTP archive and restore were verified on each profile. The first
generic ARM password run archived and listed actual data before the sender
reached its original shutdown deadline. A separate run with the same deadline
verified restoration and normal shutdown. The cause of the first timeout
remains unknown.
[Additional FTP and SFTP results](https://github.com/AresJef/verysync-sidecar/actions/runs/44408051901)
· [Generic ARM shutdown and restoration](https://github.com/AresJef/verysync-sidecar/actions/runs/44409737075/job/135174354222)

The first-generation refusal check covers the six standard profiles and the
fifteen additional profiles on the measured x64 GitHub-hosted runner images
with the dedicated FTP peer. It matches both owned cores to their verified
preparation receipts, catalog archive SHA-256 and known official executable
fingerprints. The additional profiles also require the observed runner image
and target OS and architecture. Tests with missing or mismatched proof retain
the positive archival requirement. The underlying cause of the native refusal
remains unresolved. Minimum operating-system execution and other FTP servers,
authentication methods and native URI query selections have independent gates.
[Strict hosted FTP and SFTP regression](https://github.com/AresJef/verysync-sidecar/actions/runs/44413217678)

Changing location preserves policy parameters and unknown fields. The SDK does
not migrate existing archives; native retention can clean the selected location.
Earlier versions can become absent from current
browsing because they remain in the prior location. The native core can precreate
an empty default Archive directory even while using a selected location. Check
actual archive files and hashes. An external versioner chooses its own storage;
this setting does not rewrite its command. The public local case checks selected
and restored-default archival, old-location data retention and actual native age
cleanup.

Archive browsing returns one bounded native response. `None` selects the root;
an explicit relative target path selects a prefix. Prefix browsing lists
descendants, so using a file as the prefix can produce an empty listing. A
native null is an observed empty listing. Returned paths and timestamps remain
untrusted data and are never opened as controller paths. Use `TargetPath::remote`
with the target's syntax when controlling another system.

The browse response describes one directory level. A directory entry has an
empty version array, even when descendants have archived files. Read that
directory with an explicit prefix to see its children. An empty directory marker
does not prove that its whole subtree contains no historical versions.

Restoration submits a bounded map of 1–1024 unique relative files and exact
native timestamps through POST `/rest/folder/versions`. Logical selection text
is limited to 64 KiB. Timestamps should come from a fresh archive listing and
are not converted to the controller's timezone. A per-path error map can report
partial failure. An empty map acknowledges the request; it does not prove that
data changed. Confirm actual content separately. Native archive timestamps
have one-second resolution; closely spaced edits require particular care when
selecting and checking a historical version.

Fixed v2.33.2 has an observed native same-second collision: restoring over an
existing file can first archive its current content using the selected archive's
same timestamp, replace that selected archive, and restore the current content
again. The selected old bytes can be lost despite an empty error report. An
isolated controlled case reproduced this in one native second while a distinct
older archive restored correctly. This affects the native restore primitive,
including directory planning. Keep an independent copy before destructive
restoration and coordinate the target's writers and timestamp generations.
The SDK does not silently sleep, retry, patch the official program or claim to
fix this engine defect. Functional test fixtures explicitly separate archive
generations; same-second recovery remains a distinct unresolved condition.

Typed restore calls now refuse a request with `ArchiveRestorePrecondition`
unless the selected archive timestamps precede a fresh `nowTime` reported by
the target. RFC3339 offsets are compared as instants; the original native token
is sent unchanged. The controller's wall clock and timezone are not consulted.
Leap-second values and precision finer than nanoseconds are rejected rather than
normalized or truncated. Whole-second archive comparisons use floor seconds,
including native timestamps before the Unix epoch.
Same-second/future timestamps, missing or unrecognized target clocks, and
unrecognized archive timestamps produce no restoring POST. After inspecting the
target, callers can make another explicit request once the precondition holds.
There is no implicit sleep, retry or unsafe fallback.

Directory preflight reads the native one-level archive API recursively within
the explicit scope. It opens no controller files and never constructs a native
filesystem path from a returned name. It refuses inconsistent hierarchy,
unobserved or file-valued directory scopes, empty archive selections, or more
than 1024 relevant entries/records, 64 KiB of logical names/timestamps, or
30 seconds of inventory work. Every observed archived record in the scope must
be older than the target's current second; this is deliberately conservative
even when an oldest-version choice might select an earlier record. No partial
inventory is silently submitted. Use bounded exact file selections when a
directory exceeds these preflight limits.

This is a preflight observation, not an atomic transaction or a backup. External
writers and target-clock changes after the observation still need caller
coordination. The underlying official engine defect remains, including for raw
requests that bypass the typed precondition. Real isolated checks verify
same-second refusal with both the selected archive and current file hashes
preserved, followed by successful explicit restoration of an older version.

Coordinate active writers and peers before restoration. The SDK does not pause
them, rescan, retry, create a backup, or roll back partial effects. A cancelled
future does not establish that a native operation stopped. A failure after POST
can leave an unknown outcome. A later synchronization can change restored data
again.

`restore_directory_versions(folder, scope, order)` requests the native
items-based directory planner with `DirectoryVersionOrder::Newest` or `Oldest`.
Select one explicit `VersionedDirectory::Path(TargetPath)` or
`VersionedDirectory::FolderRoot`. The latter uses the observed dot-root spelling;
an arbitrary dot or parent input path remains invalid. The fixed GUI's empty-root
spelling did not reliably restore the isolated samples. The SDK does not retry
it or translate an empty acknowledgement into successful data recovery.

Directory restoration can affect multiple historical files, including nested
descendants. Coordinate other writers, inspect the per-path report and verify
actual content. Local isolated tests check nested oldest/newest restoration,
an unselected root file, a deeper descendant, and explicit root restoration
against actual bytes/SHA-256. Native Windows AMD64 and ARM64 tests also verified
all of those directory effects, including the Unicode/percent path and both
normal owned-process exits. Their complete six-case history suites passed;
the relevant runtime, fixture and case sources are unchanged. Full regression
for the final delivery candidate remains required. The SDK performs the bounded read-only preflight described above;
the native planner still selects and restores content. No controller filesystem
path is opened.

Isolated macOS ARM64 tests have checked actual remote
overwrites, retention of two versions, trashcan retention after remote deletion,
restored bytes/SHA-256, unchanged stopped-source data and owned process exits.
See the release checks for the applicable archive operations and the separate
Pro audit history cases.
The separate global history setting is Pro-gated in the fixed GUI; the free
isolated instance did not retain an attempted enable. Positive licensed history
recording, pagination and reset are pending and are not implied by file-version
restoration.

`audit_history_settings` observes global audit configuration.
`set_audit_history_settings` submits only the enabled flag and retention ceiling,
then reports actual readback. Zero retention explicitly requests unlimited native
history. An attempted enable can remain false on a free instance; a successful
HTTP response does not establish entitlement. `audit_history(page, per_page)`
reads one positive numbered page of 1–1000 requested records. Native null, empty
arrays, reported totals and errors remain distinguishable. Record contents stay
opaque until their separate licensed schema/effects have been verified. The raw
request entry point remains available for unmodeled native filters.

`reset_audit_history` deliberately treats native GET `/rest/history/reset` as a
mutation. It checks fresh identity, serializes with other writes, requires the
native error-free response, and never retries. It clears the global audit log,
independently from version archives. Follow-up totals are a separate observation;
an empty free-instance reset is not evidence of removing real recorded history.

`reset_audit_history_and_verify` checks the first page before and after the
request within one deadline. A device that reports an already empty history
needs no reset. The report preserves the original reply. If the later page
contains records, check their timestamps and scope before considering another
reset because new activity can have added them.

## Whole-folder version inventory

`folder_version_inventory(folder)` reads the distinct `/rest/folder/versions`
endpoint once. It returns the existing `FolderVersionHistory` and
`ArchivedFileVersion` types for the versioner's whole-folder map, without a
prefix parameter, SDK recursive traversal, automatic paging or restore.
`folder_versions(folder, prefix)` keeps its separate `/versions/browse`
semantics, including descendant-prefix behavior. Neither method substitutes a
file-manager resource listing or global audit records for archived versions.

The whole-folder read checks fresh identity and configured scope before one GET,
requires configuration-read permission and retains normal response/deadline
bounds. A native empty object is valid. Null or malformed root maps remain
errors on this route; prefix browsing's older native-null normalization is
unchanged. Paused/unavailable versioners and other native failures remain errors,
not empty histories. Preflight and inventory are separate observations.

Untrusted native relative names, exact version/modification timestamps, byte
sizes and unknown record fields are retained without path traversal or clock
conversion. Debug omits names, timestamps and unknown values. The read performs
no controller filesystem access, scan, restore or additional archive requests.
Large native inventories can exceed configured response bounds; the SDK does
not silently return a partial map or select an archive version automatically.

```no_run
# async fn versions(client: &verysync_sidecar::Client, folder: &verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
let inventory = client.folder_version_inventory(folder).await?;
// Explicitly inspect inventory.0 and redact private names/timestamps before logging.
# let _ = inventory;
# Ok(()) }
```

The 0.1.1-rc.2 regression exercised ordinary history and archive operations on
all six standard native profiles with fixed v2.33.2. The remote case observed
the paused-folder error, an empty active inventory and two retained archives
after three remote updates. Root and prefix reads returned the same known archive
records and left current bytes intact. The tests checked the real effects of
archive retention, explicit restore, refusal to restore an archive from the
target's current clock second and normal owned shutdown. Positive generation,
paging and deletion of licensed global audit records remain deferred.
[Native test run](https://github.com/AresJef/verysync-sidecar/actions/runs/44998190581)


Use `restore_versions_and_verify` when you have the expected length and
SHA-256 of every selected version. Supply one checksum per path and native
archive timestamp for a file selection. For a directory, supply checksums for
the complete set of files in the archive inventory under that directory.
The SDK checks the selected paths and target's clock before it sends a request.
It then reads the files through the same VerySync instance and reports each
comparison separately. If all the selected files already have the expected
bytes, it leaves them and the archive unchanged. These checks describe the
selected device. Verify any intended updates on other devices separately.


Use `change_versioning_and_verify` to edit the policy, archive location, or
both in one request. Choose an existing folder or the future-folder template.
If the selected settings already match, there is no write. Check the
independent archive inventory for an existing folder when it is available.
Changing location affects where VerySync looks for versions. Keep a separate
copy of any earlier archives you need.
