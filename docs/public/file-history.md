# File versions and restoration

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

`Disabled`, `Simple` and `Trashcan` select explicit policies. Simple keeps a
positive number of versions. Trashcan keeps the last archived version. A zero
cleanout age disables age-based expiry. Positive cleanup intervals are whole
seconds. These settings describe native retention; the SDK runs no cleanup job.
The archive filesystem/location, unknown fields and inactive policy parameters
are preserved. Native PATCH merges parameter maps, so disabling a policy retains
its unused values. Check `requested_fields_match` and the actual configuration.
Disabling versioning does not delete existing archives; re-enabling can expose
them again. Access while disabled is subject to the kernel's versioner state.

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
against actual bytes/SHA-256. Same-source multi-platform acceptance remains
pending. The SDK performs the bounded read-only preflight described above;
the native planner still selects and restores content. No controller filesystem
path is opened.

These APIs are unreleased. Isolated macOS ARM64 tests have checked actual remote
overwrites, retention of two versions, trashcan retention after remote deletion,
restored bytes/SHA-256, unchanged stopped-source data and owned process exits.
Complete acceptance on the same candidate across six native targets is pending.
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
