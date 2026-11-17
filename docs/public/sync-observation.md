
## Synchronization snapshots and explicit pages

`folder_completion`, `folder_completions` and `batch_folder_status` read actual
engine snapshots. A completion value is a reported percentage for an index;
even 100 can accompany `remote_state = Some("unknown")`. It does not establish
live peer presence, a durable generation or completion of a caller's business
batch. Missing counters stay `None`, unknown labels/fields are retained, and
malformed percentages do not become zero or success.

`folder_need`, `remote_need`, `local_changes` and `folder_errors` read exactly
one explicitly selected page. `ListPage::new` requires nonzero values, requests
at most 1000 items per page and keeps the requested item offset in signed
32-bit range. These are SDK input bounds, not a claim that every engine array
is limited to that length. The existing response-byte limit also applies.
No method automatically follows another page or starts a scan/transfer.

```no_run
# async fn example(client: &verysync_sidecar::Client, folder: &verysync_sidecar::FolderId, peer: &verysync_sidecar::DeviceId) -> verysync_sidecar::Result<()> {
use verysync_sidecar::ListPage;
let first = ListPage::new(1, 100)?;
let completion = client.folder_completion(folder, peer).await?;
let needed = client.folder_need(folder, first).await?;
let remote = client.remote_need(folder, peer, first).await?;
let changes = client.local_changes(folder, first).await?;
let errors = client.folder_errors(folder, first).await?;
# let _ = (completion, needed, remote, changes, errors);
# Ok(()) }
```

Local need preserves the actual `progress`, `queued` and `rest` groups. Other
file pages preserve exact names, reported kinds, optional byte sizes and
unknown metadata. Names are untrusted engine-relative strings; the library
never joins them to a local path. File, error and statistics Debug output omits
names, error text and unmodeled metadata that can contain private paths.

Folder-specific reads check the authenticated instance and current configured
folder first. They therefore require configuration-read access as well as the
selected observation route. Missing folders do not become empty lists. A
folder error response naming another folder is `FolderIdentityMismatch`.
Null/absent error lists stay `None`, distinct from an actual empty array.
HTTP/schema/identity errors remain errors. Multiple calls, including the
configuration preflight, are separate observations rather than an atomic read.

`device_statistics` and `folder_statistics` retain actual timestamps, optional
counters and unknown fields. Epoch or year-one placeholder timestamps are not
rewritten into recent activity. `last_connection_duration_seconds` uses the
engine's reported seconds. Folder incoming/outgoing/sending integers retain
their upstream names without inventing units or throughput performance.

Native tests compare three synthetic indexed files with batch/peer counters
and two real remote-need pages, preserve an unknown remote state, and separately
observe a blocked-file scanning error followed by recovery. Another private
two-core test observes nonempty receiver need, actual received bytes and zero
need, receive-only local edits, then content/time restoration and cleared local
changes. Explicit raw fixture rate/mode settings only create this observation
window; they do not establish typed rate-limit/mode control or performance.
The tests preserve source data and observe normal exit of both owned trees.

The priority-queue fixture first transfers one of its 512 synthetic files at the
normal rate. It then applies its explicit observation throttle and creates the
other 511 files, so initial authentication and index exchange are not throttled.
The first transfer and the nonempty legacy queue must both appear within the
same 20-second preparation window. The fixture explicitly selects a five-second
reconnection interval; the library and official program defaults are unchanged.
Acceptance still requires a nonfirst target to be promoted while other work
remains queued, all 512 file contents to match after rate restoration, and both
owned process trees and state leases to exit normally.

## Native index tree

`browse_index(folder, options)` reads the distinct `/rest/db/browse` native index
snapshot. It is separate from selective-mode metadata and file-manager resource
listing. The read checks the current identity and configured folder, sends one
browse request and starts no scan or transfer. Its preflight and result are
separate observations, not a coherent transaction.

`IndexBrowseOptions::default()` requests the folder root at native level zero:
immediate entries without descendants. `levels(Some(n))` includes up to n
additional descendant levels; `levels(None)` explicitly selects the native
unbounded-depth default. Existing byte, deadline and JSON decoding bounds still
apply. The SDK never fetches another level automatically. The default omits prefix
for the root scope; `prefix(TargetPath)` selects a nonempty strictly relative
path in the target's syntax. Local callers build Path/PathBuf values with native
path operations, and remote callers explicitly select the target style. No
controller filesystem lookup, string path joining or host expansion occurs.

`directories_only(false)` omits dirsonly. This matters because the fixed handler
treats every nonempty value, including the text false, as true. True explicitly
requests the native directory filter. A missing or file prefix can produce a
valid empty tree; an unconfigured folder remains FolderNotFound rather than an
empty success.

`IndexTree` retains native order and recursive entries. Each `IndexTreeEntry`
preserves the exact untrusted name, modTime offset/precision, reported size,
known file/directory kind, unfamiliar labels, optional children and unknown
metadata. Missing/null children stay None; an explicit empty list stays Some
empty. Malformed/null root bodies are errors. Debug omits names, timestamps,
unknown values and nested contents. Returned names are never implicitly joined
to a filesystem path. Index knowledge does not establish present filesystem
access, local existence, selection, peer connectivity or completed transfers.

```no_run
# async fn indexed(client: &verysync_sidecar::Client, folder: &verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
use verysync_sidecar::{IndexBrowseOptions, TargetPath};
let prefix = std::path::Path::new("reports").join("annual");
let tree = client.browse_index(folder,
    &IndexBrowseOptions::default()
        .prefix(TargetPath::local(prefix))
        .levels(Some(1))
        .directories_only(true),
).await?;
// Explicitly inspect tree.entries; redact private metadata before logging it.
# let _ = tree;
# Ok(()) }
```

The isolated native Rust case observes flat and nested depths, an explicit
unlimited snapshot, directory-filter enable/revert, target-native relative
prefixes, empty missing/file prefixes, missing-folder rejection and unchanged
identity/configuration/synthetic bytes. With watching and automatic rescans
disabled, an unscanned synthetic file stays absent from the index snapshot.
This local effect evidence is separate from full same-source native platform
acceptance, which remains pending.

## Full native indexed-file metadata

`index_file_info(folder, path)` reads the distinct `/rest/db/file` observation.
It checks the authenticated identity and current configured folder, validates a
strictly relative TargetPath in the target's syntax, and sends one GET with the
exact once-encoded file name. It performs no controller filesystem lookup,
implicit scan, download, peer contact or retry. A missing indexed object retains
the native HTTP 404 and bounded private diagnostic; an unconfigured folder is
refused by the configuration preflight. Concurrent changes can still produce a
native error after that separate preflight.

`IndexFileInfo` retains complete native global and local metadata records and
advertised availability. Each `IndexFileMetadata` preserves untrusted names,
file/directory/unknown kinds, exact modification timestamps and short modifier
IDs, sizes, deletion/ignore/invalid flags, permission strings, local flags,
rescan state, block counts/hashes, sequences, native version-vector strings and
signature metadata. No host-path conversion, permission enforcement, vector
clock merge, timestamp rewriting or implicit follow-up operation occurs.

A native local record can have an empty name, empty version vector, zero size,
zero block/sequence/signature values and a placeholder timestamp while the
global record names a remote file. The DTO preserves that actual record; it
does not turn it into an existing zero-byte local file or fabricate absent
metadata. Global index knowledge does not prove filesystem access or completion.
Native availability null stays None, while an explicit empty list stays Some
empty. `IndexFileAvailability` preserves each full device ID and the native
fromTemporary flag without probing a source or inferring that a transfer ended.

Native encoded block-list hashes are not SDK-verified content digests.
`IndexFileSignature` preserves the native Version tag and encoded Sign value
without interpreting its format version, validating the signature or making a
trust decision. Per-platform extension payloads remain explicit opaque JSON
objects; unverified ownership, ACL and extended-attribute schemas are not
normalized or applied. Unknown fields remain inspectable. Ordinary Debug omits
private names, times, modifier IDs, permissions, vectors, hashes, signatures,
peer IDs and extension values. Explicitly redact those fields before logging.

```no_run
# async fn indexed_file(client: &verysync_sidecar::Client, folder: &verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
use verysync_sidecar::TargetPath;
let path = std::path::Path::new("reports").join("annual.bin");
let info = client.index_file_info(folder, &TargetPath::local(path)).await?;
// Inspect actual global/local records; availability is not a download receipt.
# let _ = info;
# Ok(()) }
```

Controlled native cases distinguish file/directory metadata, nested target paths,
native missing-object errors, unscanned-file absence and a separately requested
scan. A separate two-core private-loopback case observes a real advertised peer
and signed global metadata while the receiver retains the native zero local
record and has no completed file. Its explicit rate/configuration setup and
caller-controlled polling are test fixtures, not implicit behavior of this read.
They do not establish WAN behavior, completed downloads or signature trust.
Full same-source native platform acceptance remains pending.

## Native index-file diagnostic route

`Client::index_file_diagnostics(folder, &TargetPath)` reads the independent
`GET /rest/debug/file` endpoint once after current identity, configured-folder
and strict target-relative path checks. It reuses `IndexFileInfo`,
`IndexFileMetadata`, `IndexFileSignature` and `IndexFileAvailability` because the
fixed program returns the same full metadata schema as the ordinary index-file
endpoint. Unknown fields, target-native names, null availability and encoded
hash/signature fields are retained with the same private Debug policy.

The endpoints have different missing-file behavior. A native diagnostic lookup
can return HTTP success with both global and local zero records: empty names and
version vectors, size/block count zero, null hashes and an empty signature.
These records are not existing zero-byte files. The ordinary `index_file_info`
endpoint instead returns a native 404 for a missing file in the exercised
baseline. Neither route causes a scan or reads the controller's filesystem.
An unscanned newly written file can remain a zero diagnostic record until the
caller explicitly requests a separate scan. SDK errors and schema failures are
not converted into zero records.

Directory and nested Unicode target paths use the same connected-target syntax.
An advertised peer remains an availability observation, without proof of
reachability, completed bytes or whole-folder synchronization. A real private
two-core test reads the diagnostic global signature/source while the local
record is still zero and the receiver's complete file is absent. No SDK hash or
signature verification, normalization, mutation, polling or retry is introduced.
The independent support ZIP and native profiling APIs are separate operations;
this endpoint is not a support-file download.

## Native per-file download progress

`folder_download_progress(&folder)` reads `/rest/folder/downloadprogress` once
after fresh identity and configured-folder checks. This is separate from index
need, advertised sources, folder state, selective browsing and peer completion.
It returns `FolderDownloadProgress.files`, keyed by exact, untrusted native file
names. The SDK never joins these names to controller paths or starts a scan,
transfer, observer, retry or filesystem operation.

Each `FileDownloadProgress` retains the native total, reused, origin-copy,
shifted-origin-copy, other-location-copy, pulled and pulling block counters,
plus `bytes_done` and `bytes_total`. Required fields use signed native integer
values; they are not clamped, recomputed or converted into a percentage. Unknown
per-file fields remain available. Both result types omit filenames, counters
and extension values from ordinary Debug, except the wrapper's record count.

The byte values are native estimates. In a controlled 4 MiB transfer the fixed
core reported 32 blocks and a total-byte estimate different from the actual
file length. Neither those estimates nor an empty map establish filesystem
existence, transfer completion, peer health or a caller's durable task outcome.
Verify required file content or separate task criteria explicitly.

The fixed program can return HTTP 500 `no such folder` before that folder has
progress-emitter state, despite its valid configuration. Paused folders can
also return HTTP 500. These native errors remain errors; they never become an
empty successful map. The SDK does not retry. Applications choose whether and
when to request another independent snapshot. An actual successful empty map
is retained when the program reports it.

The isolated native test captures partial block and byte counters while the
receiver's complete file is absent. The test caller then explicitly releases
its throttle, independently verifies all final file bytes, observes an empty
native map and checks the paused-folder error. This is private loopback
evidence, with current-source platform acceptance and real WAN tests separate.

```no_run
# async fn example(client: &verysync_sidecar::Client, folder: &verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
let snapshot = client.folder_download_progress(folder).await?;
for (untrusted_name, native) in &snapshot.files {
    // Display explicitly as private data; do not infer a completed file here.
    let _ = (untrusted_name, native.pulled_blocks, native.pulling_blocks);
}
# Ok(()) }
```
