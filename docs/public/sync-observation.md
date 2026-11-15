
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
