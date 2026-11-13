
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
