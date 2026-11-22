
## Selective index browsing and conditional selection requests

Browse the index to see which files VerySync knows about. Request a selection
explicitly when you want those files. If a selection is cancelled, check the
destination for already received files. Verify the selected files after they
appear on disk.

`browse_selective` reads one actual tree for an exact configured folder. Choose
`SelectiveScope::FolderRoot` or an explicit target-relative file/directory path.
`SelectiveBrowseOptions` defaults to one level and bounds depth to 1..=32.
Directory filtering is sent only when enabled: the fixed engine treats the
presence of `dirsonly`, including the string `false`, as a directory-only request.
The library performs no recursive follow-up or native filesystem traversal.

`SelectiveTree` preserves exact map keys and `SelectiveEntry` preserves the
engine's names, optional timestamps/sizes, selected and existence flags, children
and unknown metadata. Missing required booleans are invalid responses rather
than fabricated false values. Returned names and paths are untrusted index
data; the SDK never joins them to a native path or uses them for file operations.
Debug omits keys, names, cursor values and unknown metadata.

`search_selective` reads one explicit `SelectiveSearchPage`, distinct from the
tree format. `SelectiveSearchOptions` defaults to 100 requested results, allows
1..=1000, bounds search text/cursor size and preserves exact values. The caller
can send the returned opaque cursor in `after_cursor`; no host path conversion
or automatic paging occurs. The engine can report `has_more=true` on a full
last page; retain that observation and request the next page explicitly instead
of inventing the number of remaining matches. HTTP, schema, missing-folder and
changed-identity errors do not become empty trees/pages.

```no_run
# async fn example(client: &verysync_sidecar::Client, folder: &verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
use verysync_sidecar::{SelectiveBrowseOptions, SelectiveScope, SelectiveSearchOptions};
let tree = client.browse_selective(folder,
    &SelectiveBrowseOptions::new(SelectiveScope::FolderRoot).levels(2)).await?;
let page = client.search_selective(folder,
    &SelectiveSearchOptions::new("sample")?.limit(20)).await?;
# let _ = (tree, page);
# Ok(()) }
```

`folder_selective_configuration` and `set_folder_selective_enabled` expose only
the mode flag and its actual readback. Enabling selective mode can leave files
unselected; it neither grants a Pro entitlement nor requests file selection.
Disabling it restores ordinary folder synchronization policy. Native tests
explicitly restart the owned core after restoring that mode, then verify all
three complete source/destination samples. Readback alone does not establish
hot application, downloaded content or peer completion.

`request_selection` sends an explicit `SelectiveAction::Select`, `Deselect` or
`RemoveFromAll`. The latter is a distinct potentially destructive intent that
sends `selected=false&removefromall=true`. It can affect other nodes; never
infer retained files from an acknowledgement. Mutations recheck identity and
configured scope, share the Client clone lock and are never retried.

**Licensed success is not yet verified.** The fixed free engine actually
returns HTTP 200 with `code: 3000` and a Pro-license error for all tested file,
directory and root requests. Typed APIs report `Error::LicenseRequired`, retain
the original bounded response and do not call it successful selection. The raw
request API still returns the exact raw status/body for explicit interpretation.
Other known error envelopes remain API errors; a possible modifying outcome
stays unknown rather than being automatically retried.

The licensed success-body schema, root selection semantics, actual selected
downloads, deselection retention/removal and all-node removal still require a
dedicated licensed environment. `SelectiveAcknowledgement` therefore retains
only an opaque successful HTTP response and certifies none of those effects.
No native positive-selection or deletion support is claimed from the refusal
tests. Current native evidence covers real tree/search/cursor data, all five
typed licence refusals, unchanged selection/data after refusal, and explicit
restoration of free ordinary synchronization with exact bytes and normal exits.

The macOS native fixture records bounded process identities before normal
shutdown and checks their birth times when diagnosing a timeout. It reports
root/worker state separately from log exit markers. The observer sends no
signals, retries no shutdown request and leaves the original ten-second failure
intact. A missing or changed identity remains an observation gap, rather than
proof that the owned tree exited.

After restoring and verifying ordinary synchronization, the fixture explicitly
pauses both private peers and waits up to twenty seconds for both connection
snapshots to report no active connection. A pause acknowledgement alone does
not establish disconnection. Each subsequent normal process exit still has its
original ten-second bound. Private three-node research reproduced a fixed-engine
shutdown stall with an active connection: its close callback was waiting for an
internal SQLite write lock while model shutdown waited for that callback.
Explicit pause followed by observed disconnection avoided that stall in the
controlled comparison. A separate bounded observation retained the original
ten-second failure and subsequently observed an unforced, zero-code tree exit
at 10.011 seconds. A blocked callback at the deadline therefore does not establish
a permanent deadlock. These observations do not prove that every historical
exit timeout has the same cause, or establish successful shutdown under every
active workload.
The library's shutdown API never pauses devices implicitly; a timeout retains
ownership and requires explicit reconciliation or cleanup by the caller.
