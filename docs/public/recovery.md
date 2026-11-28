
## Explicit folder recovery

Identify which copy of the files you intend to keep. Reverting local changes
can replace tracked files on the receiving device. Overriding remote changes
can replace tracked files on connected devices with the sending folder's
version. Review both sides and save any files you need before making either
request. Check the affected files after a reply or interruption.

`request_revert_local_changes` and `request_override_remote_changes` send one
potentially destructive recovery request for an exact configured, unpaused
folder. They require the actual `receiveonly` or `sendonly` mode respectively.
The fixed engine constrains modes using its sharing permissions: the tested
RO key forces receive-only behavior, while a raw request to turn an RW-key
folder into receive-only reads back as `sendreceive`. A configuration request
does not establish that a mode changed. Query actual configuration before choosing an operation.

Reversion can replace a receiving folder's tracked local edits with the shared
version. Override can replace other peers' versions with the send-only folder's
current authoritative version. An empty successful response acknowledges the
request; it does not mean scanning, remote transfer or data recovery completed.
Observe actual `local_changes`, need/status and the relevant complete files.
The fixed RO-key engine leaves an unindexed local addition intact while
reverting the tracked edit. This API does not promise a filesystem reset.

```no_run
# async fn example(client: &verysync_sidecar::Client, folder: &verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
// Choose this only for an actual receive-only folder whose edits should revert.
client.request_revert_local_changes(folder).await?;
let changes = client.local_changes(folder,
    verysync_sidecar::ListPage::new(1, 100)?).await?;
# let _ = changes;
# Ok(()) }
```

`request_marker_repair` asks the engine to repair the selected folder's marker.
`MarkerRepairResult` preserves the actual success/error fields and unknown
metadata. The typed method rejects a false success flag or a nonempty error,
even when HTTP succeeds. Debug omits error text and unknown metadata because
they can contain private paths. Acknowledgement remains separate from a real
marker directory, restored scanning, intact data and retained sharing identity.
The caller must establish that the intended storage is present before requesting
marker repair. The SDK itself does not create, remove or inspect local paths,
replace keys, reset configuration or restart the engine automatically.

`repair_folder_marker_and_verify` takes the expected configured folder path.
It resolves the path through an unambiguous native local mount and reads the
marker directory through VerySync. A matching directory already in place
requires no request. After a repair, review the observed marker and folder
activity separately. When the target storage cannot be verified, the function
leaves the folder untouched. To confirm a resumed scan, observe its activity and
check the relevant files.

All three mutations perform a fresh identity and exact-folder preflight, share
the Client clone mutation lock, and have no automatic write retries. External
writers remain the caller's responsibility. An unexpected nonempty recovery
acknowledgement or malformed marker response after a possible write is
`MutationOutcomeUnknown`; read actual state before deciding what to do next.
These requests have no invented task ID, atomic rollback or peer-completion
guarantee. They operate on an explicitly selected running instance and do not
provide the file-history restoration API, which has a separate scope.

Native recovery evidence is collected with synthetic files, separate engine
identities and explicit private TCP peers. In particular, the fixed RO-key
engine can restore a locally deleted tracked file before an explicit revert;
that automatic effect must not be attributed to this method. Marker tests retain
the original marker as a backup and verify the same folder/key identity, intact
sample bytes and successful scanning after an explicit caller restart.
