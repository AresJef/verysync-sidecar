# Explicit resource mutations

These methods change real filesystem data through the engine's file manager.
They do not detach a synchronization folder or move content to a trash/history
area. Select the intended mount and target syntax with `ResourcePath`. Every
mutation refuses a volume root. Paths and returned metadata are not a filesystem
jail against symbolic links, mount aliases or other writers.

`create_resource_directory` uses native POST with a real trailing URL separator,
refuses an already observed resource, and requires actual directory readback.
The native operation creates missing parent directories. PUT is a different,
destructive file-content editing operation; it is not directory creation.

```rust,no_run
# async fn manage(client: &verysync_sidecar::Client,
#     base: &verysync_sidecar::ResourcePath) -> verysync_sidecar::Result<()> {
use verysync_sidecar::{ResourceConflictPolicy, ResourceDeleteScope};
let directory = base.clone().child("reports")?;
client.create_resource_directory(&directory).await?;
let original = base.clone().child("original.txt")?;
let copy = directory.clone().child("copy.txt")?;
let observed = client.copy_resource(
    &original, &copy, ResourceConflictPolicy::RejectExisting,
).await?;
client.write_resource_text(&observed.destination, "updated UTF-8 text\n").await?;
client.delete_resource(&observed.destination, ResourceDeleteScope::File).await?;
# Ok(())
# }
```

`copy_resource` and `move_resource` accept an explicit collision policy:

- `RejectExisting` refuses an observed existing destination before PATCH.
- `OverwriteAndMerge` overwrites colliding files and merges directory trees.
  Destination-only children remain. It does not replace an entire directory.
- `KeepBoth` preserves an existing requested target and lets the kernel generate
  a name. The SDK compares bounded parent listings and requires one unambiguous
  new entry. Missing/ambiguous listings are unknown outcomes, not guessed names.

A `ResourceMutation` returns the actual observed destination, its metadata and
whether its name changed. The source must remain observed for a copy and must
be observed absent for a move. Size/kind readback does not recursively verify
all copied content, lock a source snapshot, or promise a filesystem transaction.
Keep sources stable during a copy when their precise content matters.

The fixed kernel interprets mutation destination components within the source
mount and can ignore a different destination volume ID. The SDK refuses distinct
volume IDs before sending any request, preventing misrouted writes. Choose both
paths within one explicitly intended logical mount. Cross-filesystem and remote
backend behavior are separate verification conditions; no fallback mapping,
controller-side copy or implicit alternate operation occurs.

`write_resource_text` explicitly overwrites an existing file with up to 16 MiB
of UTF-8 text, including an empty string. It refuses a missing resource or a
directory, then checks the actual size and native SHA-256. For streamed file
inputs and explicit new uploads, use [file transfers](file-transfers.md).

`delete_resource` requires `ResourceDeleteScope::File` or
`ResourceDeleteScope::RecursiveDirectory`, checks the observed resource kind,
and requires absence after the known acknowledgement. Recursive deletion is
explicit data removal. No local or remote backup is created automatically.

Mutations authenticate the current target and serialize changes through clones
of the same connection. Preflights do not coordinate with external writers.
Errors after a possible write use `MutationOutcomeUnknown`; reconcile the exact
source/destination before retrying. No mutation is retried or rolled back.
Dropping/cancelling a future does not promise that the native handler stopped.
The isolated baseline copy continued after cancellation and finished a 64-MiB
merge. Partial or complete effects, including overwritten original data, must be
inspected explicitly. HTTP acknowledgement, fresh metadata and complete file
content evidence are separate observations.

These APIs are unreleased. Local isolated effects have been verified on macOS
ARM64; complete same-source multi-platform acceptance is pending. The native
cross-volume routing restriction is preserved as a refusal, never represented
as a successful cross-volume capability.
