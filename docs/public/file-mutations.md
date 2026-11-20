# Explicit resource mutations

These methods operate through the authenticated official core's file
manager. A `ResourcePath` selects one mounted volume and target-syntax components;
it is independent of a synchronization folder ID. The SDK does not implement a
local filesystem fallback. Volume-root mutations and source/self/descendant
targets are rejected. Distinct volume IDs are refused before copy/move because
the fixed native route did not reliably honor a different destination volume.

`create_resource_directory()` requests native parent/directory creation and reads
back a directory. `copy_resource()` and `move_resource()` take an explicit
`ResourceConflictPolicy`: reject an existing destination, overwrite colliding
files and merge directories while preserving destination-only children, or keep
both and require one unambiguous newly generated name. Native merge is not
whole-tree replacement. `ResourceMutation` returns observed destination metadata;
it does not attest every recursive byte or make the operation atomic.

`write_resource_text()` explicitly replaces an existing file with bounded UTF-8
text, including an empty value, and verifies native size/SHA-256 readback. It
rejects missing files and directories. `delete_resource()` requires an explicit
file or recursive-directory scope and verifies absence after a known native
acknowledgement. It removes filesystem data; it does not detach a synchronization
registration, use a recycle bin or create a backup.

Preflights and readback are observations. Coordinate other filesystem/management
writers. Client clones serialize mutations; failures after sending a write can
return `MutationOutcomeUnknown`. The action can have partially or fully applied.
The SDK does not retry, roll back, stop a peer or force a garbage collection.
Cancelling a request does not stop native copying. A controlled 64-MiB, 128-file
case observes cancellation after partial overwrite, reconciles actual retained
bytes and preserves all source files and destination-only data.

## Observed fixed-version Windows limitation

On both tested modern Windows architectures, v2.33.2 has returned HTTP 500 after
moving directory contents or recursively deleting children while retaining the
old directory itself. The SDK propagates an unknown mutation outcome. Existing
data may already have changed; do not interpret the error as an unchanged tree.
Explicit native heap collection did not establish a remedy. No such collection,
restart, direct filesystem compensation or silent success is added by the SDK.

The fixed-version release check for Windows AMD64 and ARM64 accepts this
precise outcome for directory move-and-merge and recursive directory deletion.
It requires the original HTTP 500 through `MutationOutcomeUnknown`, the
observed residual directory and partial effects, file protection and normal
cleanup. A move check verifies the transferred bytes and destination-only
files. A deletion check verifies which synthetic children disappear.
Complete native directory removal in those cases awaits separate positive
verification. File operations, directory creation and copying, and other
platforms retain their own positive checks.

Default diagnostics omit private resource values and response bodies. Callers
can explicitly inspect bounded error diagnostics, then reconcile actual target
data before deciding the next action.
