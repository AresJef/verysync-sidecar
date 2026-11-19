# Explicit file transfers

File-manager mounts and synchronization folders have separate identities. Select
an actual `ResourceVolumeId` and use `ResourcePath` with the connected target's
syntax, as described in [file resources](file-resources.md). These operations
transfer bytes through the authenticated management connection. They do not
register synchronization folders or promise delivery to other peers.

`download_resource` streams a complete file or one finite inclusive
`ResourceByteRange` to an absolute local `Path`. It uses `create_new`: an existing
file or symbolic link is refused. The caller selects the destination; upstream
Content-Disposition filenames are never used. Existing parent directories must
already exist and belong to a location the caller trusts. This is not a
filesystem sandbox against a concurrent actor changing those directories.

Local parent components and directory links retain the controller operating
system's own path semantics. The SDK does not lexically collapse a link followed
by `..` or assume that Windows and POSIX resolve that input identically. Remote
`ResourcePath` components instead retain the connected target's syntax and
reject parent traversal. Case sensitivity and Unicode filename equivalence are
properties of the actual target filesystem; the SDK does not normalize or fold
the names to infer those properties.

A dedicated native test independently probes the filesystem before checking
actual metadata/content/checksums and a download through a linked local parent.
It exercises a real path exceeding 320 UTF-16 units, literal Chinese/percent/space
names, case and Unicode-equivalent name pairs, and a remote directory link.
Native paths that cannot be represented in the management protocol must return
`PathEncoding` while preserving the complete native folder configuration. Local
download destinations use native filesystem operations without that protocol
conversion. A local macOS run has passed; complete
current-source target evidence remains independently required. This test does
not establish support beyond the target filesystem's own limits.

```rust,no_run
# async fn transfer(client: &verysync_sidecar::Client,
#     remote: &verysync_sidecar::ResourcePath,
#     output: &std::path::Path) -> verysync_sidecar::Result<()> {
use verysync_sidecar::{ResourceByteRange, ResourceTransferOptions};
let limits = ResourceTransferOptions::default();
let receipt = client.download_resource(
    remote, output, Some(ResourceByteRange::new(0, 1023)?), &limits,
).await?;
assert_eq!(receipt.bytes, 1024);
// receipt.sha256 hashes exactly the selected bytes written to this new file.
# Ok(())
# }
```

Ranges require HTTP 206 and the exact requested Content-Range. A server that
ignores the range, returns another interval, or truncates the body produces an
error. Open-ended and suffix ranges are not inferred. A JSON file containing an
`error` field remains ordinary downloaded data. Authentication/HTTP errors are
separate and retain bounded private diagnostics where available.

`download_resource_archive` asks the engine to archive a directory.
`download_selected_resources` accepts explicit relative target paths within one
base resource directory. Both stream the native archive to a new local file.
The native formats are ZIP, TAR, TAR with gzip, bzip2, XZ, LZ4 frames or Snappy
frames, selected through `ResourceArchiveFormat`. The SDK does not extract or
recompress them. Archive methods first require bounded directory metadata; very
large listings can require a larger configured management response limit. Untrusted archive member names are not local output paths.
Selection is bounded to 1..=1024 distinct paths and 64 KiB of encoded native
selection text. Paths are relative to the explicit base in the Rust API; the
SDK sends full volume-relative resource URIs to the native root endpoint. Each
URI is escaped before the whole comma-separated query value, preserving literal
commas, percent signs, Unicode and Unix control filenames. Native archive member
layout can retain volume-relative directory prefixes, including on Windows;
no fixed directory-relative layout is promised.
Adding `algo` to a single regular file does not make that file an archive;
archive methods require the expected native archive media type.

`ResourceTransferOptions` defaults to a one-GiB payload bound and a five-minute
complete-operation deadline. The deadline includes identity checks and local
I/O; uploads also include input hashing and remote checksum verification.
Individual management reads, including checksum requests, retain the connection's
request timeout and buffered-response bound. Streamed payloads bypass the small
management-body buffer without buffering the complete file. No throughput,
process-memory or disk-durability guarantee is implied by these limits.

Stopping the owned engine can interrupt a transfer independently of cancelling
its Rust future. A native fault test explicitly force-stops the exact owned tree
after a nonempty incomplete download, requires a connection/integrity error, and
checks the retained bytes against the source prefix. It then explicitly restarts
the same state, verifies identity and configuration, and downloads the complete
source into a new destination without changing the old partial file. A local
macOS run has passed; the current six-profile fault evidence remains required.

Ordinary receive failures flush accepted local writes before returning. A
deadline can interrupt this flush. On failure or cancellation, a new output can remain empty
or partial. It is retained for explicit inspection/cleanup. Tokio filesystem
I/O already submitted to its blocking pool can finish after the future is
dropped. A successful receipt gives the actual flushed byte count and SHA-256;
it does not establish that another writer left the remote file unchanged.

```rust,no_run
# async fn upload(client: &verysync_sidecar::Client,
#     remote: &verysync_sidecar::ResourcePath,
#     input: &std::path::Path) -> verysync_sidecar::Result<()> {
use verysync_sidecar::{ResourceTransferOptions, ResourceUploadConflict};
let observed = client.upload_resource(
    remote, input, ResourceUploadConflict::RejectExisting,
    &ResourceTransferOptions::default(),
).await?;
// The complete local input digest matched the remote target after upload.
# let _ = observed;
# Ok(())
# }
```

Uploads accept an absolute regular local file and reject a final symbolic link
or Windows reparse point. The input is opened once, hashed with a fixed 64-KiB
working buffer, rewound, and streamed with the observed length and byte bound.
Keep it immutable until the future completes. An open handle cannot prevent a
separate writer from changing file contents. The known native acknowledgement
must be followed by a matching remote SHA-256; an acknowledgement alone is not a
successful verified upload.

`RejectExisting` asks the kernel to refuse an existing target. `Replace`
explicitly permits destructive replacement; neither is a transaction against
other writers. A request failure, deadline or cancellation after POST may leave
the old target replaced, partial, complete or absent. In the isolated baseline
case, an in-flight new upload disappeared after request cancellation. This is
an observed kernel outcome, not SDK rollback. The same isolated test observed
an existing target disappear after cancelling an explicit in-flight replacement. The SDK never retries the write,
deletes a partially uploaded target, or restores an old target automatically.
Inspect the exact target before choosing recovery or retry. Failures after a
possible write use `MutationOutcomeUnknown`; an upload deadline before POST
remains a read/preparation timeout.

These APIs are unreleased. Native effects are verified locally on macOS ARM64;
the complete same-source multi-platform acceptance is pending. Archive decoding
libraries used by the isolated tests are development dependencies and are not
required by applications using these streaming methods.

## Real disk-full boundary

The interruption fixture performs large synthetic-file generation and independent
hash verification on Tokio's blocking pool. These checks preserve the full byte
and hash assertions while allowing the single-threaded test runtime to service
the management connection before the final normal shutdown.

The explicit CI driver `scripts/run-bounded-disk-full-tests.py` provisions a small owned filesystem only in the matching GitHub runner environment. It uses a private tmpfs on Linux, an owned disk image on macOS, and an owned VHD on Windows. Actual capacity is checked by both the driver and the Rust case before creating payloads. No physical disk is selected, and cleanup checks the exact mount or image identity. The driver is never invoked by Cargo builds or library calls.

After verified detach, the driver removes only its exact mount-directory entry,
including a dangling Windows volume mount point whose target no longer exists.
Unknown siblings still cause a cleanup failure; cleanup never recursively walks
a mounted filesystem. Native provisioning failures retain bounded diagnostics.

The `disk_full_engine` case requires a real native disk-full local I/O error while streaming a 64 MiB resource to that filesystem. It verifies the nonempty retained prefix, source bytes, configuration, identity, and volume sentinel. Only the caller explicitly removes its partial output; a new 1 MiB download must then complete and match its hash. Engine state and source data remain outside the bounded filesystem. Native results on all six standard platform profiles are pending; compilation and fixture guard tests do not establish disk-full acceptance.
