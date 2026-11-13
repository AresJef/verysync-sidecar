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
Selection is bounded to 1..=1024 distinct paths and 64 KiB of logical selection
text. Native comma-separated selection cannot express comma-containing names;
those are refused explicitly. A directory archive can contain such names.
Adding `algo` to a single regular file does not make that file an archive;
archive methods require the expected native archive media type.

`ResourceTransferOptions` defaults to a one-GiB payload bound and a five-minute
complete-operation deadline. The deadline includes identity checks and local
I/O; uploads also include input hashing and remote checksum verification.
Individual management reads, including checksum requests, retain the connection's
request timeout and buffered-response bound. Streamed payloads bypass the small
management-body buffer without buffering the complete file. No throughput,
process-memory or disk-durability guarantee is implied by these limits.

On a download failure or cancellation, a newly created output can remain empty
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
