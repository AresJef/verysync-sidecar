# File-manager volumes and resource reads

The file manager uses its own `ResourceVolumeId`, independent of synchronization
folder IDs. `Client::resource_volumes` reads actual mounted volumes and preserves
their backend kind, display name and locator. A locator may be a target native
filesystem path or storage-backend address. It is never opened automatically
on the controller. Errors and unknown schemas are not converted to empty lists.

`ResourcePath` binds a logical relative path to one volume with explicit target
syntax. Use `TargetPath::local` with native `Path`/`PathBuf` operations for a
matching local engine, or `TargetPath::remote` for a remote target. Windows
separators are interpreted using Windows rules even on a Unix controller.
Windows device names, drive/stream syntax and invalid filename characters are
refused; Unix backslashes and non-NUL control filenames are retained. Dot,
parent, rooted and empty components are refused without lexical normalization.
URL components are encoded once, retaining literal percent signs and Unicode.

```rust,no_run
# async fn inspect(client: &verysync_sidecar::Client,
#     volume: verysync_sidecar::ResourceVolumeId) -> verysync_sidecar::Result<()> {
use verysync_sidecar::{PathStyle, ResourceChecksum, ResourcePath, TargetPath};
let relative = TargetPath::remote(PathStyle::Unix, "reports/二 空格 %.txt")?;
let path = ResourcePath::relative(volume, &relative)?;
let metadata = client.resource_info(&path).await?;
let sha = client.resource_checksum(&path, ResourceChecksum::Sha256).await?;
assert_eq!(sha.len(), 64);
# let _ = metadata;
# Ok(())
# }
```

Select a volume from the actual list and verify it belongs to the caller's
intended target. Native syntax must match the connected target. These input
guards do not establish a filesystem jail: server mounts, permissions, symbolic
links and external writers remain target-side concerns. Do not use returned
names or locators as trusted local output paths.

`resource_info` returns native size/mode snapshots, the original timestamp
string, directory entries, optional inline text and retained unknown metadata.
Missing/null `items` is distinct from an actual empty directory. File responses
can include text, so the management response-byte limit also applies to content.
An oversized or malformed response is an error. Reads never write controller
files, follow a redirect or silently retry a state-changing action.

`resource_checksum` requests MD5, SHA-1, SHA-256 or SHA-512 from the engine and
requires the selected digest's actual hexadecimal length. MD5/SHA-1 remain
compatibility checksums. Digest snapshots do not authenticate an external
writer or establish that synchronization/transfer completed. Missing digests
retain the bounded private response diagnostic and are not empty successes.
Metadata/path Debug output omits names, content and private mount information.

`resource_thumbnail` reads the native `inline=true` preview and returns its
actual image Content-Type and complete bounded bytes in `ResourcePreview`.
Empty responses and responses not advertised as image content are errors.
The SDK does not decode or resize images itself. The engine may populate its
own preview cache. Size/encoding and source-format availability are native
conditions; no fixed output dimensions are promised.

```rust,no_run
# async fn preview(client: &verysync_sidecar::Client,
#     volume: verysync_sidecar::ResourceVolumeId) -> verysync_sidecar::Result<()> {
use verysync_sidecar::{PathStyle, ResourcePath, TargetPath};
let input = TargetPath::remote(PathStyle::Unix, "images/sample.png")?;
let path = ResourcePath::relative(volume, &input)?;
let preview = client.resource_thumbnail(&path).await?;
assert!(preview.media_type().starts_with("image/"));
let bytes = preview.body_bytes(); // Private image content; do not log blindly.
# let _ = bytes;
# Ok(())
# }
```

The native scenarios use only synthetic files under the isolated engine's own
profile mount. They verify root/directory/empty listings, actual text and byte
sizes, Unicode/literal-percent filenames, four independent expected checksums,
missing-file errors, retained data and normal owned exit. Unix additionally
checks an actual newline filename. Preview scenarios use distinct 512×256 PNG
inputs, returned raster dimensions/content and complete retained source bytes.
Remote storage mounts, other preview source formats,
streamed file transfer, mutations and version/history effects have separate
implementation and acceptance requirements; this read surface does not certify
those operations.
