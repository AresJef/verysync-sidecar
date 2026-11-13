# Explicit official program preparation

Enable the optional `download` Cargo feature to prepare a fixed official program.
Selecting a source, adding the crate or compiling it never downloads or executes
the vendor program. `DownloadOptions::prepare` is the explicit runtime action;
it requires a Tokio runtime with I/O and timers.

```rust,no_run
# #[cfg(feature = "download")]
# async fn prepare(destination: std::path::PathBuf) -> verysync_sidecar::Result<()> {
use verysync_sidecar::{BuildVariant, DownloadOptions, OfficialProgram, PinnedVersion,
    ProgramArchitecture, ProgramOs, ProgramTarget};

let asset = OfficialProgram::select(&PinnedVersion::new("v2.33.2")?,
    ProgramTarget::new(ProgramOs::Linux, ProgramArchitecture::Amd64,
        BuildVariant::Standard))?;
let prepared = DownloadOptions::new(asset, destination)?.prepare().await?;
let local_program = prepared.program().clone();
// Pass local_program to ManagedOptions for a separate explicit owned start.
# let _ = local_program;
# Ok(())
# }
```

The destination must be a new absolute native directory under an existing,
caller-controlled parent. Existing files, directories and symlinks are refused
without an HTTP request. Use a trusted parent whose ancestors cannot be replaced
by another actor. The newly created directory is private to the current user
(and SYSTEM on Windows). Preparation never installs services or runs a binary.

The transfer uses no ambient HTTP proxy or management credentials. The default
deadline is five minutes for the complete operation; `timeout` sets a finite,
nonzero caller deadline. Redirects are bounded and must retain the source scheme,
host and port. `source_url` explicitly selects a mirror without changing the fixed
official archive length or SHA-256; it accepts HTTPS or literal loopback HTTP,
without userinfo, query or fragment. Non-200 status, truncation, excess data or
checksum mismatch never enables an executable. The library does not retry writes
or downloads automatically.

After the entire archive matches the fixed catalog, only the exact archive-root
executable is copied. Service/firewall helpers and all other paths are never
materialized. Unsafe paths, duplicates, symbolic/hard links and special entries
are rejected. Limits bound member count, expanded input and executable size;
ZIP CRC/length and gzip integrity checks remain enabled. The executable's basic
format, CPU, bitness and endianness must match the selected target. This static
check does not establish libc/float ABI, minimum OS or actual runtime version.
Managed startup separately verifies the pinned inner digest and actual baseline
version before authenticating the private instance.

Partial files have private permissions. A short-lived native file owner handles
streaming and extraction, so dropping the future or shutting down its Tokio
runtime requests cleanup independently of that runtime. Cleanup is cooperative
between bounded I/O operations. Unix cleanup checks directory identity; Windows
retains a directory handle that prevents replacement. A deliberately moved or
substituted directory is retained for explicit repair instead of cleaning an
unrelated path. Cleanup removes only known partial files and its empty owned
directory; it does not recursively delete caller data.

The final executable is committed through a same-directory hard link without
replacing an existing file, with mode 0700 on Unix and inherited private ACLs on
Windows. Filesystems without this operation return an error. Cancellation racing
the final commit can leave a complete verified executable at the known
destination; inspect and reconcile before retrying. A later preparation always
refuses an existing destination. Cache reuse, offline resolution and upgrade
orchestration have separate APIs and acceptance gates.

`PreparedProgram::executable_sha256` reports the actual inner executable digest;
`asset().archive_sha256()` identifies the complete downloaded archive. The vendor
program is not bundled in this crate, and its license and redistribution
conditions remain distinct from the library's MIT OR Apache-2.0 license.
