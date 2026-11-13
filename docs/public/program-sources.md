# Fixed program sources

`EngineSource` separates an explicitly supplied `LocalProgram` from a selected
`OfficialProgram`. Both are values: constructing them does not inspect a file,
download an archive, start an engine or require a Tokio runtime. Managed startup
continues to accept a caller-selected local program. Downloading and preparing
an official selection is a separate explicitly requested operation.

```rust
use verysync_sidecar::{BuildVariant, EngineSource, OfficialProgram, PinnedVersion,
    ProgramArchitecture, ProgramOs, ProgramTarget, Result};

fn choose() -> Result<EngineSource> {
    let version = PinnedVersion::new("v2.33.2")?;
    let target = ProgramTarget::new(ProgramOs::Windows,
        ProgramArchitecture::Amd64, BuildVariant::Legacy);
    Ok(EngineSource::from(OfficialProgram::select(&version, target)?))
}
```

The initial fixed catalog is v2.33.2. It contains 21 in-scope macOS, Windows and
Linux artifacts from the recorded official index and SHA-256 list. Two FreeBSD
reference entries remain outside this project's supported OS scope. An unknown
version or OS/architecture/build combination is an error; there is no `latest`
selector, standard/legacy fallback or architecture guess from the controller.

Each descriptor retains the fixed official HTTPS URL, expected complete archive
SHA-256, published byte length, archive encoding and executable basename. The
archive digest is different from an executable digest: do not pass it to
`LocalProgram::expected_sha256`. The latter pins the actual inner program before
execution. URLs describe a verified snapshot and do not guarantee future online
availability. The official programs are obtained from the vendor, not included
in this crate; their redistribution permission remains a separate question.

The official program's architecture label, its runtime ABI, a candidate Rust
controller triple and the minimum OS are distinct facts. ARM, ARMHF and ARMv6,
MIPS endianness and standard/legacy builds have separate identities. `ProgramAbi`
retains the mapping/ABI/minimum OS evidence notes. Candidate triples are not a
promise of successful controller compilation or engine execution. Native
acceptance on a named modern runner does not establish its exact minimum OS,
libc or every legacy environment. Unknown conditions remain explicit.

The embedded artifact record is
[`releases/verysync-v2.33.2.json`](../../releases/verysync-v2.33.2.json), including
the retrieval time and checksum-list identity. The public platform table records
separate build/runtime conditions. Neither model tests nor the earlier test-only
download helper count as acceptance of the Rust download/cache/upgrade APIs.
