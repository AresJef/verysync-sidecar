# Fixed program cache and offline resolution

With the optional `download` feature, `ProgramCache` resolves one explicitly
selected official asset. Construction performs no I/O. Its new absolute root
must have an existing trusted parent. An explicitly selected empty private root
can also be initialized; a nonempty existing root must carry the library's
private cache marker. A nonempty unmarked caller directory is refused without
adoption or cleanup of its contents. Concurrent initializers create the same
marker atomically rather than relying on a guessed startup delay.

```rust,no_run
# #[cfg(feature = "download")]
# async fn resolve(root: std::path::PathBuf) -> verysync_sidecar::Result<()> {
use verysync_sidecar::{BuildVariant, CachePolicy, ProgramCache, OfficialProgram,
    PinnedVersion, ProgramArchitecture, ProgramOs, ProgramTarget};

let asset = OfficialProgram::select(&PinnedVersion::new("v2.33.2")?,
    ProgramTarget::new(ProgramOs::Linux, ProgramArchitecture::Amd64,
        BuildVariant::Standard))?;
let cache = ProgramCache::new(root)?;
let ready = cache.resolve(asset.clone(), CachePolicy::DownloadMissing).await?;
let program = ready.program().clone();
// A separate explicit ManagedInstance::start can use this pinned LocalProgram.
let offline = cache.resolve(asset, CachePolicy::Offline).await?;
assert_eq!(offline.program().path(), program.path());
# Ok(())
# }
```

`Offline` never downloads or initializes a missing cache. A valid hit is read
again and checked against its exact version, target, archive identity, recorded
inner byte length and SHA-256, native privacy and executable permissions.
`CacheMiss` distinguishes an unavailable complete entry; `CacheCorrupt` reports
an invalid index or changed executable. It never treats a partial download as a
usable program, switches to another target or chooses a newer version.

`DownloadMissing` explicitly permits fetching only the selected fixed asset
when absent or corrupt. The fixed preparation API performs full archive checks
and safe extraction. An optional `source_url` mirror follows the same URL rules
and keeps the official archive checksum and size. A finite caller `timeout`
(five minutes by default) covers native lock waiting, validation, transfer and
index commit together. Ordinary network and lock waits are part of that deadline.

Preparation uses a native cross-process lock per archive identity. Concurrent
callers recheck the index after acquiring the lock, so the next caller verifies
the first complete generation instead of downloading it again. Cancelled
preparation retains its lease until the independent native file owner cleans its
exact partial generation. Index updates happen only after a complete private
program exists and use a same-directory atomic file replacement.

Every successful replacement gets a new immutable generation path. The cache
never overwrites, deletes or repairs an old executable in place. An already
running instance retains the same bytes and path, including persistent instances
whose original controller has exited. There is no automatic eviction or pruning;
old generations consume disk space until the caller explicitly removes them
after establishing that they are unused. Cache resolution does not infer that
a program has stopped merely because a controller's lock or process disappeared.

Cancellation can race a completed index commit. In that case the complete entry
remains available for a later offline resolve. A deliberately moved/substituted
directory is retained for explicit repair. These checks cover process/future
interruption and incomplete files; they are not a claim of power-loss durability
on every filesystem. Managed startup independently rehashes the selected local
program and verifies the actual fixed runtime version and instance identity.

The cache never runs an engine, installs a service, changes global logging or
signals, or touches a caller-provided local executable. Local paths remain
independently available through `LocalProgram`. The `cache_program` example
demonstrates an explicit fixed-target cache request:

```sh
cargo run --features download --example cache_program -- \
  linux-amd64-standard /absolute/private/new-cache
```

The example prints the selected target, actual download/hit outcome and a native
debug representation of the program path. It does not start the program.
