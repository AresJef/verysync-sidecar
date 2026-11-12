# Contributing

Use Rust 1.85 or later and the locked dependency set. The default quality checks
are listed in the README. The CI quality workflow runs on standard hosted
Linux runners, with separate current-toolchain and MSRV jobs. These checks
establish source/build quality; they do not establish engine functionality.

Keep changes small and include tests for the observable behavior they change.
Document public interfaces in English, including error and completion semantics.
Alpha interfaces may change without compatibility adapters. The first formal
release begins compatibility commitments.

## Running engine tests

Engine test fixtures run separately from ordinary unit tests. Do not
point a fixture or manual request at an existing personal or production instance.
An engine test must require an explicit executable and checksum, create its own
private state, identity and management credential, and use an explicit private
socket or loopback address. Missing prerequisites must fail an explicitly
requested engine test, rather than produce a skipped passing acceptance result.

Set `VERYSYNC_TEST_BINARY` to the absolute path of a dedicated, verified official
v2.33.2 test executable and `VERYSYNC_TEST_BINARY_SHA256` to its executable
SHA-256. The fixture checks this digest before running anything, generates fresh
state and GUI credentials, authenticates a private management address, and
compares the generated identity before any mutation.

The fixture also writes `auto_startup: false` in its own `appconf.yaml` and
explicitly disables the tracker and tray options. Child processes use private
working and temporary directories; Windows profile/data environment paths are
scoped to that state. On macOS a child sandbox denies non-loopback IP traffic
and file writes outside the fixture. These controls apply to helpers as well as
the serving process, and never change host startup settings or a firewall.

```sh
cargo test --features engine-tests --test fixture_contract --locked -- --test-threads=1
```

The `engine-tests` feature selects tests that require this explicit environment;
it does not download or launch an engine when the crate is built or imported.
Invoking the engine tests without the variables fails. The ordinary `--lib`
quality check does not run engine tests and cannot establish their acceptance.

For explicit test preparation, `scripts/prepare-test-engine.py prepare` accepts
one of the six alpha package IDs from the fixed release manifest and a `--parent`
directory. It downloads with HTTPS validation, verifies archive size/SHA-256,
and writes only the selected executable into a newly created private directory.
Its JSON receipt contains the executable path and digest for the variables above.
`--archive` permits an existing archive with the same pinned checksum; no latest
release is selected. The helper never starts the program or installs bundled
service samples. CI uses Python 3.13 and runs its extraction safety tests before
using the helper. No official program archive, executable or raw state is
uploaded as an artifact.

The `Engine fixture` workflow runs matching official engines and native Rust
toolchains on six standard hosted runners. Its results establish fixture
infrastructure, not public control API support or complete lifecycle behavior.
The helper's explicit `check-cleanup` command inspects only the exact test binary
path and reports lingering processes; it does not kill by name.

Use synthetic files. Disable discovery, trackers, relay, NAT and external
connections unless the particular network case requires them. Await only owned
child processes when cleaning up; never kill by executable name. Keep private
keys, raw configurations and diagnostics containing credentials out of logs,
commits and artifacts. A successful request is not evidence that a transfer,
shutdown, restore or upgrade completed.

When the source directory is synchronized by another program, configure
`CARGO_TARGET_DIR` outside that directory to avoid synchronization placeholders
interfering with compiler caches. Keep that machine-specific choice local.

## Public content

The repository tracks source, tests, English user documentation, CI and sanitized
metadata. Local internal plans, archived discussions and private research are
excluded. Do not add upstream engine archives/executables, account credentials,
real device identities or business data. Download official programs directly
from the fixed upstream links only when explicitly running the relevant test
or application API; never from a Cargo build script.
