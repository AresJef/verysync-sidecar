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

Engine test fixtures are developed separately from ordinary unit tests. Do not
point a fixture or manual request at an existing personal or production instance.
An engine test must require an explicit executable and checksum, create its own
private state, identity and management credential, and use an explicit private
socket or loopback address. Missing prerequisites must fail an explicitly
requested engine test, rather than produce a skipped passing acceptance result.

Use synthetic files. Disable discovery, trackers, relay, NAT and external
connections unless the particular network case requires them. Await only owned
child processes when cleaning up; never kill by executable name. Keep private
keys, raw configurations and diagnostics containing credentials out of logs,
commits and artifacts. A successful request is not evidence that a transfer,
shutdown, restore or upgrade completed.

## Public content

The repository tracks source, tests, English user documentation, CI and sanitized
metadata. Local internal plans, archived discussions and private research are
excluded. Do not add upstream engine archives/executables, account credentials,
real device identities or business data. Download official programs directly
from the fixed upstream links only when explicitly running the relevant test
or application API; never from a Cargo build script.
