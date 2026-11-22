# API compatibility from the first stable release

Use the published 0.1.0 Rust API as the compatibility baseline. In application
code, match the public error variants and status fields you need. Descriptions
that appear in logs or dialogs can change to explain the same result more
clearly. Keep documented machine output and explicit protocol values stable.

For example, applications can continue to match errors from `GuiSession::login()`.
When the application needs to know whether sign-in stopped before or after a
possible session, use `GuiSession::login_with_outcome()` and inspect the typed
phase and cause. Earlier alpha releases preceded the stable API contract.

The fixed checker preparation uses
[`cargo-semver-checks v0.51.0`](https://github.com/obi1kenobi/cargo-semver-checks/releases/tag/v0.51.0)
and Rust 1.99.1, separately from the SDK's Rust 1.85 minimum. Installation is an
explicit CI step with an official fixed archive size and SHA-256; Cargo does not
download or execute this tool while building or consuming the SDK.

`scripts/check-api-compatibility-tool.py` verifies the checker against independent
toy crates. Identical APIs must pass. Removing a public function must produce
exit 100 and the specific `function_missing` diagnostic. A removed optional API
is invisible in the default feature set but must fail with all features enabled.
Any unexpected exit, including an infrastructure/build error, fails the self-test.
The fixtures have no dependencies and their checks run with Cargo offline.

The first stable public API baseline is the accepted and published
`verysync-sidecar` **0.1.0**. Use the crate's exact registry version and
checksum together with the commit at the GitHub tag `v0.1.0`. The release
record binds the source, package and verified feature and platform scope.

For subsequent compatible releases, compare the complete public API with the
accepted stable source using `--baseline-rev` with that commit or
`--baseline-version 0.1.0` with the published package. Check default features,
`--only-explicit-features` with none, and `--all-features`. Retain
target-specific checks for supported public APIs.
The checker must run against the actual release candidate and immutable baseline.
Version and migration review must handle intentional incompatible changes before
publishing them. Do not suppress a failed check or change its baseline just to
obtain a green result. A changed checker/compiler needs a new controlled self-test.

Semver checks complement API review, compile tests for callers and actual native
behavior tests. They do not prove authentication, data retention, process cleanup,
licensed capabilities, WAN behavior or resource use. Passing the tool self-test
does not pass the SDK's formal compatibility or complete release gate.
