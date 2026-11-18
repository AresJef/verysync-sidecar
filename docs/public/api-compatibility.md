# API compatibility from the first stable release

Every public alpha interface remains unstable: types, names, parameters, results,
errors, events and module structure may change. No compatibility layer or old
alpha API branch is required. Current behavior, isolation and data protection
still require tests. The tooling below does not make an alpha API stable.

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

This is preparation only. The SDK's formal API baseline is **not yet selected**.
Choose it after all required functional prerequisites and the first stable
candidate are accepted. Pin the first stable version, immutable source tag/commit,
package identity and feature/platform matrix together; never use an alpha or a
moving branch as the formal compatibility baseline.

For subsequent compatible releases, compare the complete public API with the
accepted stable source using `--baseline-rev` or an explicitly selected published
stable version. Check default features, `--only-explicit-features` with none,
and `--all-features`; retain target-specific checks for supported public APIs.
The checker must run against the actual release candidate and immutable baseline.
Version and migration review must handle intentional incompatible changes before
publishing them. Do not suppress a failed check or change its baseline just to
obtain a green result. A changed checker/compiler needs a new controlled self-test.

Semver checks complement API review, compile tests for callers and actual native
behavior tests. They do not prove authentication, data retention, process cleanup,
licensed capabilities, WAN behavior or resource use. Passing the tool self-test
does not pass the SDK's formal compatibility or complete release gate.
