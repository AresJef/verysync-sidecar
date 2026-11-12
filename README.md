# verysync-sidecar

A general-purpose Rust library for managing and controlling the official VerySync program. The goal is complete coverage of its actual programmable capabilities, with explicit version, platform, license, and verification conditions.

The project is under active development. The Rust engineering foundation is in place; management features are being implemented and tested. No crate has been published yet, and no functional or platform support is claimed by this initial source snapshot.

The development plan runs through full delivery. Alpha releases are intermediate milestones: after publishing an alpha, development continues in the same project until the complete agreed functionality, platforms, documentation, and examples pass acceptance and the full release is delivered.

## Development decisions

- Tokio-based asynchronous APIs, separate management connections and managed-instance ownership, observable long-running tasks, and an event stream.
- One crate with internal modules and optional features for capabilities such as downloading the official program.
- Local development on macOS; cross-platform builds and runtime acceptance through GitHub Actions.
- English-only documentation for the first public release.
- Source on GitHub and package releases on crates.io. First implement genuine, tested functionality with accurate English documentation, then publish an alpha to acquire the package name. Continue toward the complete agreed scope; full release acceptance remains unchanged.

The library remains independent of application frameworks and business workflows. Callers choose when to run instances, what roles devices take, and how to combine operations.

The [capability inventory](docs/capabilities.csv) separates behavior candidates, aliases, resources and unresolved entries. The [platform inventory](docs/platforms.csv) records the official package mapping and planned execution paths. An inventory entry is not a support claim. The fixed baseline is VerySync **v2.33.2**; there is no implicit update to the latest engine.

## Development

Rust 1.85 or later is required. APIs use the caller's Tokio runtime. Adding this crate as a dependency and building it does not download or start VerySync, install a service, or configure global logging or signals.

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo test --lib --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo doc --no-deps --all-features --locked
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before running engine integration tests. Tests must use an explicitly supplied official executable, isolated state and synthetic data. The existing user instance is never a test target.

## API stability

All public APIs are unstable throughout alpha. Methods, modules, parameters, return values, configuration, errors, and events may be added, removed, renamed, or reorganized without backward compatibility. Compatibility layers for earlier alpha releases are not required. Pin an exact alpha version and review the changelog before upgrading.

Compatibility commitments begin with the first formal release. Compatible updates preserve existing usage; incompatible changes require an explicit incompatible version and migration guidance.

## Licensing

Project-owned code is licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. The official VerySync program and third-party dependencies remain subject to their own terms. The controller's license does not grant redistribution rights for the official program. No official executable is included in this repository or crate.
