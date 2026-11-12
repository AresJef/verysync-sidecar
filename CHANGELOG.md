# Changelog

## Unreleased

- Establish the single Tokio crate, fixed VerySync v2.33.2 baseline, dual source
  license, capability/platform inventories and build-quality checks.
- Add explicit Unix socket and HTTP(S) endpoint values, target path syntax,
  lossless native-path conversion checks, and matchable input errors.
- Add explicit API-key connections, authenticated version/identity snapshots,
  optional expected-ID matching, strict/default version policy, bounded reads,
  request deadlines, and credential-safe diagnostics. Connections do not own
  or stop an engine process.
- No management feature or platform runtime support is claimed by the initial
  engineering foundation.

All public interfaces are unstable during alpha. There is no published package
or reserved crates.io name yet.
