# Changelog

## Unreleased

- Establish the single Tokio crate, fixed VerySync v2.33.2 baseline, dual source
  license and explicit capability/platform inventories.
- Add explicit Unix socket and HTTP(S) endpoint values, target path syntax and
  lossless native-path conversion checks.
- Add authenticated version/identity policy, fresh version/system/folder status,
  optional/unknown status preservation and credential-safe diagnostics.
- Add guarded folder registration from upstream defaults, exact configuration
  queries, partial label/pause updates and unregistering without requesting file
  deletion. Readback and runtime/batch completion remain distinct observations.
- Distinguish authentication, ambiguous access denial, HTTP/schema/body failures
  and unknown mutation outcomes; retain complete-response deadlines, body bounds,
  cancellation/reconciliation behavior and disabled automatic modification retries.
- Add structured raw requests with protected connection headers, exact bounded
  status/header/body responses and explicit caller-declared request effects.
- Report implementation, recorded native evidence, target coordinates and unknown
  instance permissions/licenses independently, without extra probes.
- Provide English rustdoc/guide code and dedicated-instance connection, creation
  and complete management examples. Runtime validation is scoped to its actual
  fixed-engine evidence; owned program management and the remaining full-project
  families continue after the initial alpha milestone.

All public interfaces are unstable during alpha. There is no published package
or reserved crates.io name yet.
