# Release checks

This project publishes real validated Rust controls. The first alpha is an
intermediate milestone; development continues through the remaining full-delivery
families and their platform, authorization and recovery gates.

## Source, effects and scope

- Select one exact clean candidate and record its source/tree, crate version and
  official fixed-engine archive/executable checksums.
- Run the complete required native controller/engine matrix on that candidate,
  including actual control effects, faults, compiled examples and exact cleanup.
- Execute current/minimum compiler contracts, doc-tests, feature checks, strict
  lint/docs and dependency advisories. Preserve failures and unverified conditions.
- Keep actual version/platform/transport/authorization coverage explicit. Raw
  transport, successful HTTP, compilation and previous candidates are not a
  replacement for the candidate's required effects.

## Package and dependencies

- Inspect `cargo package --list --locked` and the actual `.crate` archive. Include
  owned source, English documentation, licenses and sanitized metadata only.
  Official program binaries, credentials, state, raw private logs and internal
  development records stay outside the package.
- Check declared dependency licenses and current RustSec advisories without
  silently changing dependency compatibility or suppressing warnings.
- Run `cargo publish --dry-run --locked --registry crates-io` from a clean source.
  Keep the unpacked-package build and VCS identity associated with that candidate.
- Consume the unpacked artifact from a new Rust 1.85 project and separate target
  directory. Verify ordinary dependency construction has no implicit VerySync
  download, process startup, global logger, signal handler or exit policy.
- Exercise the compiled consumer examples on an explicit isolated engine before
  upload, retaining actual configuration/file hashes and cleanup evidence.

## Identity and upload

- Verify the repository/publisher account, target crate name and credential
  presence. Name availability is a dated observation, not a reservation.
- Use the configured Cargo credential provider. Do not put a token in command
  arguments, source, environment logs, issue bodies or release notes.
- Restrict the manifest and command to the intended `crates-io` registry. Confirm
  that the exact final candidate has passed required same-source gates.
- Upload the real package only after those checks. Record name acquisition only
  after successful registry publication, and check the registry if an upload's
  index-wait result is inconclusive.
- Create/check the matching immutable version tag and GitHub release against the
  same accepted source. Notes state the narrow implemented scope and pending work.

## Registry consumption

- Start a fresh consumer with an exact `=version` registry dependency.
- Check the registry checksum/owner/version and resolved dependency source.
- Rebuild and execute actual isolated examples through that registry dependency.
- Record remaining work in the same project ledger; alpha success does not
  complete owned runtime, P2P, events/tasks or other full-delivery requirements.

The [Cargo publishing reference](https://doc.rust-lang.org/cargo/reference/publishing.html)
describes package verification and registry upload. [RustSec](https://rustsec.org/)
provides the advisory database used by the explicit dependency-audit check.
