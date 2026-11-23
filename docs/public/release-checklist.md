# Release checks

For the 0.1.1 repair candidate, review the exact crate, generated API docs,
examples and user-facing output together with the six repair results. Sign off
each message or page against the behavior it describes. Check the stable
0.1.0 caller examples for matching error types and verify that machine output
and private diagnostics retain their contracts.

Release claims describe the behavior verified through the public Rust API on
the exact candidate with the fixed VerySync v2.33.2 engine. The first alpha
is an intermediate milestone. The first stable release requires every applicable
gate below and actual consumption of the published package.

## First stable release coverage

The following Pro behaviors await validation with an isolated, entitled core.
Previously verified behavior and entitlement refusal checks keep their own
evidence. The pending positive cases remain available for future validation.

| Area | Positive validation deferred | Checks required for applicable behavior |
| --- | --- | --- |
| [Selective sync](selective-sync.md) | Entitled selection, file download, deselection and removal on all peers, with their data effects | Ordinary browsing and synchronization, native license refusals and file retention |
| [File history](file-history.md) | Generating, paging and clearing the Pro global audit history | Ordinary version archives and recovery, file preservation and native refusal behavior |
| [Local storage jobs](local-sync.md) | Entitled change watching, fixed intervals and calendar schedules | Manual runs, applicable launch triggers, authenticated backend transfer and recovery |
| Pro license and trial | Effective license reads, refresh, persistence and trial activation | Observed empty, denied and indeterminate results and preserved state |
| Official Pro remote management | A real official tunnel session, verified target identity and management operations | Explicit caller-configured HTTP(S) management and identity checks |

Positive [Local-API](local-api.md) cases that require an official entitlement
remain deferred. The 28 typed entries, ordinary native effects and actual
license refusals retain their separate evidence. Enterprise control is also
deferred until the official caller contract and a dedicated entitlement are
available.

Release 0.1.0 verified live [ordinary cloud account](official-accounts.md)
sign-in, wrong-password rejection (code 2404), persistence across restart
and sign-out followed by an empty account state. The native isolated
blocked-network check returned 5000. Keep those results separate from Pro
session, trial and license validation.

Generating, reading and dismissing a real nonempty pending-device record was
outside the final 0.1.0 acceptance scope under R32. Typed reads, native empty
results and missing-record rejection retain their evidence. Pending-folder
validation has its own checks. [Invitations](invitations.md)

Verify actual disconnection and retained file bytes for
`disconnect_and_remove_device()`. For `remove_device()`, verify the single
DELETE's configuration snapshot and file retention, then verify native
readmission and a new transfer with the existing shared keys.
See [device configuration](devices.md).

Use a fixed isolated test instance with the required entitlement for
positive licensed cases. Record applicable outcomes and gaps with release
evidence.

For v2.33.2 on Windows AMD64 and ARM64, the [directory mutation check](file-mutations.md)
covers the observed native HTTP 500 and partial contents after directory
move-and-merge or recursive deletion. Require the typed unknown outcome,
actual filesystem effects and exact cleanup. Verify complete positive effects
for ordinary file operations and the other applicable native profiles.

The six required native functional profiles cover macOS, Windows and Linux
on AMD64 and ARM64. Use the [platform index](../platforms.csv) to identify
additional targets and their actual execution mode.

### Minimum verified systems

R31 established minimum verified systems for 0.1.0 and fixed v2.33.2 from
actual standard hosted runs. These cover Ubuntu 22.04.5 on AMD64 and ARM64,
macOS 15.7.9 on Intel and 15.8.2 on ARM64, Windows Server 2022 on x64 and
Windows 11 desktop on ARM64. The Windows x86 standard package has a separate
WOW64 result on Server 2022 x64. The initially considered older systems
remain historically untested. Check exact builds, original jobs and scope in
[Platform validation](platform-validation.md#verified-release-baselines).

### Field network evidence

Release 0.1.0 completed the five VS-035 field cases with fixed v2.33.2 and
isolated peers: attributable direct transfer, link-loss recovery with
retained data, discovery followed by authenticated transfer, controlled
native QUIC traversal through NAT with matching bytes on both rounds, and a
selected relay carrying authenticated file traffic. Those results cover the
observed peers and routes. The Pro official management tunnel retains its
separate entitlement requirement.

The [controlled network evidence](controlled-network-acceptance.md) retains
the observed IPv4 and IPv6 routed paths, file effects, recovery and node
lifecycle checks. Revalidate the applicable controlled cases on the final
candidate. Run the separate [Windows packet validation](controlled-network-acceptance.md#windows-packet-traffic-class)
for IPv4 and IPv6. The fixed Windows AMD64 direct TCP check includes the
observed default-octet boundary. For the fixed Windows ARM64 direct TCP path,
IPv4 and the IPv6 zero control must match the configured class. For IPv6
settings 16 and 32, independent capture can also confirm the observed all-zero
v2.33.2 behavior. Both architectures require the applicable same-link controls,
persisted settings, actual file effects, authenticated identity and exact cleanup.

### Resource measurements

Release 0.1.0 completed four formal and two independent Intel resource cycles
on macOS 15.7.9 with the approved per-process resident memory bounds. The
accepted 24 workloads and the five other standard profiles remain linked to
their frozen inputs. The later 0.1.1-rc.2 v33 run stopped at input fingerprint
checks before any sample. Candidate resource claims require measured results
from the corresponding frozen inputs.
[Intel release result](https://github.com/AresJef/verysync-sidecar/actions/runs/44906299987/job/136852498144) ·
[RC2 input checks](https://github.com/AresJef/verysync-sidecar/actions/runs/44998190563)

The final [capability index](../capabilities.csv), platform index and release
notes record the precise support, conditions and evidence. A deferral contributes
no passing evidence. Keep a prerelease candidate with accurate gaps whenever an
applicable required outcome remains open.

## Source, effects and scope

- Select one exact clean candidate and record its source/tree, crate version and
  official fixed-engine archive/executable checksums.
- Run the complete required native controller/engine matrix on that candidate,
  including actual control effects, faults, compiled examples and exact cleanup.
  Native Windows AMD64 also checks one lost HTTPS reply, followed by exact
  authenticated HTTP readback after the listener change.
- Push the exact candidate to an owned `ci/formal-candidate/*` branch to run
  quality, native engine, additional-platform, formal resource and both Windows
  packet validations on the same commit. You can also dispatch registered workflows on that ref.
  Record each workflow's numeric run ID and attempt in the private candidate
  metadata under `candidate_runs` with keys `quality`, `engine`,
  `platforms`, `resources`, `windows_amd64_packets` and `windows_arm64_packets`. Each entry
  contains `id` and `attempt`. Run the read-only
  `python3 scripts/publish-github-release.py --metadata /absolute/private/release.json --check-actions`
  with GitHub CLI access to workflow metadata. This checks the candidate commit
  and tree, registered workflow identities, exact run attempts, complete job
  listings and required acceptance steps. Each native diagnostic in the catalog
  at the candidate commit must have a matching job with its execution and cleanup steps.
  Use the historical Intel-deferral procedure only if a future release has
  an explicit approval for that exception. Push that exact candidate to
  `ci/formal-candidate/r23-intel-deferred/<candidate>` in this repository.
  Set the top-level metadata field
  `"deferred_formal_resource_profile": "macos-amd64-standard"`.
  The verifier requires the resource planning job to record this deferral
  and the five other resource jobs to pass. Any full resource run uses all
  six profiles and omits that metadata field.
  Each required measurement job replays the frozen raw measurements, requires the
  registered resource verdict to pass, and verifies the checked-out
  commit, tree and engine executable digest. Its replay report is saved with the
  raw evidence.
- Review the evidence for applicable licensed effects, verified network
  topologies, minimum operating systems, compatibility and formal resource
  comparisons against the same candidate. Record each documented case and
  its resumption requirement before authorizing upload. The automated GitHub publisher is scoped to the
  first recorded alpha. The stable registry and release checks below use the
  accepted stable candidate's private metadata.
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
- From the clean candidate checkout, run
  `python3 scripts/publish-github-release.py --metadata /absolute/private/release.json --check-package /absolute/package.crate`.
  Give the metadata the candidate commit, tree and independently obtained
  archive SHA-256. Use the same Cargo toolchain as for the supplied archive.
  The offline check assembles a temporary reference package, checks the exact
  member list and normalized manifest, and matches packaged public source files
  to the candidate's Git blobs. It also checks the generated manifest's feature,
  license and registry settings. Use the same package checksum for subsequent
  registry verification. Review native and authorization evidence separately.
- Once the archive and hosted run attempts are available, run the combined
  read-only check from the clean candidate checkout with the same Cargo toolchain
  and GitHub CLI access.

  ```sh
  python3 scripts/publish-github-release.py --metadata /absolute/private/release.json --check-candidate /absolute/package.crate
  ```

  A successful check reports one source, tree and archive digest together with
  the verified hosted attempts and job counts. Complete the other applicable
  release checks in this guide before authorizing upload.
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

## Verify a stable publication

Use the selected `MAJOR.MINOR.PATCH` version in the accepted candidate's private
metadata. Include `publisher` and `publisher_id` for the intended crates.io
account alongside the existing source, tree, archive digest and workflow attempts.
From the clean candidate checkout, run this read-only check after registry upload.

```sh
python3 scripts/publish-github-release.py --metadata /absolute/private/release.json --verify-stable-registry /absolute/package.crate
```

The command repeats the candidate preflight and compares the downloaded registry
archive, publisher and ownership record with the local candidate. It also checks
that Cargo's sparse index lists the exact version and checksum as available.

After creating the matching GitHub tag and release for the accepted source, run
the complete read-only check from the same checkout.

```sh
python3 scripts/publish-github-release.py --metadata /absolute/private/release.json --verify-stable-release /absolute/package.crate
```

This also resolves the version tag to the accepted commit and verifies the
published stable GitHub release for that tag. Retain both receipts with the
manual native, licensed, minimum-system and WAN evidence.

## Registry consumption

- Start a fresh consumer with an exact `=version` registry dependency.
- Check the registry checksum/owner/version and resolved dependency source.
- Rebuild and execute actual isolated examples through that registry dependency.
- Record remaining work in the same project ledger; alpha success does not
  complete owned runtime, P2P, events/tasks or other full-delivery requirements.

The [Cargo publishing reference](https://doc.rust-lang.org/cargo/reference/publishing.html)
describes package verification and registry upload. [RustSec](https://rustsec.org/)
provides the advisory database used by the explicit dependency-audit check.
