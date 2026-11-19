# Release checks

Release claims describe the behavior verified through the public Rust API on
the exact candidate with the fixed VerySync v2.33.2 engine. The first alpha
is an intermediate milestone. The first stable release requires every applicable
gate below and actual consumption of the published package.

## Planned first stable release coverage

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

Verify account operations, Local-API, enterprise controls and Windows packet
traffic class against their own requirements. Apply the original positive and
negative checks to each of these areas. Assign an explicit unresolved status
where an applicable required outcome remains unverified.

The six required native functional profiles cover macOS, Windows and Linux
on AMD64 and ARM64. Use the [platform index](../platforms.csv) to identify
additional targets and their actual execution mode.

The following minimum-system runtime cases are deferred for this release.
The available hosted runners use newer Windows and macOS images. No matching
authorized older host or guest was available for these cases.

| Runtime case | Requirements to resume validation |
| --- | --- |
| macOS 11 on Intel and ARM64 | An isolated environment booted into macOS 11 on the corresponding architecture |
| Windows 10 standard packages on x86, AMD64 and ARM64 | A matching authorized Windows 10 environment and a confirmed minimum build for the target |
| Windows 7/8 and Server 2008/2012 legacy packages on x86 and AMD64 | Matching authorized environments for the applicable architecture and OS combinations, with the tested build and service pack recorded |

A resume run verifies authenticated management, file effects, restart,
failure handling and exact shutdown with the matching fixed engine. The
named modern-host and older Linux guest results retain their documented
scope.

Dedicated field peers on independently controlled networks were unavailable
for this release. The following field network cases are deferred.

| Field case | Requirements to resume validation |
| --- | --- |
| Direct connection | Two dedicated peers on the observed independent networks, with an attributable direct route and matching transferred files |
| Discovery | Dedicated peers with the relevant discovery service and evidence that discovery leads to an authenticated connection and transfer |
| NAT traversal | Independently controlled address translation on the relevant path and observed traversal with matching transferred files |
| Relay | A controlled relay path with attributable relay selection, authenticated peers and matching transferred files |
| Link loss and recovery | A controlled field-link interruption with observed disconnection, retained data and verified recovery over the restored link |

The [controlled network evidence](controlled-network-acceptance.md) retains
the observed IPv4 and IPv6 routed paths, file effects, recovery and node
lifecycle checks. Revalidate the applicable controlled cases on the final
candidate. Run the separate [Windows packet validation](controlled-network-acceptance.md#windows-packet-traffic-class)
for IPv4 and IPv6. The fixed Windows AMD64 direct TCP check includes the
observed default-octet boundary. Windows ARM64 keeps its own packet-effect
requirement.

macOS Intel formal resource collection and its independent reruns are deferred.
Both standard Intel labels produced zero qualifying formal samples. Resume
on a native Intel host that passes the original preparation and sampling gates.
Intel native functionality is required. Use the frozen resource protocol and
independent reruns on the five other standard profiles.
[macOS 15 Intel preparation](https://github.com/AresJef/verysync-sidecar/actions/runs/44321858142/job/134862617712)
and [macOS 26 Intel preparation](https://github.com/AresJef/verysync-sidecar/actions/runs/44324838496/job/134873243209).

The final [capability index](../capabilities.csv), platform index and release
notes record the precise support, conditions and evidence. A deferral contributes
no passing evidence. Keep a prerelease candidate with accurate gaps whenever an
applicable required outcome remains open.

## Source, effects and scope

- Select one exact clean candidate and record its source/tree, crate version and
  official fixed-engine archive/executable checksums.
- Run the complete required native controller/engine matrix on that candidate,
  including actual control effects, faults, compiled examples and exact cleanup.
- Push the exact candidate to an owned `ci/formal-candidate/*` branch to run
  quality, native engine, additional-platform, formal resource and both Windows
  packet validations on the same commit. You can also dispatch registered workflows on that ref.
  The scoped Intel resource deferral requires the push described below.
  Record each workflow's numeric run ID and attempt in the private candidate
  metadata under `candidate_runs` with keys `quality`, `engine`,
  `platforms`, `resources`, `windows_amd64_packets` and `windows_arm64_packets`. Each entry
  contains `id` and `attempt`. Run the read-only
  `python3 scripts/publish-github-release.py --metadata /absolute/private/release.json --check-actions`
  with GitHub CLI access to workflow metadata. This checks the candidate commit
  and tree, registered workflow identities, exact run attempts, complete job
  listings and required acceptance steps. Each native diagnostic in the catalog
  at the candidate commit must have a matching job with its execution and cleanup steps.
  For the Intel formal-resource deferral above, push the exact candidate to
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
