# Changelog

## Unreleased (0.1.0-alpha.2)

- Add explicit ignored-device reads and changes using the fixed engine's full
  configuration PUT, preserving unknown fields and unrelated ignore records.
  Refuse implicit removal of configured peers and protect the local identity.

- Add pending-folder reads, exact offer dismissal, per-peer persistent ignores
  and explicit folder-peer associations. Keep remote offer IDs, local IDs and
  independently validated keys separate; retain pending-device validation limits.

- Add typed remote-device reads, default-preserving creation, partial name,
  protocol-address, compression and pause changes, and exact-ID removal with
  association readback. Protect the local identity, preserve unknown fields,
  and distinguish acknowledged configuration from actual peer effects.

- Give fresh owned instances an independent auxiliary loopback address while
  retaining explicitly configured addresses across restart. Verify native
  owned IPv4 listeners without connecting to unrelated local endpoints.

- Add explicit offline cache resolution, cross-process preparation leases,
  rehashed hits and atomic indexes over immutable program generations. Preserve
  previous executables during corrupt-entry recovery and cancellation.

- Add optional explicit fixed program preparation with bounded streaming,
  complete archive SHA-256 checks, exact regular executable extraction,
  private permissions and runtime-independent partial-file cleanup.

- Add explicit pinned program-source and official target models, fixed archive
  identities and separate controller/runtime ABI conditions. Reject unlisted
  versions/targets without selecting a newer or different program.

- Add redacted sharing-key types, engine generation/validation and target-bound
  key registration with explicit material readback. Keep local registration IDs
  separate from peer association; reject invalid keys and duplicate groups.

- Add explicit whole-folder scan requests and bounded observation of actual
  scanning entry/exit, optional reported progress and fresh terminal status.
  Preserve state when a wait is cancelled; gaps remain indeterminate and
  observation cancellation sends no engine-stop or pause command.

- Restrict Windows child handle inheritance to explicitly selected private
  standard I/O, while retaining suspended creation, private Job containment and
  exact process/thread ownership. Verify caller-output EOF while a persistent
  core remains alive, including native paths with spaces and Unicode.

- Add explicit persistent lifetime, protected read-only state reconnection and a
  borrowed shutdown request with acknowledgement-only semantics. Keep cancelled
  startup cleanup active until authenticated readiness commits. Add a compiled
  owned/persistent/reconnect/shutdown example and actual native lifetime cases.

- Add bounded caller-owned event subscriptions, preserved unknown events,
  credential-safe Debug, explicit cursor gaps and finite read-only recovery.
  Keep producer queue positions separate from consumed cursors; close/drop
  cancels only the subscription, including pending HTTP/backpressure waits.
- Exercise public Windows caller return, no-destructor exit and forced exit
  inside a retained outer Job, including an unrelated live child and native UI
  observations. Confirm core exit before any test cleanup or explicit retry.
- Allocate Unix PTYs with close-on-exec from creation, isolate child Unix
  HOME/XDG paths, and add real public-API caller return/exit/SIGKILL/inherited-HUP
  and unrelated-exec lifetime regressions. Preserve caller environment/signals.
- Run engine tests behind an explicit test-only nonforwarding HTTP proxy,
  with credential-safe observations and an independent no-forwarding control.
- Add explicit local-program selection and initial owned startup, private state
  leases, fixed-version/checksum checks, authenticated readiness, persisted
  identity/configuration reuse and actual process-tree exit observation.
- Add typed normal shutdown with one total deadline and observed process-tree
  exit; explicit force_stop remains a separately chosen action.
- Add owned restart with one total deadline, retained state and authenticated
  new-generation readiness; expose actual stop/start failures for explicit retry.
- Validate startup cancellation after actual core creation, caller/SDK deadlines
  and Tokio runtime shutdown. Preserve incomplete identity/configuration for
  explicit repair; confirm exact private process exit before successful retry.
- Reject linked/unprotected persisted identity resources and configuration left
  without a complete identity before invoking identity generation/read helpers.
  Inspect dangling control-file aliases before treating state as new, and retain
  keys when configuration is missing instead of silently rebuilding it.
- Keep further lifecycle policy gates
  in the same full-delivery development plan. This development version has not
  been published.

## 0.1.0-alpha.1

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

All public interfaces are unstable during alpha. This initial release is an
intermediate milestone; the same development plan continues through full delivery.
