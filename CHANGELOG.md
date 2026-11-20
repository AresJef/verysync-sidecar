# Changelog

## 0.1.0

Version 0.1.0 is the first stable public Rust API baseline. The entries below
record changes since the first alpha, including the validation state when
individual changes landed. Current coverage and deferred cases are documented
in the [release checks](docs/public/release-checklist.md).

- Document the fixed v2.33.2 Windows ARM64 IPv6 traffic-class boundary. In
  two native runs settings 16 and 32 persisted, while the captured TCP packets
  carried class 0. IPv4 and the IPv6 zero control matched their settings.

- Retain the typed pending-device, official cloud-account and Local-API
  interfaces. Defer the nonempty pending-device dismissal, actual cloud-account
  sessions and Local-API cases requiring unavailable entitlements. The
  [release checks](docs/public/release-checklist.md) describe what remains
  applicable and the requirements for each deferred case.

- Add an isolated native Local-API regression that installs fixed v2.33.2 over
  v2.33.1 on Apple Silicon, preserving identity, index, share keys and file bytes.

- Add typed per-peer encryption password controls and capability entries for
  folder-peer encryption and native device introduction. On VerySync v2.33.2,
  six standard native profiles verified wrong-password rejection, exact recovery
  from an encrypted replica, and peer introduction, withdrawal, retention and
  direct transfer.

- Add a source-bound native anonymous FTP case with actual named-user refusal,
  independently observed anonymous login, exact data across restart and normal
  cleanup. Keep default password peers and pending platform acceptance explicit.

- Record strict HTTPS WebDAV native verification on six standard macOS,
  Windows and Linux AMD64/ARM64 profiles: trusted chain and hostname, incorrect
  hostname and credential rejection, exact payloads across restart and normal
  cleanup. Keep SFTP host identity and full final-source acceptance separate.

- Record six standard native profiles for SMB domain/guest authentication and
  SFTP inline-key refusal, browsing and exact transfer. Preserve the SFTP limits
  probe's actual HTTP500 parser failure on each profile; successful key transfer
  does not establish server host identity or a complete final-source pass.

- Reconcile the native omitted `insecureTls: false` default for SFTP and WebDAV
  job creation and endpoint updates. Keep the raw omission in returned snapshots;
  explicit true, null, malformed values and unrelated missing settings still
  fail matching. This does not establish SFTP host-key verification or retry an
  uncertain write.

- Replace Chrono with Jiff for verified native wire timestamps while retaining
  Rust 1.85. Preserve offset-based ordering and original request spelling; reject
  unsupported leap seconds and precision beyond nanoseconds, and retain floor
  seconds for archive timestamps before the Unix epoch. Dependency auditing
  continues to reject vulnerabilities and informational maintenance warnings.

- Preserve native signed general-option selections for temporary retention,
  folder/dial concurrency, temporary-index block selection and traffic class.
  Their fields and setters use `i64` in the unstable alpha API. Preserve
  native normalization receipts, including a zero temporary-index selection
  returning 2 and a nonmatching readback; runtime policy effects are separate.

- Preserve signed native incoming-request budgets with an `i64` field and patch
  setter, including negative selections, zero and target-supported positive
  values. This changes the unstable alpha API. Configuration persistence and
  real transfer checks remain separate from actual memory-limit effects; old
  resource measurements retain their original source binding.

- Correct native SOCKS5 preferences to use the fixed core's host:port authority,
  including percent-encoded credentials, instead of a full URI. On explicit
  managed startup/restart, apply the persisted selection only to the owned core's
  environment so direct-core mode retains native proxy initialization. Verify
  actual authentication refusal, file transfer, disable and data preservation
  separately from configuration readback; six-platform acceptance is pending.

- Add explicit native FTP/SFTP archive URI selection while preserving version
  policy and unknown fields. Keep configuration acknowledgement separate from
  real archival; SFTP has an isolated remote restore case and FTP effects remain
  unverified after native failures.

- Add a separate opt-in Windows SDK browser acceptance runner with restored
  per-user dispatch, exact native process-handle cancellation and private data
  retention checks. Actual Windows results remain required.

- Extend the opt-in isolated Windows protocol pilot to query the current ProgID,
  retain protected UserChoice and refuse merged COM/DDE handlers before dispatch.
  Actual native results remain separate from SDK browser acceptance.

- Add explicit inline SFTP private keys for native backend operations and correct
  empty-password omission during key-authenticated job readback. Keep the native
  limits-probe and verified-host-identity limitations explicit.

- Add source-bound Local-API index event subscriptions, explicit restart/shutdown
  and server-selected upgrade requests, and guarded native temporary cleanup.
  Keep acknowledgements separate from real process, file and installation effects.

- Add licensed Local-API full folder configuration reads, guarded template-based
  creation, partial updates, full item/collection replacement and unregister
  requests, with clone serialization through readback and preserved uncertainty.

- Add native Local-API history filters/records, hardware error-preserving reads,
  typed shared statistics/progress snapshots and licensed share generation/key
  checks, keeping source schemas and positive authorization gates explicit.

- Add typed native Local-API folder/device projections, target-scoped scanning,
  selective browse/need/selection requests and distinct native code3001 license
  errors. Preserve the separate Local-API schema and licensed-effect gates.

- Add a separate explicit Local-API connection with typed version/status reads,
  bounded scoped raw requests and an opt-in owned startup flag. Correct the
  generated native app settings root without replacing arbitrary caller settings.
  Licensed Local-API effects and final platform validation remain separate gates.

- Add explicit native browser dispatch with a separate private helper profile,
  actual root outcomes and desktop-lifetime release; native acceptance pending.

- Retain native console preambles separately from complete CLI path reports;
  preserve exact Windows unsupported-shell exits and private diagnostics.

- Request native Linux file-watch minimums with independent bounded kernel
  observations, preserving zero-exit failures instead of assuming application.

- Request native shell-completion instructions with private exact text, explicit
  action/exit outcomes and stopped-state alias checks; never evaluate shell code.

- Inspect native CLI storage locations on stopped owned instances with typed
  local paths, private output and explicit exit/schema outcomes.

- Add native wallpaper image and conditional-304 resources with opaque private
  bytes, exact cache metadata and no implicit saving or wallpaper changes.

- Add explicit target-native folder/trash open requests with private receipts,
  mutation uncertainty and no inferred graphical window success.

- Read independent native per-file download-progress maps with exact block
  counters, byte estimates, private results and preserved missing-state errors.

- Expose explicit native path-writeability snapshots with conservative mutation
  semantics, preserving the fixed core permission-detection limitation.

- Read the independent native index-file diagnostic endpoint using the existing
  full metadata types, preserving its successful zero-record missing-file result.

- Add explicit native support ZIP collection with bounded private bytes,
  mutation uncertainty and no implicit save, extraction or request retry.

- Add native event-name selections with bounded canonical filters and validated
  serialized cursors. Different selections retain separate source identities.

- Add source-bound disk-change subscriptions that reuse bounded event recovery,
  cancellation and gap reporting. Preserve the fixed program's empty-buffer
  interruption and require explicit caller retry; never seed events implicitly.

- Add a distinct whole-folder native version inventory using existing typed
  archive records, preserving paused/error and empty-map semantics.

- Require actual JSON objects for native error envelopes so legitimate data
  arrays cannot be mistaken for API or license failures.

- Add explicit target-native path completions and filesystem selector requests,
  preserving private returned paths and native empty-result ambiguity.

- Add full native indexed-file metadata, advertised sources and encoded signature
  records, preserving native empty local state without inferring file presence,
  completed downloads or signature trust.

- Add native indexed-tree snapshots with explicit depth, target-relative prefix
  and directory filters, exact private recursive metadata and no implicit scan.

- Classify live GUI/API hot-disable as unsupported on fixed v2.33.2. Keep the
  explicit stored configuration request, passive owned-listener observations
  and separate caller-selected process cleanup; never infer closure from a flag.

- Add exact private native text-log snapshots with explicit timestamp filters,
  preserved line endings, valid empty output and strict UTF-8 error handling.

- Add explicit native random-string generation with verified optional lengths,
  private result formatting, preserved unknown fields and uncertain mutation
  errors without retries. Keep native generation separate from secure API keys.

- Pin the verified libc 0.2.186 Unix bindings and assert the MIPS64 GNU socket
  ABI at compile time. Preserve the original runtime deadlines and report
  actual platform effects separately from successful compilation.

- Add typed native CPU, memory, disk/partition and NIC observations with private
  nested values, nullable records, signed unknowns and connected-target mount
  paths. Preserve native unsupported errors separately from successful data.

- Add typed native system locations and explicit folder temporary/session-file
  cleanup. Retain special output/template values, target path syntax and private
  fields; distinguish native receipts from independently observed file removal.

- Add future-folder versioning and target archive-location controls with shared
  policies, snapshot edits and actual inherited archive/restore checks. Keep full
  save normalization visible when inactive parameter maps are filled natively.

- Add native folder-type, block-order, copy-strategy and ordered attribute-filter
  selectors, including per-registration overrides without editing shared defaults.
  Support initial receive-encrypted registration and protect existing-type
  transitions; keep configuration and platform/data-path effects separate.

- Share additional typed device selections with existing create/update/default
  paths. Preserve absent introduction sources and private unknown values, retain
  exact field matching, and keep template inheritance separate from introduction,
  auto-acceptance and encrypted-transfer effects.

- Add scoped typed advanced-folder selections and share validated scan, pull-order,
  selective and advanced inputs with creation templates. Preserve native absence,
  unknown/private fields, actual readback differences and existing-object settings;
  keep configuration distinct from platform metadata and transfer effects.

- Select native managed HTTPS with explicit per-instance transport policy and
  same-identity owner connection adoption. Retain trust/endpoints across normal
  startup, stop, restart and existing-state connection without transferring
  process ownership or changing global trust.

- Add typed native GUI listener selections and single explicit listener changes.
  Keep acknowledgement, caller reconnection, actual TLS/bind/socket-mode effects
  and process ownership separate; retain private unknown selectors on reads.

- Add per-connection PEM/DER trust roots and explicit authenticated HTTP(S)
  management proxies for API-key and GUI-session connections. Retain policy
  through credential reconnects, verify hostnames normally, and omit reflected
  proxy credentials from ordinary version diagnostics. No global trust changes.

- Add explicit per-peer native remote-management permission and port settings,
  canonical tunnel probes with private negative results, and gateway connection
  options that check the target identity and preserve explicit base paths. Keep
  licensed sessions and cross-network effects pending independent acceptance.

- Add identity-checked native license observations and explicit refresh/Pro-trial
  requests. Preserve collection shapes, private metadata and actual uncertainty;
  compare expiry only against a caller-selected Unix-second reference, without
  inferring licensed effects from configuration or an acknowledgement.

- Add explicit official-account status, login and logout with typed native
  rejection codes, private credential/session formatting and fresh observed
  state. Keep GUI authentication and commercial entitlements separate; do not
  infer login success from an HTTP-success error envelope.

- Validate native priority relative to caller inheritance and verify cloned
  profiling request order through complete HTTP response bodies. Keep native
  profile timestamps as diagnostics and preserve bounded, redacted protocol
  start-failure details instead of inferring sequence from mixed clocks.

- Add explicit event-audit, thumbnail and native proxy preferences with target
  paths/default selectors and preserved unrelated options. Separate actual event
  log data from licensed folder history, cache artifacts and proxy connections.

- Add typed native GUI preferences with one bounded write/reload reconciliation,
  actual field matching and owned connection adoption. Retain credentials and
  listener selection, and redact submitted preference text in version errors.

- Read native diagnostic preferences and explicitly update crash-report settings.
  Preserve private destinations/identifiers without ordinary Debug disclosure.
  Keep normalized legacy usage fields read-only rather than promising consent,
  opt-out or report transmission from configuration readback.

- Observe Windows upstream state locks without creating absent files. Keep the
  same regular-file, reparse-point and private-ACL checks on existing handles.

- Preserve signed progress-report intervals, including the native disabled value
  `-1`. Add typed minimum configuration-volume free space and scoped temporary
  index, remote-name, full-index resend and IP traffic-class preferences. Separate
  persisted selections and observed owned-process priority from other policies.

- Confirm upstream owned-state lock release after process containment exit, within
  the existing cleanup window. Report `ManagedExit.state_released` separately,
  and require it for successful exit waits, offline backup and upgrade admission.
  Preserve an interrupted FTP run's observed optional cancellation flag when
  native peer failure can finish before a separate stop request arrives.

- Preserve a complete Local Sync run's native execution error as private typed
  data alongside finish time, counts and cancellation. Continue rejecting API
  error envelopes, malformed records and wrong job identities. Distinguish
  current-run result pages, explicit interrupted-work recovery and owned force
  termination from durable history, normal stop and automatic rollback.

- Add bounded native transfer/channel preferences and full scoped Local Sync
  endpoint, direction, ignore, file-operation and explicit mirror-deletion
  settings. Preserve native null/omitted shapes and recognize only verified
  clear/default readback semantics. Keep native unsupported compression and
  unverified private-key behavior separate from configuration selection.

- Verify native reverse, two-way newer/larger/manual conflicts and selected-only
  data effects independently for FTP, SFTP, SMB and WebDAV with owned protocol
  peers. Keep per-protocol authentication, in-flight and recovery conditions
  separate from directional acceptance.

- Add explicit marker rebuilding and two-way baseline recovery against complete
  reviewed job snapshots. Refuse stale settings and active/unknown states, retain
  exact acknowledgements and preview identities, and never execute recovery
  plans automatically. Permission-comparison updates remain separately explicit.

- Add explicit native startup, watch and interval/calendar schedule settings.
  Automatic triggers default off; selecting them can start unattended native
  writes. Scoped updates preserve other settings and report actual normalization.
  Free watch/schedule requests are reconciled without mutation retries; licensed
  positive execution remains pending. Startup copied real files on enablement
  and after restart through the public API.

- Add operation-identity-checked Local Sync pause/resume/stop receipts and native
  progress/cancellation observations. Add separate pull-driven Local Sync events
  with bounded batches, consumed cursors, explicit gaps and cancellation, without
  background tasks, automatic recovery or global handlers.

- Add explicit bounded Local Sync action selection and native selection totals,
  reverse mirror effects and two-way newer/larger/manual conflict controls.
  Manual resolution returns a readback-verified replacement preview without
  executing it; predicted copy bytes remain distinct from completed transfers.
  Empty/outside selections are refused before execution, with no automatic range
  expansion, conflict resolution, retry or rollback.

- Add explicit native remote endpoint selection and separate credentials, target
  connection limits, SFTP key paths and SMB/WebDAV identity settings. Protocol
  and platform effects remain independently verified, with private test peers.
  Require a nonempty label in `CreateLocalSyncJob::new`; preserve omitted groups
  as `Option<String>` and signed native storage sizes such as unknown `-1`.
  These are intentional alpha API changes without compatibility aliases.

- Add native Local Sync basic endpoints and typed job, preview, execution,
  result/history and scoped registration controls. Keep acknowledgements, actual
  completion and per-protocol acceptance separate; no controller copy engine or
  SDK scheduling timers, retries or rollback are introduced.

- Add explicit resource directory creation, same-volume copy/move, existing-file
  UTF-8 replacement and scoped deletion with collision/merge policies. Keep
  observed Windows directory partial failures and required positive acceptance
  separate; cancellation does not imply native rollback or copy termination.

- Add native staggered/external versioners and explicit basic/default archive
  locations, preserving earlier archive data when selecting a location. Observe
  actual external callbacks and native failure effects separately from config.
  `FolderVersioningPolicy` is now `Clone` rather than `Copy` because an external
  policy owns its command text; alpha interfaces remain unstable.

- Add explicit folder/global index-reset acknowledgements and stopped-owner
  statistics, counts, file metadata and database reset commands. Keep actual
  exit, index effects, data retention and restarted readiness distinct.

- Refuse unverified/same-second archive restores before native POST using the
  target's clock and a bounded directory preflight; preserve selected archives
  and current data in the observed v2.33.2 timestamp-collision case.

- Add explicit bounded native heap/CPU profiles and authenticated Prometheus
  snapshots, preserving private payloads, collection effects and uncertainty.

- Add explicit native error registration/clearing, bounded log snapshots,
  partial package-level changes and target-syntax diagnostic locations,
  with private Debug output and uncertain-write handling.

- Add explicit directory oldest/newest version restoration, including an
  explicit native dot-root selection, with observed nested-file effects.

- Add explicit file versioning policies, native archive listings and exact file
  restoration, with bounded selection and per-path errors. Preserve unknown
  archive settings and expose conditional audit-log settings/pages/reset.

- Add bounded streamed file uploads/downloads, exact finite byte ranges and all
  seven native archive formats, with caller-selected new output paths, verified
  post-upload digests and explicit cancellation/unknown-mutation semantics.

- Add explicit file-manager mount/path values, bounded directory/text metadata
  and native checksums plus bounded native image previews, with target-system
  path guards, exact encoded control filenames and private diagnostics.

- Add explicit version-policy-aware program transitions, kernel check/trigger,
  fixed-archive streaming upload and contained stopped-owner CLI upgrades.
  Preserve unknown mutation outcomes and require explicit executable reselection.

- Add bounded private-state snapshots with pinned manifests and file hashes,
  fresh-directory restoration, cooperative cancellation and incomplete-state
  admission protection. Keep external synchronized files outside state rollback.

- Add a native three-node read-only handoff scenario with the source stopped,
  an explicit wrong-endpoint failure, complete hashes and peer byte counters.

- Add guarded receive-only reversion, send-only override and marker repair,
  separating acknowledgements from actual file and identity recovery.

- Add selective tree/search pages, opaque cursors and mode settings. Recognize
  known HTTP-success Pro-license refusals without claiming authorized effects.

- Add file pull-order settings, relative-file priority requests and explicit
  global/per-device KiB/s limits with separate queue and byte-cap observations.

- Add exact ignore-rule replacement and default restoration, preserving null
  file lines and reporting HTTP-success parser rejection as a typed error.

- Add relative subpath and all-folder scans, partial periodic scan/watcher
  settings and separate native index, automatic-scan and notification effects.

- Add fresh typed completion/status batches, bounded need/local-change/error
  pages and device/folder statistics. Preserve unknown remote state, null lists
  and untrusted file names; verify native access errors, active need, local edits
  and content/time restoration without claiming business-batch completion.

- Add explicit tracker/NAT/UDP/relay-client settings and fresh reported state,
  official relay server control, typed effective timeouts and explicit probes.
  Observe private UDP/QUIC and real three-core relay paths independently from
  unverified WAN, public-provider and relay-authentication conditions.

- Release the private diagnostic file before publishing managed exit, and
  verify immediate post-stop diagnostic rename in native program preparation.

- Add partial network settings, typed transport selectors and fresh listener,
  connection and discovery-cache observations. Keep stored configuration,
  candidate addresses and actual connectivity distinct; retain the fixed
  kernel's custom-discovery-server and unverified transport boundaries.

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
