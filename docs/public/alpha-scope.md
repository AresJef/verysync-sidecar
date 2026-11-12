# Initial alpha validation scope

The initial alpha controls an explicitly chosen, already running official
**VerySync v2.33.2** instance. Its Rust API provides authenticated identity/version
policy, fresh status, guarded folder registration/configuration reads, partial
label/pause changes, unregistering without a file-deletion request, bounded
failure/reconciliation semantics, constrained raw requests and a capability
snapshot. Three real compiled examples exercise the dedicated-instance workflow.

The [source-linked validation record](../../releases/alpha-0.1.0-alpha.1-validation.json)
records one complete candidate, each matched compiler/engine target, official
archive and executable SHA-256, native run and actual effect groups. Individual
previous commits are not combined to manufacture a final all-pass candidate.
Final publication metadata receives another same-source regression before upload.

| Controller and engine | Modern native runner | Selected management transport |
| --- | --- | --- |
| macOS amd64 | `macos-15-intel` | Unix socket |
| macOS arm64 | `macos-15` | Unix socket |
| Windows amd64 | `windows-2022` | Loopback HTTP |
| Windows arm64 | `windows-11-arm` | Loopback HTTP |
| Linux amd64 GNU | `ubuntu-24.04` | Unix socket |
| Linux arm64 GNU | `ubuntu-24.04-arm` | Unix socket |

These native jobs use Rust 1.85 and default TLS-enabled crate builds. Current and
minimum compiler quality jobs also check formatting, contracts, lint/build/docs,
actual doc-tests and the no-default-feature contract build. Real program tests
use independently verified binaries, private state/credentials, explicit
addresses and synthetic data, followed by exact owned-process cleanup.

The observed outcomes include actual new-directory creation; duplicate/path
guards; retained upstream and unrelated settings; paused scan rejection and
actual two-file indexing after resume; retained sample hashes after unregister;
lost-response/deadline/cancellation after a real applied write; raw response
retention and actual raw label change; honest unknown authorization conditions;
and actual independent executable runs with the borrowed engine left alive.

The table does not establish minimum-OS, other-architecture/ABI, HTTPS-engine,
cross-network or mismatched controller/engine coverage. Raw passthrough and a
successful HTTP response do not establish typed support or business completion
for unmodeled operations. Program ownership/hidden lifecycle, P2P sharing,
events/tasks, fixed-program acquisition/upgrades, history/storage, optional
commercial authorization and other planned families continue in the same
full-delivery project after the alpha milestone. Their current conditions are
listed separately rather than inferred from this initial scope.
