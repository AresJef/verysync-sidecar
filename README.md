# verysync-sidecar

Unreleased [file transfers](docs/public/file-transfers.md) stream explicit local
inputs/outputs with finite bounds, inclusive ranges, all seven native archive
formats and post-upload digest verification. Complete native acceptance is pending.

A general-purpose Rust library for managing and controlling the official VerySync program. The goal is complete coverage of its actual programmable capabilities, with explicit version, platform, license, and verification conditions.

The unreleased [program upgrade and state snapshot API](docs/public/program-upgrades.md)
separates explicit executable selection, kernel upgrade requests and offline
state restoration. A restored old snapshot is distinct from opening a migrated
database with an older executable.

The unreleased [file-manager read API](docs/public/file-resources.md) separates
opaque mounted-volume IDs from sync-folder IDs, preserves target path syntax,
and exposes bounded resource metadata and actual file checksums.

The unreleased optional [`download` feature](docs/public/program-preparation.md)
adds explicit fixed-version transfer, full archive SHA-256 verification and
bounded extraction into a new private directory. Preparing a program and
starting its isolated managed instance remain separate runtime operations.

The unreleased [program cache](docs/public/program-cache.md) adds explicit
offline resolution, cross-process preparation and immutable generations that
preserve previously returned or running program paths.

The project is under active development. The current API provides explicit endpoints and target paths, authenticated version/identity checks, fresh typed status reads, and folder registration, partial label/pause updates and unregistering while retaining files. Further management operations are being implemented and tested. The initial alpha version is `0.1.0-alpha.1`; pin it exactly and review the validation scope. Runtime acceptance is tracked per operation and platform; successful engine fixture tests alone do not establish control-library functionality.

The working branch also develops explicit owned-program startup and deliberately selected persistence. See [managed instances](docs/public/managed-instances.md) for the unreleased API and its distinct lifetime/state responsibility; the published initial alpha still targets already running instances.

The unreleased [event subscription API](docs/public/events.md) provides bounded
queues, explicit continuity gaps and finite read-only recovery. Its task belongs
to the subscription; closing it leaves the engine running.

The unreleased [scan observation API](docs/public/long-running-operations.md)
separates an explicit scan request from observed scanning entry/exit and fresh
status. Cancelling observation closes only its read subscription; completion
does not certify peer synchronization or invent a server job identifier.

The unreleased [sharing API](docs/public/sharing.md) generates and validates
actual engine keys, preserves reported read-only/read-write permissions and
registers using the target's proposed local ID. Registration readback and peer
association are separate observations.

The unreleased [device configuration API](docs/public/devices.md) reads actual
defaults, guards creation and partial updates, controls a remote device's pause
layer, and observes removal and remaining folder associations. Configuration
readback remains separate from connection and file-transfer evidence.

The unreleased [invitation and folder-peer APIs](docs/public/invitations.md)
distinguish remote offers, persistent ignores, local key registration and explicit
peer association. Nonempty pending-device records remain separately unverified.
Explicit device-ignore changes preserve the full fixed-version configuration
and report settings separately from observed connection rejection/recovery.

The unreleased [network API](docs/public/network.md) separates explicit settings,
listener status, discovery cache records and live peer snapshots. Real private
TCP and isolated discovery lookup effects have dedicated tests; LAN, UDP, relay,
announcements and WAN acceptance remain separate.

The unreleased [transport](docs/public/transports.md) and
[relay-server APIs](docs/public/relay.md) add explicit protocol settings,
tracker/NAT observations, official relay runtime and caller-selected probes.
Dedicated tests cover private UDP/QUIC peers and a three-core relay path.
Cross-WAN traversal, public providers and authenticated relay enforcement
retain separate acceptance requirements.

The unreleased [synchronization snapshots](docs/public/sync-observation.md)
preserve completion uncertainty, explicit need/change/error pages and actual
device/folder statistics. Synthetic file/index, active need and local-change
effects have dedicated native tests; snapshots do not certify business batches.

The unreleased [scan control API](docs/public/scan-control.md) adds explicit
relative subpaths, all-folder requests and partial periodic/watcher settings,
with actual index changes checked separately from configuration readback.

The unreleased [ignore-pattern API](docs/public/ignore-patterns.md) preserves
ordered engine rules, reports stored parser failures explicitly, and separates
clearing rules from restoring the engine's built-in defaults.

The unreleased [scheduling API](docs/public/scheduling.md) adds file pull-order
settings, explicit priority pages and global/per-device KiB/s limits. Native
queue and byte-cap effects have distinct mode and measurement conditions.

The unreleased [selective index API](docs/public/selective-sync.md) provides
actual trees, scoped search pages, opaque cursors and explicit mode settings.
Conditional selection requests report real Pro-license refusals as typed errors;
licensed selection and all-node removal effects remain unverified.

The unreleased [folder recovery API](docs/public/recovery.md) sends explicit
receive-only reversion, send-only override and marker-repair requests. Real
data, marker and identity observations remain separate from acknowledgements.

The [read-only three-node scenario](docs/public/three-node-relay.md) verifies
source handoff using real sharing permissions, complete file hashes and actual
protocol byte counters. Loopback evidence is separate from WAN acceptance.

[Fixed program sources](docs/public/program-sources.md) distinguish local paths
from explicitly selected official v2.33.2 artifacts, standard/legacy builds and
their ABI evidence. Selecting a source performs no download or execution.

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

`Client::connect(ConnectOptions)` reads the target's version and device identity
using an explicitly supplied `ApiKey`. It defaults to the fixed v2.33.2 version
policy. `expected_device_id` adds an exact out-of-band identity check; without
it, the authenticated identity is returned for inspection. An explicit
`VersionPolicy::AllowUnverified` permits experiments and marks the resulting
snapshot `Unverified`.

Run the future inside your Tokio runtime with I/O and timers enabled. Connecting
does not launch an engine or change its settings, and dropping a `Client` does
not stop it. Reads have deadlines and response-size limits. Automatic retries,
redirects and ambient proxies are disabled. The default `tls` feature enables
normal HTTPS certificate verification; it can be disabled for an HTTP/socket
build. Engine connection tests currently exercise private Unix sockets and
loopback HTTP; HTTPS engine acceptance is separate from enabling its transport.

The [connection example](examples/connect_existing.rs) accepts an explicit
`http` or `socket` address, an optional expected device ID, and then an optional folder ID. It reads the key
from `VERYSYNC_EXAMPLE_API_KEY`, never from command-line arguments. Use a
dedicated instance when trying examples. No endpoint is discovered or selected
automatically.

`client.instance()` is the immutable handshake snapshot. `client.version()` and
`client.system_status()` issue new authenticated reads; system status must match
the connected identity. `client.folder_status(&FolderId)` reads one configured
folder, encoding its opaque ID as one query value. Reconnect after replacing or
upgrading an engine to apply connection version/identity policy again.

Missing or null status metrics remain `None`, while a reported zero is
`Some(0)`. Unknown fields remain available in `extra`; unrecognized activity
states remain `FolderState::Unknown`. Unknown account/license values in system
status are data for explicit inspection, and ordinary status debug output omits
those extra values. An idle folder or zero reported need count does not certify
completion of an arbitrary file batch, every peer, or a business transaction.
A missing upstream folder is an error rather than a fabricated idle snapshot.

```rust
use verysync_sidecar::{Client, FolderId, FolderStatus};

async fn read_folder(client: &Client, id: &str) -> verysync_sidecar::Result<FolderStatus> {
    let id = FolderId::parse(id)?;
    client.folder_status(&id).await
}
```

`client.folders()` reads folder configuration snapshots; `client.folder(&id)`
returns an exact configured ID or `Error::FolderNotFound`. Target-reported paths
retain the target OS syntax. Use `CreateFolderOptions` with a `FolderId` and
`TargetPath` to register a new folder. The library reads this instance's defaults
and changes only the explicit ID, path, and optional label/paused overrides.

Creation rejects an existing ID and, by default, an identical configured path
string before POST; it serializes requests made through clones of one Client.
The fixed upstream POST can replace an existing ID and ignores the tested
conditional-write headers. Coordinate independent clients and external writers;
this is not an atomic create-if-absent transaction. Exact path checks do not
canonicalize aliases, symlinks or case; `allow_shared_path(true)` explicitly
permits identical configured strings when required.

A successful create returns current configuration readback. The engine may still
be preparing the directory or scanning it afterward. Inspect folder status for
activity and reconcile the ID before retrying after cancellation or
`Error::MutationOutcomeUnknown`; no modifying request is retried automatically.
The [folder creation example](examples/create_folder.rs) requires an explicit
instance, expected identity, new ID and absolute native path, and registers the
folder paused. It does not start or stop an engine. Remote paths should use the
target's explicit `PathStyle`, independently of the controller's host.

Use `FolderPatch::default().label("New label")` with
`client.update_folder(&id, &patch)` for a partial update. Only the requested
fields are sent; paths, device associations and other upstream settings are not
rewritten. `client.pause_folder(&id)` and `client.resume_folder(&id)` change
only that folder's configured pause setting. Check the returned
`FolderUpdate::requested_fields_match` and actual `configuration`: a false
match can reflect pending application or another writer's change. A readback
failure after PATCH is an unknown mutation outcome and is not retried.

Configuration readback and runtime activity are separate. In the fixed baseline,
a paused folder can report an empty activity string and zero counters; the
library retains `FolderState::Unknown("")` rather than interpreting this as idle
or complete. Dedicated-instance tests separately observe scan rejection while
paused and actual indexing of a newly added file after resumption. Other pause
layers, peer transfers and business batches require their own observations.
Folder item URLs encode IDs as one path segment. Literal `.` and `..` IDs are
rejected for updates before network I/O because URL normalization would change
the target. Configuration reads continue to use exact ID lookup.

`client.remove_folder_keep_files(&id)` unregisters one folder using only the
configuration DELETE, without a file-deletion parameter or request body. It
checks the fresh instance identity and exact configured ID first. The returned
`FolderRemoval` includes the previous configuration and `configuration_absent`
from a subsequent read. Check that flag rather than treating acknowledgment as
proof of absence: pending application or another writer can leave the ID visible.
Missing targets are errors and are never silently treated as completed removals.
The controller performs no filesystem deletion or inspection; independent
fixed-engine tests verify retained nested sample files and unchanged hashes.

Endpoint construction performs no I/O and never discovers an existing instance.
Supply an explicit Unix socket path or HTTP(S) base URL. Private LAN addresses
are accepted; URL user information, queries and fragments are rejected. Keep
credentials in connection authentication. Reverse proxy base paths are retained
and normalized to a trailing slash.

```rust
use verysync_sidecar::{ManagementEndpoint, PathStyle, TargetPath};

fn main() -> verysync_sidecar::Result<()> {
    let _endpoint = ManagementEndpoint::http("https://synthetic.invalid/control")?;
    let folder = TargetPath::remote(PathStyle::Windows, r"C:\Synthetic Data")?;
    assert_eq!(folder.to_protocol()?, r"C:\Synthetic Data");
    Ok(())
}
```

For local filesystem paths use `TargetPath::local(path_buf)`, composing paths
with native `Path::join` operations. Native encoding is retained until the
protocol boundary, where unrepresentable paths return `Error::PathEncoding`.
Remote paths require an explicit target style and are preserved without host
normalization. These values do not access files or start a management request.

Rust 1.85 or later is required. APIs use the caller's Tokio runtime. Adding this crate as a dependency and building it does not download or start VerySync, install a service, or configure global logging or signals.

Typed management failures retain their meaning. `Authentication` identifies HTTP 401;
`AccessDenied` retains bounded HTTP 403 diagnostics without guessing whether
the cause is a key, permission or license. `Http`, `InvalidResponse` and `Api`
distinguish non-success HTTP statuses, malformed typed responses, and a nonempty
error-only JSON envelope under a successful status. An ordinary state object
that also contains an error description remains status data. Other upstream
error shapes retain their operation's HTTP/schema behavior until verified.

`request_timeout` applies separately to each complete request and response body;
a multi-request operation can take longer than one deadline. A modifying
transport failure, timeout or failed readback returns `MutationOutcomeUnknown`
with its cause. Dropping a future stops waiting and yields no result; it does
not roll back an already sent request. Reconcile the exact ID before choosing
to retry. No modifying request is retried automatically. Dedicated-engine tests
apply a real creation before dropping/holding its response and verify the
applied configuration after lost response, deadline and cancellation.

Ordinary error Debug/Display excludes response bodies and credential-bearing
arguments. `ResponseDiagnostic::body_bytes()` explicitly exposes bounded
upstream data that may contain secrets; review it before logging. The crate
does not install a logger, signal handler or process-exit policy.

For an unmodeled operation, `client.raw_request(&request)` uses the same selected
endpoint, authentication, per-request deadline, response-body bound and disabled
redirect/retry policy. Build a `RawRequest` from `RawMethod`, path components and
an explicit `RequestEffect`; components and query values are encoded under the
configured base path. Host, authentication and framing headers cannot be
overridden. Bodies are explicitly buffered bytes or JSON, with no implicit file I/O.

```rust
use verysync_sidecar::{Client, RawMethod, RawRequest, RawResponse, RequestEffect};

async fn read_raw_version(client: &Client) -> verysync_sidecar::Result<RawResponse> {
    let request = RawRequest::new(
        RawMethod::Get,
        ["rest", "system", "version"],
        RequestEffect::ReadOnly,
    )?;
    client.raw_request(&request).await
}
```

Raw responses retain every HTTP status, duplicate headers and exact bounded body
bytes, including binary data and error-only JSON. A returned raw response means
the HTTP response was received, so inspect its status/body and reconcile effects;
it does not establish business success or typed support for that operation.
`MayModify` rechecks instance identity and serializes with typed modifications.
Declare effects correctly: some upstream GET routes change state. Transport or
body failures after a possible write remain unknown outcomes. Header/body values
are sensitive opt-in data, omitted from raw request/response Debug.

`library_capabilities()` exposes each narrow family's implementation and
recorded validation independently. `client.capabilities()` adds the handshake
target/controller coordinates and instance observations without sending requests.
Authentication is recorded at handshake time; unprobed operation permissions
and commercial licenses remain `Unknown`. Reconnect after replacing the engine
to obtain a new snapshot.

`MatchesRecordedCoordinates` checks the recorded version, OS/architecture pair,
transport and TLS build feature. It does not certify the current OS version,
translation environment or network. The evidence specifies modern native runners,
Unix sockets on macOS/Linux, and loopback HTTP on Windows with the default TLS
feature. Other combinations are outside that evidence, rather than declared
unsupported. Planned families stay `NotImplemented` / `NotRun`, and raw transport
retains its own status separately from typed feature coverage.

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo test --lib --locked
cargo test --test client_contract --locked
cargo test --test transport_contract --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo doc --no-deps --all-features --locked
```

Read the [initial alpha validation scope](docs/public/alpha-scope.md) and the [getting-started guide](docs/public/getting-started.md) for explicit connection, folder control, failure interpretation and actual example commands. The [complete management example](examples/manage_existing.rs) confirms create/update/resume/pause/unregister configuration readbacks on a deliberately chosen instance.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before running engine integration tests. Tests must use an explicitly supplied official executable, isolated state and synthetic data. The existing user instance is never a test target.

## API stability

All public APIs are unstable throughout alpha. Methods, modules, parameters, return values, configuration, errors, and events may be added, removed, renamed, or reorganized without backward compatibility. Compatibility layers for earlier alpha releases are not required. Pin an exact alpha version and review the changelog before upgrading.

Compatibility commitments begin with the first formal release. Compatible updates preserve existing usage; incompatible changes require an explicit incompatible version and migration guidance.

## Licensing

Project-owned code is licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. The official VerySync program and third-party dependencies remain subject to their own terms. The controller's license does not grant redistribution rights for the official program. No official executable is included in this repository or crate.
