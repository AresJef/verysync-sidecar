# verysync-sidecar

A general-purpose Rust library for managing and controlling the official VerySync program. The goal is complete coverage of its actual programmable capabilities, with explicit version, platform, license, and verification conditions.

The project is under active development. The current API provides explicit endpoints, target paths, and authenticated connections with version/identity checks, and fresh typed system/folder status reads. Further management operations are being implemented and tested. No crate has been published yet. Runtime acceptance is tracked per operation and platform; successful engine fixture tests alone do not establish control-library functionality.

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

```sh
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo test --lib --locked
cargo test --test client_contract --locked
cargo test --test transport_contract --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo doc --no-deps --all-features --locked
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before running engine integration tests. Tests must use an explicitly supplied official executable, isolated state and synthetic data. The existing user instance is never a test target.

## API stability

All public APIs are unstable throughout alpha. Methods, modules, parameters, return values, configuration, errors, and events may be added, removed, renamed, or reorganized without backward compatibility. Compatibility layers for earlier alpha releases are not required. Pin an exact alpha version and review the changelog before upgrading.

Compatibility commitments begin with the first formal release. Compatible updates preserve existing usage; incompatible changes require an explicit incompatible version and migration guidance.

## Licensing

Project-owned code is licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. The official VerySync program and third-party dependencies remain subject to their own terms. The controller's license does not grant redistribution rights for the official program. No official executable is included in this repository or crate.
