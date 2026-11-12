# Getting started

`verysync-sidecar` controls the official VerySync program through an explicit
management connection. The official synchronization engine remains a separate
program with its own license. The crate does not download or start it when added
as a dependency or compiled. This release's `Client` borrows a running instance;
dropping it leaves that instance running.

The development version has not been published yet. Use a local path dependency
or pin a reviewed Git revision during development. Once an alpha is published,
pin its exact version: all alpha interfaces can change without compatibility
layers. Rust 1.85 or later and a caller-owned Tokio runtime with I/O and timers
are required. The validated engine baseline is exactly **v2.33.2**; changing it
requires an explicit `VersionPolicy::AllowUnverified` choice.

## Choose a dedicated instance

For learning and integration tests, prepare an independent official v2.33.2
instance with its own state directory, device identity, management credentials,
explicit communication address and synthetic files. Do not point experiments at
an instance containing real data. Obtain the API key and device ID from that
chosen instance; the crate never discovers another running instance.

Use `ManagementEndpoint::unix_socket(PathBuf)` for an absolute Unix socket, or
`ManagementEndpoint::http(url)` for an explicit HTTP(S) base URL. Private LAN
addresses and reverse-proxy base paths are accepted. URL user information,
queries and fragments are rejected. HTTPS validates certificates normally;
successful native HTTPS-engine acceptance is outside the currently recorded
Unix-socket/loopback-HTTP evidence.

Keep API keys out of command arguments, logs and source. The examples read
`VERYSYNC_EXAMPLE_API_KEY` from their environment. Set it locally through a hidden
terminal input or your own secret manager; do not send the key in a chat.

## Connect and inspect

```rust
use std::path::PathBuf;
use verysync_sidecar::{ApiKey, Client, ConnectOptions, DeviceId, ManagementEndpoint};

async fn connect_dedicated(
    socket: PathBuf,
    key: String,
    expected_id: &str,
) -> verysync_sidecar::Result<Client> {
    let options = ConnectOptions::new(
        ManagementEndpoint::unix_socket(socket)?,
        ApiKey::new(&key)?,
    ).expected_device_id(DeviceId::parse(expected_id)?);
    Client::connect(options).await
}
```

Connection reads the version and identity before returning. `instance()` keeps
that handshake snapshot. `version()` and `system_status()` perform fresh reads;
a fresh system identity must still match. A version read does not reset the
handshake version policy. Reconnect after replacing or upgrading the engine.

`capabilities()` is a synchronous snapshot with no new requests. Library
implementation, historical validation, current version/platform/transport
coordinates and unprobed instance permissions/licenses are separate. Matching
coordinates do not certify the current OS version or network. Consult each
entry's actual evidence scope.

## Register and control a folder

Compose local paths with `Path`/`PathBuf` and native `join` operations, then use
`TargetPath::local`. For another target OS, use `TargetPath::remote` with an
explicit `PathStyle`; the controller does not normalize remote paths. A path
that cannot be represented by the management protocol fails without lossy
conversion. Folder IDs remain opaque values.

```rust
use std::path::PathBuf;
use verysync_sidecar::{Client, CreateFolderOptions, FolderConfig, FolderId, TargetPath};

async fn register_paused(
    client: &Client,
    id: &str,
    local_path: PathBuf,
) -> verysync_sidecar::Result<FolderConfig> {
    let options = CreateFolderOptions::new(
        FolderId::parse(id)?, TargetPath::local(local_path),
    ).paused(true);
    client.create_folder(&options).await
}
```

Creation retains upstream defaults and rejects existing IDs and identical
configured path strings by default. An explicit `allow_shared_path(true)` permits
an intentional identical string. Symlinks, case aliases and independent writers
are not part of that check. The upstream POST is an upsert, so coordinate other
writers; the precheck is not an external atomic transaction.

`folders()` and `folder(&id)` read exact current folder configuration.
`update_folder` with `FolderPatch` sends only explicit label/pause fields.
`pause_folder` and `resume_folder` change only folder-level pause configuration.
Check each `FolderUpdate::requested_fields_match` and its actual configuration;
false can mean pending application or another writer's change.

`remove_folder_keep_files` sends only the configuration DELETE, with no file
deletion switch or body. Check `FolderRemoval::configuration_absent` after the
write. A missing ID is an error. The library does not inspect or delete local
files; fixed-engine tests separately verify retained directories and hashes.

## Interpret observations and failures

Configuration acknowledgment/readback, directory preparation, runtime activity,
indexed counts and actual peer/batch completion are different observations.
`folder_status` preserves optional metrics and unknown activity strings. In the
fixed baseline, a paused folder can report an empty state and zero counters;
`Unknown("")` is retained and must not be interpreted as completed work.

Each request has a complete-response deadline and a bounded buffered body.
Multi-request operations can take longer than one request deadline. Errors
distinguish authentication, ambiguous access denial, HTTP, typed schema and
known error-only body envelopes. Diagnostic bodies and raw headers may contain
secrets and require explicit inspection before logging.

After `MutationOutcomeUnknown`, read the exact ID before choosing to retry.
Dropping a future stops waiting and produces no result; already sent work can
still apply. The crate never retries modifying requests. The fixed engine's
state may need reconciliation even when the caller saw a timeout.

`raw_request` preserves every HTTP status, duplicate headers and exact bounded
bytes, with caller-declared read-only or possibly modifying effects. A raw HTTP
response requires protocol/business interpretation by the caller. Raw transport
does not make an unimplemented typed feature supported.

## Run the examples

Build them explicitly with `cargo build --examples --locked`. For a chosen
dedicated instance, run the compiled `connect_existing`, `create_folder` or
`manage_existing` executable. Pass arguments as separate native arguments;
replace the placeholders below with your chosen values.

```text
connect_existing <http|socket> <address> [expected-device-id] [folder-id]
create_folder <http|socket> <address> <expected-device-id> <new-folder-id> <absolute-local-target-path>
manage_existing <http|socket> <address> <expected-device-id> <new-folder-id> <absolute-local-target-path>
```

The complete management example registers paused, updates a label, confirms
resume/pause configuration and unregisters while retaining files. It reports
configuration readbacks and does not claim peer-transfer completion. It leaves
the explicitly chosen engine running.

Native evidence currently covers matched controller/engine macOS, Windows and
Linux on amd64/arm64 with default TLS-enabled builds, Unix sockets on macOS/Linux
and loopback HTTP on Windows on the selected modern runners. Other transports,
minimum OS versions, remote controller/engine pairs and licensed feature effects
retain their separate validation gates. Owned runtime, events/tasks, P2P control,
downloads/upgrades and the remaining planned families are still being developed.
