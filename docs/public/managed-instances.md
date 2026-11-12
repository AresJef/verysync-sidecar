# Managed instances (unreleased)

This guide describes the **0.1.0-alpha.2 development API**, not the published
initial alpha. Use a reviewed checkout/path dependency to evaluate it. The
published `0.1.0-alpha.1` controls an explicitly selected running instance.

`ManagedInstance` owns a selected local official **v2.33.2** program and a
dedicated persistent state directory. `Client` remains borrowed management
access: cloning or dropping a Client does not acquire or release process
ownership. Construction and compilation never download or start VerySync.

```rust
use std::path::PathBuf;
use verysync_sidecar::{LocalProgram, ManagedInstance, ManagedOptions, ManagementEndpoint};

async fn open_dedicated(
    executable: PathBuf,
    new_or_owned_state: PathBuf,
    explicit_address: ManagementEndpoint,
) -> verysync_sidecar::Result<ManagedInstance> {
    let program = LocalProgram::new(executable)?;
    // Use program.expected_sha256(digest) when a trusted executable digest is available.
    let options = ManagedOptions::new(program, new_or_owned_state, explicit_address)?;
    ManagedInstance::start(options).await
}
```

The caller supplies a Tokio runtime with I/O/timers, an absolute executable path,
an absolute state path whose parent already exists, and an explicit endpoint.
On Unix use `state.join("gui.sock")`; the portable socket path limit is checked.
HTTP uses a literal loopback IP and an explicit nondefault port, with no proxy
prefix or TLS. Startup does not discover a running instance or choose a default
management address. State must be representable losslessly by the program's
UTF-8 configuration protocol; local filesystem operations retain native paths.

Startup acquires an exclusive library lease and checks an existing official
`verysync.lock` before writing configuration. An ordinary existing application
directory, symlink/reparse control resource, unprotected state or busy lease is
rejected. The new directory is private from creation: owner-only on Unix, and a
protected owner/SYSTEM DACL on Windows. The program's identity, GUI/API credential,
folders and unrelated settings persist across subsequent starts. Fresh state
disables discovery, trackers, relays, NAT, automatic upgrades and tray/browser
startup; explicitly configured later networking settings are retained.

The executable's actual SHA-256 is recorded, an optional expected checksum is
checked before execution, and its actual CLI version must report exactly v2.33.2.
Keep a caller-provided executable stable while starting it: an external writer
can replace its bytes after inspection. CLI credentials travel through private
stdin/configuration, never command-line arguments or ordinary Debug output.
Configuration changes use a private synchronized temporary file and atomic
replacement; malformed or partial identity/configuration is not silently reset.

The private owner thread retains the native child/containment and state lease.
Unix uses a separate session and private PTY; Windows assigns a suspended,
hidden child to a noninheritable kill-on-close Job before resuming it. Linux's
fixed-program inner-process environment is version-specific. There is no
production supervisor executable, installed service, caller-global logger,
signal handler or exit hook. Dedicated startup helpers are temporary invocations
of the explicitly selected official program.

Startup returns only after authenticated management readiness and comparison
with the persisted device identity. Spawn, HTTP acknowledgement, configuration
readback and process-tree exit are separate observations. `wait_for_exit()` sends
no shutdown request; it waits for actual exit/empty native containment and release
of the state lease. A timeout around that wait leaves the owner intact. Dropping
the owner requests exact cleanup; a cloned management Client does not keep it
alive. Await an explicit exit observation when completion matters.

Do not independently launch or modify the same state while its library owner is
active. The library lease coordinates SDK owners; handing the official lock back
immediately before the core acquires it is not an atomic protocol with unrelated
launchers. Normal typed shutdown/restart, startup cancellation/recovery, inherited
signal/descriptor stress, intentional persistence and full platform UI/lifetime
acceptance continue in the same development plan. Modern native runner evidence
does not establish other architectures, minimum systems or cross-network scope.

The capability catalog reports this initial runtime subset as `Typed/Pending`
while the remaining lifecycle and platform gates are under development.
