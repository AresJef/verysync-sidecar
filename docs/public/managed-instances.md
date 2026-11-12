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
launchers. Startup cancellation/recovery, inherited
signal/descriptor stress, intentional persistence and full platform UI/lifetime
acceptance continue in the same development plan. Modern native runner evidence
does not establish other architectures, minimum systems or cross-network scope.

The capability catalog reports this initial runtime subset as `Typed/Pending`
while the remaining lifecycle and platform gates are under development.

Management requests default to a separate 10-second deadline, configurable with
`management_request_timeout`; the total startup deadline remains independent.
Private program diagnostics are read with a 64 KiB bound. The owner periodically
resets its private core capture; output is never forwarded to a caller-global
logger. Diagnostic bytes require explicit inspection/redaction.

## Explicit shutdown and termination

`shutdown(total_timeout)` first rechecks the selected identity, sends one typed
normal-shutdown request, then waits for the exact process tree and state lease to
finish. A successful HTTP response is only acknowledgement. Inspect the returned
`ManagedExit` code/signal, `tree_stopped` and `forced`; an already observed exit is
returned without a second request.

```rust
use std::time::Duration;
use verysync_sidecar::{ManagedExit, ManagedInstance};

async fn close_dedicated(instance: &mut ManagedInstance) -> verysync_sidecar::Result<ManagedExit> {
    instance.shutdown(Duration::from_secs(10)).await
}
```

The deadline covers the identity check, API request and exit wait together.
Authentication/business failures retain the normal typed errors; a possible
write without a conclusive response remains an unknown outcome. No request is
retried automatically. Timing out or cancelling the wait leaves the owner intact
and does not revoke a request the core may already have applied. Reconcile with
`wait_for_exit()` before choosing another explicit action.

`force_stop(total_timeout)` is a separate choice that signals the existing private
owner thread to terminate only its retained group/Job and confirm actual exit.
It bypasses management authentication, can interrupt work and cannot be undone
by cancelling the wait. It is never selected implicitly by `shutdown`. Invalid
zero deadlines are rejected before sending either action. Dropping the owner
still follows its documented cleanup policy. Borrowed `Client` objects gain no
implicit lifecycle responsibility from these methods.

On macOS, exit observation queries native private-group membership and process
state. Exited zombies are not treated as running members; an incomplete or denied
inspection remains a failure to confirm exit. The retained direct child is reaped.


## Restart the owned generation

`restart(total_timeout)` normally shuts down the current generation and starts
with its retained local program, state, endpoint and startup settings. It returns
success only after the new generation authenticates as the persisted identity and
accepts management queries. The total deadline covers both phases; the configured
startup timeout still bounds the new start. Restart rechecks the selected program
and any expected SHA-256 before execution.

```rust
use std::time::Duration;
use verysync_sidecar::ManagedInstance;

async fn restart_dedicated(instance: &mut ManagedInstance) -> verysync_sidecar::Result<()> {
    instance.restart(Duration::from_secs(30)).await?;
    let fresh = instance.client().system_status().await?;
    println!("Restarted device: {}", fresh.device_id);
    Ok(())
}
```

Successful restart replaces the owner's Client, PID, program information and exit
observation. Identity, API credential, private key/certificate, folders, unrelated
settings and local files are retained. Existing borrowed Client clones keep their
previous connection metadata; reconnect when a fresh snapshot matters.

If normal shutdown fails or times out, restart retains that owner and does not
start another process or select force. If the old generation stopped but the new
start fails, the object retains the old exit observation and options for an
explicit retry. Its `wait_for_exit()` then describes the **old generation**. The
failed startup requests its own exact cleanup; an immediate retry can find its
lease still busy while that cleanup completes. There is no automatic retry,
credential replacement, data reset or rollback. Zero total deadlines do nothing.

This owned operation uses normal shutdown followed by explicit startup. It does
not claim a typed implementation of the official `POST /rest/system/restart`
route for borrowed instances; that direct system action remains separately
tracked in the complete capability inventory.

Native tests record startup/restart UI observations separately from authenticated
readiness: macOS queries the owned process group's CGWindow/AppKit registration;
Windows queries owned descendants' top-level windows and console association from
a separate probe process; Linux runs without DISPLAY/Wayland. Desktop runs compare
visible windows of named common browsers with their baseline, without collecting
window titles or contents. These observations are scoped to the runner's current
session, do not visually inspect every menu/tray icon, and do not establish a
minimum OS or every possible browser. Further host-exit and platform UI/lifetime
gates remain in the same full-delivery plan.
