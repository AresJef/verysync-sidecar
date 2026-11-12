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
Unix child processes also receive state-local HOME and XDG profile/cache paths;
the caller's environment is not changed. Windows retains its dedicated
APPDATA/LOCALAPPDATA/USERPROFILE and temporary paths.

The executable's actual SHA-256 is recorded, an optional expected checksum is
checked before execution, and its actual CLI version must report exactly v2.33.2.
Keep a caller-provided executable stable while starting it: an external writer
can replace its bytes after inspection. CLI credentials travel through private
stdin/configuration, never command-line arguments or ordinary Debug output.
Configuration changes use a private synchronized temporary file and atomic
replacement; malformed or partial identity/configuration is not silently reset.

The private owner thread retains the native child/containment and state lease.
Unix uses a separate session and private PTY whose master/slave descriptors are
close-on-exec at allocation, without an open-then-fcntl inheritance interval.
Windows assigns a suspended,
hidden child to a noninheritable kill-on-close Job before resuming it. Direct
inner-process mode on Linux/Windows is specific to the fixed program baseline.
There is no production supervisor executable, installed service, caller-global logger,
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
launchers. Intentional persistence and further platform UI/lifetime
acceptance continue in the same development plan. Modern native runner evidence
does not establish other architectures, minimum systems or cross-network scope.

The capability catalog reports this initial runtime subset as `Typed/Pending`
while the remaining lifecycle and platform gates are under development.

Management requests default to a separate 10-second deadline, configurable with
`management_request_timeout`; the total startup deadline remains independent.
Private program diagnostics are read with a 64 KiB bound. The owner periodically
resets its private core capture; output is never forwarded to a caller-global
logger. Diagnostic bytes require explicit inspection/redaction.

## Startup cancellation and partial state

Dropping the actual `ManagedInstance::start` future, or allowing its configured
startup deadline to expire, closes the startup ownership channel. The private
native owner thread terminates and reaps only its retained processes, then
releases the state lease. This cleanup does not require the Tokio runtime to
continue running: shutting down a runtime drops its pending startup tasks too.
Dropping a task's `JoinHandle` alone detaches the task and does **not** cancel its
startup. Abort the task or retain and cancel the actual future when that is the
intended action.

Cancellation requests cleanup asynchronously; it is not a synchronous process
exit acknowledgement. An immediate explicit retry can encounter `ManagedStateInUse`
while cleanup completes. Do not remove the lease/state or assume that a free
lease alone proves all processes exited. The native tests first observe the
actual private core PID before cancellation, then independently enumerate that
exact executable until no process remains, separately check lease release and
authenticate an explicit retry using the original identity.

The directory, identity, private key/certificate, configuration and caller files
remain available after cancellation. A missing half of the key/certificate pair
or existing configuration without a complete identity is rejected without
silently generating a replacement identity or resetting configuration. Persisted
key, certificate and configuration resources must remain private regular files;
links/reparse resources, including dangling links and the persisted identity and
completion markers, are rejected before any metadata helper or identity generation.
A dangling link, including the official state lock, is never treated as an absent file. A missing configuration with
retained keys, or malformed configuration, is also rejected. Preserve the original files and repair or
restore them explicitly before retrying. The tests restore only their own
synthetic fixture's original files and verify identity and sample hashes.

## Unix caller lifetime

The default Unix ownership policy retains the private PTY master in the caller.
Ordinary owner drop requests exact termination; exiting the caller closes its
owned descriptors, including when the caller skips destructors or is killed.
The core receives its own default HUP disposition and unblocked signal mask in
the new child only. The caller's ignored/blocked HUP settings are preserved.

Dedicated test hosts invoke the public API, authenticate their real core and
then return, exit without destructors or undergo actual SIGKILL. A separate
test keeps an unrelated exec child alive after the caller dies: the core must
exit while that child is still independently observed, before the test stops
the unrelated process. Exact-program inventory confirms absence before any
fallback; identity/sample hashes and another isolated instance are checked,
then an explicit retry must authenticate the retained identity. The test host
is a test executable, not a production supervisor.

These cases cover ordinary exec inheritance on the tested Unix systems. Code
that deliberately retains or duplicates the private ownership descriptors
outside the normal exec boundary can retain the terminal connection. Intentional
persistence is a separate API policy under development. Stopping an in-flight transfer
can interrupt work; use explicit normal shutdown when the caller can cooperate.

## Windows caller lifetime

The caller owns an unnamed, noninheritable Job handle. The library assigns its
suspended core to that Job before allowing execution; the Job terminates its
remaining processes when its last handle closes. Dedicated test hosts exercise
ordinary return, exit without destructors and actual forced termination inside
an existing caller Job. The observer retains that outer Job while confirming
the SDK's core has exited, so observer cleanup cannot supply the passing result.

An unrelated child launched after startup must remain alive while the core
exits. The test then stops and independently observes that child, checks the
outer Job is empty and retries the retained identity explicitly. These cases
cover the tested nested Job configuration on the recorded Windows runners;
arbitrary restrictive ancestor Jobs can reject assignment, which is a startup
error. They do not establish compatibility with every host Job policy. The
forced-exit case also records native window/console observations separately.

The official core can issue maintenance/NAT HTTP requests even with discovery
and relays disabled. Runtime tests use a temporary nonforwarding loopback HTTP
proxy to reject those requests. Proxy observations do not establish an OS-wide
egress restriction, and the library does not install a global proxy or firewall.

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


Windows console association is recorded separately from an **additional** console.
The official core can share its caller's existing console. Native mutual process
membership verifies that sharing; it is not classified as a new console/window.
The independent test probe calibrates absent and newly allocated console cases
inside its own temporary process, then frees its calibration console. Acceptance
rejects an additional/unverified owned console or a newly visible console window,
while preserving the raw association/member observations. It does not detach or
hide the caller's existing console.
