# Contributing

Use Rust 1.85 or later and the locked dependency set. The default quality checks
are listed in the README. The CI quality workflow runs on standard hosted
Linux runners, with separate current-toolchain and MSRV jobs. These checks
establish source/build quality; they do not establish engine functionality.

Keep changes small and include tests for the observable behavior they change.
Document public interfaces in English, including error and completion semantics.
Alpha interfaces may change without compatibility adapters. The first formal
release begins compatibility commitments.

## Running engine tests

Engine test fixtures run separately from ordinary unit tests. Do not
point a fixture or manual request at an existing personal or production instance.
An engine test must require an explicit executable and checksum, create its own
private state, identity and management credential, and use an explicit private
socket or loopback address. Missing prerequisites must fail an explicitly
requested engine test, rather than produce a skipped passing acceptance result.

Set `VERYSYNC_TEST_BINARY` to the absolute path of a dedicated, verified official
v2.33.2 test executable and `VERYSYNC_TEST_BINARY_SHA256` to its executable
SHA-256. The fixture checks this digest before running anything, generates fresh
state and GUI credentials, authenticates a private management address, and
compares the generated identity before any mutation.

The fixture also writes `auto_startup: false` in its own `appconf.yaml` and
explicitly disables the tracker and tray options. Child processes use private
working, temporary and profile/cache directories; child HOME/XDG paths on Unix
and Windows profile/data environment paths are scoped to that state. On macOS a child sandbox denies non-loopback IP traffic
and file writes outside the fixture. These controls apply to helpers as well as
the serving process, and never change host startup settings or a firewall.
On Windows, fixture engines start suspended and join a private Job Object before
resuming. The job contains descendants, uses kill-on-close, and is explicitly
terminated and checked when a fixture unwinds. A separate panic-path test checks
that the entire job becomes empty. Normal shutdown must empty it without force.
The state directory has a protected owner/System DACL; the configuration and
private key ACLs are inspected too, using native ACL queries and SID equality.
A negative check grants an extra reader to an empty test directory and verifies
that the permission check rejects it. These are test-harness controls, not public
library lifecycle guarantees.

```sh
cargo +1.85.0 fetch --locked
python scripts/run-isolated-engine-tests.py --toolchain 1.85.0 \
  --test-target engine_control --evidence-dir "<absolute-new-private-evidence-dir>"
```

The explicit runner also accepts `managed_instance`, `example_control` and the
native `managed_lifetime` target. It starts a test-only loopback HTTP proxy
that returns 403 without forwarding. Only hostnames/method counts are recorded;
credentials, query values and headers are excluded. A separate loopback canary
tests that neither HTTP nor CONNECT reaches a forwarding destination. The core
can attempt maintenance/NAT HTTP requests despite disabled discovery/relays;
this wrapper blocks the observed requests without installing a global proxy,
firewall or persistent process. It is not an OS-wide no-egress proof. Runtime
dependencies are prepared first; the runner uses offline Cargo execution.

The `engine-tests` feature selects tests that require this explicit environment;
it does not download or launch an engine when the crate is built or imported.
Invoking the engine tests without the variables fails. The ordinary `--lib`
quality check does not run engine tests and cannot establish their acceptance.

The `upgrade_engine` target additionally requires an explicitly prepared pinned
v2.33.1 `VERYSYNC_TEST_UPGRADE_SOURCE_BINARY` and
`VERYSYNC_TEST_UPGRADE_SOURCE_SHA256`, plus the verified baseline
`VERYSYNC_TEST_ARCHIVE`. `prepare --upgrade-source` prepares only the older
six-target test fixture and exports its separate variables; it does not change
the default baseline. Its dedicated writable copies are the only executables
modified by native upgrade tests. `check-cleanup --upgrade-source` independently
checks the original older fixture image.

Only `upgrade_engine` may select `--allow-upgrade-metadata` and
`--serve-pinned-upgrade-archive`. This explicit test exception permits end-to-end
TLS to `upgrades.verysync.cn:443` and serves only the exact already size/SHA-verified
local v2.33.2 archive for the fixed official HTTP asset URL. Every other external
host remains blocked by the proxy. Reports accurately mark external metadata
forwarding and do not claim loopback-only or OS-wide no-egress isolation. The
tests refuse a changed provider version instead of downloading an unknown
program. Plain fixture tests retain their default blocking behavior.

For explicit test preparation, `scripts/prepare-test-engine.py prepare` accepts
one of the six alpha package IDs from the fixed release manifest and a `--parent`
directory. It downloads with HTTPS validation, verifies archive size/SHA-256,
and writes only the selected executable into a newly created private directory.
Its JSON receipt contains the executable path and digest for the variables above.
`--archive` permits an existing archive with the same pinned checksum; no latest
release is selected. The helper never starts the program or installs bundled
service samples. CI uses Python 3.13 and runs its extraction safety tests before
using the helper. No official program archive, executable or raw state is
uploaded as an artifact.

The `Engine fixture` workflow runs matching official engines and native Rust
1.85 toolchains on six standard hosted runners, while quality checks also use
the current compiler. The `engine_control` target combines the earlier fixture
contracts with public API acceptance so shared harness checks run only once.
Tests are named to distinguish fixture evidence from public control behavior;
fixture success alone is not complete lifecycle acceptance.
The helper's explicit `check-cleanup` command inspects only the exact test binary
path and reports lingering processes; it does not kill by name.

The optional `lifetime_probes` target investigates native process mechanisms;
it is not the production managed-instance implementation. On macOS its explicit
underlying runner is `scripts/run-macos-lifetime-probes.py`, which requires the prepared
engine environment, a Rust toolchain, and a new absolute evidence directory.
It compiles a standalone Rust test host into a private temporary directory and
tests only its own processes, groups and PTY. Host SIGKILL, native exit and
observer fallback are recorded separately. An unsupported platform or missing
prerequisite fails the explicitly requested probe; it does not pass as skipped.
On native Linux, `scripts/run-linux-lifetime-probes.py` additionally investigates
creating-thread termination, parent-death signal installation races, exec/fork
inheritance and whole-group outcomes. An isolated PTY is compared with the
parent-death signal; negative mechanism results remain explicit. These helpers
are test hosts only and do not add a product daemon or managed-runtime API.
On native Windows, `scripts/run-windows-lifetime-probes.py` runs an explicitly
filtered Rust test host to investigate last-Job-handle closure, forced host
termination, nested containment, startup failures and an explicitly non-killing
persistent candidate. Observers retain process handles, never the tested inner
Job handle. Ancestor Job restrictions remain applicable to persistence; modern
runner results do not establish Windows 7/legacy support.
Only sanitized result JSON enters CI logs; upstream programs, raw state, keys
and private logs are not uploaded.

Use `run-isolated-engine-tests.py --mechanism macos` (or `linux`/`windows` on the
matching native system) with the same toolchain/evidence arguments to wrap these
investigations too. The public `managed_lifetime` target is separate: dedicated
hosts call `ManagedInstance`, then actually return, exit without destructors or
undergo forced termination (SIGKILL on Unix). Native process observations must confirm core exit before any
fallback. An unrelated exec case verifies its process identity/start time while
the core exits, then explicitly stops and observes that test process as well.
Windows retains a separate outer Job throughout the verdict to test an existing
caller Job and avoid confusing observer cleanup with SDK-owned termination.
Do not rename successful mechanism probes as public-library acceptance.

The `events` engine-test target uses the public subscription API for real
configuration/state events, bounded backpressure, newest-tail gaps, ahead
cursors, actual shutdown and same-identity restart recovery. Run it through the
same isolated HTTP proxy wrapper (`--test-target events`). The default-feature
`events_contract` target separately exercises synthetic schema, finite recovery,
backpressure and cancellation of actual pending HTTP connections; it does not
count as real-engine effects. Never print raw configuration-event payloads.

The `operations` engine-test target separately checks public whole-folder scan
requests and actual phase observations, file-index effects, cancellation of
only the observer and paused-target rejection. Run it with `--test-target
operations` through the same isolation wrapper. Scan contracts in
`events_contract` use synthetic transport and failure responses. A successful
request, an observed phase exit and synchronized files are separate verdicts.

The `sharing` engine-test target exercises actual key generation/validation,
target-bound preparation, read-only/read-write registration and typed rejections.
Its controlled loopback fixture uses only two task-owned engines and explicit
loopback listeners/peer identities; discovery, relays and NAT remain disabled.
No fixture setup is a typed device-management or WAN acceptance claim. Keep
sharing keys out of all logs and publish only effect flags.

Use synthetic files. Disable discovery, trackers, relay, NAT and external
connections unless the particular network case requires them. Await only owned
child processes when cleaning up; never kill by executable name. Keep private
keys, raw configurations and diagnostics containing credentials out of logs,
commits and artifacts. A successful request is not evidence that a transfer,
shutdown, restore or upgrade completed.

When the source directory is synchronized by another program, configure
`CARGO_TARGET_DIR` outside that directory to avoid synchronization placeholders
interfering with compiler caches. Keep that machine-specific choice local.

## Public content

The repository tracks source, tests, English user documentation, CI and sanitized
metadata. Local internal plans, archived discussions and private research are
excluded. Do not add upstream engine archives/executables, account credentials,
real device identities or business data. Download official programs directly
from the fixed upstream links only when explicitly running the relevant test
or application API; never from a Cargo build script.

Native process containment and private state creation use small platform modules under `src/managed/native`. These modules locally permit audited unsafe OS calls with safety comments; the crate-wide unsafe-code deny lint remains in effect elsewhere. Keep blocking filesystem/process reaping on the private owner thread and test actual effects on the native matched controller/engine targets.

Native engine acceptance runs on pull requests and explicit workflow dispatches.
The same accepted source tree is not automatically run again merely because its
PR was merged. The lighter quality workflow still runs on main pushes. A direct
main change requires an explicit native workflow dispatch before claiming native
acceptance; an absent run is never a passing result.
