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

File-history failure traces retain the original deadline and error, reporting
elapsed time, the bounded SDK error chain, HTTP status/size and boolean checks
of synthetic data. They omit bodies and private values and issue no extra
native requests. A later pass alone does not establish an intermittent cause.

The core version assertions use the observed Go architecture names (`amd64`,
`arm64`, `386` and `arm`) for their corresponding Rust controller targets. Unknown
mappings fail explicitly. Additional-architecture execution does not promote the
capability report into the six recorded 64-bit native profiles: those controllers
must still report `OutsideNativeEvidence`, including builds without default TLS.

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

Unix fixture commands start in a private process group. Panic cleanup signals
that group only while its retained, unreaped root still reserves the group ID
and the ownership check matches. A previously reaped root is never used to
signal a possibly reused group. Synthetic process tests require a positive
descendant inventory and verify panic cleanup; exact official-core inventory
remains a separate gate. This test-fixture behavior does not replace the public
managed-runtime lifecycle tests.

The native Unix fixture panic case also requires positive exact-executable
inventory and verifies that no matching image survives outside its original
group. A separate public managed-owner panic case catches caller unwinding,
checks exact exit and lease release, retains identity files, explicitly restarts
the same state and requires normal shutdown. These distinguish test-fixture
cleanup from the library's ready-owner cleanup.

The independent Linux fixture explicitly selects the official direct-core
environment mode (`VSMONITORED=yes`), matching the SDK's Linux launch mode.
Unix group creation uses a child-only pre-exec `setpgid` call, including under
emulation. Exact-image absence remains required alongside group absence, so a
detached descendant cannot make cleanup pass.

The additional Linux matrix prepares four separate emulated profiles:
LoongArch64/LA464 with the LP64D GNU sysroot and GCC 14, PPC64LE/POWER9,
RISC-V64/rv64 and S390x/max. Each records its exact compiler, target, sysroot,
fixed QEMU image and emulator SHA, registration flags, and official ELF headers.
An independent Rust canary must preserve arguments through registered and
explicit execution and reject the original unpadded explicit form. Both native
version-launch paths must pass the selected fixed CPU before the SDK cases run.
There is no automatic fallback to a different CPU or a no-TLS runtime suite.
The default-TLS management, startup and host-exit suites retain positive core
inventory, normal shutdown and exact-image cleanup requirements. These are
emulated execution candidates; native hardware, minimum kernel/libc and the
remaining feature suites require separate evidence. The Rust 1.85 LoongArch
target enables LSX; selecting LA464 does not establish a native minimum ISA.

PPC64LE also runs a standalone Rust catch-unwind/drop canary before any SDK
panic case. POWER8 failed both standalone unwind paths; POWER9 and POWER10
passed both paths. POWER9 is now the explicit candidate, while POWER8 failures
remain recorded and no minimum native ISA is inferred. Another model cannot
replace the selected profile's result. A failed standalone unwind prevents starting a native
core for those SDK cases. This separates runtime prerequisites from SDK cleanup.

S390x zero-CPU observations require the exact empty response, bounded guest
procfs shape, declared profile and the fixed core's ghw v0.13 build record.
Only that verified parser limitation is recorded as native empty CPU data,
with `cpu_positive=false`. Other cases still require positive CPU data.
The SDK neither substitutes hardware nor changes returned counts.

The four MIPS candidates explicitly build the Rust 1.85 standard library from
its matching `rust-src` component. `cargo-mips-std.py` requires a declared MIPS
target, the frozen compiler, an explicit custom-std marker and a pre-existing
per-job `RUSTC_BOOTSTRAP=1`; it does not set bootstrap or edit Cargo configuration.
This is an experimental custom-toolchain route. Cargo's supported `build-std`
workflow requires nightly; these checks are not stock distributed Rust 1.85
standard-library support. The source-lock hash is verified independently.
Arguments, unwind/Drop, default-TLS linking and actual SDK lifecycle effects
remain separate required checks. The fixed container image lacks ELF32 MIPS
interpreters. Those two profiles explicitly extract Ubuntu's fixed
`qemu-user-static` 1:8.2.2+ds-0ubuntu1.16 amd64 package without installing it;
the workflow pins both the package and each selected interpreter by SHA-256.
The reviewed Debian `-binfmt-P` naming convention preserves argv0 through both
registered and padded explicit execution. MIPS64 keeps the existing pinned
9.2.2 image. ELF32 registrations are created only on disposable CI VMs with
exact endian/class/machine selectors and PF flags; existing entries are never
replaced. This is an explicit change of emulation profile, not a CPU fallback.
No registration or custom compiler configuration is applied by the library.
The [Ubuntu package record](https://packages.ubuntu.com/noble/qemu-user-static)
and [file list](https://packages.ubuntu.com/noble/amd64/qemu-user-static/filelist)
identify the two ELF32 interpreters. The matching fixed Debian source archive
contains `linux-user-binfmt-P.diff`, which defines the selected argv0 convention.

The MIPS candidate first requires the existing authenticated management test.
Failure retains its original deadline, bounded transport/error classification
and exact cleanup. The remaining suites stay unexecuted and required, so the
final job fails; an absent readiness prerequisite cannot turn into acceptance.
Fixture summaries omit error messages and URLs while retaining reqwest flags,
native I/O error kinds and errno, without sending another request.

The Unix dependency graph pins `libc` 0.2.186. The reviewed 0.2.190/0.2.191
GNU architecture selection omits MIPS64 and selects generic socket type values;
the observed MIPS64 management failure reports EPROTOTYPE (errno 98).
A MIPS64 GNU compile-time assertion requires the native stream/datagram values
before any runtime claim. See the [affected bindings](https://github.com/rust-lang/libc/blob/ccc2ff4aaab962f7fde7b8edda7379c045b1ca12/src/new/glibc/sysdeps/unix/linux/mod.rs)
and [GNU MIPS socket definitions](https://github.com/bminor/glibc/blob/glibc-2.39/sysdeps/unix/sysv/linux/mips/bits/socket_type.h).
Dependency updates must preserve that ABI assertion and pass the actual
management/lifecycle gates. Registry files and caller toolchains are unmodified.

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

The isolated upgrade proxy records at most 64 official metadata tunnel summaries:
connection/total durations, transferred byte counts, completion and EOF/timeout
classification. It retains no TLS contents, headers, raw error messages or
credentials. Pending records are explicitly incomplete. The native provider
check also reports its single-read elapsed time and selected 10-second management
request deadline; no automatic retry or deadline extension is introduced. These
observations distinguish test transport stages and do not prove the cause of an
older CI failure without those fields. All existing upgrade data/identity/hash
and exact process cleanup assertions remain required.


Only `upgrade_engine` may select `--allow-upgrade-metadata` and
`--serve-pinned-upgrade-archive`. This explicit test exception permits end-to-end
TLS to `upgrades.verysync.cn:443` and serves only the exact already size/SHA-verified
local v2.33.2 archive for the fixed official HTTP asset URL. Every other external
host remains blocked by the proxy. Reports accurately mark external metadata
forwarding and do not claim loopback-only or OS-wide no-egress isolation. The
tests refuse a changed provider version instead of downloading an unknown
program. Plain fixture tests retain their default blocking behavior.

For explicit test preparation, `scripts/prepare-test-engine.py prepare` accepts
an in-scope package ID from the fixed release manifest and a `--parent`
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
The focused Linux device-removal diagnostic job runs the original condition
twice in independent private states. Both raw outcomes and exact cleanup remain
required; a later success cannot override a failure. These observations are
separate from the complete native feature bundle.
The native authentication suite verifies stored GUI disable as the fixed
v2.33.2 limitation: one explicit PATCH, persisted false flag, an unchanged
eight-second passive exact-image monitor/worker listener observation, retained
identity/data and separately selected process cleanup. It starts with an empty
exact-image inventory and requires a positive owned-listener observation before
the request. It never reserves the address or probes a released endpoint. Missing
observations fail; continued listening is recorded as unsupported live
hot-disable. The earlier closure failure and bind-reservation false positive
remain historical evidence; a duplicate diagnosis-only job is no longer needed.
The active-need fixture explicitly selects and reads back a five-second native
redial interval on both private instances before creating its peer observations.
This is an owned test condition, not an SDK retry or production default. An
initial connection can close while peer/folder configuration is being established;
a default twenty-second redial gap can consume the complete preparation window.
The original CI failure remains evidence, and a local passing baseline alone
does not establish that intermittent cause or validate the new platform condition.
The active-need fixture first receives a small readiness file at normal speed,
then applies the explicit 1 KiB/s receive limit and creates the original 1 MiB
payload. Resuming, readiness, rate selection and nonempty-need observation share
one original 20-second preparation window. Complete-byte transfer, receive-only
edit and content/mtime restoration retain their original 40/15/15-second
observation windows. Normal exit and exact cleanup keep their separate gates.
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

The FTP disconnect fixture traces the single explicit Stop request without
changing its workload, deadline or retry count. It reports state booleans and
operation/run identity matches, excluding identifiers and native payloads. On
failure it unwraps only the SDK uncertainty to its credential-safe error, prints
response status/byte metadata, and permits at most two seconds of concurrent
read-only status/run observations. It then returns the original Stop error;
observations never rescue the test or automatically repeat a control request.
A later passing run does not establish the cause of an earlier native failure.

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
