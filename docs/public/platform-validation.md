# Platform validation

Find your system and processor in [the platform table](../platforms.csv).
Use the evidence for your exact combination. A native run used the target
program on the corresponding architecture. Compatibility or emulation tests
ran the selected program through a compatibility layer or emulator. A compile
or link result verifies that a build was produced. Notes name the source and
conditions for those historical observations.

The fixed v2.33.2 catalog contains 21 packages within the agreed Linux, macOS
and Windows scope. `docs/platforms.csv` retains each package's exact identity,
candidate Rust target, execution mode and remaining conditions. Preparing a
verified archive is separate from compiling this crate or running the core.
The two FreeBSD catalog entries are outside the agreed operating-system scope.

The main engine workflow runs six matching standard 64-bit core/controller
combinations on native hosted runners. Its accepted evidence, current candidate
results and individual feature conditions must be distinguished. A failed or
cancelled candidate is not an accepted platform revision.

## Verified release baselines

Release 0.1.0 and the corresponding official VerySync v2.33.2 program passed
management authentication, real file operations, restart, expected failures and
exact process cleanup on the following systems. These were the earliest
verified GitHub standard hosted systems for their OS and CPU combinations
under the release's R31 support rule. The recorded version and build come
from the actual jobs.

| System | CPU | Observed version and build | Release evidence |
| --- | --- | --- | --- |
| Linux GNU | x64 | Ubuntu 22.04.5 LTS, 6.8.0-1070-azure | [Native job](https://github.com/AresJef/verysync-sidecar/actions/runs/44913798518/job/136874972750) |
| Linux GNU | ARM64 | Ubuntu 22.04.5 LTS, 6.8.0-1070-azure | [Native job](https://github.com/AresJef/verysync-sidecar/actions/runs/44914019215/job/136875649261) |
| macOS | Intel x86_64 | macOS 15.7.9, 24G830 | [Native job](https://github.com/AresJef/verysync-sidecar/actions/runs/44694441058/job/136209870439) |
| macOS | Apple Silicon ARM64 | macOS 15.8.2, 24H232 | [Native job](https://github.com/AresJef/verysync-sidecar/actions/runs/44694441058/job/136209870533) |
| Windows Server | x64 | Server 2022 Datacenter, 10.0.20348 | [Native job](https://github.com/AresJef/verysync-sidecar/actions/runs/44694441058/job/136209870411) |
| Windows desktop | ARM64 | Windows 11 Enterprise, 10.0.26200 | [Native job](https://github.com/AresJef/verysync-sidecar/actions/runs/44694441058/job/136209870581) |

Both Ubuntu jobs reported kernel build #78~22.04.1-Ubuntu. The standard
Windows x86 controller and core also ran through WOW64 on the x64 Server 2022
host, with management, file, restart and cleanup effects.
[WOW64 job](https://github.com/AresJef/verysync-sidecar/actions/runs/44694440919/job/136160928736)

The older macOS and Windows systems previously considered for validation
retain their historical untested status. The x64 Windows result applies to
the server edition, and the desktop result applies to ARM64.

The 0.1.1-rc.2 native regression used Ubuntu 24.04.5 LTS in the two Linux jobs,
the listed macOS builds, Windows Server 2022 x64 and Windows 11 ARM64. Use the
individual candidate jobs to check the actual behavior and exceptions.
[RC2 native run](https://github.com/AresJef/verysync-sidecar/actions/runs/44998190581)

## Earlier compatibility runs

The [additional-platform run for source 712ea2e](https://github.com/AresJef/verysync-sidecar/actions/runs/43709925411)
passed all 13 selected jobs with matching fixed archives and controller targets.
Those logs verify the selected default-TLS management, managed-instance and
lifetime suites, explicit examples and exact cleanup. This is evidence for that
source and those conditions; newer candidate helpers and the full feature set
still require their own same-source acceptance. The inventory retains native,
compatibility and emulation classes rather than combining them into a native
hardware or minimum-system support claim.

Candidate `6c650422` passed the selected runtime suites for 13 additional
targets with the matching fixed v2.33.2 archives. The suites exercised
management and file effects, startup, cancellation, state reuse and owned host
exit. The two x86 compatibility jobs also exercised peer lifecycle and
key-based sharing. The same candidate linked the `connect_existing` and
`manage_owned` examples for both Win7 targets on Windows Server 2022.
That run used selected features on modern hosts. Older Windows releases
remain historically untested.
[Candidate additional-platform results](https://github.com/AresJef/verysync-sidecar/actions/runs/44337786187)

## Windows legacy program examples on a modern runner

Source `6f9387c` built four original examples with Rust 1.85, default TLS
features and the custom standard libraries for the two Win7 targets. Each
example set then controlled the matching fixed v2.33.2 legacy program on
Windows Server 2022 build 20348 through explicit loopback HTTP. The
`i686-win7-windows-msvc` set ran under WOW64 and the
`x86_64-win7-windows-msvc` set ran as a native x64 process.

The two runtime cases per target exercised authenticated attachment, folder
creation and removal with unchanged file digests, and managed persistence
across example exits. The owned example also verified reconnection to the same
identity, normal termination and exact process cleanup. Windows 7/8 and
Server 2008/2012 remain historically untested. Use the release baseline above
for minimum validated systems. [Both legacy program jobs](https://github.com/AresJef/verysync-sidecar/actions/runs/44388241515)

## Older Linux guest kernels

Source `83942f5` used the matching fixed VerySync v2.33.2 and a Rust 1.85
default-TLS controller linked against glibc 2.17. Each offline full-system QEMU
guest verified loopback management authentication, folder creation, native
file write and download with matching bytes and digest, restart with the same
identity and folder, and normal process exit with the state lock released.

| Controller target | Debian guest kernels | Runtime evidence |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `2.6.32-5-amd64`, `3.2.0-4-amd64` | [x86-64 results](https://github.com/AresJef/verysync-sidecar/actions/runs/44367172923) |
| `i686-unknown-linux-gnu` | `2.6.32-5-686`, `3.2.0-4-686-pae` | [32-bit results](https://github.com/AresJef/verysync-sidecar/actions/runs/44369946963) |
| `aarch64-unknown-linux-gnu` | `3.16.0-6-arm64` | [ARM64 results](https://github.com/AresJef/verysync-sidecar/actions/runs/44373632836) |

Each guest had initialized entropy, a working Unix PTY and a root CA from the
corresponding Debian archive. In each CA-absent control, the default TLS
client failed to initialize, even for loopback HTTP. The engine still answered
its health request and released the exact process and state lock after the SDK
deadline. The upstream minimum, other Linux architectures, remaining
minimum-system checks and final same-source suites retain separate evidence
requirements.

For s390x, the official v2.33.2 executable refused version initialization on
Debian's `3.2.0-4-s390x` guest. The Go 1.23.10 runtime requires the vector
facility bit in the kernel's `AT_HWCAP` report. Identical program and shell
bytes on the same QEMU CPU reported that bit clear on Debian 3.2 and set on
Debian `4.9.0-13-s390x`. In this contrast the earlier guest reached its
deadline and the latter printed the expected version and exited normally.
Full Rust SDK management, file and lifetime checks on the vector-capable
guest remain pending. [Original startup refusal](https://github.com/AresJef/verysync-sidecar/actions/runs/44381696057)
· [Guest-specific CPU and version results](https://github.com/AresJef/verysync-sidecar/actions/runs/44389860206)
· [Go 1.23.10 startup check](https://raw.githubusercontent.com/golang/go/go1.23.10/src/runtime/os_linux_s390x.go)

The additional platform workflow uses a 32-bit Rust host toolchain and matching
32-bit core for Linux x86 on an x64 Linux host and Windows x86 through WOW64.
Its first execution slice checks real management/file effects, managed startup
and cancellation, process ownership, host exit, peer lifecycle and synthetic
sharing, with exact executable cleanup. These selected compatibility effects passed on source 712ea2e; the remaining
feature and minimum-system conditions stay pending. The Linux x86 Rust host requires the explicit
32-bit loader, C/C++ runtime and zlib packages. Windows x86 default TLS builds
require NASM; the job installs the fixed Chocolatey 2.16.3 package (NASM
2.16.03), retaining the default TLS and assembly configuration. See the
[upstream Windows build requirements](https://aws.github.io/aws-lc-rs/requirements/windows.html).
Passing this slice does not validate every
storage protocol, upgrade, licensed feature or minimum operating system.

The first ARM32 execution slice selects the three separate official packages
and matching Rust targets: ARMv5 soft float, ARMv6 soft float and ARMv7 hard
float. It uses pinned QEMU bytes, an explicit emulated CPU and a matching GNU
controller sysroot. Controller tests execute through the registered interpreter.
The pinned binfmt image defaults to preserving argv[0]; explicit invocation
supplies a separate target argv[0]. A standalone Rust canary checks registered,
corrected explicit and old unpadded argument handling before any core starts,
including the single-thread test flag. This follows the upstream
[preserve-argv0 patch](https://github.com/tonistiigi/binfmt/blob/master/patches/preserve-argv0/0001-linux-user-default-to-preserve-argv0.patch).
The fixed core ELF files inspected for these three packages
have no dynamic interpreter or dynamic program segment, despite reporting CGO
enabled. That observation does not establish a minimum kernel or native runtime.

The generic ARM package's ARM926 candidate terminated with SIGILL through both
registered and explicit execution. That result remains in the CPU calibration
and its original failed candidate. A separate runtime candidate explicitly selects
ARM1176, where both version routes passed, while retaining the ARMv5TE Rust
controller target. This is not an automatic CPU fallback, native ARM evidence,
or a minimum-ARMv5 claim. The package's actual minimum native ISA remains
unverified; its `GOARM=5` metadata alone does not establish that requirement.

The same fixed executable also returned SIGILL in a full-system ARM926
Versatile guest after Debian `3.2.0-4-versatile` booted with only loopback.
The guest then restarted and QEMU exited normally. A separate user-mode
comparison on the same host reproduced SIGILL on ARM926 and returned
`v2.33.2` on ARM1176 and Cortex-A9. The inspected ELF attributes report
ARMv6 and `arm1136j-s` alongside the Go build metadata `GOARM=5`.
The minimum native ISA still requires separate evidence.
[Full-system ARM926 result](https://github.com/AresJef/verysync-sidecar/actions/runs/44417958259)
· [Matched CPU comparison](https://github.com/AresJef/verysync-sidecar/actions/runs/44418527982)

A separate full-system Cortex-A9 fixture booted Debian's `4.9.0-13-armmp`
kernel with ARMEL glibc 2.24 and Rust 1.85.0's ARMv5TE GNU target. With the
archived Debian CA and default TLS, the Rust client authenticated to the fixed
v2.33.2 core, created a directory, wrote actual file bytes and downloaded 29
hash-verified bytes after the core restarted with its identity and data intact. The owned
program and state shut down normally. With the CA absent, the native health
endpoint still returned HTTP 200 and the SDK reached its original management
deadline, then released the exact program and state. Both QEMU guests had
only loopback and closed normally. Minimum native OS and kernel claims
remain pending.
[Debian Stretch ARMEL runtime effects](https://github.com/AresJef/verysync-sidecar/actions/runs/44423671149)

The ARMv6 package and its soft-float Rust controller passed the same
actual management, file, restart and no-CA cleanup cases in Cortex-A9
QEMU. That fixture booted Debian Wheezy's `3.2.0-4-vexpress` kernel and
used archived ARMEL glibc 2.24 with Wheezy platform trust.
[Older ARMv6 runtime](https://github.com/AresJef/verysync-sidecar/actions/runs/44426181994/job/135231507073)

The hard-float package reached SIGILL on the same Cortex-A9 and kernel
before version output. The recorded A32 instruction decodes as `udiv`,
which Cortex-A9 lacks. Both isolated guests ended normally. The same fixed
hard-float executable passed the full Rust management, file, restart and
no-CA cleanup cases on Cortex-A15 with Debian's `4.9.0-13-armmp` kernel,
the archived hard-float glibc 2.24 and matching platform trust. These
measurements cover the named full-system QEMU combinations. Other native
hardware and kernel minima still require evidence.
[Cortex-A9 refusal](https://github.com/AresJef/verysync-sidecar/actions/runs/44426181994/job/135231507265)
· [Cortex-A15 runtime](https://github.com/AresJef/verysync-sidecar/actions/runs/44427000751)
· [Arm hardware divide support](https://developer.arm.com/community/arm-community-blogs/b/architectures-and-processors-blog/posts/divide-and-conquer)

The three ARM jobs passed their selected real core/controller management, file,
startup, cancellation and host-exit effects on source 712ea2e. Each Unix case
observed an exact-core inventory of zero, one during the controlled panic, then
zero after cleanup. A positive inventory remains required before absence can
mean successful cleanup. User-mode
emulation can change process observation and signal behavior; those are tested
conditions, not automatic exceptions to the original deadlines or exit gates.
Other feature suites, native ARM hosts and minimum systems retain separate gates.

ARM emulation uses explicit optimization level 3 for the Rust development and
test profiles, retaining their debug assertions and overflow checks. This build
condition applies to both controller tests and their examples. Startup deadlines
include the controller's complete executable hash and native metadata helpers;
an unoptimized emulated controller can consume that budget before a serving
process exists. The original 12-second SDK-deadline test, 25-second normal startup
budget, positive process observation and cleanup requirements remain unchanged.
An early timeout records only private-stage existence flags and remains a failed
serving-process test. This profile change is not a throughput or native-CPU
performance claim, and no execution time is excluded as CPU noise.

Emulated process observation explicitly binds the selected core's argument and
mapped file identity to the declared emulator or original executable image,
with stable process-birth checks. An unverified empty snapshot is insufficient
for cleanup acceptance. Bounded version probes record each explicit CPU model;
a different model's success cannot validate the requested model. A successful
version probe is neither Rust runtime acceptance nor minimum-native-ISA proof.
The probe uses the same private controlling stderr terminal and bounded stdout
file as the Rust metadata helper, an independent process session and child-only
signal settings. Before each invocation it writes the SDK's private startup-
disabled application configuration. Each CPU is observed in independent states
through the SDK's registered direct-core execution and an explicit emulator
invocation. Each invocation retains the original 12-second limit. The requested
CPU must pass the SDK execution path itself; an explicit-emulator result cannot
replace it. Both results remain recorded, and neither establishes SDK runtime
acceptance. A plain pipe launch or missing startup configuration is a different
condition. Timeout cleanup targets only the exact unreaped child's private
group, and the job still requires exact-core cleanup.

The four MIPS packages passed the selected suites through explicit frozen
Rust 1.85 source/bootstrap custom standard libraries, GNU sysroots and pinned
interpreters. This experimental build mode is separate from distributed stock
standard libraries and official stable build-std support. MIPS64 GNU socket ABI
constants are guarded at compile time and libc is pinned to the verified
0.2.186 mapping; the earlier protocol-type connection failures remain historical
evidence. ELF32 MIPS uses the separately checksummed Ubuntu QEMU 8.2.2 static
package and reviewed binfmt-P alias; no package post-installation runs.

The two fixed ELF32 MIPS programs also returned their v2.33.2 versions and
exited in offline Debian `4.9.0-13-4kc-malta` full-system QEMU guests. Each
guest used the matching Release 2 kernel byte order, 24Kf CPU model and
256 MiB of memory. The first program-bearing initramfs failed to unpack
with 128 MiB. Earlier Debian 3.2 guests stopped during early memory setup
with both CPU models. Minimum native hardware requires separate evidence.
[Debian 3.2 CPU comparison](https://github.com/AresJef/verysync-sidecar/actions/runs/44429147303)
· [Exact Debian 4.9 versions](https://github.com/AresJef/verysync-sidecar/actions/runs/44431736967)

The Rust 1.85 MIPS32 controllers failed to link against the original
Stretch glibc 2.24. The Rust standard library and managed bootstrap both
require `getrandom`. The archived Buster O32 glibc 2.28 supplies the
symbol, and both controller binaries linked with the expected
`/lib/ld.so.1` interpreter. The first attempt with Buster stopped when
the guest fixture rejected that loader name.
[Stretch link results](https://github.com/AresJef/verysync-sidecar/actions/runs/44433606538)
· [Buster link and fixture results](https://github.com/AresJef/verysync-sidecar/actions/runs/44434639120)

With the fixture accepting the exact archived loader, both 24Kf guests
ran the Rust 1.85 default-TLS controller on the Debian Stretch 4.9 kernel
with Buster glibc 2.28. With the archived CA installed, each controller
authenticated to the fixed core, created a folder, wrote and downloaded 29
verified bytes and retained its identity and data after restart. With the
CA absent, both reached the original management deadline while the native
health endpoint returned HTTP 200. All four guests released the exact
core and state and exited normally. Evidence covers these named, offline
full-system QEMU combinations.
[MIPS and MIPSel Rust runtime results](https://github.com/AresJef/verysync-sidecar/actions/runs/44435447736)

LoongArch64, RISC-V64 and S390x passed their selected pinned QEMU profiles;
PPC64LE passed the explicit POWER9 profile, retaining the earlier POWER8 SIGILL
without claiming a native minimum ISA.

An offline QEMU pSeries POWER9 guest also ran the stock Debian Stretch
4.9.0-13-powerpc64le kernel with Debian Buster glibc 2.28. Both guests
executed a Power ISA 3.0 instruction and exposed only loopback. With the
archived CA, the Rust 1.85 controller authenticated to VerySync v2.33.2,
created a folder, performed a native file write, downloaded 29 verified
bytes and retained the identity and folder after restart. Without the
CA, the native health endpoint answered HTTP 200, and managed startup
reached its original deadline. Both guests released the exact process
and state. Separate evidence is required for native hardware, other
kernel or libc combinations, and the complete candidate feature matrix.
[PPC64LE full-system runtime evidence](https://github.com/AresJef/verysync-sidecar/actions/runs/44455214019)

Green native hardware-handling tests include faithful native limitations.
S390x's declared emulation profile reports an empty CPU inventory, and the
selected 32-bit GNU cores can return the known ghw memory arithmetic error.
These are retained native empty/error outcomes, not positive CPU or memory data
support, and the SDK does not substitute controller hardware data.

MIPS, LoongArch64, PPC64LE, RISC-V64, S390x and the two Windows legacy
packages retain their remaining feature and minimum-system requirements. Cross compilation, user-mode
emulation, compatibility execution and native execution are different evidence
classes. An emulator on a modern host does not establish an old kernel's
process-lifecycle behavior. Wine does not establish an actual Windows 7/8 or
Server 2008/2012 minimum. No unavailable runner, Rust standard library or test
license silently removes a target from the pending scope.

All runtime tests explicitly select a fixed program and use private state,
independent identities, controlled addresses and synthetic data. Download and
preparation are explicit CI operations; adding the Cargo dependency or compiling
the crate performs neither. The test helper never installs the program's service
or firewall examples. Native backend refusals, skipped tests and compile-only
results are not positive runtime support evidence.

## Focused native diagnostics

Earlier source-bound focused results include six-profile temporary-index threshold
validation ([run 44040037108](https://github.com/AresJef/verysync-sidecar/actions/runs/44040037108)),
six-profile full-index resend after the explicitly pinned test upgrade
([run 44044835585](https://github.com/AresJef/verysync-sidecar/actions/runs/44044835585)),
and both Windows profiles for the retained sleep-request boundary
([run 44048891608](https://github.com/AresJef/verysync-sidecar/actions/runs/44048891608)).
The Windows result verifies explicit disabling plus normal stop and persistent
restart; automatic release within 150 seconds remains unreliable for the two
verified native fingerprints. [Configuration](configuration.md) describes each
fixture and its limits. These focused results retain their original source
identities and do not replace the complete integrated native matrix, resource
gates, additional-platform or minimum-system acceptance.

The diagnostic catalog in `.github/native-diagnostic-matrix.json` retains the
explicit profile, compiler target, native test filter and trace selection for
every helper case. Ready-for-review and manually dispatched Engine workflows
schedule the complete catalog. The independent six-profile complete native
matrix, additional-platform acceptance and final outcome/cleanup gates remain
required.

An owned draft can select current investigation labels in
`.github/native-diagnostic-selection.json`. The current selection investigates
actual Windows sleep requests and explicit normal-stop release of retained
requests on both standard Windows profiles. The
163-row complete catalog retains all 157 earlier cases, including concurrency,
failed-producer, Mac/Windows sleep and temporary-index threshold gates, alongside
six new upgrade-policy cases. Catalog tests
independently retain the required profile/filter mappings for every earlier
case; they do not force unrelated investigations into each draft. Missing
selection uses the whole catalog; empty, duplicate,
unknown or unsafe selections fail before scheduling. Fork pull requests keep
complete diagnostic coverage. Selection and cancellation of a superseded draft
are scheduling decisions, never successful capability acceptance. Completed
results retain their original producer and test identities.

When an ancestor draft still carries distinct required evidence, the explicit
boolean in `.github/native-diagnostic-preservation.json` can preserve those runs.
Without an explicit duplicate list, the retirement step returns before credential
access or cancellation API calls. A bounded list in
`.github/exact-native-retirements.json` can identify a specific redundant Engine
run by exact run/PR/commit identities and the complete changed-path/blob map from
its equivalent ancestor. Only a fixed set of observer/resource/documentation
paths is allowed; library, native-case and Engine-workflow differences are
refused. Every listed proof is checked before mutation, followed by fresh run
and open-draft checks. Completed, newly ready or otherwise ineligible runs stay
preserved and unaccepted. All unlisted native runs, resource/clock/quality runs
and ready candidates remain preserved. The bounded operation uses only its CI
job's ephemeral Actions token. This scheduling control does not accept any test or reduce the complete
ready/manual catalog or final native gates. The current concurrency investigation
preserves the separate priority and Windows sharing observations in PR #183.
The explicit `ci/exact-native-retirement-control-20261117-01a1ca9b` draft runs
only this maintenance job within the Engine workflow, allowing distinct pending
evidence to reach runners before redundant jobs. Its native jobs are skipped,
not accepted. Converting it to ready for review or manually dispatching the
workflow restores all ordinary Engine jobs and existing complete gates.

The separate Mac observer-timer workflow compares the existing absolute Mach
wait with a periodic kqueue timer using the Apple SDK's minimum-coalescing flag.
It retains four ABBA blocks of 64 waits at a requested 10 ms interval, complete
wall/thread-CPU readings, timer expiration counts and garbage-collection events.
The probe starts no native worker and changes only its own observer thread's
existing QoS. Clock diagnosis does not establish resource-sampling validity or
acceptance, and it does not change the frozen workload or quality thresholds.
