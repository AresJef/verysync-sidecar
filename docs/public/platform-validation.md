# Platform validation

The fixed v2.33.2 catalog contains 21 packages within the agreed Linux, macOS
and Windows scope. `docs/platforms.csv` retains each package's exact identity,
candidate Rust target, execution mode and remaining conditions. Preparing a
verified archive is separate from compiling this crate or running the core.
The two FreeBSD catalog entries are outside the agreed operating-system scope.

The main engine workflow runs six matching standard 64-bit core/controller
combinations on native hosted runners. Its accepted evidence, current candidate
results and individual feature conditions must be distinguished. A failed or
cancelled candidate is not an accepted platform revision.

The [additional-platform run for source 712ea2e](https://github.com/AresJef/verysync-sidecar/actions/runs/43709925411)
passed all 13 selected jobs with matching fixed archives and controller targets.
Those logs verify the selected default-TLS management, managed-instance and
lifetime suites, explicit examples and exact cleanup. This is evidence for that
source and those conditions; newer candidate helpers and the full feature set
still require their own same-source acceptance. The inventory retains native,
compatibility and emulation classes rather than combining them into a native
hardware or minimum-system support claim.

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
LoongArch64, RISC-V64 and S390x passed their selected pinned QEMU profiles;
PPC64LE passed the explicit POWER9 profile, retaining the earlier POWER8 SIGILL
without claiming a native minimum ISA.

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

The diagnostic catalog in `.github/native-diagnostic-matrix.json` retains the
explicit profile, compiler target, native test filter and trace selection for
every helper case. Ready-for-review and manually dispatched Engine workflows
schedule the complete catalog. The independent six-profile complete native
matrix, additional-platform acceptance and final outcome/cleanup gates remain
required.

An owned draft can select current investigation labels in
`.github/native-diagnostic-selection.json`. The current selection investigates
actual full-index resend across a fixed-version upgrade on all six standard profiles. The
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
