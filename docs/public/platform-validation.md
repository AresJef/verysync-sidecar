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

The additional platform workflow uses a 32-bit Rust host toolchain and matching
32-bit core for Linux x86 on an x64 Linux host and Windows x86 through WOW64.
Its first execution slice checks real management/file effects, managed startup
and cancellation, process ownership, host exit, peer lifecycle and synthetic
sharing, with exact executable cleanup. Until these jobs pass, these remain
pending execution candidates. The Linux x86 Rust host requires the explicit
32-bit loader, C/C++ runtime and zlib packages. Windows x86 default TLS builds
require NASM; the job installs the fixed Chocolatey 2.16.3 package (NASM
2.16.03), retaining the default TLS and assembly configuration. See the
[upstream Windows build requirements](https://aws.github.io/aws-lc-rs/requirements/windows.html).
Passing this slice does not validate every
storage protocol, upgrade, licensed feature or minimum operating system.

The first ARM32 execution slice selects the three separate official packages
and matching Rust targets: ARMv5 soft float, ARMv6 soft float and ARMv7 hard
float. It uses pinned QEMU bytes, an explicit emulated CPU and a matching GNU
controller sysroot. The fixed core ELF files inspected for these three packages
have no dynamic interpreter or dynamic program segment, despite reporting CGO
enabled. That observation does not establish a minimum kernel or native runtime.

ARM jobs remain pending until their real core/controller management, file,
startup, cancellation and host-exit effects pass. A positive exact-core process
inventory is required before absence can mean successful cleanup. User-mode
emulation can change process observation and signal behavior; those are tested
conditions, not automatic exceptions to the original deadlines or exit gates.
Other feature suites, native ARM hosts and minimum systems retain separate gates.

Emulated process observation explicitly binds the selected core's argument and
mapped file identity to the declared emulator or original executable image,
with stable process-birth checks. An unverified empty snapshot is insufficient
for cleanup acceptance. Bounded version probes record each explicit CPU model;
a different model's success cannot validate the requested model. A successful
version probe is neither Rust runtime acceptance nor minimum-native-ISA proof.
The probe uses the same private controlling stderr terminal and bounded stdout
file as the Rust metadata helper, an independent process session and child-only
signal settings. Each selected CPU retains the original 12-second probe limit.
A plain pipe launch is a different condition; its timeout does not prove that
the same CPU cannot run the library. Timeout cleanup targets only the exact
unreaped child's private group, and the job still requires exact-core cleanup.

MIPS, LoongArch64, PPC64LE, RISC-V64, S390x and the two Windows legacy
packages retain separate execution requirements. Cross compilation, user-mode
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
