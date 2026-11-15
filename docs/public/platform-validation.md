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
pending execution candidates. Passing this slice does not validate every
storage protocol, upgrade, licensed feature or minimum operating system.

ARM32, MIPS, LoongArch64, PPC64LE, RISC-V64, S390x and the two Windows legacy
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
