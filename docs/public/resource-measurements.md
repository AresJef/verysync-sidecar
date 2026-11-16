# Resource measurement evidence

The explicit `resource_usage_engine` target runs one registered workload against
an isolated owned VerySync instance: idle, an 8 MiB download, a 128 MiB download,
or 256 separate 8 KiB files. Source generation uses a fixed 64 KiB buffer. Every
transfer checks its receipt and actual bytes; source data, configuration, identity,
and normal owned-process-tree shutdown are checked separately.

`scripts/measure-native-resources.py` observes only the controller PID supplied
by that fixture and its verified engine descendant. It verifies loaded executable
paths and hashes, uses explicit start/end handshakes, and retains raw monotonic
timestamps, RSS in bytes, and cumulative process CPU seconds. Build, startup,
source generation, sampler setup and large-file independent verification are
outside the operation timer. The measured transfer loop includes destination
creation, SDK hashing/writes/flush, receipt checks and removal between repeated
fresh-output transfers. The many-file workload also checks each output's bytes
inside the loop. Normal I/O and asynchronous waits remain part of elapsed time.

RSS values are sampled resident memory, not instantaneous kernel high-water
marks. Sampling gaps and boundary-read intervals must accompany results; missing
or inadequately observed windows are insufficient evidence. Controller figures
include the constant-size test harness buffers. Engine figures describe the
separate owned engine root. No system-wide process search is used.

Install the fixed optional measurement dependency only in your test environment:

```console
python -m pip install -r scripts/resource-test-requirements.txt
```

Preparation supports explicit `--stage calibration` and `--stage pilot` runs with
a fresh absolute `--evidence-dir`. A pilot also requires `--cargo`, the explicit
fixed-program test environment, and a registered `--scenario`. Preparation is
never mixed into formal samples.

The frozen configuration is `tests/fixtures/resource-protocol.json`. After explicit
fixed-core preparation and release compilation, collect with:

```console
python scripts/collect-native-resources.py --stage all \
  --protocol tests/fixtures/resource-protocol.json \
  --cargo /absolute/path/to/cargo --toolchain 1.85.0 \
  --evidence-dir /absolute/fresh/evidence
```

Four formal cycles and two independent cycles use balanced opposite orders. Each
cycle contains all four scenarios; each scenario starts a fresh real controller
and owned native process. A complete cycle is accepted atomically only after all
original-order members pass frozen quality, source, artifact and process identity
checks. Failed and insufficient attempts remain recorded. An insufficient cycle
retries its original order with a fixed attempt limit; errors stop collection.
`--resume` preserves the saved deadline, attempts and immutable accepted groups.

Collection coverage and resource conclusions are separate. The frozen controller
memory criterion compares the conservative sampled RSS envelope for 8 MiB and
128 MiB files, with a 16 MiB increase limit and an 8 MiB repeat-span screen. These
are operational observations in that tested range, supported by the streamed
implementation; they do not establish instantaneous peaks or universal asymptotic
bounds. Engine RSS/CPU curves and absolute latency are reported separately, with
no invented upstream efficiency target or baseline speedup. Formal results and
the final resource report remain pending.

The v2 protocol preserves all quality and memory thresholds. It increases the
small/large batch repetitions to 128/8 after Linux AMD64 produced sub-500 ms
windows. The historical Darwin observer used a kqueue nanosecond timer with
`NOTE_CRITICAL` to request minimal coalescing; it changes no global timer, power
setting or process priority. A balanced sleep/critical-timer calibration retains
actual wakeup gaps on each CI host. CPU calibration retains the original read-cost
window and adds bounded self-process work before native startup so a sub-tick
window cannot be mistaken for a valid zero counter. Typed calibration errors are
retained. All v1 evidence and failures remain separate; new source dependencies
require complete new formal and independent cycles.

Each actual CI profile must complete both opposite preparation orders before its
formal run starts, using the frozen readiness policy described below. Preparation
failures retain their typed errors and metrics; they never become formal samples.
The historical Darwin timer flags follow
[Apple's public event header](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/event.h).

The v3 source identity includes explicit creator-owned state-lease release and
uses psutil's per-snapshot `oneshot()` context to share underlying kernel reads.
The live PID identity check remains outside and before each context; its cache is
cleared before the next snapshot. Every counter, read boundary and the 5% read-cost
limit remain required. This follows the pinned
[psutil 7.2.2 contract](https://psutil.io/7.2/#psutil.Process.oneshot).
The v2 macOS Intel pretrial exceeded that limit; its insufficient observation is
retained. Every v3 profile requires fresh preparation and complete new formal and
independent cycles. Earlier v1/v2 rows cannot supply v3 coverage.

Revalidate downloaded evidence offline using the exact frozen validation helpers:

```console
python scripts/report-native-resources.py \
  --protocol tests/fixtures/resource-protocol.json \
  --profile macos-arm64-standard=/absolute/extracted-artifact \
  --output /absolute/fresh/report-directory
```

Repeat `--profile registered-profile=directory` for all six registered profiles.
Each artifact root must contain one matching all-stage collection and its own
opposite-order preparation. For local evidence stored separately, add
`--preparation registered-profile=/absolute/pretrial-directory`. The reporter
never starts VerySync, compiles Rust, downloads files, or changes raw evidence.
It writes JSON and Markdown, returns 0 only for complete strict PASS, 2 for
INCONCLUSIVE, and 1 for failed criteria or invalid evidence. A partial profile
report remains INCONCLUSIVE overall even if that profile's memory criterion passes.

The reporter rehashes manifests and raw records, recomputes quality from all
snapshots, checks the independent process and binary identities, and preserves
all attempted-case counts. Its tables include all accepted slow and fast values;
JSON retains per-observation provenance, formal/independent statistics, CPU and
RSS curves, and the frozen memory envelope. RSS and CPU describe the controller
and the engine root separately; engine descendants are not included in root
counters. The latency relative-MAD screen is descriptive and does not introduce
a new latency target or replace the required RSS repeatability criterion.

The v4 protocol keeps every quality, workload and memory criterion. Durable JSON
records use explicit UTF-8/LF bytes, and each nested collector copies the exact
frozen protocol bytes before checking its digest. The Windows v3 parent/child
CRLF identity mismatch remains invalid evidence under its original identity.

From v4 through v18, after both real worker processes were ready, the short-lived Darwin observer
requested `QOS_CLASS_USER_INITIATED` only for its own current thread, retaining
the requested and observed class. Workers are started before that assignment;
the library, worker priorities and host-wide settings are unchanged. Other
systems retain their existing policy. This follows
[Apple's pthread QoS API](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/power_efficiency_guidelines_osx/PrioritizeWorkAtTheTaskLevel.html).
The request offers no scheduling guarantee: a gap over 50 ms still rejects the
whole original-order cycle. All v3 attempts, including the three insufficient
macOS ARM64 cycles, remain separate from the new v4 acquisition.

The v19 observer requests `QOS_CLASS_USER_INTERACTIVE` for its brief snapshots,
after both real workers are ready. It records the exact native class and policy
name; offline validation rejects a mismatched receipt. This candidate follows
v18 traces with 80 ms to over one second between observations, predominantly
inside the native wait, while metric-read overhead remained within its original
limit. It changes neither worker priorities nor library behavior, counters,
timestamps, workloads, formal and independent quotas, or quality thresholds.
The scheduling request offers no guarantee: a gap over 50 ms still rejects the
complete original-order cycle. Native API failures remain errors. Calibration
and preparation are separate evidence and never become formal samples.

Resource CI also retains observer and native worker console logs, including
failures before the first ready event. An exit code without its diagnostic log
does not establish a root cause. Earlier datasets with omitted logs retain
that limitation.

The v20 identity includes the library's remote version-archive URI selection.
Resource worker routines, the observer and all measurement requirements are
unchanged, but the complete measured Rust source is frozen again. Earlier
datasets retain their own source identity and are not v20 formal members.

The v5 identity includes the corrected bounded WOW64 helper query. It also
retains diagnostic durations for journal polling, the preceding raw-record write
and timer wait, so an observer gap can be investigated from its original trace.
An unobserved preceding interval is null. These diagnostics do not replace a
required counter, alter an operation timestamp, or relax the sampling-gap check.
Actual preparation must validate the extra recording before new formal data;
v1-v4 samples retain their own identities.

The v7 observer retains every raw metric row in a bounded in-memory buffer and
persists the complete UTF-8/LF journal after its owned workers have stopped.
The 32,768-row bound fails an attempt on overflow and preserves the recorded
prefix; it never drops observations to satisfy coverage. The observer's memory
is separate from the measured controller and engine processes. The preceding
buffer-append duration is recorded as `previous_record_buffer_ns`.

This change follows a v5 macOS Intel observation where a 125.3 ms sampling gap
contained 124.7 ms of record writing. It does not fix or excuse scheduler/timer
gaps: separate v5 macOS ARM64 and Windows ARM64 gaps remained above 50 ms, and
the first local v7 preparation also remained insufficient. Native correctness
and complete measurement-quality acceptance remain separate. Earlier attempts
retain their original source/protocol identities and strict results.

Draft pull requests run actual calibration and both full preparation orders.
Formal/independent collection runs when the candidate is ready for review or is
explicitly dispatched. A green preparation-only job does not establish resource
coverage or acceptance; all six complete formal/independent reports remain
required. This keeps changing library sources from invalidating repeated formal
collections before the implementation candidate is stable.

The v15 observer distinguishes an empty kqueue return, an error event (including
its flags and native error data), and a failed syscall. It records the failed
wait interval and preserves the original acquisition error alongside the actual
owned-worker exit result, even if bounded cleanup also fails. Saved acquisition
or cleanup failures remain `ERROR` during offline revalidation. No failed wait is
retried or converted into a sample. Sampling methods, workloads, quality limits,
formal coverage and deadlines remain unchanged; earlier evidence keeps its
original protocol identity.

The v17 Darwin observer uses one blocking `mach_wait_until` call for each
absolute deadline. It obtains the architecture-specific conversion with
`mach_timebase_info`, rounds the requested interval up to whole native ticks, and
records that ratio and period. A delayed wakeup advances to the first future
deadline; it never fills missed observations, spins, or adjusts recorded sample
timestamps. Nonzero native returns, early returns and unrepresentable deadlines
remain errors. Other platforms keep their existing wait method.

The interface and conversion follow [Apple's Mach time header](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/osfmk/mach/mach_time.h)
and its [archived unit-conversion explanation](https://developer.apple.com/library/archive/qa/qa1398/_index.html).
This replaces the periodic kqueue mechanism after an actual Intel CI attempt
returned no event after a one-second wait. It is a measurement candidate, not a
scheduling guarantee or a claim that unrelated platform gaps are fixed. Both
opposite preparation orders and complete new formal/independent evidence remain
required on every profile. All original workloads, metric reads, timing
boundaries, 50 ms coverage limit, other quality/resource criteria and acquisition
deadlines remain unchanged; earlier failures and datasets retain their identities.

Protocol v18 retains the v17 observer and every formal quality/resource rule. It
changes preparation admission: execute all eight cases in the two original
opposite orders, require native correctness/source/calibration for every case,
and require at least one entire order with four `VALID` cases. A coverage or other
mechanical `INSUFFICIENT` case in the other order remains a recorded rejection;
it is never a formal member. Any native, identity, counter, source or acquisition
error still stops preparation immediately. Neither order may be reconstructed
from selected members of the two trials.

This distinguishes a bounded readiness trial from the final evidence. Formal
collection still requires four complete original-order cycles and two complete
independent cycles, with every accepted member satisfying the original 50 ms,
5% and all other frozen checks. Its original deadlines and retry limits remain.
The offline reporter recomputes readiness from all eight raw trials and shows
their valid/insufficient counts separately from formal attempts. No qualifying
preparation order means incomplete readiness and `INCONCLUSIVE`, even when formal
data is otherwise complete. Protocols without this policy retain the old strict
preparation rule. Old rejected trials and all earlier datasets keep their original
identities; v18 binds both the changed preflight and offline reporter hashes.
