# Resource measurement evidence

Each result below belongs to its recorded software version, run and
measurement protocol. The legacy frozen resource workflow checks these
inputs before sampling. A new candidate with different inputs needs a new
recorded preparation and measurement before you can compare its resource use.

Protocol v27 binds literal external compilation inputs as well as Rust source
files. This includes the runtime release catalog and, conservatively, rustdoc
`include_str!` documents. Missing files, unsupported nonliteral includes and
paths outside the owned source tree fail identity collection. A local macOS ARM
current/old-document/current release build comparison produced identical test
binaries, but this does not establish equivalence on other architectures.
Fresh v27 preparation and complete formal/independent evidence remain required;
v26 and earlier observations keep their original identities and strict results.
Workloads, timing/quality/resource limits, original complete orders, process/data
checks and finite acquisition quotas are unchanged. No formal v26 acquisition
was started. This identity correction does not establish resource acceptance.


Protocol v26 binds the required Local Sync strict-TLS default reconciliation.
Its resource sampler, wrapper, observer activity, dependency lock, workload,
quality limits, four formal plus two independent fresh-process cycles, profile
environments, and finite acquisition quotas remain unchanged. The Rust source
has changed, so v25 results remain attached to their original producer. New
v26 native preparation and full resource acceptance remain pending.

## Retained v25 timestamp-repair evidence

Protocol v25 replaced Chrono with Jiff while retaining Rust 1.85. The
[source-bound v25 collection](https://github.com/AresJef/verysync-sidecar/actions/runs/44082376843)
was independently replayed: all six archive digests and 176 raw native cases
with 352 fresh process identities were checked. Linux AMD64/ARM64, Windows
AMD64/ARM64 and macOS ARM64 completed all four formal plus two independent
cycles, valid coverage, and both controller memory and repeat-span criteria.
The two rejected ARM Mac groups remain retained and contribute no accepted
members.

Intel macOS completed eight native preparation cases with correct data,
configuration, identity and normal exits, but only three windows were valid.
Neither complete order passed; formal collection did not start. Gaps up to
1,016.512 ms exceeded the unchanged 50 ms coverage limit. Recorded native waits
dominate the largest gaps; this does not identify an underlying host cause.
The complete six-profile resource conclusion remains inconclusive.

These results belong to producer `329e6680abd7dc5424e263ad2f41642112700642`,
tree `5ab134ee957f7208391c2d99e8930c317049e5ac`, protocol digest
`5c8938038b1722e47f2d35d42089fa81fe397bf27a9772ef188e01d35be262d8`.
They are not v26 samples. Intel retains the original standard
`macos-15-intel` environment and critical kqueue observer timer. A separate
bounded native diagnostic compared kqueue/Mach/Mach/kqueue with activity on
in every arm. Both Mach runs and the first kqueue run had insufficient coverage;
all four retained actual data and normal cleanup. No alternative was adopted,
and these explicitly bound diagnostic pilots cannot become frozen samples.

## Retained v24 observer configuration and evidence


Protocol v24 adds a scoped process activity request to the Darwin measurement
observer, after its owned native workers have started. It combines
`NSActivityLatencyCritical` with `NSActivityUserInitiatedAllowingIdleSystemSleep`,
ends the exact token during cleanup, and records both receipts. It does not
request idle or display sleep prevention or change system settings. Other
platforms keep their existing observer policy and record that this activity is
not applicable. The helper is part of the frozen source identity.

This is a distinct measurement configuration. The original 50 ms sample-gap,
5% read/boundary limits, workloads, complete fresh-process orders, four formal
cycles, two independent cycles, memory limits, and finite acquisition budgets
remain unchanged. All six profiles must complete fresh calibration and both
full preparation orders before their v24 formal results can be accepted. The
Intel preparation uses `macos-26-intel`. Historical v23 results remain tied to
their original source and are not members of v24.

The preceding Intel off/on/on/off diagnostic had one invalid off control,
two valid on runs, and a valid final off control. This supports testing the
explicit observer configuration; it does not establish a cause for the old
missed wakeups or guarantee formal collection will pass. A local ARM64
canonical pilot passed quality and owned cleanup. The retained v24 collection
then completed full formal/independent acceptance on five profiles; Intel
preparation remained insufficient and contributed no formal cycles. Those
results retain producer `4cc84a3` and tree `fd59fc0`, separately from v25/v26.

## Retained v23 evidence


Protocol v23 changes the Darwin observer's blocking wait to an owned periodic
critical kqueue timer. Rust workload/source inputs, native worker scheduling,
original orders, every quality/resource limit and acquisition controls remain
unchanged. All v22 and earlier results retain their original producer and source
binding. Complete v23 preparation, formal collection and independent cycles on
all six profiles remain required.

The retained [v23 collection](https://github.com/AresJef/verysync-sidecar/actions/runs/44020194748)
has source-bound, offline-replayed complete results on five profiles. Each has
four formal and two independent fresh-process cycles, valid measurement coverage,
the 16 MiB controller-envelope criterion and the 8 MiB repeat-span criterion.
The envelope is the actual conservative large-file peak minus small-file minimum;
a negative observed difference is retained.

| Profile | Accepted complete cycles | Controller envelope difference (bytes) | Resource/stability result |
| --- | --- | ---: | --- |
| Linux AMD64 | 4 formal + 2 independent | 299,008 | PASS |
| Linux ARM64 | 4 formal + 2 independent | 233,472 | PASS |
| macOS ARM64 | 4 formal + 2 independent | 16,384 | PASS |
| Windows AMD64 | 4 formal + 2 independent | 28,672 | PASS |
| Windows ARM64 | 4 formal + 2 independent | -114,688 | PASS |
| macOS AMD64 | None | Not concluded | INSUFFICIENT |

All six ZIP size/digest checks and 184 raw native cases were independently
replayed against producer `a6df5afb7e05f5fe6f3327d7f74d6de829223c29`, tree
`2dcf2e7361033d7d1e4a93a0d2ed7861e85d579a`, protocol digest
`c0d0d4c15aec47a78152c9785181b38b03593f9a16c466a2d912581fb8efd131`.
Rejected attempts remain in the dataset. macOS ARM64 used one original-order
retry; its rejected group contributes no accepted members.

Intel macOS completed both native preparation orders with eight valid cases.
Its three original-order formal attempts each rejected the many-small window
for an 89.86, 114.47 or 129.56 ms maximum gap, above the unchanged 50 ms limit.
The largest gaps were dominated by actual timer waits and retained their real
coalesced expiration counts; other metric-read/boundary criteria and native
correctness passed. This does not establish the underlying scheduling cause.
The original three-attempt limit and 900-second deadline remain consumed with
that run; successful members are not stitched into a replacement cycle. The
complete six-profile resource conclusion therefore remains inconclusive.

The earlier Intel native-observer diagnosis ran four fresh pilot controllers
in the fixed small/many/many/small order with the original 128/16 repetitions.
It records each actual wait's wall and thread-CPU intervals, expiration count
and error, plus bounded complete GC events. It changes no worker, QoS, timer
backend, workload or quality criterion. Its bootstrap and sampler form a distinct
combined source digest: the v23 validator must reject those pilots as frozen
preparation or formal evidence. The bounded diagnosis may identify a scheduling
or CPU cause; a green diagnostic job itself establishes no resource acceptance.

The first [Intel native-wait diagnosis](https://github.com/AresJef/verysync-sidecar/actions/runs/44027582724)
completed all four pilots in 80.39 seconds. No wait exceeded 50 ms; the largest
waits were about 11 ms. It did not reproduce the earlier rejection and therefore
does not establish whether that delay came from GC, thread scheduling or another
host condition. These distinct diagnostic records remain ineligible for v23
preparation or formal coverage.

A single separate macOS 26 Intel preparation uses immutable producer
`a6df5afb7e05f5fe6f3327d7f74d6de829223c29` and the exact unchanged v23 protocol.
It first repeats actual counter/timer calibration and all eight native preparation
cases in the two original opposite orders. Formal collection requires readiness and a subsequent
explicit `resource-formal` label (or ready/manual execution), which starts fresh
preparation before the original four formal plus two independent cycles. The
Mac 15 failures, attempts and original deadline remain unchanged; no members
are stitched across environments. A different image is not a timing guarantee.

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

The frozen configuration is `tests/fixtures/resource-protocol.json`. The workflow
checks the frozen source inputs and actual Rust version before preparing the
engine or building the workload. To check a local checkout, run the preflight
with `--check-source`.

```console
python scripts/preflight-native-resources.py --check-source \
  --protocol tests/fixtures/resource-protocol.json \
  --cargo /absolute/path/to/cargo --toolchain 1.85.0
```

After explicit fixed-core preparation and release compilation, run the collector.

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
explicitly dispatched. The `resource-formal` pull-request label also explicitly
requests complete collection on a frozen draft without launching unrelated full
native jobs. Applying that label starts fresh preparation and acquisition; it
does not reuse an earlier run's preparation or alter any source, workload,
quality, complete-group or deadline check. A green preparation-only job does not establish resource
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

The v17 Darwin observer used one blocking `mach_wait_until` call for each
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

The separate `Mac resource environment check` workflow evaluates the same frozen
protocol on the explicit standard `macos-26` and `macos-26-intel` images. GitHub
lists both as generally available standard runners and provides standard runners
without usage charges for public repositories ([runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
[image announcement](https://github.blog/changelog/2026-02-26-macos-26-is-now-generally-available-for-github-hosted-runners/)).
This bounded environment check follows actual Mac 15 hosted-capacity refusals
and insufficient observation gaps. A different image is not a capacity or timing
guarantee. Each new environment must independently calibrate, complete both
preparation orders, then collect all four formal and two independent cycles.
Old deadlines, attempts and results remain with their original runs; Mac 15
preparation members are never combined with Mac 26 members. Original observation
limits, source bindings, native correctness and cleanup gates remain unchanged.
The existing six-profile collection and native acceptance workflows still run
their original jobs. Image-specific results do not prove a minimum supported OS
or complete platform coverage.

The [first Mac 26 environment run](https://github.com/AresJef/verysync-sidecar/actions/runs/43945972526)
completed all eight native preparation cases on each architecture. Intel had
zero `VALID` cases and ARM64 had three; neither completed a whole valid order,
so formal and independent collection did not start. All native correctness and
normal cleanup checks passed, but every rejected case exceeded the unchanged
50 ms observation-coverage limit. The observation-read and boundary fractions
met their separate limits. These are insufficient measurements, with no strict
resource or performance acceptance.

The largest observed internal gaps were usually dominated by the actual native
timer wait; one Intel case also retained a 1.32-second gap dominated by journal
polling. These recorded segments do not establish the underlying host scheduling
or storage cause. The existing observer already used native Mach deadlines and
observer-thread QoS without changing worker priority. This run keeps its own
producer and unchanged v21 measured inputs; it is not combined with Mac 15
trials or treated as evidence for another environment.

The later [observer-only ABBA diagnosis](https://github.com/AresJef/verysync-sidecar/actions/runs/44016131525)
completed four 64-wait blocks on each actual Mac 15 architecture, without starting
an engine. The original Mach blocks reached 77.26/81.24 ms on Intel and
64.52/80.60 ms on ARM64, with repeated waits over 50 ms. The critical-kqueue blocks
reached 10.33/10.63 ms on Intel and 17.19/14.45 ms on ARM64, with none over 50 ms.
These observations support trying that observer method; they do not establish
resource coverage, explain the host's underlying scheduling cause, or guarantee
future wakeups. The producer was commit
`6111d36406c3cc1da038015d0c15c0bba4048a17`, tree
`b4f9e15f9f49bb26799047411c9eeeda7349072a`.

The v23 sampler uses that same interval-mode timer with `NOTE_NSECONDS` and
`NOTE_CRITICAL`, whose values follow the Apple SDK event header. It checks the
actual event identity, filter, error flag and positive expiration count. A delayed
event's count remains diagnostic; it never creates missing observations. Missing
or invalid events and syscall failures remain acquisition errors, retaining the
actual wait duration and native error details without retry. The exact owned
queue is closed on registration failure and final cleanup. The explicit legacy
Mach backend remains available to the diagnostic probe so its labels continue
to identify the actual mechanisms being compared. No native worker, global
priority, timer setting or power policy changes. Both native preparation orders
and all four formal plus two independent cycles must succeed under the new
frozen source identity before any v23 resource claim.

The later v26 preparation keeps these quality thresholds and complete-group
requirements. Its source is the strict-TLS-default repair, producer
`ec108cb13e605cb9b9807a47043d319552f37479`, tree
`97cdd4e3932a1ff9f445d0c26ca7776729d2711e`, in
[resource run 44093746127](https://github.com/AresJef/verysync-sidecar/actions/runs/44093746127).
All six profiles completed both original opposite orders. The four Linux and
Windows profiles had eight valid preparation cases each; macOS AMD64 had seven
valid cases and one insufficient case, with one complete valid order. macOS ARM64
had six valid cases and two insufficient cases, leaving neither order complete.
Those two cases retained gaps of 79.663 ms and 152.929 ms against the original
50 ms limit. Their measured waits accounted for most of the gap; this locates the
delay without establishing its operating-system or host cause. All eight ARM64
cases passed native data, configuration, identity and normal process-exit checks.

The ARM64 job's first attempt received no runner and executed no steps. A single
job recovery produced the eight actual cases above; the other five profiles were
preserved. No formal v26 collection was started. Preparation data, valid members
of incomplete orders and earlier protocol results remain excluded from formal
acceptance. The overall resource conclusion remains `INCONCLUSIVE`.
