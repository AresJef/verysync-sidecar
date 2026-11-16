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
windows. On Darwin, the observer owns a kqueue nanosecond timer with
`NOTE_CRITICAL` to request minimal coalescing; it changes no global timer, power
setting or process priority. A balanced sleep/critical-timer calibration retains
actual wakeup gaps on each CI host. CPU calibration retains the original read-cost
window and adds bounded self-process work before native startup so a sub-tick
window cannot be mistaken for a valid zero counter. Typed calibration errors are
retained. All v1 evidence and failures remain separate; new source dependencies
require complete new formal and independent cycles.

Each actual CI profile must complete both opposite preparation orders before its
formal run starts. Preparation failures retain their typed errors and metrics;
they never become formal samples. The Darwin timer flags follow
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
