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
