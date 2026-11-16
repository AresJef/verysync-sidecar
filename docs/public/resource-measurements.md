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

Preparation currently supports explicit `--stage calibration` and `--stage pilot`
runs with a fresh absolute `--evidence-dir`. A pilot also requires `--cargo`, the
explicit fixed-program test environment, and a registered `--scenario`.
Calibration and pilot samples are preparation evidence. Formal parameters,
coverage, independent process repeats, quality, stability and resource conclusions
remain pending. No speedup is claimed without an equivalent implementation baseline.
