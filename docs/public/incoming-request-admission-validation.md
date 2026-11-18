# Incoming request admission validation

`GeneralOptionsPatch::max_concurrent_incoming_request_kib()` selects the native
incoming request byte budget. The typed options update and full configuration
replacement APIs preserve the signed native setting. A successful write or
readback alone does not demonstrate its runtime effect.

The native regression case uses three authenticated receivers and one owned
sender. It selects 32 MiB and 64 MiB in separate sender processes, first through
the typed patch and then through a retained complete configuration replacement.
Every receiver uses one explicit loopback TCP connection, no compression, and a
128 MiB per-device request setting. Tracker, relay, NAT, UDP and discovery remain
disabled. No existing instance is discovered or contacted.

Each phase indexes a new 96 MiB synthetic file containing 768 distinct 128 KiB
blocks. Blocks also differ between phases, preventing an earlier transfer from
satisfying the next workload by local reuse. All three receivers must be actively
syncing while a native LAN send limiter holds back response completion.

Two calls to `Client::collect_core_support_bundle()` per phase obtain the
official core's goroutine snapshots. Collecting this bundle has native profiling
effects, including a four-second CPU profile; it is an explicit test operation.
The test requires the native configuration inside each bundle to match the
selected budget, LAN limiter and disabled external transports.

In the fixed v2.33.2 implementation, `newLimitedRequestResponse` takes request
credits before creating its response-completion callback. That callback waits
for completion before returning the credits. The inspector counts callbacks
actually waiting for completion and separately requires request constructors
blocked waiting for admission. With the homogeneous 128 KiB requests, the
32 MiB setting must show 256 admitted callbacks and the 64 MiB setting must show
512, in both snapshots. Received request headers, allocation stack origins,
retained buffer-pool objects and total process RSS are not admission counters.

After observation, the caller explicitly releases the send limit. Every file
must complete with exact source and receiver bytes. Identities, keys,
certificates, unrelated configuration and a caller sentinel must remain intact.
All four owned processes must exit normally and release their process trees and
state. Private support archives are inspected in place and deleted; CI logs
contain only bounded counts, archive hashes and validation flags.

The initial isolated macOS ARM64 pilot passed these four saturated observation
windows with counts 256/256 and 512/512 and with blocking admission demand in all
four. This is a bounded runtime effect, not an all-time bound on total memory or
a throughput measurement. The reusable case has independent native CI entries
for the six standard macOS, Linux and Windows AMD64/ARM64 profiles; its final
source and each profile's results must be checked separately. This does not
accept the remaining general-options effects or the final integrated release.

Run the focused case through the existing isolated native wrapper after
explicitly preparing the fixed private executable and its SHA-256:

```sh
python scripts/run-isolated-engine-tests.py --toolchain 1.85.0 \
  --test-target configuration_engine \
  --test-filter incoming_admission_cases::native_incoming_request_cap_bounds_saturated_admission_and_preserves_files \
  --evidence-dir /absolute/private/evidence-directory
```

The separate signed-domain case remains necessary for negative, zero and
positive setting preservation. This saturation case uses positive settings
at or above the native implementation's lower bound; it does not infer a portable
zero or negative admission policy from a readback or a small successful copy.

The first complete final-source CI attempt (PR #223, native run 44206659171,
source `8b502998548003ebb6d3dfcea0dca227f848cbac`) passed on Linux AMD64 and
ARM64. macOS ARM64 and both Windows profiles completed the 32 MiB phase but
expired in the 64 MiB phase before producing a snapshot; macOS AMD64 instead
failed while reading management status. Those original failures remain open.
The bounded follow-up records the exact stage and native receiver state on only
the four failed profiles. It preserves the original 30-second phase deadline,
payload geometry, admission predicates and required normal exits. All 236
ready/manual/fork catalog commands and their original runners remain present;
the temporary draft labels only scope this information-producing diagnosis.
