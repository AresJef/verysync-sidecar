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
syncing. A 512 KiB/s bootstrap limit lets new metadata propagate; the caller
independently confirms the new file size, block count and local/global counts on
all three receivers. Only then does it select the 1 KiB/s LAN send limit used to
hold back response completion during the snapshots.

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

After observation, the caller explicitly saves the unlimited send setting,
normally restarts the same owned sender and authenticates a fresh connection
epoch to all three peers. The persisted identity and selected cap must remain
unchanged, with new owned PIDs and no forced stop. Every file must complete with
exact source and receiver bytes. Preparation and saturated observation have a
30-second bound; recovery, fresh connections and full-file completion have a
separate 30-second bound. The earlier single 30-second aggregate fixture bound
is explicitly replaced, with its failures retained.
This fixture does not claim that changing a rate setting cancels already waiting
native writes on an existing connection. Identities, keys,
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

The bounded stage diagnosis at PR #224 (source
`91e34452e9a53014807352598e23e2429adf1d15`, run 44208612148) showed the second
phase waiting for all receivers to become active: one or two still had only the
old file's index. Windows ARM64 completed both phases; both macOS profiles and
Windows AMD64 retained that exact preparation failure. The next local producer
confirmed that preparing all three new indexes first permits both 256/512
admission observations; its separate completion failure after changing to
unlimited is also retained. The explicit normal-restart epoch makes completion
independent of outstanding rate-limited writes. The six-profile regression of
this revised fixture remains required; the earlier transport and preparation
failures are preserved, and no deadline, payload or admission predicate is
relaxed.

## Functional fixture timing

The prepared-index and fresh-epoch producer at PR #225 (source
`e634f8684f565836a3bfe41a64cf3c741a81a714`, run 44211326062) passed on Linux
AMD64. The other five profiles confirmed the new indexes, the two 32 MiB
admission snapshots, and the normal restart and authenticated connections, but
expired at full-file completion. For example, Windows AMD64 recorded its second
snapshot at 00:56:11.408 UTC and the fresh epoch at 00:56:28.295; the aggregate
deadline expired at 00:56:29.040. Almost no time remained to finish three 96 MiB
files after the native profiling and restart operations.

The revised functional test therefore composes two explicitly bounded stages:
30 seconds for receiver preparation and the saturated observations, then
30 seconds for recovery and exact-byte completion. A failure reports which
stage expired and the current receiver state. This changes the fixture's prior
aggregate bound; it does not preserve or relabel that old timing result. There
is no throughput or total-memory performance claim in this admission test.
The 32/64 MiB selections, 96 MiB unique payloads, four strict admitted-request
snapshots, blocking demand, unrelated configuration, identities and required
normal exits remain necessary. The separate frozen resource/performance
protocol and its original negative results are unchanged. Each final-source
native profile remains independently required.

## Independent owned-instance shutdown

The staged fixture at PR #226 (source
`3c43ae1de7d242c9e5c140b2e26c9db20e9a46ff`, run 44213760582) passed completely
on both macOS profiles, Linux ARM64 and both Windows profiles. Linux AMD64
completed both admission phases, exact file bytes and identity/configuration
checks, then reached the ten-second deadline while gracefully stopping an owned
instance. That original failure remains preserved; it is not a cap failure or a
complete test pass.

The follow-up sends the four independent normal-stop requests concurrently and
records each actor's result. Each still has its own original ten-second deadline
and must return code zero, no force, a stopped process tree and released state.
All four results are awaited, including when one fails. This is a test cleanup
ordering change; the focused Linux native run must verify its effect. A local
pass alone does not establish the cause of the original timeout. The local preparation passed in 95.69s with
four explicit successful actor receipts. The owned draft scopes only the
original Linux AMD64 failure; all 236 ready/manual/fork commands and their
original runners remain present. The final integrated candidate still requires
its complete platform and feature gates.
