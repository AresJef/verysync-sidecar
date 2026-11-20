# Native progress-reporting interval validation

`GeneralOptionsPatch::progress_update_interval_seconds` selects the native
progress-reporting interval. The update returns configuration readback; it does
not restart an instance or establish that reports have changed. The controlled
native test explicitly restarts its owned receiver before observing each
selection.

The final case in [PR #222](https://github.com/AresJef/verysync-sidecar/pull/222)
selects `1`, then `-1`, then `1`, with three distinct 8 MiB file transfers between
two independent private TCP peers. The negative selection disables matching
file-progress reports in this scenario while synchronization continues. The
following positive selection restores them. Zero and other signed selections
retain their separately documented native policy; this case does not certify
their runtime effects or immediate application without a restart.

Each observation covers at least six seconds of actual `Syncing` state with
nonempty need. The connected receiver's byte count must advance by at least
128 KiB during that window. A positive phase requires at least three matching
native `DownloadProgress` events; the disabled phase requires none. The
caller-owned event stream must retain cursor continuity, without reconnecting
or accepting gaps. These events are preserved as `EventKind::Unknown` names,
and their matching file payloads are checked with the existing typed
`FileDownloadProgress` model.

The final source passed on all six standard native macOS, Windows and Linux
AMD64/ARM64 profiles in
[run 44199225241](https://github.com/AresJef/verysync-sidecar/actions/runs/44199225241).
Each positive window contained four or five matching events; every disabled
window contained zero. All 18 windows advanced their connected receiver's
byte count by approximately 1.5 MiB. The three source and received payloads
remain byte-identical on every profile, totaling 144 MiB across the six cases.
The source is `8f4151c82e2bb6819a85bd78e2872b8d5b16fb47`, tree
`f402613f1b81bf242a12de7d01a426974153c9f8`, with Rust 1.85 and each profile's
verified official v2.33.2 program.

The case preserves the original identities, keys, certificates, caller sentinel
and unrelated configuration on both instances. Only the sender's explicitly
updated receiver address is excluded from its device-address comparison.
All other receiver options remain unchanged. Both final owned process trees
and state leases must stop normally: 12 final exits across six native cases.
Tracker, NAT mapping, UDP and relay transport remain disabled in the fixtures.

The initial macOS preparation case retains its own source and results; it is
not relabeled as this final, stricter case. These are functional observations,
without a precise reporting-latency guarantee or throughput claim. Other
configuration effects, actual incoming-request memory bounds, licensed controls
and final integrated release acceptance remain independent requirements.
