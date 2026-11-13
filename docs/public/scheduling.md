
## File scheduling and explicit bandwidth settings

`folder_scheduling_configuration` reads the actual file pull order.
`set_folder_pull_order` changes only that field and reports actual readback.
`FolderPullOrder` covers random, alphabetic, smallest/largest first and
oldest/newest first. Unfamiliar readback values remain `Unknown`; typed writes
reject them. Configuration does not preempt an active file or change block
order and other advanced puller settings.

`prioritize_file` submits one exact relative target filename and returns the
engine's actual need page. Paths follow the same target-syntax validation as
subpath scans, and each filename/page query is encoded once. An absent,
already active or nonqueued file does not become a completed transfer receipt.
Paused folders are refused with `FolderPaused`, and missing/changed targets
remain errors. No method resumes a folder, retries a write or cancels an active
file implicitly. Coordinate independent writers and inspect actual queue state.

Native priority evidence uses an explicitly configured legacy puller fixture.
It promotes a nonfirst file while other work remains queued, then checks all
512 received file contents after removing the fixture limit. The default
ants/session mode has not shown this queue effect in the bounded investigation;
its behavior remains separately unverified. The test's raw advanced-mode setup
does not establish typed control or acceptance of those advanced fields.

`bandwidth_configuration` and `update_bandwidth_configuration` expose global
upload/download limits and whether they include engine-classified local peers.
`DeviceConfig`, `DeviceDefaults` and `DevicePatch` also expose independent
per-device upload/download limits. Units are KiB/s: one unit is 1024 bytes per
second, despite the engine's historical JSON field names `maxSendKbps` and
`maxRecvKbps`. Zero removes the selected limiter; other configured limits and
network/storage bottlenecks remain independent. Invalid signed-32-bit ranges
and empty patches are rejected before I/O. Unknown settings are preserved and
hidden from Debug.

```no_run
# async fn example(client: &verysync_sidecar::Client, folder: &verysync_sidecar::FolderId, peer: &verysync_sidecar::DeviceId) -> verysync_sidecar::Result<()> {
use verysync_sidecar::{BandwidthPatch, DevicePatch, FolderPullOrder};
client.set_folder_pull_order(folder, &FolderPullOrder::Alphabetic).await?;
client.update_bandwidth_configuration(&BandwidthPatch::default()
    .max_send_kib_per_second(256).limit_in_lan(true)).await?;
client.update_device(peer, &DevicePatch::default()
    .max_receive_kib_per_second(128)).await?;
# Ok(()) }
```

Settings return actual readback, separate from enforcement or transfer
completion. Shared Client clones serialize mutations and recheck identity;
other writers still need coordination. Failed modifying readback or malformed
post-priority responses have explicit unknown outcomes, without automatic retry.

Rate tests use separate fresh-process preparation and acceptance trials, four
global/device upload/download cases and a distinct incompressible 2 MiB file
per case. They retain complete monotonic counter windows, allow token bursts,
check positive bounded received bytes while work is still needed, and verify
exact full bytes after explicit limit removal. All I/O and scheduling delays
remain in the measured interval. These are absolute functional observations,
not an optimization speedup, throughput promise or universal burst guarantee.
The fixed engine labels these private loopback peers `isLocal=false`; no local
classification is inferred from an address. Actual exemption/enforcement for
peers classified as LAN remains a separate final-network acceptance gate.
