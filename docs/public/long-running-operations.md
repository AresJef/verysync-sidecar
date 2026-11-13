# Observing long operations

The unreleased scan API observes actual folder state transitions in VerySync
v2.33.2. The published `0.1.0-alpha.1` package predates this API. A scan request,
an observed scanning phase, and peer synchronization are distinct results.

`Client::observe_next_scan` first establishes a bounded event subscription at
the current position, then admits only an idle folder. It submits no scan
request. `Client::request_scan` explicitly requests one whole-folder scan after
checking the connected identity and configured, unpaused target. It returns an
acknowledgement, not a completion receipt; modifying requests are never retried
automatically. Reconcile an unknown mutation outcome before choosing a retry.

```rust
use std::time::Duration;
use verysync_sidecar::{Client, FolderId, Result, ScanCompletion};

async fn request_and_observe(client: &Client, id: &FolderId) -> Result<ScanCompletion> {
    // Coordinate other scan initiators for this folder before admission.
    let mut observation = client.observe_next_scan(id).await?;
    let (request, observed) = tokio::join!(
        client.request_scan(id),
        observation.wait(Duration::from_secs(30)),
    );
    observation.close().await?;
    request?;
    observed
}
```

The engine supplies no request-specific scan job ID. `ScanObservation` is a
local session; its folder ID and event cursors cannot correlate concurrent
requests or resume this observation across processes. Coordinate external
writers and background scan initiators. An observed cycle may have been caused
by another initiator, and a request can finish before the observer drains its
already queued events. Start observing before submitting the request.

`next_update` exposes awaiting-start, queued and scanning phases. `wait` needs
both an actual entry into scanning and its later exit, followed by a fresh
folder-status read. The completion retains both event cursors, the actual next
state and that separate status snapshot. An exit into paused or error is not a
successful scan. An exit into syncing does not wait for or certify peer
synchronization. Even idle is not a receipt for an arbitrary business file batch.

`ScanProgress` retains optional upstream current/total/rate values and an
explicit raw payload. Missing or unrecognized values remain unknown. The API
does not invent zeroes, percentages, byte units, remaining time or a server job
ID. The real small-file scan acceptance observed state transitions and actual
indexing but no progress event; that result is recorded as unknown progress.
The progress parser's additional shapes have separate synthetic evidence.
Ordinary Debug omits the raw payload; inspect it explicitly and avoid logging
unknown fields indiscriminately.

Any event gap or unavailable continuity makes the observation indeterminate.
It does not reconnect and turn a later idle status into success. Reconcile the
folder's actual state, then establish a new observation when it is idle. General
event subscriptions retain their separately configurable recovery policy.

The nonzero `wait` deadline belongs to this call. Timeout or cancellation
preserves consumed state, including a terminal event whose status read is still
pending. The caller may wait again or close the session. Closing or dropping
only cancels its read subscription. It does not stop the engine, stop a scan,
pause a folder, or cancel a separately owned request future. Keep ownership of
an independent modifying request if it must continue after observation closes.
This API supplies no scan-stop command without verified engine support.

Native acceptance uses new private engine states and synthetic files. It
checks actual entry/exit, 1,280 newly indexed files, retained original sample
hashes, independent request completion after observation cancellation, paused
rejection and normal process-tree exit. These are functional effects, not a
throughput or latency benchmark. Subpath/all-folder scheduling and other long
operations require their own contracts and acceptance.
