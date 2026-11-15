# Event subscriptions

The unreleased API provides caller-owned event subscriptions for VerySync
v2.33.2. The published `0.1.0-alpha.1` package predates this API. A subscription
observes the engine; it never owns, restarts or stops that engine.

```rust
use verysync_sidecar::{Client, EventOptions, EventStreamItem, Result};

async fn observe(client: &Client) -> Result<()> {
    let options = EventOptions::default()
        .queue_capacity(32)?
        .reconnect_attempts(3)?;
    let mut subscription = client.subscribe_events(options).await?;
    while let Some(item) = subscription.next().await {
        match item? {
            EventStreamItem::Event(event) => {
                // Process before storing this cursor with your application state.
                let cursor = event.cursor.clone();
                // Inspect event.data() explicitly if needed; it may contain secrets.
                let _ = cursor;
            }
            EventStreamItem::Gap(_) => {
                // Re-query all state relevant to your application before treating
                // event-derived views as complete. This example only reads status.
                let _status = client.system_status().await?;
            }
            EventStreamItem::Reconnected { .. } => {}
            _ => {}
        }
    }
    subscription.close().await?;
    Ok(())
}
```

Without a resume cursor, `subscribe_events` establishes the current position
before returning and excludes earlier history. `EventOptions::resume_from`
accepts a previously consumed `EventCursor`. A cursor includes the authenticated
device ID, native `EventSource`, last sequence ID and the engine's reported start
time when available. Ordinary and disk buffers have independent sequence IDs;
a cursor from one source is rejected by the other before any network reads.
It is serializable, but is not a server-side subscription or a durable checkpoint.
The subscription's `cursor()` advances only when `next()` returns an event or
gap; a producer filling its queue does not acknowledge those unconsumed items.

Known names include configuration saves, folder pause/resume and folder state
changes. Other names remain `EventKind::Unknown`, with the exact name, payload,
optional global ID and unknown envelope fields preserved. Sequence IDs and
global IDs are distinct. Payload interpretation stays explicit; a configuration
event is not proof that files have synchronized. Ordinary Debug omits payload
values, extra values, unknown names and the reported generation string. Real
configuration events can include management credentials. Avoid logging or
publishing `data()` and `extra()` indiscriminately.

## Disk changes

`Client::subscribe_disk_events(EventOptions)` reads the separate fixed
`GET /rest/events/disk` buffer. It shares the bounded queue, cancellation,
generation checks, finite read recovery and explicit gap notifications described
here. Its cursors use `EventSource::Disk`; ordinary subscriptions use
`EventSource::Standard`. Persist the complete cursor, including its source.

`EventKind::LocalChangeDetected` and `RemoteChangeDetected` identify native disk
change records. Inspect `data()` explicitly for the target-native `path`,
`folder` / `folderID`, `action`, file `type`, `label`, `modifiedBy` and
`modifiedTime`. Strings and unknown fields are retained without controller-side
filesystem access, path normalization, timestamp conversion or identity
expansion. A native `modifiedBy` short identifier is not a full `DeviceId`.
These records describe native changes; a file event alone does not prove that a
whole folder, every peer or an external network has synchronized. Debug hides
paths and all payload values.

The v2.33.2 disk buffer is created lazily. When it contains no records, the first
request can interrupt its response instead of returning an empty list. The
library returns that initial transport error without starting a background task
or silently retrying. That request has registered the native subscription; the
caller can explicitly try again after an actual change occurs. The library
does not write a file, scan a folder or change configuration to seed the buffer.
An empty list, if returned, remains a valid empty observation. After successful
initial reads, the shared bounded recovery policy applies.

Without a resume cursor, a successful subscription starts after the latest
available disk record. To consume available records from the beginning, supply
an explicit disk cursor with `last_id: 0`, the authenticated device identity and
the currently reported start time; the usual resumed-continuity gap is still
reported. The buffer is finite and is not a durable audit trail. Earlier changes
that predate native subscription registration cannot be recovered through this
endpoint. No event-name filter is invented for its fixed disk mask.

## Continuity and recovery

Gap notifications require the caller to refresh relevant state. They cover ID
discontinuities, a newest ID behind the cursor, changes in the reported start
time, unavailable advertised batches and observed transport interruptions. A
resumed subscription always reports uncertain continuity before replaying
available events. The upstream start time has limited precision and is optional;
it is not a unique generation token. This API cannot prove that an unobserved
restart never occurred, and does not promise exactly-once or lossless delivery.

The fixed program can interrupt an event response when the supplied cursor is
ahead of its available sequence. The library first reads a newest-event snapshot
and reconciles that position instead of sending an ahead cursor directly. A
restart between reads can still interrupt observation; that is reported and
handled by the bounded recovery policy. A small batch limit asks the upstream
for its newest tail and can itself cause a gap. Skipped IDs are reported rather
than treating a truncated tail as complete history.

Established subscriptions retry transport failures, request deadlines and
observed generation changes across a snapshot read. Status is checked before
and after the newest-event snapshot; disagreement produces an explicit
`ObservationChanged` gap instead of tagging that snapshot with an old generation.
Fetched batches also have their reported generation checked before any event is
queued. These checks detect observed changes, not same-timestamp unseen restarts.
The default is three total attempts with a one-second fixed delay. Success does
not reset this budget. Set `reconnect_attempts(0)` to disable recovery; an
interruption gap precedes the terminal error. Authentication, permission,
identity, version, response-size and schema failures terminate without automatic
retry. Initial subscription reads return their failure without starting a task.
Reconnection performs reads only and never repeats a modifying request.

## Resource ownership

The default queue holds 32 items, the batch request is limited to 256 events and
snapshot polling occurs once per second. Capacity is configurable from 1 to
1024, the batch limit from 1 to 256, and polling/recovery delays from 10ms to
60s. The reconnect budget is at most 64. These are resource policies, not
throughput or latency guarantees. Responses retain the Client's byte limit
and request deadline. Queue bounds count items; large payloads still consume
memory up to the configured response bounds. One fetched batch can be waiting
behind the bounded queue.

Polling brackets a newest-event snapshot with authenticated status reads, then fetches an
available tail when needed. Backpressure pauses the producer instead of silently
dropping queued items; upstream history may still move past a slow consumer and
produce a later gap. No unbounded retry, queue or auxiliary process is created.

Cancelling a pending `next()` preserves the subscription without consuming an
item. `close().await` cancels and joins the task, including an in-flight HTTP
read or blocked queue send. Dropping requests cancellation without awaiting it.
Both leave the management Client and engine usable.

Native tests separately verify actual configuration/state events, unknown names,
credential-safe Debug, bounded backpressure, deliberately truncated tails,
ahead-cursor recovery, actual normal engine shutdown and same-identity restart
with reconnection and generation-gap notification. Synthetic transport tests
exercise malformed/unknown schemas, finite/disabled recovery and cancellation
observed as an actual closed HTTP connection. Evidence is recorded separately.

Native disk-event tests separately observe three actual local file changes,
bounded backpressure and four received changes during a real two-core private
transfer. They retain the original archive/restoration byte checks, normal
owned process exits and caller data. The initial empty-buffer interruption is
recorded as a native limitation, with no implicit mutation or retry. These are
functional observations, not event latency or throughput guarantees.
