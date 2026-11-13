
## Relay server control and explicit probes

`relay_server_configuration` and `RelayServerPatch` manage the official engine's
own relay server. This is independent of `TransportPatch::relay_client` and
`relay_addresses`. Starting a server can open listeners and contact pools;
the caller chooses those settings explicitly. The SDK does not create an
additional daemon or helper for production relay operation.

Updates send only selected fields after a fresh identity check. Client clones
serialize mutations, and independent configuration writers must coordinate.
No write is retried. An acknowledged write followed by failed readback reports
`MutationOutcomeUnknown`. `requested_fields_match` describes stored settings;
inspect `relay_server_status` for actual operation. Disabled runtime responses
omit counters, runtime options and the relay URL rather than inventing zeros.

Stored zero timeout selectors can produce nonzero runtime defaults. Explicit
network, ping and message timeout values use seconds; their effective runtime
values are modeled separately in `RelayRuntimeOptions`. Session and aggregate
limits use bytes per second; zero is the engine's unlimited selector. Settings
and effective options do not constitute a throughput measurement.

`relay_rate_samples` preserves the actual bounded numeric history array. It
does not invent sample units, observation timestamps or an interval. An empty
array, a disabled server and a failed request remain separate observations.
Fields not yet verified remain in the actual configuration/statistics `extra`
maps; the raw request API is available for caller-verified advanced operations.

```no_run
# async fn example(client: &verysync_sidecar::Client, selected_relay: &str) -> verysync_sidecar::Result<()> {
use verysync_sidecar::RelayProbeResult;
let result = client.probe_relay(selected_relay).await?;
match result.result {
    RelayProbeResult::Success => { /* Inspect result.error as well. */ }
    RelayProbeResult::Failed => { /* The engine reported a failed probe. */ }
    RelayProbeResult::Unknown(_) => { /* Preserve an unfamiliar result. */ }
}
# Ok(()) }
```

Probing is an explicit network operation. The engine receives the selected
`relay://` URL, which may include sensitive query values. The SDK checks the
management identity before issuing it once and does not infer success from
HTTP 200. Probe URLs, token values, error text and unmodeled metadata are omitted
from ordinary Debug formatting. Explicit field inspection remains available.

Private native tests start one official relay and two independent official
peers on selected loopback endpoints, with TCP, UDP, tracker, discovery and NAT
disabled at the peers. They independently observe relay-only peer connections,
an active relay session, proxied bytes, a successful probe, a failed probe after
server shutdown, listener closure and normal exit of all three owned trees.
This does not establish public-pool operation, WAN reachability or rate limits
under load. On the tested free isolated engine, a requested authentication flag
was read back as disabled; that observation does not establish a cause or a
successful authenticated relay. Authorization and enforcement require separate
positive evidence. Server URLs and tokens may be sensitive even when readback
does not match the requested authentication policy.
