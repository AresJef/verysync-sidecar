
## Network settings and live observations

`network_configuration` reads listener, discovery and reconnection settings.
`update_network_configuration` sends only the fields explicitly selected by a
`NetworkPatch`, checks the instance identity before writing, and reads back the
configuration. Client clones serialize mutations. Independent configuration
writers must coordinate their updates. A failed readback after a write produces
`MutationOutcomeUnknown`; the library does not retry the mutation.

```no_run
# async fn example(client: &verysync_sidecar::Client) -> verysync_sidecar::Result<()> {
use verysync_sidecar::NetworkPatch;
let update = client.update_network_configuration(
    &NetworkPatch::default()
        .global_discovery(false)
        .local_discovery(false)
        .reconnection_interval_seconds(5)
).await?;
assert!(update.requested_fields_match);
let listeners = client.listener_status().await?;
let connections = client.connections().await?;
let cache = client.discovery_cache().await?;
# let _ = (listeners, connections, cache);
# Ok(()) }
```

Matching configuration is a settings receipt. Listener addresses and errors,
discovered candidate addresses, connected peer flags and file synchronization
are separate observations. `connections` preserves an absent peer separately
from a present disconnected record. Missing byte counters remain `None`.
Unrecognized connection and transport labels are retained on reads; typed
device writes reject unknown transport labels. `DevicePatch::allowed_transports`
selects protocols independently of peer addresses and pause state. TCP has a
separate native private-peer test; UDP and relay effects have separate gates.

`discovery_cache` reads records with candidate `addresses` and retained unknown
metadata. It does not start a query, enable discovery or establish connectivity.
Cache keys remain upstream strings. `listener_status` includes upstream external
address reports; these are not independent evidence of WAN reachability.
Debug formatting omits address values and unmodeled metadata from record types.

The fixed v2.33.2 kernel was observed saving custom `globalAnnounceServers`
values yet continuing to use built-in discovery providers after restart.
`NetworkConfig::global_announce_servers` therefore describes stored values;
the library does not expose a typed custom-server setter or claim that the
kernel uses those values. The explicit raw request interface remains available
for caller-verified version-specific behavior.

Native acceptance separately observes selected loopback listeners, two real
TCP peers, an owned incorrect-address rejection and successful restoration.
The discovery test routes only allowlisted built-in discovery HTTPS CONNECTs
to an explicitly selected private fixture; it never resolves or contacts the
original provider hosts. Actual lookup, cache population and dynamic connection
are checked. This is a test-only routing mechanism, not a production helper or
an OS-wide no-egress guarantee. It does not establish public provider operation,
global announcements, LAN discovery, NAT traversal, UDP, relay or cross-WAN
support. Enabling discovery in an application can emit network traffic.
