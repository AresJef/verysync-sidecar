
## Network settings and live observations

`network_configuration` reads listener, discovery, reconnection and reported
connection-limit settings.
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
        .connection_limit_max(8)
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

`NetworkPatch::connection_limit_max` selects the maximum simultaneous
connections, including incoming connections. Zero removes the configured cap;
it is sent explicitly. Values above `i32::MAX` are rejected before I/O for
portability across native integer widths. This setter shares the existing
identity check, clone mutation lock, single PATCH and actual readback. An absent
or null reported maximum remains `None` and cannot produce a matching receipt
for a selected value. A malformed readback after the write produces
`MutationOutcomeUnknown`. Existing connections are not promised to be evicted
when a cap is lowered. One device pair can use multiple underlying connections;
do not equate a connection limit with a device limit.

The native maximum test explicitly selects one connection per device pair,
observes exactly one of two incoming peers throughout a twelve-second window
under maximum one, and then observes both connected after explicitly selecting
zero. Maximum two survives an owned restart with the same identity. Other
options remain unchanged by the maximum-only PATCH, and original settings are
restored before normal tree cleanup. This is a functional connection-count
observation, with separate final platform acceptance.

`NetworkConfig::connection_limit_enough` retains the engine's stored outgoing
threshold as an optional observation. Its complete runtime contract remains
pending: bounded private trials could save a change from one to two while a
second outgoing peer still failed to connect within twenty seconds, including
a trial selecting one connection per device pair. There is no typed setter for
that threshold yet. The raw request entry point remains available for explicit
version-specific investigation; a saved value is not a verified dialing effect.

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
