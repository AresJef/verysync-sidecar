
## Transport settings and tracker/NAT observations

`transport_configuration` reads the fixed engine's actual tracker, UDP, NAT,
relay-client, TCP-punching and server-address settings. `TransportPatch` changes
only explicit fields. The write checks the target identity and shares the
client clone mutation lock. It performs no automatic retry. Failed post-write
readback produces `MutationOutcomeUnknown`.

```no_run
# async fn example(client: &verysync_sidecar::Client) -> verysync_sidecar::Result<()> {
use verysync_sidecar::TransportPatch;
let changed = client.update_transport_configuration(
    &TransportPatch::default()
        .tracker(false).udp(false).nat_mapping(false)
        .relay_client(false).tcp_punching(false)
).await?;
assert!(changed.requested_fields_match);
let status = client.transport_status().await?;
# let _ = status;
# Ok(()) }
```

Enabling these features can emit network traffic. Constructing settings and
reading snapshots do not enable them. UDP ports are separate from management,
TCP listening and local discovery ports. STUN and relay selectors are retained
as the engine returns them; empty address lists are not replaced by SDK defaults.
NAT lease/renewal values use whole minutes and its request timeout uses seconds.
The engine may normalize or defer settings; check readback and actual runtime
separately. Native UDP tests apply an explicit managed restart before testing
the selected ports. The update operation does not silently restart an instance.

`transport_status` checks the identity in the fresh response and preserves the
reported tracker state, optional disconnect reason and NAT classification.
`disabled` is not registration; `unknown` is not a successful NAT mapping.
Unknown labels and fields are retained. Debug omits state/reason text and
unmodeled values that can contain private network data.

Separate native tests use only UDP device selectors, disable TCP listeners and
other discovery/tracker/relay/NAT features, and observe both real private peers
with `quic-client`/`quic-server` types. An owned incorrect UDP address receives a
datagram without connecting a peer; restoring the selected address reconnects.
This establishes the isolated transport path, not cross-WAN traversal, a public
tracker, STUN classification, automatic port mapping or throughput performance.
Those conditions require their own acceptance evidence.
