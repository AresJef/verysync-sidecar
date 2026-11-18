# Explicit official tracker validation

`Client::transport_status()` returns the official program's tracker observations.
`TrackerStatus::connection_state` preserves the actual `connectStatus` label;
an unfamiliar label remains unfamiliar. Version-specific `state`, `host` and
`connectError` fields remain in `extra`. Tracker and peer connectivity are
separate observations. Registration does not establish NAT traversal, relay,
file transfer or cross-WAN reachability.

The fixed v2.33.2 isolated macOS preparation observed `connected` together with
`state:synchronized`, a nonempty tracker host and an empty native error. A
nonce-controlled cut of the fixture's own proxy connections was followed by an
unconnected observation and a nonempty native error. The strict Rust case passed
in 14.11s, restored tracker-disabled configuration and observed normal exit.
This is local preparation; native CI results must be associated with their own
source. No provider outage is inferred from a test-controlled disconnect.

The specialist test starts one empty instance with independent state, identity,
keys and management endpoint. Only tracker is enabled; global and LAN discovery,
NAT, UDP, relays and TCP punching remain disabled. Its child HTTP proxy forwards
only HTTPS CONNECTs to `control.verysync.cn:443`, `control-v4.verysync.cn:443` and
`control-v6.verysync.cn:443`, preserving end-to-end native TLS. Other HTTP proxy
requests are denied. This is a scoped HTTP proxy observation, not an OS-wide
no-egress guarantee or a complete enumeration of native network destinations.

Running this test sends native registration metadata, potentially including the
synthetic device ID, public key, version, IP and ports, to official services.
It requires explicit authorization and `--allow-official-tracker`. The ordinary
network command selects all seven existing `actual_` cases and does not enable
the tracker test. Invoking the specialist Rust case without its explicit opt-in
fails before creating state or starting a program; it never reports a skipped
registration as a pass.

After observing actual registration, the Rust case writes the private fixture
nonce. The fixture then shuts down only socket connections it owns and denies
further official CONNECTs. Within a thirty-second observation bound, the Rust
case must observe both actual registration and the resulting native error.
It checks full configuration before, while enabled and after restoration,
preserves key/certificate bytes and device identity, keeps the folder list empty
and verifies a synthetic sentinel. Finally it requires code zero, no force, a
stopped owned process tree and released state. Public receipts contain flags
and timings; raw host, error and identity values are omitted.

With an explicitly prepared fixed private core and its verified SHA-256 in the
usual `VERYSYNC_TEST_BINARY` and `VERYSYNC_TEST_BINARY_SHA256` environment:

```sh
python scripts/run-official-tracker-test.py --allow-official-tracker \
  --toolchain 1.85.0 --evidence-dir /absolute/private/new-tracker-evidence
```

The six native CI profiles have separate specialist commands and exact owned
executable cleanup. The full final integrated candidate and all other network
capabilities remain independent acceptance requirements. No user account,
trial subscription, purchase, vendor contact or real synchronization folder is
part of this fixture.
