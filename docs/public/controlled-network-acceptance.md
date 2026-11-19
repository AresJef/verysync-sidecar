# Controlled network acceptance nodes

`acceptance_node` is a finite example for dedicated test machines provided by
the caller. It uses the public `ManagedInstance` API. It is not a system service
and installs no background helper. Building the example does not download or run
VerySync. Supply the exact official **v2.33.2** executable and its independently
verified SHA-256; the SDK checks both digest and reported version before readiness.

```sh
cargo build --locked --example acceptance_node
./target/debug/examples/acceptance_node /absolute/path/to/verysync SHA256 /absolute/new-test-root 1800
```

The root must not already exist. Parent directories must belong to the caller;
do not use another application's directory. The program creates fresh identity,
credentials and isolated state. Management uses an automatically selected IPv4
loopback port, refuses the protected port 18886 and authenticates the new identity.
The fresh SDK configuration disables peer discovery, NAT mapping and relays;
its peer listener binds only to loopback with an automatically selected port.
Enable only the network behavior required by the agreed test
through the explicit management API. No real folders are selected automatically.

Readiness is one JSON line on stdout, containing the device identity, loopback
endpoint, verified program version and SHA-256, and receipt path. The private
receipt includes the same program identity. Retain the version and digest from
both test nodes with the network evidence. The API key is written only to
`NEW_ROOT/state/acceptance-connection.json`. The SDK creates the state directory
privately: Unix owner access, or a Windows protected DACL for the caller and
SYSTEM. The receipt uses Unix mode 0600 and inherits that private Windows DACL.
The state and receipt remain after exit for private evidence review; they contain
credentials and must not be uploaded to issues, public CI logs or chat.

Keep stdin open while controlling the node. Send `stop` followed by newline,
close stdin, or let the 1–7200 second TTL expire. TTL begins at readiness; startup
has the SDK's separate bounded deadline. Each path requests normal shutdown and
requires actual exit code zero, no signal or force, an empty owned process tree
and released state. An oversized input command also requests normal shutdown.
No global signal handlers or logging are installed. Abrupt owner death uses the
SDK's separately documented ownership cleanup; it is not evidence of a normal
shutdown. A shutdown timeout is a failure, not a successful stop receipt.

For a remote dedicated node, use an authenticated SSH session and retrieve the
private receipt over that session. Forward only its management port, for example
`ssh -N -L 127.0.0.1:LOCAL_PORT:127.0.0.1:REMOTE_PORT TEST_HOST`.
Connect a Rust `Client` to the forwarded loopback endpoint with the receipt key
and `expected_device_id`. Keep the key in a private file or memory, never command
arguments or logs. A loopback endpoint relies on the private host and SSH trust;
it does not independently authenticate the SSH server or remote operating system.
This kit does not configure SSH, firewall rules, public addresses or paid services.

Use synthetic files and isolated peer identities for the eventual two-network
test. Record addresses and topology, exact SDK/core identities, observed peer
connection and discovery/relay path, source and destination file hashes, failure
recovery, retained local data and every actual normal exit. A successful local
kit test establishes the kit's lifecycle behavior only. It does not pass WAN,
NAT traversal, relay selection, Windows packet-class observation, licensed
features or the final same-candidate acceptance gate.

The bounded local verifier is `scripts/verify-acceptance-node.py`. It requires an
explicit compiled example, fixed core and digest; it checks stdin stop, EOF and
TTL independently, authenticated status/configuration, retained synthetic bytes,
identity/private-key preservation and actual owned-process exit. It matches the
ready and receipt program fields to the owned executable digest and authenticated
version response. It logs no keys.

## Observe a prepared pair

Configure only the two dedicated test nodes for the selected scenario. Confirm
that the receiver lacks the sample before writing it to the sender. Keep the
original length and SHA-256 and the evidence for the route or network failure.
After synchronization, pass a private JSON plan to the read-only example:

```sh
cargo run --offline --locked --example observe_acceptance_pair -- /absolute/private/pair.json
```

```json
{
  "sender": {
    "receipt": "/absolute/private/sender-connection.json",
    "management": {"kind": "loopback", "port": 22101},
    "volume": "SENDER_TEST_VOLUME_ID",
    "resource": "test-folder/synthetic.bin",
    "path_style": "unix"
  },
  "receiver": {
    "receipt": "/absolute/private/receiver-connection.json",
    "management": {"kind": "loopback", "port": 22102},
    "volume": "RECEIVER_TEST_VOLUME_ID",
    "resource": "test-folder/synthetic.bin",
    "path_style": "unix"
  },
  "transport": "tcp",
  "expected_bytes": 3,
  "expected_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
}
```

The example digest is for the three bytes `abc`. Replace the paths, file-manager
volume IDs, ports and sample details with those for the actual test. The ports
are the dedicated local forwarding ports. Copy receipts over the authenticated
private channel and keep them owner-only. Use `"windows"` for Windows resource
paths. A dedicated local Unix management socket can use
`{"kind":"unix_socket","path":"/absolute/private/gui.sock"}`.

Both fresh management sessions must authenticate the identities in their node
receipts. The example checks each peer's reported connection and address for the
requested `tcp`, `quic` or `relay` transport. It downloads both copies into new
private temporary files, compares each sample of up to 16 MiB against the
declared length and SHA-256, and removes the temporary files. The report contains
node and peer addresses. Keep it with the private topology evidence and normal
shutdown receipts. Record routed or external topology and the actual failure and
recovery separately from these point-in-time connection and file observations.

The initial focused validation passed on all six standard native profiles
(macOS, Linux and Windows; AMD64 and ARM64), using the same PR merge
`ceecf3e9c7eecdd579afcf45cc2ca014933dfd9c`. Run
[44236239790](https://github.com/AresJef/verysync-sidecar/actions/runs/44236239790)
contains 18 actual normal lifecycle paths and 18 negative boundaries with exact
prepared-image cleanup. Both Quality jobs passed in run
[44236239605](https://github.com/AresJef/verysync-sidecar/actions/runs/44236239605).
These results validate the finite node tool, not the eventual external networks.

A focused Linux AMD64 diagnostic used separate sender and receiver network
namespaces joined by a third kernel router in each runner. For both IPv4 and
IPv6, the SDK observed native direct TCP peer addresses and the receiver
obtained two successive 262,181-byte samples with their expected SHA-256
digests. Pausing both devices disconnected the peers and retained the first
sample. Resuming delivered the second sample. Each process exited normally and
all private network namespaces were removed. See the
[routed diagnostic jobs](https://github.com/AresJef/verysync-sidecar/actions/runs/44457047575).
External network paths, discovery, NAT and relay require their own acceptance
on the controlled nodes.

The receiving Linux interface also recorded TCP data headers from the
authenticated sender after one IP hop. The six cases covered IPv4 and IPv6
with traffic class octets 16, 32 and 0. Each sender applied the configuration
with the SDK and restarted with its original identity and credentials. The
paired nodes checked both sample versions and shut down normally. The capture
recorded header counts and indicated TCP payload lengths.
[Receiver header diagnostic](https://github.com/AresJef/verysync-sidecar/actions/runs/44458772679).

An isolated Windows Server 2022 AMD64 runner booted a diskless Linux guest
with one Hyper-V internal switch and no guest default route. Explicitly bound
Windows sockets sent and received the same 1 MiB synthetic sample on IPv4 and
IPv6. The guest logged both Windows source addresses, shut itself down, and
the host removed the exact test VM, switch, routes and storage.
[Native Windows-to-guest link](https://github.com/AresJef/verysync-sidecar/actions/runs/44461709708).

The fixed v2.33.2 Windows Server 2022 AMD64 sender used the public SDK to set
the traffic-class octets to 16, 32 and 0 for IPv4 and IPv6. The configured
value survived a normal restart in every case. The authenticated Linux guest
received six 262,181-byte files and verified each SHA-256 digest. Its separate
capture matched 96 data packets to the active peer ports. With ECN bits
masked, each captured octet was 0. The two zero cases met the packet check.
The four nonzero cases failed it. Both native processes stopped normally and
the private guest, switch, routes and temporary state were removed.
[Native Windows VerySync packet run](https://github.com/AresJef/verysync-sidecar/actions/runs/44465985532).

A separate Windows Server 2022 AMD64 diagnostic reproduced the isolated link
with Windows qWAVE per-connection marking. The same test addresses and
destination port carried all six 262,181-byte samples. The independent guest
verified 79 data packets, exact received bytes and zero capture drops. It
observed octets 16 and 32 when requested for both IPv4 and IPv6, and only
0 in both unmodified controls. This establishes that the isolated link can
carry both nonzero markings.
[Native socket marking control](https://github.com/AresJef/verysync-sidecar/actions/runs/44470165596).

One comparison then ran both phases on the same Windows host, using the same
Linux guest, switch and virtual adapter. The reference phase verified all
six octets in 80 captured TCP data packets. The VerySync phase verified
all six file digests, configuration readbacks and normal exits. Its 99
matched TCP data packets again carried only 0 after ECN masking. The four
nonzero cases failed the strict packet-effect check. This evidence covers
the observed Windows Server 2022 AMD64 direct TCP path. Windows ARM64 and
remote paths require their own observations.
[Same-host native comparison](https://github.com/AresJef/verysync-sidecar/actions/runs/44471010544).
