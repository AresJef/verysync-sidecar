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
endpoint and receipt path. The API key is written only to
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
identity/private-key preservation and actual owned-process exit. It logs no keys.

The initial focused validation passed on all six standard native profiles
(macOS, Linux and Windows; AMD64 and ARM64), using the same PR merge
`ceecf3e9c7eecdd579afcf45cc2ca014933dfd9c`. Run
[44236239790](https://github.com/AresJef/verysync-sidecar/actions/runs/44236239790)
contains 18 actual normal lifecycle paths and 18 negative boundaries with exact
prepared-image cleanup. Both Quality jobs passed in run
[44236239605](https://github.com/AresJef/verysync-sidecar/actions/runs/44236239605).
These results validate the finite node tool, not the eventual external networks.
