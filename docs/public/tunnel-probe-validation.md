# Native tunnel probe validation

A successful tunnel probe means the peer answered the probe through the
configured route. It does not sign in or verify that you can manage that peer.
Use the separate authenticated connection for management and check the
expected device identity.

The existing public Rust `Client::probe_device_tunnel()` has a positive native
path with two isolated VerySync v2.33.2 instances and explicit auxiliary
listeners. The permission setting, probe result and authenticated remote
management session remain separate operations; see
[official remote management](remote-management.md) for the API contract.

The first run in [PR #220](https://github.com/AresJef/verysync-sidecar/pull/220)
tested the same source on all six standard profiles:

| Platform | Native Rust target | Probe after explicit permission |
| --- | --- | --- |
| macOS AMD64 | `x86_64-apple-darwin` | Available |
| macOS ARM64 | `aarch64-apple-darwin` | Available |
| Linux AMD64 | `x86_64-unknown-linux-gnu` | Available |
| Linux ARM64 | `aarch64-unknown-linux-gnu` | Available |
| Windows AMD64 | `x86_64-pc-windows-msvc` | Available |
| Windows ARM64 | `aarch64-pc-windows-msvc` | Available |

The test reserves distinct nonzero loopback addresses for both auxiliary
listeners and the target HTTP management listener. It sets the known
`localTunnelAddress` configuration field through the public raw request API,
restarts each owned core, checks its identity and configuration, and passively
confirms the selected owned listening ports. The library's default ephemeral
auxiliary address and the shared upstream port 18886 are not used as gateways.

One explicit private TCP dialer establishes an actual connection between the
two configured peer identities. A denied probe must return `tunnel=false` and
the native authorization diagnostic. After both peer permissions are explicitly
granted, one probe must return `tunnel=true` with no native error. A false result
fails this positive requirement. The synthetic caller sentinel remains exact,
and both owned cores must stop normally with their process trees stopped and
state released. Execution requires explicit opt-in on a disposable GitHub
Actions VM before any state or program is selected.

The original run is
[44188046831](https://github.com/AresJef/verysync-sidecar/actions/runs/44188046831),
using source `69c9819f8c2cddbe617a4d1e855b061a037c3876` and tree
`fdb56f0d15cfac8c694461c2901f67abcdf21aba`, Rust 1.85 and each profile's
fixed, verified official v2.33.2 program. All six original native cases passed;
the final shutdown checks cover 12 owned instances. These are functional
observations, with separate final release regression requirements.

No licensed gateway session or remote management operation was attempted. The
fixtures reported no license, and a positive probe does not establish commercial
entitlement. Public tracker registration, real NAT mappings, WAN traversal and
licensed remote sessions retain independent acceptance requirements. This
result also does not establish why an earlier ephemeral-address fixture could
return a transient failure.
