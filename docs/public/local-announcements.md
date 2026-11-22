# Native local announcements

Enable local announcements when your own devices need to find each other on
the local network. After a device appears, check which identity and connection
VerySync recognized before sharing files with it.

`NetworkPatch` exposes the local discovery enable flag, UDP port and multicast
address. Readback reports settings; discovery-cache entries and authenticated
peer connections provide separate runtime evidence. Local discovery can emit
local-network traffic. Disabling it does not promise to evict an existing peer.

The isolated native case uses a unique nondefault UDP port and multicast group,
separate state and identities, and native-to-native announcements. It does not
construct or assume a discovery packet schema. Global discovery, relay and NAT
paths remain disabled. One peer uses dynamic discovery and the other has no
fixed dialing address. The case requires a real cache entry, authenticated TCP
connection and complete 262181-byte file copy. After disabling discovery and
normally restarting, a fresh third identity must observe no peer or cache during
a bounded 12-second interval. Original payloads and all eight normal owned
process-tree/state exits are checked independently.

This case requires the explicit `VERYSYNC_TEST_LOCAL_ANNOUNCEMENT` value
`github-actions-isolated-vm` and `GITHUB_ACTIONS=true`. It binds ephemeral P2P
listeners on an isolated CI VM and must not be run on a user's active host.
Passing native cases cover all six standard macOS, Windows and Linux AMD64/ARM64
profiles. Windows, Linux and macOS ARM evidence retains the original
[six-profile run](https://github.com/AresJef/verysync-sidecar/actions/runs/44178212719).
The initial macOS ARM job had no runner or executed steps when cancelled; its
single job recovery supplied the actual passing native evidence. The
[MacIntel diagnostic run](https://github.com/AresJef/verysync-sidecar/actions/runs/44181113489)
passed the same positive runtime path, unchanged by failure-only diagnostics.
The source producers are `a41bd9856544377d370f9c0ca82a0bf2c7fb61e6` and
`d2bb7dc4799c8675357de1862fac7331b4be013f`; shared runtime modules and the
positive test path were compared before combining this functional coverage.

The original MacIntel case timed out at its 45-second peer-connection bound
after receiving a discovery candidate. That strict failure is retained; the
later diagnostic run passed without emitting a failure snapshot. The cause is
unresolved, and no fix or timing guarantee is claimed. These observed control,
data and normal-exit results do not establish WAN/NAT traversal, immediate
runtime shutdown, universal packet delivery, or a discovery SLA. Complete final
acceptance on one final candidate and all required platforms remains separate.
