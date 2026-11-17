# Native local announcements

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
Native execution and six-profile acceptance are pending. These controls do not
establish WAN/NAT traversal, immediate runtime shutdown, or a discovery SLA.
