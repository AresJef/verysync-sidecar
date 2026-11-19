# LAN bandwidth inclusion

`BandwidthPatch::limit_in_lan` controls whether the global byte-rate limit also
applies to peers the official engine classifies as local. Read this classification
from `PeerConnection::is_local`; an address alone does not establish it.

The separate `VS033-LAN-inclusion-v1` native case uses two owned v2.33.2 processes,
private state, synthetic data and explicit loopback TCP listeners. It requires
`isLocal=true` and an initialized connection timestamp before measuring. An
initial `connected=true` snapshot can still contain the year-one timestamp.
Readiness retains its original 20-second deadline.

The receiver keeps a 64 KiB/s global setting throughout. With LAN inclusion off,
a distinct 4 MiB file must finish within 15 seconds, with actual incoming bytes
exceeding the same limiter's 1 MiB allowance plus 64 KiB/s for the complete
observation interval. With inclusion on, another distinct 4 MiB file must still
be needed after a complete 3–6 second window with positive monotonic received
bytes below that allowance. Each window requires the same connection timestamp.
Changing only the LAN flag back to false must finish the second file without
removing the numeric limit. Both full source and destination payloads, actual
peer disconnection, normal exit codes, stopped trees and released state are
checked independently.

The initial macOS ARM run and all six standard native macOS, Windows and Linux
AMD64/ARM64 profiles passed these conditions in
[the LAN inclusion run](https://github.com/AresJef/verysync-sidecar/actions/runs/44165398388).
The producer is commit `d5b19a772018290327581d046c191447c29f8446`, with tree
`f2b5ecf787c02aa21c56ca164c9210694725f0bb`. Original per-profile logs retain
the official archive and binary identities, complete byte windows and normal
cleanup. Additional architectures, minimum systems and the complete final
candidate remain separate requirements.

Two original local failed runs are retained: the diagnostic showed that the
initial year-one connection timestamp was being sampled before initialization.
No transfer window or assertion was relaxed. This case does not change the
separate S4 v3 bandwidth protocol, imply cross-WAN validation, or promise
throughput, latency or a universal token burst.
