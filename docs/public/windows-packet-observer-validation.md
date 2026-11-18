# Windows packet observer feasibility

The existing actual packet-class evidence uses macOS/Linux observers. Windows
effects remain a required unverified scope; configuration readback is separate.

The first Windows-specific diagnostic reads the in-box Packet Monitor command
syntax, current status and administrator availability in fresh GitHub Windows
AMD64/ARM64 VMs. It starts no VerySync program or packet capture, changes no
filter, and cannot count as native packet-class acceptance. It is restricted to
an explicit Windows Actions invocation and selects the system executable by
absolute path. Unknown tool/status semantics must be resolved before capture.

Microsoft documents Packet Monitor as an in-box, cross-component diagnostics
tool with [port/protocol/address filters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-filter-add),
[bounded packet snapshots and component selection](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-start)
and [pcapng conversion](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-etl2pcap).
These facilities do not themselves prove loopback observability or successful
native class marking. Microsoft also directs applications to its QoS API for
[IPv4 TOS selection](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options);
this is not evidence that the fixed VerySync implementation uses that API.

A subsequent runtime gate must identify only the owned synthetic flow, preserve
header bounds and exact observer ownership, require actual data and class
observations, and retain file/configuration/identity and normal-exit checks.
Absent packets or an unsupported observer mean inconclusive evidence, not a
passed or globally unsupported VerySync feature. No global user-host setting,
driver installation, paid tool, account or real file is part of this workflow.
