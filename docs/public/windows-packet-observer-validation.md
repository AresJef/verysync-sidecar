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


The exact merge source `21c0ae0d608e95f1e92b3cb3b35fb514956e5723`
(tree `7dd4df9dd8a4bcb028e43ef7c50742dcf0b9b2f0`) completed both read-only
probes in [PR #233](https://github.com/AresJef/verysync-sidecar/pull/233),
[run 44229768935](https://github.com/AresJef/verysync-sidecar/actions/runs/44229768935).
Both native Windows runners reported administrator availability, the explicitly
selected in-box tool and `Packet Monitor is not running`. Only help/status
commands were invoked; there were zero VerySync cases and no capture/filter
mutation. The `help start` variants returned general help, so exact capture
option syntax is not claimed as a measured result. A bounded owned-loopback
header feasibility test and the subsequent actual VerySync class gate remain
required. The initial runner queue has finished; its cause is not inferred.


The next explicitly selected diagnostic uses generated TCP sockets, before any
VerySync program is involved. It first requires the monitor to be inactive and
an explicitly recognized empty filter table. It adds one uniquely named rule
for both prebound source/destination ports and the exact loopback address,
records its actual filter ID, and uses a 128-byte packet snapshot and a 16 MiB
circular log. Unknown state, unknown ownership or unrelated filters stop the
attempt. Cleanup removes only the recorded filter and stops only the session
started by this diagnostic; uncertain start outcomes require its own log name.

Two independently bounded IPv4/IPv6 phases each transfer and verify 1 MiB of
synthetic bytes. A bounded pcapng parser accepts only complete owned TCP data
headers, checks block lengths/interface bounds and both ports, and returns
counts/class bytes without raw packet contents. Capture files stay private and
are removed. Missing headers, unsupported link formats or cleanup failures are
inconclusive diagnostics with a failing result, never a VerySync capability
verdict. The actual fixed-program 16/32/0 class test remains separate.
