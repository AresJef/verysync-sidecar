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
attempt. Cleanup first reconfirms that the whole filter table contains only the owned
rule, then uses the native whole-table removal; it stops only the session
started by this diagnostic; uncertain start outcomes require its own log name.

Two independently bounded IPv4/IPv6 phases each transfer and verify 1 MiB of
synthetic bytes. A bounded pcapng parser accepts only complete owned TCP data
headers, checks block lengths/interface bounds and both ports, and returns
counts/class bytes without raw packet contents. Capture files stay private and
are removed. Missing headers, unsupported link formats or cleanup failures are
inconclusive diagnostics with a failing result, never a VerySync capability
verdict. The actual fixed-program 16/32/0 class test remains separate.


The actual merge source `903efe0f98784ab2bf59e26b135065cfa8c87aa1`
(tree `b79aee50a3d776bad0a4c57f290727fd35953bca`) produced two failed
diagnostic jobs in [PR #234](https://github.com/AresJef/verysync-sidecar/pull/234),
[run 44232438620](https://github.com/AresJef/verysync-sidecar/actions/runs/44232438620).
All four generated IPv4/IPv6 flows delivered exactly 1 MiB, stopped the monitor,
restored an empty filter table and removed private captures. Both Windows
architectures reported zero captured packets and metadata-only pcapng files.
These are inconclusive observer failures, with zero VerySync cases. Neither
native class support nor a native inability to mark packets is established.
The unchanged loopback observer is not retried to seek a passing result.

The native filter-removal command also revealed a fixture assumption error:
it clears every filter even when an ID is supplied. The original VMs began
empty and contained only the owned rule, so actual cleanup removed no unrelated
rule. The corrected helper explicitly reconfirms whole-table ownership before
using this native operation; additional or unknown rules prevent removal.
The original source/results and this correction remain separate.

The diagnostic is retained for explicit manual reproduction. A required Windows
VerySync packet-class gate remains open and must use a validated observer or an
actual controlled external receiver, with the original 16/32/0 selections,
complete file bytes, protected state and normal owned exits. An observer failure
does not waive that gate or complete the configuration group.

The failed loopback observer is retained as an explicit `workflow_dispatch`
reproduction tool. Ordinary pull requests do not repeat that unchanged native
capture path. The required Windows VerySync wire-class acceptance remains open;
this diagnostic scheduling change grants no support or acceptance credit.
