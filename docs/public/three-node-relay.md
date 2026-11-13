
## Read-only nodes and source handoff

A read-only sharing permission prevents a receiver from becoming a writer for
that share. It does not, by itself, establish whether a particular engine can
serve already received blocks to another read-only receiver. The native
`p2p_three_nodes` scenario exercises that behavior through the public Rust API.

The scenario uses three independent managed instances, device identities,
state directories and explicit loopback TCP addresses. Global/local discovery,
tracker, UDP, NAT, TCP punching and relay clients remain disabled. Its steps are:

1. Generate a real RW/RO key pair on A. Validate the RW key on A and the RO key
   on B, then call `join_folder` using each target's proposed registration ID.
   No local ID is manually aligned and B receives no RW material.
2. Create exact devices and folder-peer associations using `create_device` and
   `share_folder_with`. Resume the selected folders and observe all four unique
   synthetic files, totaling 2 MiB, on B with zero reported need.
3. Normally stop A and verify its entire owned process tree exited. Only then
   create C with a fresh identity and a new empty destination. Validate the RO
   key on C and associate C with B. C has no configured relationship with A.
4. First point C at an owned rejecting TCP endpoint while B's C device is
   explicitly paused. Require an actual connection attempt at that endpoint,
   no successful peer connection and no received sample. Restore the explicit
   address/device settings, then resume C's folder separately.
5. Observe B serving C while A remains stopped. Compare every complete file
   and SHA-256 on A's retained source directory, B and C. Check B/C still have
   no RW material, then normally stop their complete owned process trees.

`connections` supplies actual per-peer protocol byte counters. The scenario
records A→B, B→A, B→C and C→B before/after values and checks monotonicity plus
a B→C outgoing delta covering the unique payload. Metadata and protocol bytes
are part of those counters; they are not a filesystem-byte accounting API.
No post-stop A counter is fabricated, and no bandwidth-saving percentage,
throughput guarantee or speedup is inferred.

This is a logical three-node scenario on a single native host. Its local macOS
arm64 execution observed complete read-only B→C transfer with A stopped. The
same-source macOS/Windows/Linux amd64/arm64 matrix is a separate gate. Physical
network topology, WAN discovery/NAT/relay behavior, minimum operating systems
and other architectures require their own evidence. A successful loopback
handoff does not certify those conditions.
