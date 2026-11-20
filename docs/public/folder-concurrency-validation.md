# Native folder concurrency validation

`GeneralOptionsPatch::max_folder_concurrency` has functional evidence for
selecting one and two simultaneously synchronizing folders. The controlled
fixture uses two independent authenticated source peers and one receiver;
each source provides one shared folder over its own private TCP connection.
See [configuration](configuration.md#native-folder-concurrency) for the contract.

The existing three-instance fixture already passed all six standard native
profiles in PR #186, source `fb4e9677151394f250441fc9db672fb15a50f401`.
Those results retain their original source. Its subsequent implementation
changes add phase logging without changing the scheduling assertions.

[PR #221](https://github.com/AresJef/verysync-sidecar/pull/221) verifies the
current dependency graph, including the chrono-to-jiff migration, on native
macOS, Windows and Linux AMD64/ARM64. The common execution source is
`6129c5ee7d77487a4a24c743985d0c1ea13d97ae`, tree
`3ebc502e4b5559598f927048bd052e3981ea5d75`, with Rust 1.85 and the matching,
verified official v2.33.2 program for each profile.

Each case retains the original 45-second observation bound and derives
concurrency from one continuous, source-bound native `StateChanged` history.
The observed maximum must equal one and then two. Under selection one, the
other folder must actually wait while one synchronizes. No observation gaps,
event reconnections or inconsistent state transitions are accepted; separate
HTTP snapshots do not establish overlap. Delivery timestamps are not native
event timestamps.

All four 8 MiB payloads remain byte-identical at source and receiver. The
selected policy survives explicit restarts, unrelated configuration and caller
sentinel bytes remain intact, and all three final owned process trees and state
leases must stop normally. Across six native cases, these final checks cover
18 owned instances.

All six current native cases passed in
[run 44193280491](https://github.com/AresJef/verysync-sidecar/actions/runs/44193280491).
The two Linux preparations initially lost their official archive connections
before native execution. Each Linux case first executed after one preparation
recovery; the original archive-read failures remain recorded. The four earlier
native successes were reused without repeating their executions.

This is a scheduling observation for this fixture. Incoming-request memory
limits, dial concurrency, progress-reporting behavior, other configuration
effects and complete release integration retain independent requirements.
No throughput improvement or complete configuration-module acceptance follows
from this result.
