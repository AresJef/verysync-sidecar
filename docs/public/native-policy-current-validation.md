# Current dial and temporary-advertisement validation

The original dial-concurrency run 43991606649 had actual Windows AMD64,
Windows ARM64 and Linux ARM64 passes. Both macOS jobs were cancelled without a
runner or steps; Linux AMD64 was cancelled before a complete accepted result.
Those cancellations are not native passes or complete runtime failures.

The original source `41d3a3e7745658dd803a3a55624536124de72c0a` used
`[1_u32, 2]`. The current fixture uses `[1_i64, 2]` after the public setting
acquired its signed native contract. That is the single fixture-line difference;
existing historical positives are not relabelled as current-interface evidence.
The focused current candidate therefore runs all six actual dial profiles,
retaining pending native TLS ClientHello counts, actual connection recovery,
file bytes, configuration, identity and normal-exit assertions.

The temporary-advertisement run 44127118940, attempt two, has five actual native
passes. Its macOS ARM64 job 134229826058 was cancelled with runner zero and no
steps. This focused candidate runs that missing platform with the existing
strict native-emission fixture; earlier results retain their own producer.

All 242 ready/manual/fork command rows, targets, filters and runners remain.
Only four draft scheduling labels change, and the draft selects seven commands:
six current signed dial cases and one missing temporary-advertisement case.
Original runtime predicates and deadlines remain unchanged. These targeted
results do not substitute for the full final integrated candidate matrix.


The exact merge source `553c1da25e497bed1c51f11d973d3e450f6b8cb1`
(tree `b41339edee914fe286bfb77a18ca26c472df4b88`) passed all seven selected
native cases in [PR #231](https://github.com/AresJef/verysync-sidecar/pull/231),
[run 44225900932](https://github.com/AresJef/verysync-sidecar/actions/runs/44225900932).
The six dial case times were 68.15s/61.27s on macOS AMD64/ARM64,
53.36s/72.87s on Linux AMD64/ARM64 and 73.11s/69.92s on Windows AMD64/ARM64.
Each observed one and two actual pending native TLS ClientHellos, normal
restart closure of those attempts, subsequent authenticated connection and
complete recovery file bytes, protected state and normal exits.

The missing macOS ARM64 advertisement case passed in 129.97s. With thresholds
1/512/1 it observed actual advertisements true/false/true while complete blocks
of incomplete files were transferred and independently checked. The positive
phases each included 27 remote advertisement observations spanning more than
24 seconds, with continuous events, complete final bytes, protected identities,
keys/configuration and normal exits. Its original unassigned cancellation
remains recorded separately. These are the specific current-source results,
not completion of all configuration or final-candidate requirements.
