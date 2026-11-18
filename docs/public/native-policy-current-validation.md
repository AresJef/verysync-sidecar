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
