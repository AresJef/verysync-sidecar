# CI execution and acceptance

Open the Actions run for the candidate's exact commit. A successful quality or
compile job means that check passed. Open the six standard engine jobs to see
whether native tests actually ran, handled files correctly and cleaned up.
Pushing an authorized `ci/formal-candidate/*` branch also starts the registered
candidate workflows.

Draft pull requests run quality checks and focused native cases. The full six
standard native bundles and additional compatibility/emulation matrix run when
the candidate is ready for review or the corresponding workflow is explicitly
dispatched. Moving a draft to ready for review triggers those complete matrices.
Their individual outcomes and exact source identities are still required for
full acceptance. A skipped, cancelled, queued or incomplete job is never evidence
that a platform or feature passed. The release verifier requires completed,
successful jobs for the exact accepted source.

The six native functional profiles remain required for the first stable
release. Record actual OS, architecture and execution mode for any added
runtime evidence. The [release checks](release-checklist.md) define evidence
for available network, minimum-system and formal resource cases and record
the exact conditions for a deferral. A hosted Intel functional result and
formal Intel resource measurements have separate acceptance requirements.
The frozen sample requirements and independent reproduction apply on every
qualified resource profile.

An owned draft may retire older draft native or additional-platform runs only
when their source commits are ancestors of the new candidate. The CI helper
checks the repository, current pull-request head, draft state, workflow name and
source ancestry again before requesting cancellation. It preserves ready-for-review,
release, quality, current-source and unrelated-branch runs. Completed historical
job logs keep their original source identities; cancellation adds no acceptance.
The helper uses the repository job's narrowly scoped Actions token and never
reads a developer credential.

The Windows native-browser acceptance job is required on ordinary pull requests
and manual runs for both AMD64 and ARM64. It first verifies owned protocol
capture and exact restoration of the current effective per-user association,
then runs the public Rust SDK browser case against a fixed private core. Both
steps must succeed; neither is enabled by a research-branch prefix or optional
manual flag. The case checks actual verified/unverified dispatch, continuing
owned actors, observed native-root cancellation, preserved caller data and
identity, normal owned process exit and final exact-program cleanup. Existing
UserChoice values and installed browser files remain untouched. A guarded refusal
or skipped/incomplete execution does not establish native browser support. The
original opt-in observations retain their actual source identity; complete current
Windows execution remains required for final acceptance.
