# CI execution and acceptance

Draft pull requests run quality checks and focused native cases. The full six
standard native bundles and additional compatibility/emulation matrix run when
the candidate is ready for review or the corresponding workflow is explicitly
dispatched. Moving a draft to ready for review triggers those complete matrices.
Their individual outcomes and exact source identities are still required for
full acceptance. A skipped, cancelled, queued or incomplete job is never evidence
that a platform or feature passed. The release verifier requires completed,
successful jobs for the exact accepted source.

An owned draft may retire older draft native or additional-platform runs only
when their source commits are ancestors of the new candidate. The CI helper
checks the repository, current pull-request head, draft state, workflow name and
source ancestry again before requesting cancellation. It preserves ready-for-review,
release, quality, current-source and unrelated-branch runs. Completed historical
job logs keep their original source identities; cancellation adds no acceptance.
The helper uses the repository job's narrowly scoped Actions token and never
reads a developer credential.

The Windows protocol-association pilot is research with its own explicit
`windows_browser_pilot` dispatch option. It is not part of normal draft runs or
Windows browser API acceptance. A guarded refusal, including an existing user
protocol choice, remains an unverified native browser control path rather than
a successful browser test. The full Windows browser boundary remains pending.
