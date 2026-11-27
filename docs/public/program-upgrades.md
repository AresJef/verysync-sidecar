# Program upgrades and offline state restoration

To replace the executable or restore saved state, stop the managed instance
normally and save its private state first. The built-in upgrade receives a
request from a running instance. When VerySync is available again, check the
reported version, device identity, and the files or settings you need. If the
result is uncertain, preserve the saved state and check the running program
before requesting another upgrade.

Executable selection, the kernel's built-in upgrader and private-state snapshots
are separate explicit operations. Adding or compiling this crate performs none
of them. The default accepted version remains **v2.33.2**. An older/newer program
requires `VersionPolicy::AllowUnverified`; this opt-in does not waive identity,
authentication, configuration-schema or platform checks. Startup compares actual
CLI and authenticated management versions. A successful version change does not
establish compatibility with every previous database format.

## Stop, snapshot and select a program

`restart_with_program` normally stops the owned tree, retains the explicit new
`LocalProgram`, then starts and authenticates the same state under one total
deadline. It performs no download, executable overwrite or automatic rollback.
The selected program remains selected after failed/cancelled new startup. The
last ready `program_info` remains a separate snapshot. A later plain `restart`
retries the new selection instead of silently opening a possibly migrated
database with the old executable. Cleanup may still be ending when an immediate
retry reports the state busy.

```rust,no_run
# async fn change(core: &mut verysync_sidecar::ManagedInstance,
#     destination: std::path::PathBuf, next: verysync_sidecar::LocalProgram)
#     -> verysync_sidecar::Result<()> {
use std::time::Duration;
use verysync_sidecar::StateBackupOptions;
let stopped = core.shutdown(Duration::from_secs(10)).await?;
assert!(stopped.tree_stopped && !stopped.forced && stopped.code == Some(0));
let saved = core.backup_state(StateBackupOptions::new(destination)?).await?;
let pin = saved.info().manifest_sha256; // Retain separately in trusted storage.
let transition = core.restart_with_program(next, Duration::from_secs(45)).await?;
assert!(transition.previous_exit.tree_stopped);
# let _ = pin;
# Ok(())
# }
```

Take the snapshot from the latest owner after its normal exit. The SDK checks
the recorded run and executable hash while holding the state lease. Even a
failed or cancelled newer startup can invalidate an earlier owner's backup
eligibility. Start the intended program and let it exit normally before taking
a new snapshot. The SDK also checks the upstream lock while copying.
It copies regular state files with 64-KiB buffers, file sizes, SHA-256, file
modification times and owner executable bits. It skips runtime lock files,
`gui.sock` and `tmp`, and rejects symbolic links, Windows reparse points and
special files. Default limits are 1 GiB of file contents, 65,536 entries, a
16-MiB manifest and a 120-second cooperative deadline. Native I/O already in
progress cannot be interrupted at every instruction.
Manifest relative names must be UTF-8; non-UTF-8 names are refused without
lossy rewriting. Local filesystem operations continue to use native paths.

The snapshot contains private keys, API/GUI authentication and database data.
Its directories/files use the native private-resource policy. Do not publish
or log its contents. The manifest pin authenticates the manifest bytes when
separately retained; it is not encryption or a substitute for trusted storage.
The caller must coordinate external writers to state and snapshot directories.

`StateBackup::open(directory, pin, timeout)` checks pinned metadata; restoration
checks every copied file's size and hash. `restore_to(new_absolute_path, timeout)`
never overwrites an existing destination or starts an engine. It rejects unsafe
paths, duplicate entries, missing parents and a mismatched host OS/architecture.
It writes a restore-incomplete flag first and admits the directory only after
all copies and identity checks complete. Symbolic-link ancestors are refused.
Partial backup/restore directories remain for explicit diagnosis; they are not
automatically erased. Cancelling the future cooperatively stops the worker,
which retains its lease until its actual I/O/cleanup ends. Cancellation may race
a completed commit, so inspect the actual resulting directory before retrying.

Restoring private state does not restore synchronized payloads outside that
state directory. An old snapshot may reference newer or independently changed
external files. Coordinate them separately. Native tests populate an actual
v2.33.1 SQLite index, snapshot it, run v2.33.2 and change its index/configuration,
then restore the saved old state into a fresh directory and run v2.33.1 again.
They check identity, sharing/authentication, old index counts and retained
external samples. This is evidence for that specific version pair, not a
general database downgrade or power-loss recovery guarantee.

## Kernel check, trigger and streaming upload

The default managed core receives `--no-upgrade`; its check endpoint can return
501. `ManagedUpgradeChecks::Manual` explicitly enables manual availability
checks while forcing periodic upgrade checks to zero before serving. Merely
selecting it performs no check, download or upgrade. Disabling the check flag
does not establish that separate upload/trigger handlers are unavailable.

`Client::check_kernel_upgrade` returns required `running`, `latest`, `newer` and
`major_newer` fields with retained unknown metadata. This is the kernel's current
provider feed, independent of `OfficialProgram`'s fixed SDK catalog. A successful
check cannot atomically pin a subsequent provider-selected upgrade.

`UpgradeReleaseUnavailable` preserves the fixed kernel's known no-matching-release
refusal. The [official v2.33.2 provider metadata](https://upgrades.verysync.cn/meta.json)
observed on 2026-11-13 and checked again on 2026-11-16 omits Windows ARM64,
although that architecture has a fixed official download. Availability checks
and provider-trigger requests therefore refuse that target. The absence is
separately tested without claiming positive provider-mediated upgrading there.
Explicit program selection, archive upload and CLI `FromUrl` remain separate
paths with their own acceptance. For this fixed version and the observed feed,
provider-mediated upgrading on Windows ARM64 is unavailable. The tested result
is the native refusal, with the executable, configuration, identity, folder
index and files retained; it is not a successful provider upgrade. Native CLI
checks and provider commands likewise retain the known missing-release result.
If the feed changes, check it again before assuming this boundary still holds.
This does not relax positive upgrade requirements for other platforms or for
the explicit archive and URL paths on Windows ARM64.

`request_server_selected_upgrade` explicitly asks that provider to choose and
install a release. It can overwrite the kernel executable and end the process.
The provider's own asset transport and verification are upstream behavior; the
observed feed uses HTTP asset URLs. This method does not provide the separate
SDK downloader's HTTPS/full-archive-SHA guarantees. Coordinate provider policy
and network access before calling it.

`upload_kernel_upgrade(absolute_archive_path, &official_program)` verifies the
complete fixed catalog size and SHA-256 before making its modifying request,
then streams from the same open regular file with bounded buffering. No implicit
download/extraction occurs. Keep the input immutable until the operation ends:
an open descriptor cannot prevent another writer changing its contents.
Read-only hashing may finish in the runtime blocking pool after cancellation.
The kernel separately checks system/archive compatibility; archives above its
128-MiB upload bound are refused before sending.

Both modifying HTTP calls accept the observed `ok: restarting` acknowledgement.
That response is separate from actual replacement, process exit and readiness.
No mutation is automatically retried. Cancellation, a malformed response or a
transport failure can leave `MutationOutcomeUnknown`; explicitly reconcile the
program bytes and process state. Use a dedicated writable executable copy for
kernel-managed upgrades, never a shared program or immutable cache generation.
After `wait_for_exit`, verify the new program independently and explicitly pass
its new hash to `restart_with_program`; the old pinned hash remains stale.
Manual archive upload does not depend on a successful provider availability
check. The SDK performs no automatic fallback from a missing provider release.

## Explicit contained CLI operation

`run_cli_upgrade(KernelUpgradeCommand, timeout)` requires an already normally
stopped owner. `Check`, `Provider` and `FromUrl` map to the actual native
`upgrade --check-only`, `upgrade` and `upgrade --from URL` forms with an explicit
private `--home`. URLs require HTTP(S), a host and no credentials/fragment.
The kernel handles provider/URL transport, not the SDK's pinned downloader.

The SDK lease remains held, and the upstream lock is checked then released for
the CLI to acquire. The child has exact process-group/Job containment, bounded
private output and a deadline; it changes no caller-wide signals or logger.
The returned exit code and private diagnostic preserve the native outcome,
including a nonzero availability-check exit. Zero does not imply a new program
was installed. Cancellation requests exact cleanup and retains state until it
ends; a program mutation may already have happened. The old clean-generation
backup claim is invalidated even by a check. Explicitly start/stop before a new
snapshot, and verify/select new executable bytes before restarting an upgrade.
`KernelUpgradeExit::release_unavailable` identifies only a `Check`/`Provider`
exit 1 containing the fixed kernel's known missing-release diagnostic; other
failures stay unclassified. `FromUrl` errors do not set this flag.

A failed metadata fetch can produce `no version to select` with exit 1 while
`release_unavailable` remains false. An empty selection alone does not identify
a missing platform archive. Preserve the private diagnostic and distinguish
metadata transport/decoding failure from the known missing-archive response
before deciding how to proceed. A controlled blocked-metadata case verified
unchanged program/configuration bytes and a normal restart with the same identity.

For the tested v2.33.1-to-v2.33.2 pair, the provider CLI actually replaces the
program and exits 4, while a forced archive URL exits 0. Both are checked using
the resulting program SHA and authenticated restart, independent of the code.
Dedicated cancellation tests interrupt actual partial CLI downloads, streaming
HTTP uploads, state copies and new-version startup. They verify the specific
interrupted window; cancellation racing a completed replacement still requires
explicit outcome reconciliation.

Native acceptance uses writable copies of fixed official v2.33.1 programs and
already SHA-verified v2.33.2 archives, independent identities and synthetic data.
The upgrade test proxy explicitly permits end-to-end TLS only to the genuine
official metadata host and serves the exact verified baseline archive locally.
It reports this external metadata exception accurately. This is not a public
Internet asset-delivery, WAN, minimum-OS or arbitrary-version compatibility test.

## Keep a receipt for the attempt

Use the `_with_receipt` forms of the management check, installation request, or
archive upload when your application needs to explain where an attempt ended.
Pass a total time allowance. Each HTTP request also keeps the deadline
configured on the connection. The original methods keep their existing
signatures and behavior.

```rust,no_run
# async fn check(client: &verysync_sidecar::Client) -> verysync_sidecar::Result<()> {
use std::time::Duration;

let attempt = client
    .check_kernel_upgrade_with_receipt(Duration::from_secs(12))
    .await?;
eprintln!("Upgrade check: {:?}", attempt.receipt.outcome());
let check = attempt.result?;
println!("Provider reports a newer release: {}", check.newer);
# Ok(())
# }
```

The outer result reports whether the SDK could start recording the attempt.
The inner result retains the original operation's error and its cause. The
receipt is versioned and can be serialized for private records. It leaves out
credentials, archive URLs and local paths. The operation ID is for correlation.

For a management request, the receipt distinguishes handing the request to the
HTTP client, reading response headers and reading the complete response. Only
an independent server observation can establish receipt at the other end. A
complete refusal can be distinguished from a connection lost after the headers.
A `restarting` acknowledgement is a good point to check process exit and program
files before continuing.

For a normally stopped owner, `run_cli_upgrade_with_receipt` also records whether
a contained helper started and whether the worker saw it exit. Use the native
exit code and private diagnostic to explain a failed check. The documented
provider-installation exit code 4 is preserved as observed; independently
compare the executable before proceeding. The attempt can return an uncertain
outcome after a timeout or a lost response. Preserve the receipt and verify the
selected program before deciding whether to continue.
