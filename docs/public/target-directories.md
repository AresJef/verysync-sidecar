# Native target directory helpers

These helpers use the engine's native directory picker, independently of
file-manager volumes and synchronization-folder registrations:

- `target_directory_locations()` reads its starting locations and localized
  display titles. The native route is spelled `system/storeages`.
- `target_directories(path)` lists child directories using the verified `d`
  filter. Native error statuses, missing directories and file paths return an
  error, including when the HTTP status itself is 200.
- `create_target_directory(path)` explicitly requests directory creation, then
  reads the requested path as a directory. Existing directories are accepted;
  existing files are preserved and produce an error. It registers no sync folder
  and opens no desktop window. Native errors or failed readback after the POST
  remain `MutationOutcomeUnknown`; inspect the target before retrying. The SDK
  neither retries nor rolls back this operation.

```no_run
# async fn example(client: &verysync_sidecar::Client) -> verysync_sidecar::Result<()> {
use std::path::Path;
use verysync_sidecar::TargetPath;

// For a local engine, construct paths with the host's native Path operations.
let path = TargetPath::local(Path::new("synthetic-parent").join("selected-child"));
let created = client.create_target_directory(&path).await?;
let entries = client.target_directories(&path).await?;
# let _ = (created, entries);
# Ok(()) }
```

For a remote target, explicitly select `TargetPath::remote(PathStyle::Windows,
...)` or `PathStyle::Unix`. The selected syntax must match that engine. Returned
locations and creation paths retain the native target syntax, never a host
`PathBuf`. The engine can canonicalize aliases, separators and relative paths;
the returned creation path may differ textually from the request. The SDK does
no local directory inspection, canonicalization or path concatenation.

Directory names, paths, localized titles/messages and extra fields are private,
untrusted native data. Debug output omits their values. Access them explicitly
when needed, and validate names before constructing paths for another purpose.
Directory reads do not establish permission to write, synchronization progress,
or the state of another backend. Native creation readback establishes a directory
observation at that moment; external writers can still change it later.

`native_system_paths()` reads the connected program's actual configuration,
data, profile, configuration-file and database locations as `TargetPath` values.
Other native entries remain exact strings: `logFile` can be `-` for standard
output, and audit/panic filenames can contain native timestamp templates.
The SDK neither expands these values nor treats them as controller paths.

`request_folder_temporary_cleanup(folder)` explicitly invokes the registered
native folder runner's cleanup. In the fixed program it targets
`.verysync/*.tmp` and `.verysync/*.sess`. Matching directories and their contents
can be removed recursively. Nonmatching nested directories, ordinary `.tmp`
files outside that marker, and controller files are outside this selection.
This GET changes state: the SDK checks identity and folder registration,
serializes it, and sends it once. Paused/nonrunning native runners can refuse
the request even while the folder remains configured.

```no_run
# async fn cleanup_temporary_files(client: &verysync_sidecar::Client, folder: &verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
let locations = client.native_system_paths().await?;
let receipt = client.request_folder_temporary_cleanup(folder).await?;
assert_eq!(&receipt.folder, folder);
// Observe required target file effects independently before proceeding.
# let _ = locations;
# Ok(()) }
```

An empty native error string is an acknowledgement, without a removed-file count
or proof that every removal succeeded. The core can log per-file failures while
still returning that receipt. Native error envelopes and uncertain responses
after sending remain `MutationOutcomeUnknown`; the SDK performs no retry,
rollback, automatic scan or implicit restart. Other controllers can change the
registration after the preflight read. Coordinate maintenance with the caller's
data and transfer policy, and verify the effects the application requires.
