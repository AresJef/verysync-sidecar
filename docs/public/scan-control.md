
## Scan scope and automatic scanning

`request_scan` requests one whole-folder scan. `request_scan_subpaths` requests
1 through 256 explicit relative paths inside one existing, unpaused folder.
Use native `Path` operations and `TargetPath::local` for a local instance, or
`TargetPath::remote` with the connected target's syntax for a remote instance.
The library preserves exact names and encodes each `sub` query value separately.
Absolute paths, parent components, mismatched target syntax and an empty scope
are rejected. It does not canonicalize paths or inspect filesystem symlinks;
these checks bound request syntax, not the engine's filesystem permissions.

`request_all_scans` submits the engine's all-folder request. It does not resume
paused folders. Every modifying request checks the current instance identity,
shares the Client clone mutation lock and is never automatically retried.
An acknowledgement is separate from actual indexed files or scan completion.
The existing scan observer cannot correlate a cycle with a specific request.

```no_run
# async fn example(client: &verysync_sidecar::Client, folder: &verysync_sidecar::FolderId) -> verysync_sidecar::Result<()> {
use std::path::Path;
use verysync_sidecar::{FolderScanPatch, TargetPath};
let relative = Path::new("documents").join("sample.txt");
client.request_scan_subpaths(folder, &[TargetPath::local(relative)]).await?;
let changed = client.update_folder_scan_configuration(folder,
    &FolderScanPatch::default().rescan_interval_seconds(60)
        .watcher(true).watcher_delay_seconds(1.5)).await?;
# let _ = changed;
# Ok(()) }
```

`folder_scan_configuration` reads actual settings. `FolderScanPatch` submits
only selected fields and returns actual readback with `requested_fields_match`.
Periodic rescanning uses whole seconds; zero disables it. Watcher coalescing
delay supports fractional seconds. Watcher timeout uses whole seconds; zero is
preserved. The scan-progress interval preserves the engine's default minus-one
value. Initial scanning can be explicitly disabled independently of periodic
scans and filesystem notifications. SDK numeric bounds reject nonfinite,
negative or overflowing intervals before I/O. Updates do not restart the core.
Setting readback alone does not establish watcher readiness or scan completion.
Coordinate other configuration writers and reconcile unknown mutation outcomes
before retrying. Additional settings can contain private data; Debug omits them.

Dedicated native tests compare two selected subpaths, one whole folder and all
folders using actual indexed-file counts. They separately observe a periodic
scan with filesystem notifications disabled, and a filesystem notification with
periodic scans disabled after explicit restart. Both use new files without an
explicit scan request. The notification case also disables initial scanning
and observes a separate settling scan before creating the new sample, keeping
startup activity from becoming notification evidence. Tests preserve synthetic
bytes and require normal tree exit.
