# Creation defaults and configuration application

`folder_defaults()` and `device_defaults()` read the engine's current creation
templates. `update_folder_defaults()` and `update_device_defaults()` PATCH only
explicit fields. A change affects subsequent registrations through
`create_folder()` or `create_device()`; existing objects keep their settings.
Templates retain additional upstream fields, which can contain sharing secrets.
Their Debug implementations omit those values. A template's empty identity/path
is not a registered folder or device identity.

```no_run
use verysync_sidecar::{Client, DeviceCompression, DevicePatch, FolderDefaultsPatch};

async fn configure_future_registrations(client: &Client) -> verysync_sidecar::Result<()> {
    let update = client.update_folder_defaults(
        &FolderDefaultsPatch::default()
            .paused(true)
            .rescan_interval_seconds(300)
            .watcher_enabled(false),
    ).await?;
    if !update.requested_fields_match {
        // Readback differed: reconcile with the actual template before continuing.
        return Ok(());
    }
    client.update_device_defaults(
        &DevicePatch::default().compression(DeviceCompression::Never),
    ).await?;
    let application = client.configuration_sync_state().await?;
    // Inspect application.config_in_sync; choose an explicit restart if required.
    Ok(())
}
```

An empty patch is rejected before any request. Client clones serialize writes
and recheck authenticated identity; independent writers must coordinate. A
successful acknowledgment and matching readback establish configuration only.
`configuration_sync_state()` reports the native `configInSync` flag, independently
of matching requested values. It does not flush to disk, certify durability,
restart the engine, or prove scanning/transfer effects. The native integration
test separately checks new-object inheritance, existing-object isolation and
persistence across normal owned-instance shutdown/restart.

Writes are never retried. After cancellation or `MutationOutcomeUnknown`, read
the relevant template and reconcile before deciding whether to write again.
The library does not roll back configuration or implicitly restart an instance.
These methods do not change management credentials, start an official account
session, or acquire a commercial entitlement.

## Advanced folder selections and template inheritance

`folder_advanced_configuration(&id)` and
`update_folder_advanced_configuration(&id, &patch)` read and change explicit
native folder selections. `FolderAdvancedPatch` covers permission handling,
normalization, minimum free space, copier/hasher counts,
retry timing, conflict retention, sparse files, parent ownership, modification
time window, concurrent writes, fsync, case sensitivity, junction traversal,
ownership and extended-attribute flags, block indexing, backup-only mode,
marker-repair policy, puller selections, Live Photo selection and tags.

The observed legacy `pullerMaxPendingKiB` field is read-only in the typed model.
The selected baseline acknowledged nonzero scoped PATCH and complete PUT values
but read them back as zero; an acknowledgment does not establish mutability.

These are configuration controls. Their readback does not establish filesystem
support, metadata replication, deletion handling, resource usage or throughput.
Disabling fsync can reduce native durability. The SDK never silently enables it.
Missing advanced fields remain `None`; unmodeled values remain available through
the original `FolderConfig` or template, and ordinary Debug hides private values.

```no_run
use verysync_sidecar::{
    Client, FolderAdvancedPatch, FolderDefaultsPatch, FolderId, FolderPullOrder,
    FolderScanPatch,
};

async fn choose_future_and_existing_settings(
    client: &Client,
    existing: &FolderId,
) -> verysync_sidecar::Result<()> {
    let template = FolderDefaultsPatch::default()
        .scan_configuration(FolderScanPatch::default()
            .watcher(false)
            .watcher_delay_seconds(0.5))?
        .pull_order(FolderPullOrder::Alphabetic)?
        .advanced_configuration(FolderAdvancedPatch::default()
            .hashers(2)
            .max_conflicts(10))?;
    let future = client.update_folder_defaults(&template).await?;
    let current = client.update_folder_advanced_configuration(
        existing,
        &FolderAdvancedPatch::default().hashers(1),
    ).await?;
    // Inspect both actual configurations and requested_fields_match values.
    // Template edits affect new registrations; existing folders are independent.
    Ok(())
}
```

`FolderDefaults` provides typed `scan_configuration()`,
`scheduling_configuration()`, `selective_configuration()` and
`advanced_configuration()` views. Scan inputs use the registered-folder numeric
validation, including finite watcher delays. Replacing the selected scan or
advanced subpatch in a builder replaces that selected group; unselected native
fields remain untouched. `selective_enabled()` selects only the native flag and
does not acquire an entitlement or download files.

The native case separately verifies selected values, new-folder inheritance,
existing-folder isolation, partial edits, complete-snapshot template editing,
normal restart persistence and retained synthetic bytes. Actual platform metadata
effects, marker names, sharing secrets and remaining template controls retain
separate capability gates. The selectors below extend the typed policy surface.

## Folder types, block/copy strategies and attribute filters

`FolderAdvancedPatch` also selects `FolderType`, `BlockPullOrder`,
`CopyRangeMethod` and an ordered `ExtendedAttributeFilter`. Reads preserve unknown
selector strings; typed writes refuse them. Attribute patterns keep the target's
native matching syntax, rather than being compiled as controller-side regular
expressions. Rule order, permit flags, explicit size selectors and unknown native
filter fields are retained. Patterns and unknown values are hidden from Debug.

```no_run
use verysync_sidecar::{
    BlockPullOrder, Client, CopyRangeMethod, CreateFolderOptions,
    ExtendedAttributeFilter, ExtendedAttributeRule, FolderAdvancedPatch,
    FolderId, FolderType, TargetPath,
};

async fn register_with_explicit_initial_policy(
    client: &Client,
    id: FolderId,
    path: TargetPath,
) -> verysync_sidecar::Result<()> {
    let attributes = ExtendedAttributeFilter::new(
        vec![ExtendedAttributeRule::new("user.*", true)?,
             ExtendedAttributeRule::new("*", false)?],
        2048,
        8192,
    )?;
    let initial = FolderAdvancedPatch::default()
        .folder_type(FolderType::ReceiveEncrypted)
        .block_pull_order(BlockPullOrder::InOrder)
        .copy_range_method(CopyRangeMethod::All)
        .extended_attribute_filter(attributes);
    let actual = client.create_folder(
        &CreateFolderOptions::new(id, path)
            .paused(true)
            .advanced_configuration(initial)?,
    ).await?;
    // Inspect actual.advanced_configuration(); registration is not data proof.
    Ok(())
}
```

Initial per-registration overrides merge into actual upstream defaults and use
the existing single creation request. They never temporarily change the shared
template. An acknowledged create with invalid selected readback is an unknown
outcome, without replay. Template policy edits still affect future objects only.

The selected baseline supports initial receive-encrypted registration but
rejects changing an existing folder to or from that type. Scoped typed edits
check the existing type and refuse such transitions before PATCH. The library
does not recreate a folder or migrate data to bypass this restriction. Other
native type selections and idempotent receive-encrypted edits remain explicit.

Strategy selection does not prove a particular system call, copy-on-write
behavior, block transfer order or supported target filesystem. Initial encrypted
registration does not prove encrypted data transfer or sharing permission.
Attribute-filter configuration does not prove metadata propagation. These effects
retain independent platform/data-path acceptance gates. Marker names, versioning
template locations, sharing secrets and other remaining defaults are separate.

## Complete configuration saves

`configuration()` returns an identity-bound `ConfigurationSnapshot`, retaining
every native section and unknown field. `native_document()` exposes those values
only through explicit inspection; they include API keys and other private data.
Typed folder reads use the target's path syntax, including Windows paths when
the controller runs on another system. The snapshot can edit general options and
creation defaults without reconstructing or dropping unrelated configuration.
Other typed controls continue to manage their own sections through scoped APIs.

```no_run
use verysync_sidecar::{Client, Error, GeneralOptionsPatch};

async fn save_reviewed_configuration(client: &Client) -> verysync_sidecar::Result<()> {
    let mut snapshot = client.configuration().await?;
    snapshot.set_general_options(
        &GeneralOptionsPatch::default().keep_temporaries_hours(48),
    )?;
    match client.replace_configuration(&snapshot).await {
        Ok(receipt) => {
            // Inspect receipt.requested_fields_match and
            // receipt.application_state.config_in_sync independently.
            Ok(())
        }
        Err(Error::ConfigurationChanged) => {
            // Read a fresh snapshot, review the concurrent change, and decide
            // what to save. Never automatically replay the stale document.
            Ok(())
        }
        Err(error) => Err(error),
    }
}
```

Immediately before PUT, the current complete document must equal the original
snapshot. A known stale snapshot returns `ConfigurationChanged` without a write;
a snapshot from another identity is rejected before any request. This check is
not an atomic server-side compare-and-swap. Independent writers must coordinate
throughout the operation, including the interval between the last read and PUT.
The library does not promise atomicity, rollback or protection from an external
writer that changes configuration in that interval.

The receipt reports exact full-document equality and the native application flag
separately. A malformed or failed readback after acknowledgment returns
`MutationOutcomeUnknown`, without retry. Normal shutdown/restart persistence and
retained file bytes are checked independently by native integration tests.

`general_options()` and `update_general_options()` also provide scoped read/PATCH
operations for temporary-file retention, signed progress intervals, folder/dial/
request concurrency, process-priority policy, sleep-prevention policy, minimum
configuration-volume free space, temporary index blocks, remote-name adoption,
full-index resend after upgrade and IP traffic class. `-1` explicitly requests
disabled native progress reporting. Numeric zero values retain the engine's
interpretation. Optional additional readback fields remain `None` when absent;
missing values are not invented as zero or false.

```no_run
use verysync_sidecar::{Client, DiskFreeRequirement, DiskSpaceUnit, GeneralOptionsPatch};

async fn select_general_preferences(client: &Client) -> verysync_sidecar::Result<()> {
    let threshold = DiskFreeRequirement::new(256.0, DiskSpaceUnit::Megabytes)?;
    let update = client.update_general_options(
        &GeneralOptionsPatch::default()
            .min_home_disk_free(threshold)
            .progress_update_interval_seconds(-1),
    ).await?;
    // Inspect requested_fields_match; application and persistence are separate.
    Ok(())
}
```

`DiskFreeRequirement` preserves native `%`, `kB`, `MB`, `GB` and `TB` selectors;
byte units are decimal. Values must be finite and nonnegative, and percentages
cannot exceed 100. Unknown readback units are retained and rejected by typed
edits, including complete-snapshot edits. The SDK neither measures the controller
disk nor reserves space. The native configuration/index volume is the target.

The controlled case checks all five unit selectors, fractional values, partial
field preservation, disabled progress selection and normal restart persistence.
It independently observes the owned process/group's OS priority before and after
an explicit low-priority policy change and restart, relative to the controller's
inherited native priority. It does not change caller process priority or assume
that a CI runner starts at Unix nice 0 or Windows Normal. This does not certify actual
temporary expiry, concurrency limits, disk-pressure handling, sleep prevention,
remote-name replacement, packet QoS or a performance improvement. Network,
bandwidth, upgrade and audit settings retain their separate typed APIs and
verification boundaries. Full same-source platform acceptance remains separate.

## Diagnostic preferences

`diagnostics_options()` reads actual crash settings and legacy usage information.
Destinations and the usage identifier require explicit accessors and are omitted
from Debug, along with other private option values. A reported legacy accepted
version is not an SDK consent record or evidence that a report was transmitted.

The controlled baseline probes requested different `urAccepted`, `urSeen`,
`urPostInsecurely`, `urURL` and `urInitialDelayS` values. Configuration readback
normalized them to fixed values, including after normal restart. The typed API
therefore exposes those observations for reading. It does not promise a
configurable usage destination, opt-out or reporting behavior from those fields.
An eight-second private-receiver observation saw no POST; that finite observation
does not prove that reporting is globally absent. Platform conditions remain
subject to the full final-source gate.

`update_crash_reporting()` changes only explicit native crash settings. It checks
fresh identity, sends one partial PATCH, and returns actual readback. The matching
snapshot getter and `set_crash_reporting()` support reviewed complete saves too.

```no_run
use verysync_sidecar::{Client, CrashReportingPatch};

async fn disable_native_crash_reports(client: &Client) -> verysync_sidecar::Result<()> {
    let update = client.update_crash_reporting(
        &CrashReportingPatch::default().enabled(false),
    ).await?;
    // Check update.requested_fields_match before interpreting the selection.
    Ok(())
}
```

An explicit URL selects an HTTP(S) collector; userinfo, fragments, zero ports,
control characters and values above 32 KiB are rejected before a request.
Query tokens remain private. URL validation does not authenticate a collector.
Enabling reporting can affect future native network activity. The SDK does not
generate a crash, upload a report, accept terms, retry writes or restart the core.
The native case verifies both flag values, a private destination, unchanged usage
and terms fields, normal restart persistence and normal owned exit. Actual crash
upload and collector trust/authentication require separate evidence.

## Event audit, thumbnails and native proxy preferences

`system_preferences()` reads native event-audit, thumbnail and proxy selections.
`update_system_preferences()` sends only explicit fields, checks fresh identity
and returns actual readback. Complete snapshots provide matching typed getters
and edits. `NativePathSelection::Default` sends the native empty selector;
`Path(TargetPath)` retains the target's syntax and rejects a different path style.
The SDK does not open these target paths, move old data, create a proxy or change
its management HTTP client's independent proxy policy. Debug omits paths, proxy
credentials and other private values.

```no_run
use verysync_sidecar::{Client, NativePathSelection, SystemPreferencesPatch, TargetPath};
use std::path::PathBuf;

async fn select_event_log(client: &Client, local_log: PathBuf) -> verysync_sidecar::Result<()> {
    let update = client.update_system_preferences(
        &SystemPreferencesPatch::default()
            .event_audit_enabled(true)
            .event_audit_file(NativePathSelection::Path(TargetPath::local(local_log))),
    ).await?;
    // Match readback and explicitly restart the owned core when required.
    Ok(())
}
```

Native event audit is separate from licensed folder-history records. The
controlled case verifies actual bounded JSON event records, including
`StartupComplete`, after explicit normal restart; it checks disabling/default
selection, retained old log bytes and unrelated sample data. Native event data
can contain private context. Configuration selection does not promise a log
retention policy or every existing-file behavior.

Thumbnail/cache configuration and actual preview/cache artifacts are separate.
The proxy field is an explicitly selected native HTTP(S)/SOCKS5 URI, possibly
with credentials; it is not a verified connection or authentication receipt.
The isolated refusing proxy observed no request during its bounded startup
probe, so no actual proxy transfer is claimed. Per-platform full-source, actual
thumbnail-cache and proxy-routing conditions remain required evidence.
