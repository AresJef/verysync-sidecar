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
operations for temporary-file retention, progress intervals, folder/dial/request
concurrency, low-priority policy and sleep-prevention policy. Numeric zero values
retain the engine's interpretation. These are configuration contracts; they do
not certify actual expiry timing, concurrency, process scheduling, system sleep
behavior, or a performance improvement. Network, bandwidth, upgrade and audit
settings retain their separate typed APIs and verification boundaries.
