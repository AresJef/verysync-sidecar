# Device configuration (unreleased)

`Client::devices()` and `Client::device()` read the configured identities, including
the local identity. `device_defaults()` reads the engine's current creation
template. A template can have an empty identity; a configured `DeviceConfig`
always contains a parsed `DeviceId`. Unmodeled configuration and defaults remain
available through `extra` and are omitted from ordinary debug output.

```no_run
use verysync_sidecar::{Client, CreateDeviceOptions, DeviceCompression, DeviceId, DevicePatch};

# async fn configure(client: &Client, peer: DeviceId) -> verysync_sidecar::Result<()> {
let created = client.create_device(
    &CreateDeviceOptions::new(peer.clone()).settings(
        DevicePatch::default()
            .name("Dedicated peer")
            .addresses(vec!["tcp://127.0.0.1:42391".into()])
            .compression(DeviceCompression::Metadata)
            .paused(true),
    ),
).await?;
assert!(created.requested_fields_match);
let resumed = client.resume_device(&peer).await?;
assert!(!resumed.configuration.paused);
let removal = client.remove_device(&peer).await?;
assert!(removal.configuration_absent);
assert!(removal.remaining_folder_associations.is_empty());
# Ok(())
# }
```

Addresses are engine protocol values, not filesystem paths. The library does
not resolve them or infer that they can connect. Compression readback preserves
unknown future strings; typed writes accept the known `Always`, `Metadata` and
`Never` choices. Changing these settings provides configuration evidence, not a
compression ratio or throughput guarantee.

Creation reads the actual defaults and preserves unspecified fields. It refuses
an existing ID before the upstream POST, which is an upsert. Client clones share
a mutation lock, but separate clients and external writers must coordinate.
`update_device()` sends only explicit fields, rechecks the authenticated target
identity, and requires the remote ID to exist. Empty patches are rejected. These
remote-device mutations protect the connected instance's own identity.

`DeviceUpdate::requested_fields_match` compares requested settings with actual
readback. An acknowledgment or a matching snapshot does not prove connection,
disconnection, or completed synchronization. Device pause is independent of
folder and instance pause. The engine can also update peer names on connection
according to its separate name policy.

`remove_device()` sends a single exact-ID DELETE with no deletion body or flag.
It then reads one configuration snapshot for device absence and remaining folder
associations. The library does not access local data paths. Local file retention
and actual disconnect behavior require independent native validation; another
writer can subsequently change configuration. Removing a peer does not send a
configuration change to the other instance.

No modifying request is automatically retried. Cancellation, a lost response,
or failed readback can leave an applied change: inspect the exact identity and
folder associations before deciding to retry. `MutationOutcomeUnknown` retains
that distinction. Ordinary diagnostics omit upstream payload values.
