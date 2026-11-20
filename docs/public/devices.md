# Device configuration

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

A controlled v2.33.2 native run removed the peer once and observed its
disconnect, then observed the kernel registering it again and delivering a new
synthetic file after an explicit scan with the existing folder keys. Removing
a device record does not revoke those shared keys. Treat the returned absence
as a configuration snapshot. A durable peer-rejection policy needs separate
native capabilities and validation; the library does not add that policy to
this DELETE. That earlier observation used a 20-second window. It accepted a
disconnected remote connection snapshot or a native `DeviceDisconnected` event
for the same peer between deletion and the observation. A quick reconnection can
hide a disconnect between polls. The current release check for an actual
disconnect uses the explicit operation below. Both operations still require file
retention and normal shutdown in the applicable native tests.

No modifying request is automatically retried. Cancellation, a lost response,
or failed readback can leave an applied change: inspect the exact identity and
folder associations before deciding to retry. `MutationOutcomeUnknown` retains
that distinction. Ordinary diagnostics omit upstream payload values.

## Explicitly disconnect before deleting a registration

`disconnect_and_remove_device(&peer, timeout)` separately expresses a stronger
operation: patch only this peer's pause field, require a present native connection
entry reporting `connected=false`, then issue one DELETE and return its actual
configuration snapshot. A missing connection row is not invented as a disconnected
record. The positive total deadline includes clone-lock acquisition and all calls.
The previous configuration in the result precedes the pause. No data path is
opened and no modification is retried. Cancellation/failure can leave the peer
paused or deleted; after a submitted modification, errors retain an unknown-outcome
wrapper. Callers must reconcile state before retrying.

This explicit operation does not revoke shared keys or promise the peer remains
disconnected after deletion. The original `remove_device()` remains a single
DELETE without an implicit pause or rejection policy. Native acceptance of these
two semantics is recorded separately. The disconnect requirement belongs to the
explicit operation and still requires actual connection observation and retained
file bytes. The single-DELETE case requires its removal-time snapshot and retained
files, then separately observes native shared-key readmission and transfer of a
new canary. Previous single-DELETE disconnect failures remain historical negative
evidence; deletion alone is not a promise of disconnection or key revocation.

## Additional peer and default selections

`DeviceConfig::advanced_configuration()` and
`DeviceDefaults::advanced_configuration()` decode additional native settings
without another request. Missing fields remain absent. `IntroductionSource`
distinguishes an explicit empty source, a parsed device identity and an unknown
native value; an outer `None` means the field was absent. Debug hides identities,
unknown text and other private values.

Pass a `DeviceAdvancedPatch` to `DevicePatch::advanced_configuration()` to select
certificate name, introducer/removal policy, introduction source, native network
rules, automatic folder acceptance, outstanding request budget, untrusted-peer
flag, connection count, remote-name adoption, native self-classification or a
complete ignored-folder list.
The existing create, update, default and complete-snapshot APIs keep their
identity/existence guards and single-write behavior. Replacing the advanced
subpatch replaces only that selected group. The native `selfed` flag neither
changes a certificate identity nor proves official-account ownership.
If selected advanced values have an invalid native type after an acknowledged
create, update or template write, the result is `MutationOutcomeUnknown`.

With VerySync v2.33.2 on the six standard macOS, Windows and Linux AMD64/ARM64
profiles, three isolated instances sharing one group verified native
introductions. The receiving instance added the third
device, recorded the trusted peer as its introduction source and added the
folder association after reconnecting. With `skip_introduction_removals(false)`,
the introducer's withdrawal removed the association and the introduced device
from the receiver. The test verified the existing file bytes and normal exits
of all three instances.

After the withdrawal and file checks, the regression pauses the fixture's peer
connections and confirms their disconnection before checking normal exits.
Other runs observed a graceful-shutdown timeout with active peer connections
after successful withdrawal on macOS ARM64 and Windows AMD64.

In a second three-instance run, the receiver kept the introduced device, its
source and its folder association with `skip_introduction_removals(true)`.
The setting was in place before the first connection. After withdrawal, the
receiver restarted with the same identity and received a new file from the
introducer in the fresh session.

A third run gave the receiver an explicit loopback address for the already
introduced device and established a direct connection. With the introducer's
folder paused, the receiver obtained a new file from that device and verified
its complete bytes. The original introduction source and folder association
remained present when the receiver configured the address.
`Capability::DeviceIntroduction` records this scope in `library_capabilities()`.
[Native workflow](https://github.com/AresJef/verysync-sidecar/actions/runs/44292513846)

```no_run
use verysync_sidecar::{Client, DeviceAdvancedPatch, DeviceId, DevicePatch};

async fn choose_peer_preferences(
    client: &Client,
    peer: &DeviceId,
) -> verysync_sidecar::Result<()> {
    let patch = DevicePatch::default().advanced_configuration(
        DeviceAdvancedPatch::default()
            .num_connections(2)
            .max_request_kib(4096)
            .auto_accept_folders(false),
    )?;
    let actual = client.update_device(peer, &patch).await?;
    // Inspect actual.configuration and actual.requested_fields_match.
    Ok(())
}
```

Network-rule syntax is interpreted by the target. The SDK bounds the submitted
list and text without resolving addresses or changing the controller's routes.
An explicit `ignored_folders()` selection replaces the whole selected peer's
list; use the existing single-offer ignore/unignore operations to preserve other
entries automatically. Unknown ignored-record fields are retained.

Configuration does not prove automatic introductions, accepted folder data,
certificate-name enforcement, encrypted transfers, active connection counts or
applied network restrictions. Those require independent native effects. On the
selected baseline, a template normalizes an introduction source to the empty
value even with a configured introducer. A configured peer can retain an explicit
valid introducer identity; inspect actual field matching instead of inferring
source inheritance.
