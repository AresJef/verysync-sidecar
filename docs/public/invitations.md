# Pending offers and folder sharing (unreleased)

`pending_folders()` reads the actual remote folder IDs and their offering device
identities. An optional device filter restricts this read. A remote offer ID,
an engine-proposed local registration ID, and a sharing key have distinct roles;
the library does not equate them. Offer encryption flags describe the upstream
announcement and do not grant read/write permission or supply a sharing key.

`dismiss_folder_offer()` removes only one exact folder/device record. It does
not register a folder, access a local path, or prevent another announcement.
`ignore_folder_offer()` instead adds that exact offer to the offering device's
persistent ignored-folder configuration. It retains observed label/time and
preserves unrelated ignored entries and unknown fields. `unignore_folder()`
removes only that exact ignore. A subsequent announcement is needed before the
offer can reappear. These operations expose actual configuration and pending
readback separately; asynchronous application and other writers can race them.

Joining remains an explicit choice of a validated sharing key and a target path.
Obtain and verify the key through the caller's chosen channel, independently of
the displayed offer. The library cannot infer the correct key from an offer ID.

```no_run
use verysync_sidecar::{Client, DeviceId, JoinFolderOptions, ShareKey, TargetPath};

# async fn join(client: &Client, peer: DeviceId, key: ShareKey, path: TargetPath)
# -> verysync_sidecar::Result<()> {
let offers = client.pending_folders(Some(&peer)).await?;
// The caller checks that the independently supplied key corresponds to its
// chosen offer. No returned label or remote ID is treated as authorization.
let prepared = client.validate_share_key(&key).await?;
let joined = client.join_folder(&JoinFolderOptions::new(prepared, path)).await?;
let shared = client.share_folder_with(&joined.configuration.id, &peer).await?;
assert!(shared.association_present);
# let _ = offers;
# Ok(())
# }
```

`share_folder_with()` requires existing local folder and remote device
registrations, and preserves existing per-peer fields. It does not change the
folder's key-derived permission. `unshare_folder_from()` removes only that peer
association while retaining the device, folder registration, and local files.
Neither method certifies that a connection or transfer has completed. The local
identity is protected from these remote-peer mutations. Registering a key and
associating a peer are separate operations, with separate outcomes; they do not
form a transaction or silently roll back each other.

`pending_devices()` and `dismiss_pending_device()` provide a typed surface for
the fixed engine's pending-device route. Native validation currently observes
empty device maps and missing-record rejection. **Nonempty device records and
their dismissal remain unverified on VerySync.** Their candidate record fields
are retained with unknown values available explicitly. Do not infer device
approval, commercial authorization, or permanent device blocking from them.

Missing offers and missing ignores have distinct errors. Authentication, HTTP
errors and malformed responses are never converted into empty lists. Every
mutation rechecks target identity, shares the Client-clone mutation lock and
sends no automatic write retry. Independent clients/writers must coordinate
read-modify-write settings. Failed post-write verification remains
`MutationOutcomeUnknown`; reconcile actual state before another explicit action.
