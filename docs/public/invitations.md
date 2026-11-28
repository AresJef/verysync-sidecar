# Pending offers and folder sharing

Review pending offers first, then check which device offered the folder before
joining. A folder offer identifies what was offered. A device offer identifies
who requested contact. When a folder needs a sharing key, get it through an
approved channel and verify the permission VerySync reports.

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

`set_folder_peer_encryption_password()` sets the native folder encryption
password on one existing association. Pass `Some(password)` to set the exact
string or `None` to send the native empty value. The client verifies the target
identity, writes the peer list with only that password changed and reads the
result back. `folder_peer_encryption_password_is_set()` observes the current
setting without returning the password. Both methods preserve an omitted
native field as `None`. The update receipt also reports an exact match.

`change_folder_peer_and_verify` runs a single chosen association change and
checks the selected peer and remaining associations afterward. An already
satisfied request leaves the configuration untouched. The report retains the
original reply and the later state, including a concurrent change to another
association. Before assuming the peer received a file, check the file at the
receiving device.

When preparing a receive-encrypted replica, establish the association and
set the password with the peer and folder paused before marking the encrypted
peer untrusted. Use explicit, matching folder IDs for the tested v2.33.2
configuration described in [Configuration](https://github.com/AresJef/verysync-sidecar/blob/v0.1.0/docs/public/configuration.md).

`pending_devices()` and `dismiss_pending_device()` provide a typed surface for
the fixed engine's pending-device route. Native validation currently observes
empty device maps and missing-record rejection. **Nonempty device records and
their dismissal remain unverified on VerySync.** Their candidate record fields
are retained with unknown values available explicitly. Do not infer device
approval, commercial authorization, or permanent device blocking from them.

An empty pending list also does not prove that an unconfigured peer was refused.
An isolated macOS ARM64 v2.33.2 case established an actual one-sided connection
from another official core while the receiver still had no configuration entry
for that peer. All 48 pending-device snapshots in the bounded observation stayed
empty; dismissing the absent record returned `PendingOfferNotFound`. Receiver
configuration, caller bytes and normal owned-tree/state release were preserved.
This observation covers that connection path. The first stable release defers
the positive nonempty record and dismissal case until a reproducible authorized
input produces an actual record on an isolated fixed core. Typed reads, empty
records, missing-record rejection and pending-folder effects keep their
respective checks. Inspect live connections and persistent ignore rules when
controlling peer access.

The historical `trust-devices` argument was also checked against both startup
command forms on the fixed v2.33.2 Linux AMD64 and Windows AMD64 programs.
Native help completed normally. Both parsers rejected the historical
argument, and the isolated state remained empty throughout. This bounds
that specific command-line route on the tested images.
[Native argument check](https://github.com/AresJef/verysync-sidecar/actions/runs/44473889991).

`ignored_devices()`, `ignore_device()` and `unignore_device()` separately expose
persistent ignored identities. Ignoring requires an unconfigured remote ID;
the local ID is protected, and a configured peer must first be explicitly
removed. No implicit unregistering or folder change occurs. Unignore removes
only the chosen record. Optional metadata remains `None` when absent; new
records let the engine supply its canonical metadata rather than inventing
an observation timestamp.

The fixed v2.33.2 API rejects a PATCH to the configuration root. Device ignore
changes therefore read the full configuration and send a PUT preserving every
unrelated field, including unknown settings and management credentials. Client
clones share the mutation lock; independent clients and external writers must
coordinate the entire read-modify-write interval. This is not an atomic field
update against other writers. A failed readback remains an unknown outcome.
`DeviceIgnoreUpdate::is_ignored` reports configuration only. Future connection
attempts, existing temporary connections and live reconnection are separate
observations. Native tests use explicitly selected private redial settings and
count actual attempts reaching an owned loopback receiver; they do not establish
an unconditional reconnection deadline for applications.

Missing offers and missing ignores have distinct errors. Authentication, HTTP
errors and malformed responses are never converted into empty lists. Every
mutation rechecks target identity, shares the Client-clone mutation lock and
sends no automatic write retry. Independent clients/writers must coordinate
read-modify-write settings. Failed post-write verification remains
`MutationOutcomeUnknown`; reconcile actual state before another explicit action.


Use `observe_folder_introduction` with the selected folder, introducer, and
third device to check a current association. The report shows the trust and
withdrawal options, the recorded introduction source and folder membership,
and any current connections. Compare snapshots before and after the native
peer exchange to verify what was added or removed. The read does not change
any peer settings. A separate file check is needed to verify delivery.
