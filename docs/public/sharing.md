# Sharing keys and folder registration

The unreleased sharing API uses the official v2.33.2 engine to generate and
validate folder-sharing keys. `ShareKey` and the management `ApiKey` are distinct
types. Neither a key prefix nor a caller-chosen common folder ID determines
permission. Ordinary Debug omits keys and unknown credential-bearing fields;
`expose_secret()` and unknown-field getters require explicit access.

`generate_share` returns a fresh read/write and read-only pair without
registering a directory. `validate_share_key` checks the key on the selected
authenticated engine and returns its reported permission and proposed local
registration ID. Validation can reject a key with HTTP 200; that becomes
`Error::ShareKeyRejected`, retaining a bounded private diagnostic.

```rust
use verysync_sidecar::{Client, JoinFolderOptions, Result, ShareKey, TargetPath};

async fn register_key(client: &Client, key: ShareKey, path: TargetPath) -> Result<()> {
    let prepared = client.validate_share_key(&key).await?;
    let options = JoinFolderOptions::new(prepared, path).paused(true);
    // Retain this ID before submitting: reconcile it after an uncertain outcome.
    let _local_id = options.folder_id().clone();
    let result = client.join_folder(&options).await?;
    let material_matches = result.submitted_key_matches
        && result.read_only_key_matches && result.read_write_key_matches;
    // Configuration readback is separate from peer association and file effects.
    let _ = (material_matches, result.peer_observation);
    Ok(())
}
```

The proposed ID is local to the prepared registration. Generating keys and
validating the same key again can return different IDs. Keep the ID produced by
preparation; do not manually align two devices' folder IDs. Preparation is bound
to its authenticated target identity and cannot be submitted to another target.
The selected engine derives the stored read-only/read-write material from the
submitted key, using the actual native join route. Read-only validation and
readback do not expose a read/write key. Unknown reported permissions remain
inspectable but registration refuses to guess their meaning.

`join_folder` serializes this Client's modifications, checks fresh identity and
current configuration, reads target defaults and changes only explicit fields.
It rejects a colliding local ID, an already registered sharing group, and by
default an identical configured path string. Path matching does not resolve
aliases or symlinks. Independent clients and other writers still require
coordination: the upstream POST is an upsert, not an atomic create-if-absent.
Check each returned material-readback flag. A false flag can represent pending
application, a changed result or another writer, and must be reconciled.

The return value establishes local registration readback. Its
`JoinPeerObservation::Unobserved` expressly supplies no remote peer, pending
acceptance or file-transfer verdict. No pending-acceptance state is invented
from an empty device list or idle folder. Rejection, registration and peer
observation remain distinct. The engine may require separate connectivity and
association configuration. Closing a borrowed Client does not unregister a
folder or stop its process. A cancelled/uncertain modifying operation is not
retried; inspect `options.folder_id()` and the actual key material first.

Dedicated native tests use real generated keys, engine-proposed distinct local
IDs and independent states. Separate controlled loopback setup demonstrates an
actual file reaching the read-only registration through those keys. That fixture
setup is not acceptance of typed device management, WAN discovery, relays,
multi-peer forwarding or every read-only edit conflict. Those have separate
functional and network gates. This API does not bypass account/license checks
or change sending/receiving settings based on assumed device roles.
