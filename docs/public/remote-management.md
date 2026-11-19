# Official remote management (unreleased)

The native remote-management permission, a tunnel probe, and an authenticated
connection are separate operations. None acquires a license or proves another
operation succeeded. The bundled v2.33.2 GUI marks remote management as a Pro
feature. A positive licensed native gateway session remains pending acceptance.

`DeviceConfig` and `DeviceDefaults` preserve the optional native `allowTunnel`
and `remoteGUIPort` fields. Missing fields stay missing. Explicit
`DevicePatch::allow_tunnel()` and `remote_gui_port()` update only the selected
fields. A port must be nonzero. Grant permission on the instance that is to
accept remote management, for the appropriate peer identity; coordinate the
native remote GUI port selection with the actual target listener. The library
does not discover listeners, derive addresses from port numbers or silently
grant permission. Matching configuration readback does not establish access.

`Client::probe_device_tunnel()` checks the current local identity, requires an
exact configured remote device, and issues one native GET. This probe can
initiate peer traffic, so clones serialize it with modifying operations. It
uses the canonical trailing-slash route without following redirects. The result
checks the reported peer identity and requires the native `tunnel` boolean.
`DeviceTunnelProbe::native_error()` and `extra()` retain private native details;
ordinary Debug omits their values. A false result is an actual negative
observation, not an HTTP error or a completed remote session. Human-readable
errors are not used to infer an account's commercial entitlement.

```no_run
use verysync_sidecar::{ApiKey, Client, ConnectOptions, DeviceId, ManagementEndpoint};

# async fn connect_remote(
#   local: &Client, gateway: ManagementEndpoint, target: DeviceId, target_key: ApiKey
# ) -> verysync_sidecar::Result<()> {
let probe = local.probe_device_tunnel(&target).await?;
if probe.tunnel_available() {
    let remote = Client::connect(
        ConnectOptions::remote_tunnel(gateway, target.clone(), target_key)?
    ).await?;
    assert_eq!(remote.system_status().await?.device_id, target);
}
# Ok(())
# }
```

For a connection, supply the gateway's explicit HTTP(S) base URL and the target
instance's API key. `ConnectOptions::remote_tunnel()` appends the target device
ID beneath that base path and sets the expected handshake identity to that
target. Existing prefix paths are retained. Use the same request deadlines,
response bounds and version policy options as an ordinary connection. The
constructor rejects a Unix-socket gateway and performs no network request.
`Client::connect()` then performs the normal read-only authenticated handshake;
a different identity is an error. Losing this management connection does not
imply the remote process stopped.

Gateway creation, discovery, implicit resume, license changes and automatic
retries are not part of these calls. In particular, the library never defaults
to the upstream shared loopback port 18886. Supply only a gateway you intend
to use. An owned instance's isolated auxiliary listener and the management
listener are distinct resources. A local tunnel probe or a synthetic gateway
handshake does not establish cross-network remote management.

With a confirmed private peer connection on isolated unlicensed native
instances, a denied probe reports a false tunnel and a native authorization
diagnostic. After explicitly granting the native
permission, the probe can report availability or a transient native failure;
neither establishes a commercial license or completed session. The tests retain
the actual result and verify permission revocation,
the target identity, unrelated configuration, restart persistence and synthetic
file contents. Licensed positive sessions, actual remote operations and final
cross-network effects remain required acceptance conditions. Local-API and
enterprise control retain their separate, pending contracts.
