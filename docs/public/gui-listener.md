# Native GUI listener control (unreleased)

`Client::gui_listener()` reads the stored server enable flag, native bind address,
TLS selection and Unix socket mode after checking the current device identity.
Known management username, password and API key fields are excluded from this
DTO. Other native preferences remain explicitly inspectable through `extra()`;
ordinary Debug omits their values and the address. Unknown address or permission
selectors are retained on reads and refused by typed writes.

`update_gui_listener()` issues one explicit PATCH and returns the previous
listener snapshot and private native acknowledgement. This write can close the
current endpoint, change its protocol or disable management while synchronization
continues. Prepare a new explicit connection and trust policy before writing.
The method does not discover an address, reconnect, install certificates, restart
or stop a process, roll back a change or retry a write. A lost response can mean
an applied change; reconcile through the intended endpoint before choosing a
further action.

```no_run
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, GuiListenAddress, GuiListenerPatch,
    ManagementEndpoint, ManagementTransport,
};

# async fn change_listener(
#   old: &Client, bind: GuiListenAddress, endpoint: ManagementEndpoint,
#   key: ApiKey, trust: ManagementTransport,
# ) -> verysync_sidecar::Result<Client> {
let reconnect = ConnectOptions::new(endpoint, key)
    .expected_device_id(old.instance().device_id.clone())
    .transport(trust);
let receipt = old.update_gui_listener(
    &GuiListenerPatch::default().address(bind).use_tls(true),
).await?;
let connected = Client::connect(reconnect).await?;
let actual = connected.gui_listener().await?;
assert!(receipt.requested_fields_match(&actual));
# Ok(connected)
# }
```

`GuiListenAddress::tcp()` selects a native bind authority, not a management URL.
It accepts a hostname or IP with a numeric port, bracketed IPv6, an explicitly
empty host and port zero. Empty-host binding can expose interfaces; port zero
requires a reachable address obtained separately. Neither is substituted for a
caller-selected connection URL. A TCP binding can also differ from a reverse
proxy's external address. `unix_socket()` takes a `TargetPath`: local callers use
Path/PathBuf operations before wrapping the path, and remote callers select Unix
target syntax explicitly. Socket paths must be absolute. The library does not
rewrite them through the caller's operating-system path syntax.

`GuiSocketPermissions::NativeDefault` sends the native empty-string default;
`Mode` sends explicit octal mode bits up to `0o7777`. The Unix permission field
and socket addresses are refused for Windows targets. A matching configuration
value does not establish a file's actual mode or access by another user.

TLS server certificate/key provisioning and client trust are separate inputs.
The library does not disable certificate or hostname validation. The fixed
program's automatically generated GUI certificate names its host; callers must
provide a matching connection name and appropriate trust, or provision suitable
certificate material through their controlled environment. The native test
explicitly prepares test certificate material only while its isolated core is
stopped, then verifies direct native HTTPS without a proxy frontend.

Disabling the native GUI server does not prove the core stopped. A borrowed
connection owns no process. An owned instance can still be observed with
`wait_for_exit()` or explicitly terminated with `force_stop()`; neither action
is selected implicitly by the listener write. Existing owner and Client values
retain their prior endpoint. Manage the changed endpoint explicitly. An explicit
managed startup selects and enables its configured management endpoint again;
this is separate from the stored disabled-server state. Managed HTTPS startup
and owner endpoint adoption have separate pending implementation/acceptance
conditions and are not inferred from the borrowed Client operations.

The controlled native cases verify direct TLS enable/revert, explicit address
migration, actual GUI disable with separately chosen process cleanup, retained
identity and synthetic bytes, and actual Unix socket permission changes. Full
same-source native platform acceptance remains pending. HTTP acknowledgement,
stored readback, successful TLS authentication and process-tree exit are separate
observations throughout.
