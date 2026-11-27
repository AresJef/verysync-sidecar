# Native GUI listener control

Check the existing address before changing where VerySync accepts management
connections. After a change, read the settings and separately test whether the
old address still answers and the intended new address accepts the expected
device identity. Have a way to manage the selected process if the old
connection stops answering. Check the documented v2.33.2 live-disable limit
before depending on an address or listener setting to take effect.

`Client::gui_listener()` reads the stored server enable flag, native bind address,
TLS selection and Unix socket mode after checking the current device identity.
Known management username, password and API key fields are excluded from this
DTO. Other native preferences remain explicitly inspectable through `extra()`;
ordinary Debug omits their values and the address. Unknown address or permission
selectors are retained on reads and refused by typed writes.

`update_gui_listener()` issues one explicit PATCH and returns the previous
listener snapshot and private native acknowledgement. Address/protocol changes
can interrupt the current endpoint while synchronization continues. Prepare a
new explicit connection and trust policy before writing.
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

The stored `enabled` flag is not proof that management access has been removed.
An isolated macOS arm64 v2.33.2 experiment issued exactly one `enabled=false` PATCH, received
an acknowledgement, independently verified the persisted false flag, and
observed the native program log a new GUI/API listener followed by continued
exact-process listening. No post-disable bind, connection or request interfered
with that observation. Live GUI/API hot-disable is unsupported on this fixed baseline. The typed
setter exposes the stored configuration request; its acknowledgement does not
establish endpoint closure. A transient listener gap does not establish
successful disable. No automatic restart or process stop compensates for this
native limitation.

Neither the stored flag nor listener absence proves the core stopped. A borrowed
connection owns no process. An owned instance can still be observed with
`wait_for_exit()` or explicitly terminated with `force_stop()`; neither action
is selected implicitly by the listener write. Existing owner and Client values
retain their prior endpoint until the caller explicitly reconnects. An owned
instance can use `reconnect_management()` to authenticate the same identity and
adopt a direct local endpoint without changing process ownership. An explicit
managed startup selects and enables its configured management endpoint again;
this is separate from the stored disabled-server state. Managed HTTPS startup and owner endpoint adoption have separate native
acceptance conditions and are not inferred from borrowed Client operations.

The controlled native cases verify direct TLS enable/revert, explicit address
migration, retained identity and synthetic bytes, and actual Unix socket
permission changes. Stored disable acceptance requires one acknowledged request,
a persisted false flag, passive observation of the exact owned process, retained
identity and synthetic bytes, and separately requested process cleanup. The
eight-second observation does not reserve an address or probe a possibly reused
endpoint. Continued listening is recorded as the fixed program's unsupported
live effect; listener absence in one observation window is not a support promise.
The earlier closure test and its false-positive bind-reservation cause remain
historical evidence. The tests verify HTTP acknowledgement, stored readback,
TLS authentication and process-tree exit separately.

Replacing a Unix socket can interrupt its own PATCH response. The native case
retains a transport/timeout `MutationOutcomeUnknown` and then explicitly opens a
read-only connection with the expected device identity. It requires the selected
mode, the unchanged remaining GUI configuration and the actual filesystem mode
before recording the observed effect. The original acknowledgement stays
unknown. Separate controlled-response cases cover both applied and unchanged
readbacks and require exactly one PATCH followed by GET requests.

Passive listener observations report only bounded counts for the exact owned
process and whether its owner observed exit. Raw process IDs, addresses and
paths are omitted from ordinary output. Observation failures remain test
failures, and missing observations do not imply successful disable.

## Check a listener change after the application restarts

Use a receipt when the original application may close before a listener change
returns. Before submitting, obtain the expected device ID and plan how the next
process will reach the device. The native bind authority is the setting to
change. The connection URL is a separate choice supplied by the host each time,
with its own HTTPS trust policy.

Start with `Client::prepare_gui_listener_change()`. Pass that single-use
operation to `execute_gui_listener_change_persisted()` with your application's
save callback. The callback saves the intent and then the last checkpoint before
the write. If either save fails, the library does not send the change. Save the
returned receipt as well. If the application exits during the write or the last
save fails, the checkpoint can still say the listener may have changed.

After restarting the application, decode the saved receipt with
`ControlOperationReceipt::decode()`. Create new `ConnectOptions` with an
endpoint you already trust, the expected device ID, and the credentials your
host has supplied for that connection. Call `observe_gui_listener()` on the
receipt. It checks the selected device and reads the current listener settings.
A matching snapshot confirms what the device reports at the observation time.
The original acknowledgement remains unknown if it was lost. Another manager
could have changed the same settings. A borrowed connection also leaves the
process generation unknown.

The [gui_listener_recovery example](../../examples/gui_listener_recovery.rs)
shows two independent process invocations:

```sh
cargo run --example gui_listener_recovery -- submit "$operation_dir" < "$submit_settings"
cargo run --example gui_listener_recovery -- observe "$operation_dir" < "$observe_settings"
```

To run the example from your own package, copy it to
`src/bin/gui_listener_recovery.rs` and use `cargo run --bin gui_listener_recovery`.
Add `verysync-sidecar`, `serde` with `derive`, `serde_json`, `tempfile`, and
`tokio` with `macros` and `rt-multi-thread` as direct dependencies. Keep the
`verysync-sidecar` TLS feature enabled for HTTPS.

Create a fresh directory accessible only to the application user. The example
checks Unix permission bits. On Windows, use a directory with a caller-only
access control list. Keep both input files private or have your host pass the
JSON directly on standard input. Both commands require `endpoint`, `api_key`,
and `expected_device_id`. The `submit` input also requires the new `bind`
authority and accepts `use_tls`. Use `ca_pem` for an additional HTTPS trust root
and `timeout_ms` to change the request deadline. Set the `observe` input's
endpoint to the connection you have selected for the readback. Use separate
inputs so the new process can use current credentials and trust.

The example keeps `receipt.json` in the private directory. It syncs each new file
before replacing the saved checkpoint and syncs the directory on Unix. Keep the
receipt private because it contains the intended setting. If you opt in with
`event_log: true` on submit, the separate `events.jsonl` stores up to eight
progress entries plus a drop count. Repeated adjacent entries are combined. A
slow or unavailable log does not hold up the change, and you can remove the log
independently of the receipt.

Submit exits with code 2 if the listener may have changed without a confirmed
acknowledgement. Run observe with a trusted endpoint before making another
change. Observe exits with code 0 when it reads the original device, even when
the settings differ. Inspect `requested_fields_match` for the comparison.
If the receipt is unreadable, the endpoint is unreachable or the connected
device has a different identity, keep the receipt and check the host's endpoint,
trust and credentials.
