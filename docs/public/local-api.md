# Native Local-API

`LocalApiClient` connects to an explicitly selected, already enabled native
Local-API endpoint. It is separate from the GUI API-key `Client` and from
`ManagedInstance` process ownership. Connecting never changes configuration,
activates a trial, acquires a license, downloads a program or discovers a port.

```rust,no_run
use verysync_sidecar::{LocalApiClient, LocalApiConnectOptions, ManagementEndpoint};
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let endpoint = ManagementEndpoint::http("http://127.0.0.1:12345/")?;
let local = LocalApiClient::connect(LocalApiConnectOptions::new(endpoint)?).await?;
let status = local.system_status().await?;
println!("{}", status.device_id);
# Ok(())
# }
```

Use the address of a dedicated instance. No default endpoint is assumed. Supply
`expected_device_id` when an out-of-band identity is available. A changed
identity rejects a fresh status read or a potentially modifying raw request.
The connection follows the fixed v2.33.2 version policy, explicit transport trust,
bounded response size and complete-request deadline. It does not send a GUI API
key, reuse a GUI login session or automatically retry a request.

`version()` and `system_status()` return typed snapshots. Absent metrics remain
`None`, distinct from a reported zero. Unknown fields remain explicitly available
and are omitted from ordinary debug output. `raw()` encodes structured components
beneath `rest/localapi/` on the selected endpoint, preserving any proxy prefix.
Components exclude that fixed prefix. Raw status, headers and body are preserved;
HTTP success alone does not establish a native operation's effect or entitlement.
Declare `RequestEffect::MayModify` for state-changing routes, including GET routes
whose native behavior changes state. Those calls serialize across client clones
and check identity before sending.

For a library-owned instance, `ManagedOptions::local_api_enabled(true)` explicitly
sets the native startup flag. It requires an HTTP(S) management endpoint and
grants no commercial entitlement. The default preserves Local-API settings.
Only known library-generated `appconf.yaml` forms may be replaced, including the
earlier exact SDK startup file. Other settings are rejected without replacement.
The generated settings use the native `verysync:` root and disable automatic
startup. This is a startup option, not an assertion that a live reconfiguration
has taken effect. Caller-owned instances must be enabled by their owner.

On v2.33.2, controlled macOS ARM64 native observations distinguish disabled HTTP
404, enabled loopback HTTP reads and Unix-socket HTTP 400. The Unix-socket wrapper
fails while parsing its peer address, before its enable check; this client rejects
that transport. A disabled endpoint is not classified as a missing license.
Some native Local-API routes have separate commercial checks. A successful basic
status read does not prove licensed folder browsing, selective sync or remote
access. Those positive paths still need authorized native acceptance. Cross-platform
runtime coverage is tracked separately from these local observations.
