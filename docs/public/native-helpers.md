# Explicit native helpers

`native_health()` reads the program's native HTTP health snapshot through the
selected authenticated connection, with a fresh target-identity check. The native
route `/rest/noauth/health` itself does not require authentication; this `Client`
method is intended for an already connected instance. `NativeHealthStatus::Ok`
represents the exact `OK` token. Other nonempty tokens and additional fields are
retained, while missing, empty or wrongly typed status fields are invalid
responses. Unknown values are omitted from ordinary Debug output. Native body
errors remain typed API errors even if the HTTP status is 200. The snapshot does
not establish folder completion, task success or commercial authorization.

`normalize_device_id(text)` asks the selected engine to validate and normalize
device text. Native lowercase and ungrouped forms can return the same canonical
`DeviceId`. This differs from `DeviceId::parse`, which checks the local canonical
character layout. The native test separately checks a changed checksum that
passes the local layout check and is rejected by the engine. Neither operation
proves possession of a peer certificate or registers a device.

`lookup_target_ip(ip)` asks that engine for its IP-location data. It accepts an
explicit `std::net::IpAddr`, checks the returned address, and preserves empty or
localized native location strings. The target may consult its own services or
network. The native test uses IPv4 and IPv6 loopback only; geographically accurate
public-IP results have separate environment requirements.

`native_random_number()` explicitly requests the native decimal number and
decodes it as `u64`. This makes no cryptographic, uniqueness or distribution
claim. Use `ApiKey::generate()` for secure management credentials. The native GET
uses mutation semantics and is never automatically retried, since random state
can advance even if a response is lost or malformed.

`collect_native_usage_report()` explicitly collects the engine's report snapshot,
including its version, platform, device count and additional native fields. The
SDK neither enables reporting nor uploads the returned report. Native background
reporting remains a separate configuration concern; collection is not evidence
of system-wide network isolation or delivery. Native benchmark-like fields are
retained data, not SDK performance measurements. Collection uses mutation
semantics because native diagnostic state can change. The native test separately
checks that usage/crash preferences remain unchanged by collection.

`pending_native_link()` retrieves one native GUI-link snapshot. An empty native
string becomes `None`. Nonempty text is private, untrusted data and can contain
sharing credentials. The SDK never opens/follows it, accepts a key, or registers
a folder automatically. Delivery can consume native state, so the method uses
conservative mutation semantics, with no retry on uncertain results. The native
test currently verifies the empty-link case; nonempty transport and redaction
have synthetic contract coverage, with actual native nonempty delivery still
requiring its own effect evidence.

```no_run
# async fn example(client: &verysync_sidecar::Client) -> verysync_sidecar::Result<()> {
let health = client.native_health().await?;
let canonical = client.normalize_device_id("caller-provided device text").await?;
let report = client.collect_native_usage_report().await?;
let pending = client.pending_native_link().await?;
// Handle untrusted pending text explicitly, without automatically opening it.
# let _ = (health, canonical, report, pending);
# Ok(()) }
```

All methods check the authenticated instance identity before their native request.
Mutating helpers serialize with other mutations through cloned clients. Response
size limits, deadlines and transport authentication remain in force. Ordinary
Debug output omits private report, location and link values; inspect fields
explicitly when needed and redact them before logging.
