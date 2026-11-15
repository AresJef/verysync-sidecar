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

`native_migration_progress()` reads the global native migration snapshot from
`/rest/migrate/progress`, after a fresh target-identity check. It preserves the
native task label, signed total/completed counters, percentage, finished flag,
task error text and unknown fields. Counter units and sentinel values are not
inferred; the percentage is neither clamped nor recomputed from the counters.
All known fields must be present with the expected types. A full progress
snapshot with nonempty task error text remains data; a native request-error
envelope remains a typed API error, and unsuccessful HTTP responses retain their
typed transport/authentication or HTTP errors.

Reading progress does not start or cancel a migration. This global snapshot has
no caller job ID and may already report a finished migration on a fresh instance.
Inspect `error_message` separately from `finished`; neither flag nor percentage
alone proves the success of work initiated by your application. The native test
checks the existing completed baseline without starting migration work. Active
and failed snapshots have synthetic transport coverage. Names, task errors,
counters and additional values are omitted from ordinary Debug output.

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

`native_random_string(length)` explicitly generates one native ASCII
alphanumeric string. `None` omits the query and `Some(0)` selects the native
32-character default. Positive `u16` lengths request the exact byte count,
including 65535. The result retains unknown fields and excludes the value and
unknown data from ordinary Debug. Inspect `value` explicitly and redact it
before logging. Wrong lengths, malformed values and native body errors remain
errors, with unknown mutation outcomes after a request may have advanced state.
There is no retry, cryptographic-strength or uniqueness guarantee; use
`ApiKey::generate()` for secure management credentials. The SDK bound describes
the verified typed interface, not an inferred native maximum; raw requests remain
available for separately validated inputs.

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
let migration = client.native_migration_progress().await?;
let generated = client.native_random_string(Some(16)).await?;
assert_eq!(generated.value.len(), 16);
let canonical = client.normalize_device_id("caller-provided device text").await?;
let report = client.collect_native_usage_report().await?;
let pending = client.pending_native_link().await?;
// Handle untrusted pending text explicitly, without automatically opening it.
# let _ = (health, migration, generated, canonical, report, pending);
# Ok(()) }
```

All methods check the authenticated instance identity before their native request.
Mutating helpers serialize with other mutations through cloned clients. Response
size limits, deadlines and transport authentication remain in force. Ordinary
Debug output omits private report, location and link values; inspect fields
explicitly when needed and redact them before logging.
