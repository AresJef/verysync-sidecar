# Check an operation before making changes

Use the operation's preflight on an existing connection to inspect known
requirements. The report contains the connection-time target information and
recorded evidence. Select `PreflightReads::SelectedOperation` when you also
want to make the documented reads. The report records when those reads finished
and whether the target's reported identity and version still match.

| Operation | Static evidence | Optional reads |
| --- | --- | --- |
| `Client::preflight_gui_listener` | Existing management connection, target and recorded listener-control scope | Version and identity checks around one read of the current listener settings |
| `Client::preflight_upgrade` | The exact selected source path and reported target | Version and identity checks. The engine-provider path also makes one native release check, which can contact the configured release feed. |
| `LocalApiClient::preflight_folder_need` | Existing Local-API connection and reported target | Version and identity checks around one need request for the selected folder, using page 1 with an item limit of 1 |

`PreflightReads::None` makes zero additional requests. The connection you
already established still has its original handshake. The report leaves current
access, commercial conditions and the right to submit a mutation unknown.
Even a successful preflight is an observation at one moment. Recheck the
device, authorization and operation inputs when you make a change.

For a pinned archive, select `UpgradePreflightSource::FixedArchive` with the
exact version, operating system, architecture and build variant. A listed
artifact gives you its recorded length and checksum. The preflight does not
open an archive or URL. The fixed artifact and explicit URL routes have their
own requirements. The previously observed official v2.33.2 provider feed
omitted Windows ARM64. That historical result applies to the provider path
and the observed feed. A live provider report can supply current metadata or
preserve the kernel's explicit missing-release error.

Local-API preflight uses the exact folder ID and reads no other folder
configurations. With a matching target, HTTP 200 with the native 3001 envelope
is evidence that this need request requires a Local-API entitlement. An ordinary
403 leaves the entitlement unknown. A successful page proves only that the
page was available at that time. A successful GUI or official account login
leaves this specialized entitlement unknown. The preflight returns no folder
entries and makes no request to acquire or change a license.

## Example

The `preflight_control` example reads one JSON object from standard input. The
example connects to the explicit endpoint you provide and reports the selected
prerequisites. Run its `--help` for the fields and access choices.

```text
cargo run --example preflight_control -- gui --read
cargo run --example preflight_control -- provider
cargo run --example preflight_control -- local-need --read
```

The `provider --read` form explicitly asks the selected engine to check its
provider. Use the provider form without `--read` when you only need the recorded
source evidence. For Local-API, choose an existing connection where Local-API
is already enabled. Provide `folder_id` for the single folder you want to check.
