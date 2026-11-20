# Native licenses and explicit requests

`license_status()` reads the selected core's `myLicense` object with a fresh
device identity check. An empty object means that the response advertises no
license data. Missing/null/nonobject metadata is an error. Reported null, list
and keyed collection containers remain distinct; unknown private values and
opaque keys are preserved without ordinary Debug disclosure.

```rust,no_run
use verysync_sidecar::{Client, LicenseEntries, LicenseExpiry};

async fn inspect(client: &Client, reference_unix_seconds: i64)
    -> verysync_sidecar::Result<()>
{
    let status = client.license_status().await?;
    if let Some(LicenseEntries::List(records)) = status.licenses() {
        for record in records {
            if record.is_pro() {
                let expiry: Option<LicenseExpiry> =
                    record.expiry_at(reference_unix_seconds);
                // This compares a reported time, not actual feature rights.
                let _ = expiry;
            }
        }
    }
    Ok(())
}
```

Record fields preserve native subject, expiry, issue time and trial flag. Only
the literal `Pro` subject has the fixed GUI's mapping here. Other subjects are
retained without inventing Local-API, enterprise or remote-management rights.
Missing expiry/trial values stay absent. Times use native Unix seconds; zero
expiry uses the GUI's permanent-license convention. `expiry_at()` compares with
an explicit caller-provided reference and reads no controller/target clock. It
does not validate a signature, machine/account binding, issue time, revocation
or whether any paid operation actually works.

`fetch_licenses()` explicitly asks the native core to refresh license data.
`request_pro_trial()` explicitly asks it for a Pro trial and can consume trial
eligibility. Both are state-changing GET requests, serialized between clones of
one connection, with one native request and fresh license readback. They can
contact VerySync and persist authorization data. The SDK never activates a
trial implicitly, purchases a license or accepts service terms.

`LicenseChange` separates the selected request kind, bounded private native
acknowledgement and fresh reported metadata. An acknowledgement is not proof
that a trial was issued or that a paid feature works. Error envelopes, malformed
acknowledgements and failed post-request reads remain errors or unknown mutation
outcomes. Changing requests are not automatically retried, rolled back or
followed by account login or program restart. Reconcile account/license state
before another explicit attempt after uncertainty.

The controlled unlicensed/unlogged macOS baseline returned no complete
management response to a single explicit fetch. The SDK retains that transport
uncertainty. Actual empty license/account state, configuration, identity and
sample data remained intact through an explicit normal restart. This does not
establish the underlying native cause, an account prerequisite or successful
license refresh. Trial activation was not invoked in native validation.

Nonempty licensed collection/record shapes and explicit trial acknowledgements
currently have synthetic transport coverage. Real license refresh, trial
issuance, persistence and licensed operation effects require separate native
validation with the corresponding entitlement. The release checks specify
the deferred Pro, Local-API, enterprise and official remote-management cases.

## Enterprise control contract

Enterprise control is not implemented. The vendor's
[public release history](https://forum.verysync.com/forum.php?mod=viewthread&tid=1457)
describes a separately arranged batch key-distribution control center; it does
not supply a verified v2.33.2 caller-facing API contract. Device-side cloud RPCs
and task receivers in the selected core are not treated as an implementation of
that interface. Endpoint/operation schemas, initiating authorization and dedicated
positive test resources remain necessary, independently of GUI authentication,
Pro, Local-API and the existing remote-management gateway.
