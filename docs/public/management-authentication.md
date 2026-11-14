# Management credentials and explicit recovery

`gui_authentication()` reads the management GUI authentication mode, username and
password-presence flag. Its API key is available through an explicit `api_key()`
call as a redacted `ApiKey`. Additional settings remain available for explicit
inspection; Debug omits their values and the username, key and password.
These observations are independent of a GUI login session and an official
VerySync account session. Reporting an LDAP selector does not verify LDAP login.

`ApiKey::generate()` explicitly uses the operating system random source to create
32 random bytes encoded as ASCII. It sends no request and changes no credential.

```no_run
use std::time::Duration;
use verysync_sidecar::{ApiKey, ManagedInstance};

async fn rotate_owned_key(core: &mut ManagedInstance) -> verysync_sidecar::Result<()> {
    let proposed = ApiKey::generate()?;
    // Retain the proposed key until the outcome is reconciled, including when
    // the rotation future is cancelled by the caller.
    let rotation = core.rotate_api_key(proposed.clone(), Duration::from_secs(10)).await?;
    if rotation.requested_key_matches && rotation.previous_key_rejected {
        // The owner has adopted the freshly authenticated management connection.
    }
    Ok(())
}
```

`rotate_api_key()` performs one PATCH containing only the replacement `apiKey`.
The replacement must differ from the connection's current key and contain at
least 20 ASCII bytes, matching the library's owned-state restart admission.
Existing GUI settings are retained. A total caller-selected deadline covers the
clone mutation lock, fresh identity check, single write and read-only reconnects
across the native GUI reload. Requests keep the original explicit endpoint,
version policy, response-size bound and request deadline. Redirects, ambient
proxies and request-level automatic retries remain disabled.

The result reports the write acknowledgment, exact key readback and observed
old-key rejection independently. A successful receipt includes a new Client
after fresh version and exact device-identity checks. Old borrowed clients keep
their old key. The new client shares their mutation lock. Check both
`requested_key_matches` and `previous_key_rejected`: an open GUI policy can admit
requests with nonmatching keys. The library preserves the native 401/403 error
distinction; the controlled old-key probe records either as a refusal.

The owned-instance method also adopts the new connection for later normal
shutdown/restart operations. The Client method leaves any owning instance's
connection unchanged; callers explicitly invoke the owner's
`reconnect_with_api_key()` afterward. Neither method restarts or force-stops the
core as part of rotation.

A timed-out operation before the write reports `Timeout`. After the write begins,
a timeout or unreconcilable read reports `MutationOutcomeUnknown`. Cancellation
can also leave the write applied. The write is never replayed or rolled back.
Use the retained proposed key with `reconnect_with_api_key()` to perform fresh
read-only authentication to the same endpoint and expected identity. A failed
reconnection leaves the original client/owner intact. If neither key can connect,
inspect the exact instance and its native configuration; no automatic process
termination or credential reset is attempted.

Native integration checks separately verify key readback, old-key refusal,
unchanged root PID, retained unrelated GUI settings, an unaffected second
instance, normal restart persistence, registered-folder data retention and
explicit owner reconnection after a borrowed-client rotation. Synthetic
contracts exercise initial unknown acknowledgment, transient read-only refusal,
caller-selected unverified-version policy, wrong identity, invalid inputs and
cancellation after an observed write. Synthetic evidence does not substitute
for native platform acceptance or GUI/password/LDAP/account-session evidence.
