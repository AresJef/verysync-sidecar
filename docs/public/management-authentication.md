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

## Native GUI password sessions

`set_local_gui_credentials()` selects the native static GUI authentication mode
and PATCHes only the username and password. The API key is retained. Its receipt
reports actual username readback and password presence; a separate GUI login
verifies the supplied password. The owned-instance method adopts the API-key
connection authenticated after GUI reload, without restarting the core.

`GuiSession::login()` sends no API key. It reads the native CSRF cookie, submits
one local/LDAP login, then checks version and full identity with the resulting
session cookie. An expected identity also checks the seven-character CSRF suffix
before password submission. Forum-account login is not selected. Cookies remain
in memory and the returned session does not retain the supplied password.

```no_run
use verysync_sidecar::{GuiCredentials, GuiLoginOptions, GuiSession, ManagedInstance};
use std::time::Duration;

async fn use_gui_session(core: &mut ManagedInstance) -> verysync_sidecar::Result<()> {
    let credentials = GuiCredentials::new("explicit-gui-user", "caller-supplied-password")?;
    core.set_local_gui_credentials(&credentials, Duration::from_secs(10)).await?;
    let session = GuiSession::login(
        GuiLoginOptions::new(core.client().endpoint().clone(), credentials)
            .expected_device_id(core.client().instance().device_id.clone()),
    ).await?;
    let status = session.system_status().await?;
    let logout = session.logout().await?;
    // Inspect logout.session_rejected: the same old cookie was probed afterward.
    Ok(())
}
```

Each of the four login responses has the selected request deadline and body
limit. Login and logout writes are never retried. Cookie headers are bounded,
marked sensitive, omitted by Debug, and restricted to the selected endpoint;
unexpected device suffixes, domain/path scopes and insecure transport for a
Secure cookie are rejected. The native baseline's observed HTTP/Unix-socket
session cookie omitted HttpOnly, Secure and SameSite attributes. The SDK keeps
that credential outside a browser cookie store and preserves explicit endpoint
and TLS choices. It does not change the official server's cookie policy.

`system_status()`, `version()` and `gui_authentication()` perform typed session
reads. Reading the GUI configuration explicitly makes its API key available as
a redacted value; callers can separately choose an API-key `Client`. GUI sessions
and API-key connections remain independent authentication contexts.

`logout()` posts once, then tests the exact preceding cookie for native 401/403
refusal. Clones of the logged-out session retain that revoked cookie. Native
tests check that another independently logged-in session and the API-key client
remain usable. Password hashing and session invalidation are performed by the
official program. LDAP-mode correctness and official account login require
their own actual authentication evidence.
