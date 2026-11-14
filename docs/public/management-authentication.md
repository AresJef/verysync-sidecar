# Management credentials and explicit recovery

## Native GUI preferences

`gui_preferences()` reads stored theme, metrics authorization, debugging, native
administrative/host-check policy, frame loading, Basic prompts and cookie
duration/path. Known credentials are excluded from this DTO; Debug omits private
text and remaining values. The HTTP cookie path is distinct from a filesystem path.

`update_gui_preferences()` submits only selected fields, then reconciles a fresh
same-key, same-endpoint connection after native GUI reload. The caller-selected
total deadline covers clone-lock acquisition, identity, the single PATCH and all
read-only reconnects. The receipt separately reports acknowledgment and actual
field matches. It does not replay or roll back writes, migrate the listener or
change credentials/authentication mode. The owned-instance method adopts the
returned connection for later lifecycle operations. Other GUI sessions can be
affected by a native handler reload; inspect them separately.

```no_run
use verysync_sidecar::{GuiPreferencesPatch, ManagedInstance};
use std::time::Duration;

async fn protect_metrics(core: &mut ManagedInstance) -> verysync_sidecar::Result<()> {
    let update = core.update_gui_preferences(
        &GuiPreferencesPatch::default().metrics_without_auth(false),
        Duration::from_secs(10),
    ).await?;
    // Inspect requested_fields_match before interpreting the native policy.
    Ok(())
}
```

These settings can alter access control and browser-facing policy. Selecting an
insecure native preference is explicit, and changing a stored theme does not
prove a rendered appearance. Cookie selection is separate from observed session
expiration and cookie-path compatibility. The controlled case observes actual
unauthenticated metrics refusal/acceptance/refusal and frame-header changes,
retained credentials/identity/root process, unrelated configuration preservation,
and normal restart persistence. Full same-source platform acceptance and the
remaining individual policy/session conditions stay separate.

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

## LDAP configuration and GUI mode

`ldap_configuration()` reads the actual native address, bind template, transport,
verification flag and optional search fields. `update_ldap_configuration()` PATCHes
only explicit `LdapPatch` fields and returns actual readback while retaining other
settings. This operation performs no directory bind and leaves GUI mode unchanged.
`set_gui_auth_mode()` separately selects static or LDAP authentication, reconciling
the API-key connection across native GUI reload. These writes are independent;
callers coordinate other writers and inspect both readbacks before logging in.
The fixed program captures directory settings when its GUI authentication handler
loads. Updating LDAP fields while LDAP mode is already active can leave that
handler using its previous fields even after configuration readback succeeds.
Configure the directory before activating LDAP. For an existing LDAP handler,
coordinate an explicit transition to static mode, update the directory, then
select LDAP again, or explicitly restart the owned program. The library does not
toggle authentication modes or restart the program implicitly. A same-mode PATCH
is not evidence of a reload. Account for concurrent GUI users before changing mode.

```no_run
use verysync_sidecar::{GuiAuthMode, LdapPatch, LdapTransport, ManagedInstance};
use std::time::Duration;

async fn configure_private_ldap(core: &mut ManagedInstance) -> verysync_sidecar::Result<()> {
    let update = core.client().update_ldap_configuration(
        &LdapPatch::default()
            .address("127.0.0.1:389")
            .bind_dn("uid=%s,dc=example,dc=test")
            .transport(LdapTransport::Plain)
            .insecure_skip_verify(false)
            .search_base_dn("")
            .search_filter(""),
    ).await?;
    if update.requested_fields_match {
        core.set_gui_auth_mode(&GuiAuthMode::Ldap, Duration::from_secs(10)).await?;
    }
    Ok(())
}
```

The native plain direct-bind case has observed real LDAPv3 result 0 for correct
credentials, result 49 for incorrect passwords and unknown users, and matching GUI
login acceptance/refusal. An existing GUI session and API-key management remain
usable after the private directory stops. The test peer is an explicitly started
loopback-only process with synthetic credentials and exact child cleanup; the SDK
does not depend on it or start a directory service.

The controlled search case observes an actual LDAP search after successful bind:
`searchBaseDN=dc=example,dc=test` and `searchFilter=(uid=%s)` admit the matching
entry. An empty search result caused by a nonmatching filter or base refuses GUI
login despite a correct bind. These cases establish the native search requirement,
not compatibility with every directory schema or group-membership filter.

The controlled TLS and StartTLS cases observe encrypted successful binds and
encrypted result 49 for incorrect passwords. StartTLS must complete its extended
operation and TLS handshake before any bind credentials reach the peer. They use
an ephemeral self-signed loopback certificate and explicitly set
`insecure_skip_verify(true)` for the positive case. This setting bypasses server
identity verification and is not a production trust recommendation. No trust store
is modified and bypass is never enabled implicitly.

With verification retained, native TLS refuses the untrusted self-signed
certificate before bind. The pinned program's StartTLS path instead fails before
TLS negotiation with `either ServerName or InsecureSkipVerify must be specified
in the tls.Config`; it does not reach certificate validation in this case. The
library preserves this native limitation and performs no automatic downgrade or
bypass. A trusted-certificate positive path, further directory conditions and full
same-source platform evidence remain required before broad support claims.
