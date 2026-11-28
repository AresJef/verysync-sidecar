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

The 0.1.1 repair candidate provides `GuiSession::login_with_outcome()` for
callers whose next action depends on how far sign-in got. A final 401 or 403
from the sign-in request confirms a refusal even
if the diagnostic reply cannot be read. Inspect `cause()` for the refusal and
`rejection_body_error()` for an omitted diagnostic. If the request ended before
a final reply, or the reply did not yield a usable session, check whether
VerySync created a session before trying again. If a cookie arrived and the
version or identity check failed, verify the selected program or device before
trying again. A failed call returns no session handle and sends no automatic
sign-in retry or sign-out.

```no_run
use verysync_sidecar::{GuiLoginError, GuiLoginOptions, GuiSession};

async fn login(options: GuiLoginOptions) -> Result<GuiSession, GuiLoginError> {
    GuiSession::login_with_outcome(options).await.inspect_err(|error| {
        eprintln!("{error}");
    })
}
```

`GuiSession::login()` keeps its existing return type and top-level error types.
For example, if a refusal's diagnostic body exceeds the configured limit, the
old method still returns `MutationOutcomeUnknown` with `ResponseTooLarge` as its
cause. Use the detailed method when the confirmed refusal matters to recovery.
Session lifetime depends on the selected program and its configuration.

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

`logout_and_verify` keeps the original request outcome and the later cookie
check in one bounded report. It skips the logout request if the endpoint
already refuses that cookie. A different GUI session and API-key access
have their own credentials and should be managed separately.

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
bypass. Strict public-CA LDAPS has separate native evidence below. It does not establish
strict StartTLS success; further directory conditions and final same-source
integration remain separate.

The separate `ldap_trusted_ca_engine` target selects an explicitly prepared,
pinned public-CA certificate for the synthetic `ldap.localhost.direct` peer.
The fixture uses the publisher's internal-development certificate bundle and
keeps its key in private temporary files. It never adds or removes operating
system trust entries. Preparation occurs in an explicit CI step, outside Cargo
and the network-blocked runtime wrapper; dependency installation and compilation
do not download a certificate or start a server.

The target keeps certificate-chain and hostname verification enabled, requires
all DNS results to be loopback, and refuses other addresses before starting the
core. It tests encrypted correct-password login, wrong-password and wrong-hostname
refusal, persisted verification policy after restart, logout, normal owned-core
exit, and private peer/file cleanup. The existing self-signed cases separately
exercise untrusted-chain refusal. A changed or expired pinned certificate fails
preparation and requires an explicit fixture update; it is never silently
replaced or accepted with verification disabled. Keys and certificate bundles
must not be committed, included in Cargo packages, logged, cached, or uploaded
as workflow artifacts. The [publisher's terms](https://github.com/Upinel/localhost.direct#eula) apply to this development fixture.

These are test requirements. A prepared certificate or passing fixture boundary
contract is not native authentication acceptance; final source and platform
results remain separate evidence.

The additional strict StartTLS boundary case first logs in over LDAPS with the
same pinned certificate, matching hostname and verification enabled. It then
selects StartTLS explicitly, retains verification, and requires the server to
observe a successful StartTLS extended operation followed by a rejected TLS
handshake, with no completed handshake or bind request. The owned core must
retain the specific native missing-server-name error, API management, identity
and caller bytes, then release its tree and state normally. This case rejects
an unrelated authentication failure or unavailable peer as evidence of that
specific limitation. The two strict-certificate cases now have actual evidence on all six standard
macOS/Linux/Windows AMD64/ARM64 profiles in
[run 43959371005](https://github.com/AresJef/verysync-sidecar/actions/runs/43959371005)
under producer `174ad5fbb293b72cbfd1a028d454cedf4f6437fb`, with the original
source and input identities retained. Every profile passes the independent
strict LDAPS contract and the specific native StartTLS refusal contract.
This establishes the stated refusal boundary, with no successful strict
StartTLS identity-verification or login claim. Other architectures and final
integrated acceptance retain their own gates.



Independent API-key rotation and GUI password/session/logout contracts have
actual native evidence on the six standard macOS/Linux/Windows AMD64/ARM64
profiles in [run 43929620380](https://github.com/AresJef/verysync-sidecar/actions/runs/43929620380).
They verify old-key and wrong-password refusal, explicit owner recovery, session
logout, retained configuration/identity/files and normal owned shutdown/restart.
The LDAP target in that run separately verifies strict public-CA LDAPS login,
wrong-password/hostname refusal and cleanup on all six profiles. This does not
extend certificate-identity claims to the documented native StartTLS limitation,
licensed features or a successful official-account/remote-gateway session.
The Unix-only socket-mode case is separate from Windows applicable coverage.
Full final integration remains required; other native-suite failures are retained.


`set_local_gui_credentials_and_verify` submits one explicit credential change
and attempts a separate login after confirming the original device's stored
username, static mode, and password presence. A verified session establishes
that the supplied credentials worked. Use or explicitly close the returned
session. If the report stops during verification, check the current settings
and original response before submitting another credential change.
