# Official VerySync accounts

`official_account_status()` reads the selected core's official-account object
with a fresh device identity check. `login_official_account()` submits explicit
username/password credentials once; `logout_official_account()` explicitly
changes the official-account session through the native GET endpoint. Login can
contact VerySync's account service and persist a native session. These operations
use the existing authenticated management connection.

```rust,no_run
use verysync_sidecar::{Client, OfficialAccountCredentials, OfficialAccountState};

async fn log_in(client: &Client, username: String, password: String)
    -> verysync_sidecar::Result<()>
{
    let credentials = OfficialAccountCredentials::new(username, password)?;
    let change = client.login_official_account(&credentials).await?;
    if change.expected_state_matches {
        assert_eq!(change.status.state(), OfficialAccountState::LoggedIn);
    }
    // An acknowledgement and a reported UID do not verify a live cloud token.
    Ok(())
}
```

An empty account object or an explicitly nonpositive UID reports `LoggedOut`.
A positive UID reports `LoggedIn`, matching the fixed GUI's state test. A
nonempty future object without a usable UID reports `Unknown`; a null UID is
preserved in explicit extra data. Missing/null/nonobject account containers and
invalid UID types are response errors. The SDK does not coerce missing state to
an authenticated session or a successful logout.

The native acknowledgement is preserved as bounded private bytes. A successful
HTTP status is separate from the fresh observed state and
`expected_state_matches`. The fixed baseline can return HTTP 200 with a nested
`error` object. `Error::OfficialAccountRejected` preserves its signed native code
and private envelope. Code 5000 includes upstream network/service failures and
must not be classified automatically as an incorrect password or a rejected
management API key. Malformed acknowledgements and failed post-request reads
remain unknown mutation outcomes. No changing request is retried, reversed or
silently followed by license refresh, trial activation or restart.

Credentials preserve input spelling. Usernames must be nonblank, at most 1024
UTF-8 bytes and contain no control characters; passwords must be nonempty, at
most 4096 bytes and contain no NUL. These are SDK input bounds. Ordinary Debug
and error formatting omit username/password, personal UIDs, session metadata and
native response text. Inspect explicit accessors and response bytes only when
needed. The core owns any persisted credentials/tokens.

Official accounts, GUI cookie login/logout, API-key authentication and licensed
entitlements have separate APIs and acceptance conditions. The SDK does not
register a cloud account or accept its terms. Official logout is not a claim
that every remote token has been revoked or that all commercial entitlements
have changed.

The isolated native case verifies an empty account, explicit empty-session
logout, actual code-5000 upstream failure while the test proxy refuses external
forwarding, unchanged GUI/configuration and identity, retained sample data,
empty state after explicit restart and normal owned exit. It does not send real
user credentials. Synthetic transport cases cover positive UID receipt shapes,
unknown/malformed state, mismatched readback, identity changes and single-request
semantics. Successful real cloud login, rejection of an incorrect password by
the account service, authenticated logout/session persistence and complete
same-source platform acceptance remain pending.
