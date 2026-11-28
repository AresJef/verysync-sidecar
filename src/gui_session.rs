//! Explicit native GUI credentials and in-memory cookie sessions.
use crate::{
    Client, DeviceId, Error, GuiAuthenticationConfig, InstanceInfo, ManagementEndpoint,
    ManagementWriteEvidence, OperationCompletion, OperationOptions, OperationPhase, Result,
    VersionPolicy,
};
use reqwest::header::{HeaderName, HeaderValue};
use std::{fmt, time::Duration};

/// Local/LDAP GUI credentials, separate from an official VerySync account.
/// Debug omits both values. The library never persists the supplied password.
#[derive(Clone)]
pub struct GuiCredentials {
    pub(crate) username: String,
    pub(crate) password: String,
}
impl GuiCredentials {
    /// Select explicit nonempty username/password values, at most 4096 bytes each.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Result<Self> {
        let (username, password) = (username.into(), password.into());
        if username.is_empty()
            || password.is_empty()
            || username.len() > 4096
            || password.len() > 4096
            || username.chars().any(char::is_control)
            || password.contains('\0')
        {
            return Err(Error::InvalidCredential {
                reason: "GUI credentials are empty, oversized or contain invalid controls",
            });
        }
        Ok(Self { username, password })
    }
}
impl fmt::Debug for GuiCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GuiCredentials([REDACTED])")
    }
}

/// Explicit selected endpoint and native GUI login policy. No ambient cookies,
/// browser account, proxy or credential provider is consulted.
#[derive(Clone, Debug)]
pub struct GuiLoginOptions {
    endpoint: ManagementEndpoint,
    credentials: GuiCredentials,
    expected: Option<DeviceId>,
    policy: VersionPolicy,
    timeout: Duration,
    limit: usize,
    stay_logged_in: bool,
    transport: crate::ManagementTransport,
}
impl GuiLoginOptions {
    /// Use the validated baseline, ten seconds per complete response and a
    /// one-MiB body limit. Login selects local/LDAP credentials, not forum login.
    pub fn new(endpoint: ManagementEndpoint, credentials: GuiCredentials) -> Self {
        Self {
            endpoint,
            credentials,
            expected: None,
            policy: VersionPolicy::default(),
            timeout: Duration::from_secs(10),
            limit: 1024 * 1024,
            stay_logged_in: false,
            transport: crate::ManagementTransport::default(),
        }
    }
    /// Explicitly request the native persistent-login cookie policy. The SDK
    /// still keeps cookies only in memory and does not install a cookie store.
    pub fn stay_logged_in(mut self, value: bool) -> Self {
        self.stay_logged_in = value;
        self
    }
    /// Select per-session TLS trust and an explicit proxy. The default does not
    /// read ambient proxy settings; this does not change the system trust store.
    pub fn transport(mut self, value: crate::ManagementTransport) -> Self {
        self.transport = value;
        self
    }
    /// Require the authenticated full device identity; the CSRF suffix is also
    /// checked before transmitting the password when an identity is supplied.
    pub fn expected_device_id(mut self, id: DeviceId) -> Self {
        self.expected = Some(id);
        self
    }
    /// Explicitly choose whether to permit unverified engine versions.
    pub fn version_policy(mut self, value: VersionPolicy) -> Self {
        self.policy = value;
        self
    }
    /// Set a nonzero deadline for each complete response.
    pub fn request_timeout(mut self, value: Duration) -> Result<Self> {
        if value.is_zero() {
            return Err(Error::InvalidConfiguration {
                reason: "GUI response deadline must be nonzero",
            });
        }
        self.timeout = value;
        Ok(self)
    }
    /// Set a nonzero maximum response body size.
    pub fn response_limit(mut self, value: usize) -> Result<Self> {
        if value == 0 {
            return Err(Error::InvalidConfiguration {
                reason: "GUI response limit must be nonzero",
            });
        }
        self.limit = value;
        Ok(self)
    }
}

/// Where the one GUI login attempt failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GuiLoginPhase {
    /// No login request was sent, for example when the CSRF challenge failed.
    BeforeLoginRequest,
    /// The login request received an explicit authentication or access refusal.
    LoginRejected,
    /// The login request may have reached the engine, but its effect is unknown.
    LoginOutcomeUnknown,
    /// The login reply did not yield a usable session cookie.
    SessionCookieUnavailable,
    /// A cookie was received, but reading or checking the engine version failed.
    VerifyVersion,
    /// A cookie was received, but reading or checking the full device identity failed.
    VerifyIdentity,
}

impl GuiLoginPhase {
    fn error(self, legacy: Error) -> GuiLoginError {
        GuiLoginError {
            phase: self,
            legacy,
            confirmed_refusal: None,
        }
    }
}

/// A GUI login failure with its phase and inspectable underlying error.
pub struct GuiLoginError {
    phase: GuiLoginPhase,
    legacy: Error,
    confirmed_refusal: Option<Box<Error>>,
}

impl GuiLoginError {
    /// The phase in which the attempt failed.
    pub fn phase(&self) -> GuiLoginPhase {
        self.phase
    }

    /// The underlying SDK error, with any legacy uncertainty wrapper removed.
    ///
    /// This can distinguish an HTTP refusal from a transport, decoding,
    /// version-policy or identity failure. Treat private response diagnostics
    /// available by explicit inspection like other management diagnostics.
    pub fn cause(&self) -> &Error {
        self.confirmed_refusal
            .as_deref()
            .unwrap_or_else(|| self.legacy_cause())
    }

    /// Why the diagnostic body could not be read after a confirmed refusal.
    ///
    /// When this is present, the refusal status is available through
    /// [Self::cause]. Incomplete diagnostic bytes are discarded.
    pub fn rejection_body_error(&self) -> Option<&Error> {
        self.confirmed_refusal.as_ref().map(|_| self.legacy_cause())
    }

    fn legacy_cause(&self) -> &Error {
        match &self.legacy {
            Error::MutationOutcomeUnknown { source, .. } => source.as_ref(),
            cause => cause,
        }
    }

    fn login_request_error(legacy: Error) -> Self {
        let phase = match &legacy {
            Error::Authentication { .. }
            | Error::AccessDenied { .. }
            | Error::LicenseRequired { .. } => GuiLoginPhase::LoginRejected,
            Error::InvalidEndpoint { .. } => GuiLoginPhase::BeforeLoginRequest,
            _ => GuiLoginPhase::LoginOutcomeUnknown,
        };
        phase.error(legacy)
    }

    /// Whether the engine may have issued a session during this attempt.
    ///
    /// This is not evidence of persistence or a usable authenticated session.
    /// Resolve uncertainty at the selected endpoint before deciding to log in again.
    pub fn session_may_have_been_issued(&self) -> bool {
        !matches!(
            self.phase,
            GuiLoginPhase::BeforeLoginRequest | GuiLoginPhase::LoginRejected
        )
    }
}

impl fmt::Display for GuiLoginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.phase {
            GuiLoginPhase::BeforeLoginRequest =>
                "Sign-in stopped before the request was sent. Check the connection and sign-in settings for the selected VerySync instance.",
            GuiLoginPhase::LoginRejected =>
                "VerySync declined this sign-in. Check the credentials and permissions for the selected instance.",
            GuiLoginPhase::LoginOutcomeUnknown =>
                "We could not tell whether VerySync signed you in. Check for an existing session before trying again.",
            GuiLoginPhase::SessionCookieUnavailable =>
                "VerySync replied without a usable sign-in cookie. Check whether it created a session before trying again.",
            GuiLoginPhase::VerifyVersion =>
                "VerySync sent a sign-in cookie. The library could not verify the program version. Check which version is running before trying again.",
            GuiLoginPhase::VerifyIdentity =>
                "VerySync sent a sign-in cookie. The library could not confirm the device identity. Verify the endpoint and the expected device before trying again.",
        })
    }
}

impl fmt::Debug for GuiLoginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GuiLoginError({self})")
    }
}

impl std::error::Error for GuiLoginError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause())
    }
}

/// Fresh GUI configuration after one explicit local-credential change.
#[derive(Clone, Debug)]
pub struct GuiCredentialUpdate {
    /// API-key connection authenticated again after the native GUI reload.
    pub client: Client,
    /// Actual GUI authentication settings. Password presence is not verification
    /// of a supplied password; verify it through a separate GUI login.
    pub configuration: GuiAuthenticationConfig,
    /// Actual username equals the explicitly requested username.
    pub username_matches: bool,
    /// The modifying request returned a successful acknowledgment.
    pub write_acknowledged: bool,
}

/// An explicitly authenticated native GUI session. Cookies remain in this
/// object, are omitted by Debug and are sent only to the selected endpoint.
/// The supplied password is not retained after login. Clones share the native
/// session identity; server logout invalidates that session for its clones.
#[derive(Clone)]
pub struct GuiSession {
    wire: GuiWire,
    instance: InstanceInfo,
    logout_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

#[derive(Clone)]
struct GuiWire {
    http: reqwest::Client,
    base: url::Url,
    endpoint: ManagementEndpoint,
    cookie: HeaderValue,
    csrf_name: HeaderName,
    csrf: HeaderValue,
    limit: usize,
}
impl GuiWire {
    fn redact(&self, text: &str) -> String {
        let mut text = text.to_owned();
        for part in self.cookie.to_str().unwrap_or_default().split(';') {
            if let Some((_, value)) = part.trim().split_once('=') {
                if !value.is_empty() {
                    text = text.replace(value, "[REDACTED]");
                }
            }
        }
        text
    }
    fn request_builder(
        &self,
        method: reqwest::Method,
        route: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<reqwest::RequestBuilder> {
        let url = self.base.join(route).map_err(|_| Error::InvalidEndpoint {
            reason: "GUI route cannot be joined to its selected endpoint",
        })?;
        let mut request = self
            .http
            .request(method, url)
            .header(reqwest::header::COOKIE, self.cookie.clone())
            .header(self.csrf_name.clone(), self.csrf.clone());
        if let Some(body) = body {
            request = request.json(body);
        }
        Ok(request)
    }

    async fn request(
        &self,
        operation: &'static str,
        method: reqwest::Method,
        route: &str,
        body: Option<&serde_json::Value>,
        mutation: bool,
    ) -> Result<crate::RawResponse> {
        let request = self.request_builder(method, route, body)?;
        crate::client::send_checked(operation, request, mutation, self.limit).await
    }

    async fn post_login(
        &self,
        body: &serde_json::Value,
    ) -> std::result::Result<crate::RawResponse, GuiLoginError> {
        const OPERATION: &str = "log in to native GUI";
        let request = self
            .request_builder(
                reqwest::Method::POST,
                "rest/noauth/auth/password",
                Some(body),
            )
            .map_err(GuiLoginError::login_request_error)?;
        let response =
            crate::client::send_bounded_with_status(OPERATION, request, true, self.limit)
                .await
                .map_err(|failure| {
                    let refusal = match failure.status {
                        Some(401) => Error::Authentication { status: 401 },
                        Some(403) => Error::AccessDenied {
                            response: crate::ResponseDiagnostic::new(403, Vec::new()),
                        },
                        _ => return GuiLoginError::login_request_error(failure.error),
                    };
                    GuiLoginError {
                        phase: GuiLoginPhase::LoginRejected,
                        legacy: failure.error,
                        confirmed_refusal: Some(Box::new(refusal)),
                    }
                })?;
        crate::client::checked_response(OPERATION, response, true)
            .map_err(GuiLoginError::login_request_error)
    }
}
impl GuiSession {
    /// Perform one native local/LDAP login, without an API key. Four bounded
    /// requests establish CSRF, login, version and full identity. Login is never
    /// retried. Passwords are not retained in the returned session.
    /// Use [Self::login_with_outcome] when failure handling needs the login phase.
    pub async fn login(options: GuiLoginOptions) -> Result<Self> {
        Self::login_with_outcome(options)
            .await
            .map_err(|error| error.legacy)
    }

    /// Perform one GUI login with a typed phase on failure.
    ///
    /// Only a successful version and identity check yields a session. On
    /// failure, inspect [GuiLoginError::session_may_have_been_issued] before
    /// any explicit retry. This method never automatically logs in again or
    /// logs out an unverified session.
    pub async fn login_with_outcome(
        options: GuiLoginOptions,
    ) -> std::result::Result<Self, GuiLoginError> {
        use GuiLoginPhase::{
            BeforeLoginRequest, SessionCookieUnavailable, VerifyIdentity, VerifyVersion,
        };
        let before_login = |error| BeforeLoginRequest.error(error);
        tokio::runtime::Handle::try_current()
            .map_err(|_| Error::InvalidConfiguration {
                reason: "GUI login requires a Tokio runtime with I/O and timers",
            })
            .map_err(before_login)?;
        let (http, base) =
            crate::client::management_http(&options.endpoint, options.timeout, &options.transport)
                .map_err(before_login)?;
        let root = crate::client::send_checked(
            "read GUI CSRF cookie",
            http.get(base.clone()),
            false,
            options.limit,
        )
        .await
        .map_err(before_login)?;
        let expected_short = options.expected.as_ref().map(|id| &id.as_str()[..7]);
        let (csrf_cookie, csrf_value) =
            native_cookie(&root, "CSRF-Token-", expected_short, &base).map_err(before_login)?;
        let suffix = csrf_cookie
            .strip_prefix("CSRF-Token-")
            .ok_or_else(|| before_login(cookie_error(&root)))?
            .to_owned();
        let csrf_name = HeaderName::from_bytes(format!("X-{csrf_cookie}").as_bytes())
            .map_err(|_| before_login(cookie_error(&root)))?;
        let mut wire = GuiWire {
            http,
            base,
            endpoint: options.endpoint,
            cookie: sensitive(&format!("{csrf_cookie}={csrf_value}")).map_err(before_login)?,
            csrf_name,
            csrf: sensitive(&csrf_value).map_err(before_login)?,
            limit: options.limit,
        };
        let body = serde_json::json!({"username":options.credentials.username,"password":options.credentials.password,"stayLoggedIn":options.stay_logged_in,"forumUser":false});
        let logged_in = wire.post_login(&body).await?;
        let (session_cookie, session_value) =
            native_cookie(&logged_in, "sessionid-", Some(&suffix), &wire.base)
                .map_err(|error| SessionCookieUnavailable.error(gui_unknown(error)))?;
        wire.cookie = sensitive(&format!(
            "{csrf_cookie}={csrf_value}; {session_cookie}={session_value}"
        ))
        .map_err(|error| SessionCookieUnavailable.error(error))?;
        let version: crate::EngineVersion = parse(
            wire.request(
                "read GUI-authenticated version",
                reqwest::Method::GET,
                "rest/system/version",
                None,
                false,
            )
            .await
            .map_err(|error| VerifyVersion.error(error))?,
            "read GUI-authenticated version",
        )
        .map_err(|error| VerifyVersion.error(error))?;
        let compatibility = if version.version == crate::BASELINE_ENGINE_VERSION {
            crate::VersionCompatibility::ValidatedBaseline
        } else if options.policy == VersionPolicy::AllowUnverified {
            crate::VersionCompatibility::Unverified
        } else {
            return Err(VerifyVersion.error(Error::IncompatibleVersion {
                actual: options.transport.version_diagnostic(
                    &wire
                        .redact(&version.version)
                        .replace(&options.credentials.password, "[REDACTED]")
                        .replace(&options.credentials.username, "[REDACTED]"),
                ),
            }));
        };
        let status: crate::SystemStatus = parse(
            wire.request(
                "read GUI-authenticated identity",
                reqwest::Method::GET,
                "rest/system/status",
                None,
                false,
            )
            .await
            .map_err(|error| VerifyIdentity.error(error))?,
            "read GUI-authenticated identity",
        )
        .map_err(|error| VerifyIdentity.error(error))?;
        if let Some(expected) = options.expected {
            if expected != status.device_id {
                return Err(VerifyIdentity.error(Error::IdentityMismatch {
                    expected,
                    actual: status.device_id,
                }));
            }
        }
        Ok(Self {
            wire,
            logout_lock: Default::default(),
            instance: InstanceInfo {
                device_id: status.device_id,
                version,
                compatibility,
            },
        })
    }
    /// Inspect the authenticated identity/version snapshot without a request.
    pub fn instance(&self) -> &InstanceInfo {
        &self.instance
    }
    /// Borrow the exact selected endpoint, with no discovery or credential store.
    pub fn endpoint(&self) -> &ManagementEndpoint {
        &self.wire.endpoint
    }
    /// Read native status and recheck this session's full device identity.
    pub async fn system_status(&self) -> Result<crate::SystemStatus> {
        let status: crate::SystemStatus = parse(
            self.wire
                .request(
                    "read GUI session status",
                    reqwest::Method::GET,
                    "rest/system/status",
                    None,
                    false,
                )
                .await?,
            "read GUI session status",
        )?;
        if status.device_id != self.instance.device_id {
            return Err(Error::IdentityMismatch {
                expected: self.instance.device_id.clone(),
                actual: status.device_id,
            });
        }
        Ok(status)
    }
    /// Read fresh version metadata using this GUI session, without an API key.
    pub async fn version(&self) -> Result<crate::EngineVersion> {
        parse(
            self.wire
                .request(
                    "read GUI session version",
                    reqwest::Method::GET,
                    "rest/system/version",
                    None,
                    false,
                )
                .await?,
            "read GUI session version",
        )
    }
    /// Explicitly read GUI settings, including a separately inspectable API key.
    /// This neither changes the authentication mode nor converts this session
    /// into an API-key connection.
    pub async fn gui_authentication(&self) -> Result<GuiAuthenticationConfig> {
        self.system_status().await?;
        parse(
            self.wire
                .request(
                    "read GUI session authentication settings",
                    reqwest::Method::GET,
                    "rest/config/gui",
                    None,
                    false,
                )
                .await?,
            "read GUI session authentication settings",
        )
    }
    /// POST logout once, then test the same previous cookie. No API-key client
    /// is logged out or changed. Clones retain their now potentially revoked
    /// cookie and observe the native refusal on subsequent requests.
    pub async fn logout(&self) -> Result<GuiLogoutReceipt> {
        let _guard = self.logout_lock.lock().await;
        self.system_status().await?;
        let write_acknowledged = match self
            .wire
            .request(
                "log out native GUI session",
                reqwest::Method::POST,
                "rest/noauth/auth/logout",
                Some(&serde_json::json!({})),
                true,
            )
            .await
        {
            Ok(_) => true,
            Err(Error::MutationOutcomeUnknown { .. }) => false,
            Err(error) => return Err(error),
        };
        let session_rejected = match self.system_status().await {
            Ok(_) => false,
            Err(Error::Authentication { status: 401 }) => true,
            Err(Error::AccessDenied { response }) if response.status() == 403 => true,
            Err(error) => return Err(gui_unknown(error)),
        };
        Ok(GuiLogoutReceipt {
            write_acknowledged,
            session_rejected,
        })
    }

    /// Submit one logout for this cookie and check the same cookie within one
    /// deadline. A cookie already refused by the selected endpoint needs no
    /// new request. The original reply and later access are separate facts.
    /// This verifies endpoint access for this session only.
    pub async fn logout_and_verify(&self, options: OperationOptions) -> Result<GuiLogoutReport> {
        const LOGOUT: &str = "log out the selected GUI session";
        const VERIFY: &str = "check the original GUI session";
        let context = options.start()?;
        let dispatch = context.dispatch_deadline();
        let mut report = GuiLogoutReport {
            outcome: GuiLogoutOutcome::NotSubmitted,
            write: Default::default(),
            original: None,
            observation_error: None,
        };
        let mut guard = None;
        let started = context
            .wait(dispatch, LOGOUT, async {
                context.phase(OperationPhase::Checking);
                guard = Some(self.logout_lock.lock().await);
                match self.system_status().await {
                    Ok(_) => {}
                    Err(source) if gui_cookie_refused(&source) => return Ok(false),
                    Err(source) => return Err(source),
                }
                let request = self.wire.request_builder(
                    reqwest::Method::POST,
                    "rest/noauth/auth/logout",
                    Some(&serde_json::json!({})),
                )?;
                if tokio::time::Instant::now() >= dispatch {
                    return Err(Error::Timeout { operation: LOGOUT });
                }
                report.write.dispatched = true;
                context.phase(OperationPhase::Submitting);
                let response = crate::client::send_bounded_reporting_headers(
                    LOGOUT,
                    request,
                    true,
                    self.wire.limit,
                    &mut report.write.status,
                )
                .await?;
                report.write.response_complete = true;
                crate::client::checked_response(LOGOUT, response, true)?;
                Ok(true)
            })
            .await;
        if matches!(started, Ok(false)) {
            report.outcome = GuiLogoutOutcome::AlreadyRejected;
        } else {
            report.original = Some(crate::client::workflow_write_result(
                LOGOUT,
                report.write,
                started.map(|_| ()),
            ));
            if report.write.dispatched {
                let refused = report.write.response_complete
                    && matches!(report.original, Some(Err(ref source)) if gui_cookie_refused(source));
                context.phase(OperationPhase::Verifying);
                match context
                    .wait(context.deadline, VERIFY, self.system_status())
                    .await
                {
                    Err(source) if gui_cookie_refused(&source) => {
                        report.outcome = GuiLogoutOutcome::CookieRejected
                    }
                    Ok(_) => {
                        report.outcome = if refused {
                            GuiLogoutOutcome::RequestRejected
                        } else {
                            GuiLogoutOutcome::CookieStillAccepted
                        }
                    }
                    Err(source) => {
                        report.outcome = if refused {
                            GuiLogoutOutcome::RequestRejected
                        } else {
                            GuiLogoutOutcome::Unconfirmed
                        };
                        report.observation_error = Some(source);
                    }
                }
            }
        }
        drop(guard);
        context.phase(OperationPhase::Finished);
        Ok(report)
    }
}

fn gui_cookie_refused(source: &Error) -> bool {
    matches!(source, Error::Authentication { status: 401 })
        || matches!(source, Error::AccessDenied { response } if response.status() == 403)
}

fn sensitive(value: &str) -> Result<HeaderValue> {
    let mut value = HeaderValue::from_str(value).map_err(|_| Error::InvalidCredential {
        reason: "native GUI cookie is not a valid header value",
    })?;
    value.set_sensitive(true);
    Ok(value)
}
fn parse<T: serde::de::DeserializeOwned>(
    response: crate::RawResponse,
    operation: &'static str,
) -> Result<T> {
    serde_json::from_slice(&response.body).map_err(|_| Error::InvalidResponse {
        operation,
        response: crate::ResponseDiagnostic::new(response.status, response.body),
    })
}
fn cookie_error(response: &crate::RawResponse) -> Error {
    Error::InvalidResponse {
        operation: "read native GUI authentication cookie",
        response: crate::ResponseDiagnostic::new(response.status, response.body.clone()),
    }
}
fn gui_unknown(source: Error) -> Error {
    Error::MutationOutcomeUnknown {
        operation: "reconcile native GUI authentication",
        source: Box::new(source),
    }
}
fn native_cookie(
    response: &crate::RawResponse,
    prefix: &str,
    suffix: Option<&str>,
    base: &url::Url,
) -> Result<(String, String)> {
    let mut found = None;
    let mut bytes = 0usize;
    for (_, raw) in response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
    {
        bytes = bytes.saturating_add(raw.len());
        if bytes > 8192 {
            return Err(cookie_error(response));
        }
        let text = std::str::from_utf8(raw).map_err(|_| cookie_error(response))?;
        let mut parts = text.split(';');
        let Some((name, value)) = parts.next().and_then(|s| s.split_once('=')) else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        let Some(short) = name.strip_prefix(prefix) else {
            continue;
        };
        if found.is_some()
            || value.is_empty()
            || value.len() > 4096
            || !value.is_ascii()
            || value.bytes().any(|b| b.is_ascii_control())
            || short.len() != 7
            || !short
                .bytes()
                .all(|b| b.is_ascii_uppercase() || matches!(b, b'2'..=b'7'))
            || suffix.is_some_and(|s| s != short)
        {
            return Err(cookie_error(response));
        }
        for part in parts {
            if let Some((key, attr)) = part.trim().split_once('=') {
                if key.eq_ignore_ascii_case("domain") {
                    let domain = attr.trim_start_matches('.').to_ascii_lowercase();
                    let host = base.host_str().unwrap_or_default().to_ascii_lowercase();
                    if domain.is_empty()
                        || !(host == domain || host.ends_with(&format!(".{domain}")))
                    {
                        return Err(cookie_error(response));
                    }
                } else if key.eq_ignore_ascii_case("path") {
                    let target = base.join("rest/").map_err(|_| cookie_error(response))?;
                    if !attr.starts_with('/')
                        || !target.path().starts_with(attr)
                        || (!attr.ends_with('/')
                            && target.path().len() > attr.len()
                            && target.path().as_bytes()[attr.len()] != b'/')
                    {
                        return Err(cookie_error(response));
                    }
                }
            } else if part.trim().eq_ignore_ascii_case("secure") && base.scheme() != "https" {
                return Err(cookie_error(response));
            }
        }
        found = Some((name.to_owned(), value.to_owned()));
    }
    found.ok_or_else(|| cookie_error(response))
}
impl fmt::Debug for GuiSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuiSession")
            .field("compatibility", &self.instance.compatibility)
            .finish_non_exhaustive()
    }
}

/// Native logout observation, independently of an API-key connection.
#[derive(Clone, Debug)]
pub struct GuiLogoutReceipt {
    /// Whether the single logout POST was acknowledged.
    pub write_acknowledged: bool,
    /// The exact previous session cookie was refused with HTTP 401/403 afterward.
    pub session_rejected: bool,
}

/// What the selected GUI endpoint reports about the original cookie.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GuiLogoutOutcome {
    /// The endpoint already refused this cookie before a logout request.
    AlreadyRejected,
    /// The same cookie was refused in a fresh read after the request.
    CookieRejected,
    /// The original cookie could still read from the endpoint afterward.
    CookieStillAccepted,
    /// A complete response refused the logout request.
    RequestRejected,
    /// The workflow ended before submitting the request.
    NotSubmitted,
    /// The original session could not be reliably observed.
    Unconfirmed,
}

/// The original logout and the fresh access result for that cookie.
#[derive(Debug)]
#[non_exhaustive]
pub struct GuiLogoutReport {
    /// What could be established about the selected GUI session.
    pub outcome: GuiLogoutOutcome,
    /// Dispatch and completeness of the one optional logout.
    pub write: ManagementWriteEvidence,
    /// Preflight error or original request result. Empty if none was needed.
    pub original: Option<Result<()>>,
    /// Why the original session could not be checked after a request.
    pub observation_error: Option<Error>,
}

impl GuiLogoutReport {
    /// Summarize access for the selected cookie and endpoint.
    pub fn completion(&self) -> OperationCompletion {
        match self.outcome {
            GuiLogoutOutcome::AlreadyRejected | GuiLogoutOutcome::CookieRejected => {
                OperationCompletion::Completed
            }
            GuiLogoutOutcome::Unconfirmed => OperationCompletion::Unconfirmed,
            _ => OperationCompletion::GoalNotMet,
        }
    }
}

impl fmt::Display for GuiLogoutReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.outcome {
            GuiLogoutOutcome::AlreadyRejected => "The selected GUI endpoint already refused this session.",
            GuiLogoutOutcome::CookieRejected => "The selected GUI endpoint now refuses this session.",
            GuiLogoutOutcome::CookieStillAccepted => "The original GUI session can still read from the selected endpoint.",
            GuiLogoutOutcome::RequestRejected => "The selected GUI endpoint declined the logout request. Check this session before trying again.",
            GuiLogoutOutcome::NotSubmitted => "The call ended before sending a GUI logout request.",
            GuiLogoutOutcome::Unconfirmed => "The original GUI session could not be verified after the request. Check the session on the selected device.",
        })?;
        if self.outcome == GuiLogoutOutcome::NotSubmitted {
            if let Some(Err(source)) = &self.original {
                write!(f, " {source}")?;
            }
        }
        Ok(())
    }
}
