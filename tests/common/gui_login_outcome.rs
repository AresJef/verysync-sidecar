//! Distinguish GUI login stages while preserving the original error contract.
use super::*;
use serde_json::json;
use verysync_sidecar::{GuiCredentials, GuiLoginOptions, GuiLoginPhase, GuiSession};

const USER: &str = "synthetic-phase-user";
const PASSWORD: &str = "synthetic-phase-password";
const CSRF: &str = "synthetic-phase-csrf";
const SESSION: &str = "synthetic-phase-session";
const DIFFERENT_FULL_ID: &str = "AAAAAAA-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";

fn challenge(short: &str) -> Reply {
    Reply {
        headers: format!("Set-Cookie: CSRF-Token-{short}={CSRF}; Path=/prefix/\r\n"),
        ..Reply::json(json!({}))
    }
}

fn issue_cookie(cookie: bool) -> Reply {
    Reply {
        status: 204,
        body: Vec::new(),
        headers: if cookie {
            format!("Set-Cookie: sessionid-AAAAAAA={SESSION}; Path=/prefix/\r\n")
        } else {
            String::new()
        },
        delay: Duration::ZERO,
    }
}

fn engine_version(value: &str) -> Reply {
    Reply::json(json!({"version":value,"os":"linux","arch":"amd64"}))
}

fn status(status: u16) -> Reply {
    Reply {
        status,
        ..Reply::json(json!({"private": PASSWORD}))
    }
}

fn malformed() -> Reply {
    Reply {
        body: format!("[{SESSION} [{CSRF}").into_bytes(),
        ..status(200)
    }
}

fn options(server: &ScriptedServer) -> TestResult<GuiLoginOptions> {
    Ok(GuiLoginOptions::new(
        ManagementEndpoint::http(&server.base)?,
        GuiCredentials::new(USER, PASSWORD)?,
    )
    .expected_device_id(verysync_sidecar::DeviceId::parse(ID)?)
    .request_timeout(Duration::from_millis(500))?
    .stay_logged_in(true))
}

#[tokio::test]
async fn gui_logout_workflow_preserves_request_and_fresh_cookie_evidence() -> TestResult {
    use verysync_sidecar::{GuiLogoutOutcome as Outcome, OperationOptions};
    let identity = || Reply::json(json!({"myID":ID}));
    for (before, original, after, expected) in [
        (401, None, None, Outcome::AlreadyRejected),
        (200, Some(200), Some(401), Outcome::CookieRejected),
        (200, Some(0), Some(403), Outcome::CookieRejected),
        (200, Some(200), Some(200), Outcome::CookieStillAccepted),
        (200, Some(403), Some(200), Outcome::RequestRejected),
        (200, Some(200), Some(503), Outcome::Unconfirmed),
        (503, None, None, Outcome::NotSubmitted),
    ] {
        let mut replies = vec![
            challenge("AAAAAAA"),
            issue_cookie(true),
            engine_version("v2.33.2"),
            identity(),
        ];
        replies.push(if before == 200 {
            identity()
        } else {
            status(before)
        });
        if let Some(original) = original {
            replies.push(status(original));
        }
        if let Some(after) = after {
            replies.push(if after == 200 {
                identity()
            } else {
                status(after)
            });
        }
        let server = ScriptedServer::start(replies).await?;
        let session = GuiSession::login(options(&server)?).await?;
        let report = session
            .logout_and_verify(OperationOptions::new(Duration::from_secs(3)))
            .await?;
        assert_eq!(report.outcome, expected, "{report:?}");
        assert_eq!(report.write.dispatched, original.is_some());
        assert_eq!(
            report.write.response_complete,
            original.is_some_and(|code| code != 0)
        );
        assert!(!format!("{report} {report:?}").contains(SESSION));
        if original == Some(0) {
            assert!(matches!(
                report.original,
                Some(Err(Error::MutationOutcomeUnknown { .. }))
            ));
        }
        let used = server.finish().await?;
        assert_eq!(
            used.iter()
                .filter(|r| r.starts_with("POST /prefix/rest/noauth/auth/logout "))
                .count(),
            usize::from(original.is_some())
        );
    }
    Ok(())
}

fn kind(error: &Error) -> &'static str {
    match error {
        Error::Authentication { .. } => "authentication",
        Error::AccessDenied { .. } => "access denied",
        Error::MutationOutcomeUnknown { .. } => "unknown outcome",
        Error::Http { .. } => "HTTP",
        Error::Timeout { .. } => "timeout",
        Error::ResponseTooLarge { .. } => "response too large",
        Error::Transport { .. } => "transport",
        Error::InvalidResponse { .. } => "invalid response",
        Error::IncompatibleVersion { .. } => "incompatible version",
        Error::IdentityMismatch { .. } => "wrong identity",
        _ => "unexpected",
    }
}

#[tokio::test]
async fn preserves_legacy_errors_and_reports_the_phase_on_the_additive_entry_point() -> TestResult {
    use GuiLoginPhase::{
        BeforeLoginRequest, LoginOutcomeUnknown, LoginRejected, SessionCookieUnavailable,
        VerifyIdentity, VerifyVersion,
    };
    for detailed in [true, false] {
        let version = || engine_version("v2.33.2");
        let with_cookie = || issue_cookie(true);
        let version_timeout = || Reply {
            delay: Duration::from_millis(850),
            ..version()
        };
        let cases = [
            (
                BeforeLoginRequest,
                "invalid response",
                "invalid response",
                vec![],
            ),
            (
                LoginRejected,
                "authentication",
                "authentication",
                vec![status(401)],
            ),
            (
                LoginRejected,
                "access denied",
                "access denied",
                vec![status(403)],
            ),
            (
                LoginOutcomeUnknown,
                "transport",
                "unknown outcome",
                vec![status(0)],
            ),
            (
                LoginOutcomeUnknown,
                "HTTP",
                "unknown outcome",
                vec![status(503)],
            ),
            (
                SessionCookieUnavailable,
                "invalid response",
                "unknown outcome",
                vec![issue_cookie(false)],
            ),
            (
                VerifyVersion,
                "authentication",
                "authentication",
                vec![with_cookie(), status(401)],
            ),
            (
                VerifyVersion,
                "HTTP",
                "HTTP",
                vec![with_cookie(), status(503)],
            ),
            (
                VerifyVersion,
                "timeout",
                "timeout",
                vec![with_cookie(), version_timeout()],
            ),
            (
                VerifyVersion,
                "invalid response",
                "invalid response",
                vec![with_cookie(), malformed()],
            ),
            (
                VerifyVersion,
                "incompatible version",
                "incompatible version",
                vec![
                    with_cookie(),
                    engine_version(&format!("{USER}-{PASSWORD}-{CSRF}-{SESSION}")),
                ],
            ),
            (
                VerifyIdentity,
                "access denied",
                "access denied",
                vec![with_cookie(), version(), status(403)],
            ),
            (
                VerifyIdentity,
                "HTTP",
                "HTTP",
                vec![with_cookie(), version(), status(503)],
            ),
            (
                VerifyIdentity,
                "transport",
                "transport",
                vec![with_cookie(), version(), status(0)],
            ),
            (
                VerifyIdentity,
                "invalid response",
                "invalid response",
                vec![with_cookie(), version(), malformed()],
            ),
            (
                VerifyIdentity,
                "wrong identity",
                "wrong identity",
                vec![
                    with_cookie(),
                    version(),
                    Reply::json(json!({"myID": DIFFERENT_FULL_ID})),
                ],
            ),
        ];
        for (phase, expected_cause, expected_legacy, additional) in cases {
            let challenge_is_valid = phase != BeforeLoginRequest;
            let mut replies = vec![challenge(if challenge_is_valid {
                "AAAAAAA"
            } else {
                "BBBBBBB"
            })];
            replies.extend(additional);
            let request_count = replies.len();
            let server = ScriptedServer::start(replies).await?;
            let display = if detailed {
                let error = GuiSession::login_with_outcome(options(&server)?)
                    .await
                    .unwrap_err();
                assert_eq!(error.phase(), phase);
                assert_eq!(kind(error.cause()), expected_cause, "{phase:?}");
                let cause = std::error::Error::source(&error)
                    .and_then(|e| e.downcast_ref::<Error>())
                    .ok_or("planned GUI failure did not retain a typed cause")?;
                assert!(std::ptr::eq(cause, error.cause()));
                assert_eq!(
                    error.session_may_have_been_issued(),
                    !matches!(phase, BeforeLoginRequest | LoginRejected)
                );
                println!("GUI message: stage={phase:?} {error}");
                format!("{error} {error:?} {cause} {cause:?}")
            } else {
                let error = GuiSession::login(options(&server)?).await.unwrap_err();
                assert_eq!(kind(&error), expected_legacy, "{phase:?}");
                format!("{error} {error:?}")
            };
            assert!([USER, PASSWORD, CSRF, SESSION]
                .iter()
                .all(|s| !display.contains(*s)));
            let requests = server.finish().await?;
            assert_eq!(requests.len(), request_count);
            assert_eq!(
                requests.iter().filter(|r| r.starts_with("POST ")).count(),
                usize::from(challenge_is_valid)
            );
            assert!(!requests.iter().any(|r| r.contains("/logout")));
            if challenge_is_valid {
                assert!(requests[1].starts_with("POST /prefix/rest/noauth/auth/password "));
                let body: serde_json::Value = serde_json::from_str(
                    requests[1]
                        .split_once("\r\n\r\n")
                        .ok_or("missing POST body")?
                        .1,
                )?;
                assert_eq!(
                    body,
                    json!({"username":USER,"password":PASSWORD,"stayLoggedIn":true,"forumUser":false})
                );
                assert!(requests
                    .iter()
                    .skip(2)
                    .all(|r| r.contains(&format!("sessionid-AAAAAAA={SESSION}"))));
            }
            println!(
                "GUI login evidence: detailed={detailed} phase={phase:?} requests={request_count}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn refusal_status_is_certain_even_when_its_body_exceeds_the_limit() -> TestResult {
    let mut wrong = Vec::new();
    for status in [401, 403] {
        for limit in [18, 17] {
            for detailed in [true, false] {
                let server = ScriptedServer::start(vec![
                    challenge("AAAAAAA"),
                    Reply {
                        status,
                        body: b"Access was denied.".to_vec(),
                        headers: String::new(),
                        delay: Duration::ZERO,
                    },
                ])
                .await?;
                let options = options(&server)?.response_limit(limit)?;
                let expected_cause = if status == 401 {
                    "authentication"
                } else {
                    "access denied"
                };
                let accurate = if detailed {
                    let error = GuiSession::login_with_outcome(options).await.unwrap_err();
                    println!(
                        "GUI refusal: status={status} limit={limit} detailed=true phase={:?} possible={} cause={}",
                        error.phase(),
                        error.session_may_have_been_issued(),
                        kind(error.cause())
                    );
                    error.phase() == GuiLoginPhase::LoginRejected
                        && !error.session_may_have_been_issued()
                        && kind(error.cause()) == expected_cause
                        && if limit == 17 {
                            matches!(
                                error.rejection_body_error(),
                                Some(Error::ResponseTooLarge { limit: 17 })
                            )
                        } else {
                            error.rejection_body_error().is_none()
                        }
                } else {
                    let error = GuiSession::login(options).await.unwrap_err();
                    println!(
                        "GUI refusal: status={status} limit={limit} detailed=false error={}",
                        kind(&error)
                    );
                    if limit == 18 {
                        kind(&error) == expected_cause
                    } else {
                        matches!(
                            error,
                            Error::MutationOutcomeUnknown { source, .. }
                                if matches!(*source, Error::ResponseTooLarge { limit: 17 })
                        )
                    }
                };
                let requests = server.finish().await?;
                assert_eq!(requests.len(), 2);
                assert!(requests[0].starts_with("GET /prefix/ "));
                assert!(requests[1].starts_with("POST /prefix/rest/noauth/auth/password "));
                if !accurate {
                    wrong.push((status, limit, detailed));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "misclassified refusal cases: {wrong:?}");
    Ok(())
}

#[tokio::test]
async fn reports_a_verified_session_under_the_explicit_version_policy() -> TestResult {
    use verysync_sidecar::{VersionCompatibility, VersionPolicy};
    for (version, policy, compatibility) in [
        (
            "v2.33.2",
            VersionPolicy::ValidatedOnly,
            VersionCompatibility::ValidatedBaseline,
        ),
        (
            "v2.33.3",
            VersionPolicy::AllowUnverified,
            VersionCompatibility::Unverified,
        ),
    ] {
        let server = ScriptedServer::start(vec![
            challenge("AAAAAAA"),
            issue_cookie(true),
            engine_version(version),
            Reply::json(json!({"myID":ID})),
        ])
        .await?;
        let session =
            GuiSession::login_with_outcome(options(&server)?.version_policy(policy)).await?;
        assert_eq!(session.instance().device_id.as_str(), ID);
        assert_eq!(session.instance().version.version, version);
        assert_eq!(session.instance().compatibility, compatibility);
        assert!(!format!("{session:?}").contains(SESSION));
        let requests = server.finish().await?;
        assert_eq!(requests.len(), 4);
        assert_eq!(
            requests.iter().filter(|r| r.starts_with("POST ")).count(),
            1
        );
        assert!(requests[3].starts_with("GET /prefix/rest/system/status "));
    }
    Ok(())
}
