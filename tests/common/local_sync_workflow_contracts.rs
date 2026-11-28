use super::*;
use serde_json::json;
use verysync_sidecar::{
    LocalSyncJobId, LocalSyncPreviewId, LocalSyncRunOutcome, LocalSyncSelection,
    LocalSyncWorkflowOptions, OperationOptions,
};

fn identity() -> Reply {
    Reply::json(json!({"myID":ID}))
}

fn connection() -> Vec<Reply> {
    vec![
        Reply::json(json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        identity(),
    ]
}

#[tokio::test]
async fn local_sync_registration_never_adopts_old_id_or_same_label_with_other_endpoints(
) -> TestResult {
    use verysync_sidecar::{
        CreateLocalSyncJob, LocalSyncMode, LocalSyncRegistrationOutcome as Outcome, PathStyle,
        StorageEndpoint, TargetPath,
    };
    let input = CreateLocalSyncJob::new(
        "synthetic repeated name",
        StorageEndpoint::local(TargetPath::remote(PathStyle::Unix, "/fixture/from")?)?,
        StorageEndpoint::local(TargetPath::remote(PathStyle::Unix, "/fixture/to")?)?,
        LocalSyncMode::MirrorAToB,
    )?;
    let expected = serde_json::to_value(&input)?;
    let job = |id: &str, correct_fields: bool| {
        let mut fields = expected.clone();
        fields["jobId"] = id.into();
        if !correct_fields {
            fields["sideB"]["uri"] = "/fixture/different".into();
        }
        fields
    };
    for (name, want) in [
        (
            "one exact candidate",
            Outcome::MatchingNewRegistrationObserved,
        ),
        ("ambiguous", Outcome::Unconfirmed),
        ("old matching only", Outcome::Unconfirmed),
    ] {
        let old = job("old-id", true);
        let new = job("selected-new-id", true);
        let different = job("same-label-different-path", false);
        let mut replies = connection();
        replies.extend([
            identity(),
            Reply::json(json!([old])),
            identity(),
            Reply {
                status: 0,
                ..Reply::json(json!({}))
            },
            identity(),
        ]);
        replies.push(Reply::json(match name {
            "one exact candidate" => json!([old, new, different]),
            "ambiguous" => json!([old, new, job("other-new-id", true)]),
            _ => json!([old, different]),
        }));
        if want == Outcome::MatchingNewRegistrationObserved {
            replies.extend([identity(), Reply::json(new)]);
        }
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let report = client
            .create_local_sync_job_and_verify(&input, OperationOptions::new(Duration::from_secs(3)))
            .await?;
        assert_eq!(report.outcome, want, "{name}: {report:?}");
        assert!(matches!(
            report.original,
            Err(Error::MutationOutcomeUnknown { .. })
        ));
        assert_eq!(
            report.observed.as_ref().map(|job| job.job_id.as_str()),
            (want == Outcome::MatchingNewRegistrationObserved).then_some("selected-new-id")
        );
        let seen = server.finish().await?;
        assert_eq!(
            seen.iter()
                .filter(|r| r.starts_with("POST /prefix/rest/localsync/jobs "))
                .count(),
            1
        );
    }
    Ok(())
}

fn plan(id: &str, expires: &str) -> Reply {
    Reply::json(json!({
        "id":id,"jobId":"job-a","operationId":"preview-producer","count":2,
        "expiresAt":expires,"scanIssueCount":0
    }))
}

fn run(id: &str, completed: u64, failed: u64, finished: bool) -> Reply {
    Reply::json(json!({
        "id":id,"jobId":"job-a","started":"2026-01-02T03:04:05Z",
        "finished":if finished {"2026-01-02T03:05:00Z"} else {"0001-01-01T00:00:00Z"},
        "count":if finished {2} else {0},"summary":{"completed":completed,"failed":failed,"skipped":0},
        "cancelled":false
    }))
}

#[tokio::test]
async fn local_sync_business_reports_exact_pages_and_preserves_partial_failures() -> TestResult {
    for (name, outcome, finished, pages) in [
        (
            "success",
            LocalSyncRunOutcome::Completed,
            Some("run-a"),
            true,
        ),
        (
            "partially failed",
            LocalSyncRunOutcome::PartiallyCompleted,
            Some("run-a"),
            true,
        ),
        (
            "newer run",
            LocalSyncRunOutcome::Unconfirmed,
            Some("run-b"),
            false,
        ),
        (
            "lost response",
            LocalSyncRunOutcome::Unconfirmed,
            None,
            false,
        ),
    ] {
        let failed = u64::from(name == "partially failed");
        let mut replies = connection();
        replies.extend([
            identity(),
            plan("preview-a", "2090-01-01T00:00:00Z"),
            identity(),
        ]);
        replies.push(match name {
            "lost response" => Reply {
                status: 0,
                ..Reply::json(json!({}))
            },
            _ => run("run-a", 0, 0, false),
        });
        if let Some(finished_id) = finished {
            if name == "success" {
                replies.extend([identity(), run("run-a", 0, 0, false)]);
            }
            replies.extend([identity(), run(finished_id, 2 - failed, failed, true)]);
        }
        if pages {
            for action in [0, 1] {
                replies.extend([
                    identity(),
                    Reply::json(json!([{"actionId":action,"path":"fixture","kind":"copy","bytes":7,
                        "error":if failed != 0 && action == 1 {Some("controlled failure")} else {None}
                    }])),
                ]);
            }
            replies.extend([identity(), run("run-a", 2 - failed, failed, true)]);
        }
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let report = client
            .execute_local_sync_preview(
                &LocalSyncJobId::parse("job-a")?,
                &LocalSyncPreviewId::parse("preview-a")?,
                &LocalSyncSelection::all(),
                LocalSyncWorkflowOptions::new(2, OperationOptions::new(Duration::from_secs(4)))
                    .page_size(1),
            )
            .await?;
        assert_eq!(report.outcome, outcome, "{name}: {report:?}");
        assert!(report.write.dispatched);
        assert_eq!(report.write.response_complete, name != "lost response");
        assert_eq!(report.results.len(), if pages { 2 } else { 0 });
        assert_eq!(report.receipt.is_some(), name != "lost response");
        if pages {
            assert_eq!(report.terminal.as_ref().unwrap().summary.failed, failed);
        } else {
            assert!(report.terminal.is_none());
        }
        let requests = server.finish().await?;
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.starts_with("POST /prefix/rest/localsync/jobs/job-a/run "))
                .count(),
            1
        );
        let reads: Vec<_> = requests
            .iter()
            .filter(|r| r.contains("/results?"))
            .collect();
        assert_eq!(reads.len(), if pages { 2 } else { 0 });
        if pages {
            for (offset, request) in reads.iter().enumerate() {
                assert!(
                    request.contains(&format!("/runs/run-a/results?offset={offset}&limit=1 ")),
                    "{request}"
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn rejected_or_expired_local_sync_preview_never_submits_run() -> TestResult {
    for (id, expiry, max) in [
        ("older-preview", "2090-01-01T00:00:00Z", 2),
        ("preview-a", "2006-01-01T00:00:00Z", 2),
        ("preview-a", "2090-01-01T00:00:00Z", 1),
    ] {
        let mut replies = connection();
        replies.extend([identity(), plan(id, expiry)]);
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let report = client
            .execute_local_sync_preview(
                &LocalSyncJobId::parse("job-a")?,
                &LocalSyncPreviewId::parse("preview-a")?,
                &LocalSyncSelection::all(),
                LocalSyncWorkflowOptions::new(max, OperationOptions::new(Duration::from_secs(3))),
            )
            .await?;
        assert_eq!(report.outcome, LocalSyncRunOutcome::NotSubmitted);
        assert!(!report.write.dispatched);
        assert!(server.finish().await?.iter().all(|r| r.starts_with("GET ")));
    }
    Ok(())
}

#[tokio::test]
async fn local_sync_run_control_does_not_adopt_a_replacement_operation() -> TestResult {
    use verysync_sidecar::{
        LocalSyncOperationControl, LocalSyncOperationId, LocalSyncRunControlOutcome, LocalSyncRunId,
    };
    let generation = || Reply::json(json!({"myID": ID, "startTime": "generation-one"}));
    let status = |operation: &str, state: &str, cancelled: bool| {
        Reply::json(json!({
            "jobId":"job-a","operationId":operation,"state":state,"lastRunCancelled":cancelled,
        }))
    };
    let cancelled = || {
        Reply::json(json!({
            "id":"run-a","jobId":"job-a","started":"2026-01-02T03:04:05Z",
            "finished":"2026-01-02T03:05:00Z","count":2,
            "summary":{"completed":1,"failed":0,"skipped":1},"cancelled":true,
        }))
    };
    let version = || Reply::json(json!({"version":"v2.33.2","os":"linux","arch":"amd64"}));
    for (case, outcome) in [
        ("normal", LocalSyncRunControlOutcome::Observed),
        ("lost reply", LocalSyncRunControlOutcome::Observed),
        ("replacement", LocalSyncRunControlOutcome::Unconfirmed),
        ("wrong before", LocalSyncRunControlOutcome::NotSubmitted),
        ("already", LocalSyncRunControlOutcome::AlreadyMatched),
    ] {
        let own = "operation-a";
        let mut replies = connection();
        replies.extend([version(), identity(), generation(), identity()]);
        replies.push(status(
            if case == "wrong before" {
                "operation-b"
            } else {
                own
            },
            if case == "already" { "idle" } else { "running" },
            case == "already",
        ));
        if case != "wrong before" {
            replies.extend([
                identity(),
                if case == "already" {
                    cancelled()
                } else {
                    run("run-a", 0, 0, false)
                },
                generation(),
            ]);
        }
        if !matches!(case, "wrong before" | "already") {
            replies.push(if case == "lost reply" {
                Reply {
                    status: 0,
                    ..Reply::json(json!({}))
                }
            } else {
                Reply::json(json!({}))
            });
            replies.extend([
                generation(),
                identity(),
                status(
                    if case == "replacement" {
                        "operation-b"
                    } else {
                        own
                    },
                    "idle",
                    true,
                ),
            ]);
            if case != "replacement" {
                replies.extend([identity(), cancelled(), generation()]);
            }
        }
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let report = client
            .control_local_sync_run_and_verify(
                &LocalSyncJobId::parse("job-a")?,
                &LocalSyncOperationId::parse(own)?,
                &LocalSyncRunId::parse("run-a")?,
                LocalSyncOperationControl::Stop,
                OperationOptions::new(Duration::from_secs(4)),
            )
            .await?;
        assert_eq!(report.outcome, outcome, "{case}: {report:?}");
        assert_eq!(
            report.write.dispatched,
            !matches!(case, "wrong before" | "already")
        );
        if case == "lost reply" {
            assert!(matches!(
                &report.original,
                Err(Error::MutationOutcomeUnknown { .. })
            ));
        }
        if matches!(case, "normal" | "lost reply" | "already") {
            assert_eq!(
                report.observed_run.as_ref().and_then(|run| run.cancelled),
                Some(true)
            );
        }
        let requests = server.finish().await?;
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.starts_with("POST "))
                .count(),
            usize::from(!matches!(case, "wrong before" | "already"))
        );
    }
    Ok(())
}
