//! Public configured-folder workflow with separate request and readback facts.
use super::*;
use serde_json::json;
use verysync_sidecar::{
    FolderConfigurationOutcome, FolderId, FolderPatch, FolderState, FolderUnregistrationOutcome,
    OperationOptions,
};

fn version() -> Reply {
    Reply::json(json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}

fn identity() -> Reply {
    Reply::json(json!({"myID":ID}))
}

fn configuration(id: &str, paused: bool) -> Reply {
    Reply::json(
        json!({"folders":[{"id":id, "path":"/synthetic/user", "label":"retained label",
        "paused":paused,"enginePrivateSetting":KEY}]}),
    )
}

fn refused(status: u16) -> Reply {
    Reply {
        status,
        ..Reply::json(json!({}))
    }
}

fn controls(paused: bool) -> Vec<Reply> {
    vec![
        version(),
        identity(),
        version(),
        identity(),
        configuration("folder-a", paused),
        identity(),
    ]
}

#[tokio::test]
async fn folder_configuration_noop_keeps_zero_writes_and_can_read_activity() -> TestResult {
    let mut replies = controls(true);
    replies.extend([
        identity(),
        Reply::json(json!({"state":"paused","localFiles":3})),
        configuration("folder-a", true),
        identity(),
    ]);
    let server = ScriptedServer::start(replies).await?;
    let client = Client::connect(server.options()?).await?;
    let report = client
        .set_folder_pause_and_verify(
            &FolderId::parse("folder-a")?,
            true,
            Some(FolderState::Paused),
            OperationOptions::new(Duration::from_secs(3)),
        )
        .await?;
    assert_eq!(report.outcome, FolderConfigurationOutcome::AlreadyMatched);
    assert!(!report.write.dispatched);
    assert!(report.original.is_none());
    let observed = report.runtime.ok_or("runtime snapshot was requested")?;
    assert!(observed.expected_state_observed);
    assert_eq!(
        observed
            .last_snapshot
            .ok_or("expected paused state")?
            .local_files,
        Some(3)
    );
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 10);
    assert!(requests.iter().all(|line| line.starts_with("GET ")));
    Ok(())
}

#[tokio::test]
async fn folder_configuration_keeps_one_write_and_original_failure_before_readback() -> TestResult {
    for (response, readback, expected) in [
        (200, "folder-a", FolderConfigurationOutcome::CurrentMatches),
        (0, "folder-a", FolderConfigurationOutcome::CurrentMatches),
        (403, "folder-a", FolderConfigurationOutcome::Rejected),
        (200, "folder-b", FolderConfigurationOutcome::Unconfirmed),
    ] {
        let mut replies = controls(false);
        replies.push(refused(response));
        if response != 403 {
            replies.extend([version(), identity(), configuration(readback, true)]);
            if readback == "folder-a" {
                replies.push(identity());
            }
        }
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let report = client
            .update_folder_and_verify(
                &FolderId::parse("folder-a")?,
                &FolderPatch::default().paused(true),
                OperationOptions::new(Duration::from_secs(3)),
            )
            .await?;
        assert_eq!(report.outcome, expected);
        assert!(report.write.dispatched);
        assert_eq!(report.write.status, (response != 0).then_some(response));
        assert_eq!(report.write.response_complete, response != 0);
        assert!(!format!("{report:?}").contains(KEY));
        match (response, readback) {
            (0, _) => assert!(matches!(
                report.original,
                Some(Err(Error::MutationOutcomeUnknown { .. }))
            )),
            (403, _) => assert!(matches!(
                report.original,
                Some(Err(Error::AccessDenied { .. }))
            )),
            (200, "folder-b") => {
                assert!(report.observed.is_none());
                assert!(matches!(
                    report.observation_error,
                    Some(Error::FolderNotFound { .. })
                ));
            }
            _ => assert!(report.observed.is_some_and(|actual| actual.paused)),
        }
        let requests = server.finish().await?;
        let writes: Vec<_> = requests
            .iter()
            .filter(|line| line.starts_with("PATCH "))
            .collect();
        assert_eq!(writes.len(), 1);
        assert!(writes[0].starts_with("PATCH /prefix/rest/config/folders/folder-a "));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(writes[0].split_once("\r\n\r\n").unwrap().1)?,
            json!({"paused":true})
        );
    }
    Ok(())
}

#[tokio::test]
async fn unregister_uses_one_delete_and_reports_config_and_file_evidence_separately() -> TestResult
{
    let absent = || Reply::json(json!({"folders":[]}));
    for (name, preexisting, response, readback, expected) in [
        (
            "already absent",
            false,
            0,
            0,
            FolderUnregistrationOutcome::AlreadyAbsent,
        ),
        (
            "success",
            true,
            200,
            200,
            FolderUnregistrationOutcome::Absent,
        ),
        (
            "lost reply",
            true,
            0,
            200,
            FolderUnregistrationOutcome::Absent,
        ),
        (
            "write refusal",
            true,
            403,
            0,
            FolderUnregistrationOutcome::Rejected,
        ),
        (
            "read refusal",
            true,
            200,
            403,
            FolderUnregistrationOutcome::Unconfirmed,
        ),
        (
            "register again",
            true,
            200,
            201,
            FolderUnregistrationOutcome::RegistrationPresent,
        ),
    ] {
        let mut replies = controls(false);
        if !preexisting {
            replies[4] = absent();
        } else {
            replies.push(refused(response));
            if response != 403 {
                replies.extend([version(), identity()]);
                replies.push(match readback {
                    200 => absent(),
                    201 => Reply::json(json!({"folders":[{"id":"folder-a","path":"/synthetic/other","label":"different","paused":true}]})),
                    code => refused(code),
                });
                if readback != 403 {
                    replies.push(identity());
                }
            }
        }
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let report = client
            .unregister_folder_and_verify(
                &FolderId::parse("folder-a")?,
                OperationOptions::new(Duration::from_secs(3)),
            )
            .await?;
        assert_eq!(report.outcome, expected, "{name}: {report:?}");
        assert_eq!(report.write.dispatched, preexisting);
        assert_eq!(report.write.response_complete, preexisting && response != 0);
        assert!(!format!("{report:?}").contains(KEY));
        assert!(format!("{report}").contains("File contents were not checked"));
        if name == "lost reply" {
            assert!(matches!(
                report.original,
                Some(Err(Error::MutationOutcomeUnknown { .. }))
            ));
        }
        if name == "read refusal" {
            assert!(matches!(report.original, Some(Ok(()))));
            assert!(matches!(
                report.observation_error,
                Some(Error::AccessDenied { .. })
            ));
        }
        let requests = server.finish().await?;
        let deletes: Vec<_> = requests
            .iter()
            .filter(|line| line.starts_with("DELETE "))
            .collect();
        assert_eq!(deletes.len(), usize::from(preexisting));
        if let Some(delete) = deletes.first() {
            assert!(delete.starts_with("DELETE /prefix/rest/config/folders/folder-a "));
            assert!(delete.ends_with("\r\n\r\n"));
        }
    }
    Ok(())
}
