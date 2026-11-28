//! Public configured-folder workflow with separate request and readback facts.
use super::*;
use serde_json::json;
use verysync_sidecar::{
    FolderConfigurationOutcome, FolderId, FolderPatch, FolderState, OperationOptions,
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
