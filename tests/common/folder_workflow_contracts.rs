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
async fn registration_does_not_adopt_a_preexisting_id_or_replay_a_lost_post() -> TestResult {
    use verysync_sidecar::{CreateFolderOptions, PathStyle, TargetPath};
    let start = |exists| {
        vec![
            version(),
            identity(),
            identity(),
            if exists {
                configuration("folder-a", true)
            } else {
                Reply::json(json!({"folders":[]}))
            },
        ]
    };
    for (case, exists, response_code, read_back, expected) in [
        (
            "same ID already exists",
            true,
            0,
            None,
            FolderConfigurationOutcome::NotSubmitted,
        ),
        (
            "acknowledged",
            false,
            200,
            Some("folder-a"),
            FolderConfigurationOutcome::CurrentMatches,
        ),
        (
            "unanswered",
            false,
            0,
            Some("folder-a"),
            FolderConfigurationOutcome::CurrentMatches,
        ),
        (
            "different ID",
            false,
            200,
            Some("folder-b"),
            FolderConfigurationOutcome::CurrentDiffers,
        ),
    ] {
        let mut replies = start(exists);
        if !exists {
            replies.extend([
                Reply::json(json!({"defaultsMarker":KEY})),
                identity(),
                refused(response_code),
            ]);
        }
        if let Some(id) = read_back {
            replies.extend([version(), identity(), configuration(id, true), identity()]);
        }
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let report = client
            .create_folder_and_verify(
                &CreateFolderOptions::new(
                    FolderId::parse("folder-a")?,
                    TargetPath::remote(PathStyle::Unix, "/synthetic/user")?,
                )
                .label("retained label")
                .paused(true),
                OperationOptions::new(Duration::from_secs(3)),
            )
            .await?;
        assert_eq!(report.outcome, expected, "{case}: {report:?}");
        assert_eq!(report.write.dispatched, !exists);
        if exists {
            assert!(matches!(
                report.original,
                Some(Err(Error::FolderAlreadyExists { .. }))
            ));
        } else if response_code == 0 {
            assert!(matches!(
                report.original,
                Some(Err(Error::MutationOutcomeUnknown { .. }))
            ));
        }
        let operations = server.finish().await?;
        let posts: Vec<_> = operations
            .iter()
            .filter(|r| r.starts_with("POST "))
            .collect();
        assert_eq!(posts.len(), usize::from(!exists));
        if let Some(post) = posts.first() {
            let body: serde_json::Value =
                serde_json::from_str(post.split_once("\r\n\r\n").unwrap().1)?;
            assert_eq!(
                body,
                json!({
                    "defaultsMarker":KEY,"id":"folder-a","path":"/synthetic/user","paused":true,"label":"retained label"
                })
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn selective_path_workflow_checks_exact_index_and_never_replays_mutation() -> TestResult {
    use verysync_sidecar::{PathStyle, SelectiveAction, SelectivePathOutcome, TargetPath};
    let config = || {
        Reply::json(json!({"folders":[
            {"id":"folder-a","path":"/synthetic/user","label":"retained","paused":false,"selectiveEnabled":true}
        ]}))
    };
    let index = |name, selected, present| {
        Reply::json(json!({"item.bin":{
            "name":name,"isdir":false,"selectived":selected,"exists":present
        }}))
    };
    for (case, originally_selected, response, expected, post) in [
        (
            "already selected",
            true,
            0,
            SelectivePathOutcome::AlreadyMatched,
            false,
        ),
        (
            "exact new selected",
            false,
            200,
            SelectivePathOutcome::CurrentMatches,
            true,
        ),
        (
            "lost response",
            false,
            0,
            SelectivePathOutcome::CurrentMatches,
            true,
        ),
        (
            "unlicensed",
            false,
            3000,
            SelectivePathOutcome::Rejected,
            true,
        ),
        (
            "wrong index name",
            false,
            0,
            SelectivePathOutcome::NotSubmitted,
            false,
        ),
    ] {
        let mut replies = vec![
            version(),
            identity(),
            config(),
            identity(),
            config(),
            identity(),
            config(),
            index(
                if case == "wrong index name" {
                    "another.bin"
                } else {
                    "item.bin"
                },
                originally_selected,
                originally_selected,
            ),
            identity(),
        ];
        if case != "wrong index name" {
            replies.push(config());
        }
        if post {
            replies.push(identity());
            replies.push(if response == 3000 {
                Reply::json(json!({"error":"test permission envelope","code":3000}))
            } else {
                refused(response)
            });
        }
        if post && response != 3000 {
            replies.extend([
                config(),
                identity(),
                config(),
                identity(),
                config(),
                index("item.bin", true, true),
                identity(),
            ]);
        }
        let fixture = ScriptedServer::start(replies).await?;
        let client = Client::connect(fixture.options()?).await?;
        let received = client
            .set_selective_path_and_verify(
                &FolderId::parse("folder-a")?,
                &TargetPath::remote(PathStyle::Unix, "nested/item.bin")?,
                SelectiveAction::Select,
                Some(true),
                OperationOptions::new(Duration::from_secs(3)),
            )
            .await?;
        assert_eq!(received.outcome, expected, "{case}: {received:?}");
        assert_eq!(received.write.dispatched, post);
        if case == "lost response" {
            assert!(matches!(
                received.original,
                Some(Err(Error::MutationOutcomeUnknown { .. }))
            ));
        }
        if case == "unlicensed" {
            assert!(matches!(
                received.original,
                Some(Err(Error::LicenseRequired { code: 3000, .. }))
            ));
            assert!(received.observed.is_none());
        }
        if matches!(
            expected,
            SelectivePathOutcome::AlreadyMatched | SelectivePathOutcome::CurrentMatches
        ) {
            assert_eq!(received.expected_index_presence_observed, Some(true));
        }
        let seen = fixture.finish().await?;
        let mutation: Vec<_> = seen.iter().filter(|r| r.starts_with("POST ")).collect();
        assert_eq!(mutation.len(), usize::from(post));
        if let Some(line) = mutation.first() {
            assert!(line.contains(
                "folder=folder-a&path=nested%2Fitem.bin&selected=true&removefromall=false"
            ));
        }
    }
    Ok(())
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
