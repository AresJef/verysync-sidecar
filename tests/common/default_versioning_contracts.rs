//! Future-folder version policies retain native unknown values and target paths.
use super::*;
use verysync_sidecar::{FolderVersioningPolicy, PathStyle, TargetPath, VersionArchiveLocation};
fn original() -> serde_json::Value {
    serde_json::json!({"label":"","paused":false,"rescanIntervalS":3600,
    "fsWatcherEnabled":true,"secretKey":KEY,"versioning":{"type":"simple","params":{"keep":"1","privateFuture":KEY},
    "cleanupIntervalS":3600,"fsPath":"C:\\Old Archive","fsType":"basic","privateFuture":KEY}})
}
fn identity() -> Reply {
    Reply::json(serde_json::json!({"myID":ID}))
}
fn version() -> Reply {
    Reply::json(serde_json::json!({"version":"v2.33.2","os":"windows","arch":"amd64"}))
}

#[tokio::test]
async fn default_versioning_policy_preserves_location_and_private_inactive_parameters() -> TestResult
{
    let mut actual = original();
    actual["versioning"]["params"]["keep"] = "3".into();
    actual["versioning"]["params"]["cleanoutDays"] = "0".into();
    let server = ScriptedServer::start(vec![
        version(),
        identity(),
        identity(),
        Reply::json(original()),
        Reply::json(serde_json::json!({})),
        Reply::json(actual.clone()),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let receipt = client
        .set_folder_default_versioning(FolderVersioningPolicy::Simple {
            keep: 3,
            cleanout_days: 0,
            cleanup_interval_seconds: 3600,
        })
        .await?;
    assert!(receipt.requested_fields_match);
    assert_eq!(receipt.configuration.filesystem_path, r"C:\Old Archive");
    assert_eq!(receipt.configuration.params["privateFuture"], KEY);
    assert!(!format!("{receipt:?}").contains(KEY));
    let requests = server.finish().await?;
    let writes: Vec<_> = requests
        .iter()
        .filter(|r| r.starts_with("PATCH "))
        .collect();
    assert_eq!(writes.len(), 1);
    let body: serde_json::Value =
        serde_json::from_str(writes[0].split_once("\r\n\r\n").ok_or("body absent")?.1)?;
    assert_eq!(body, serde_json::json!({"versioning":actual["versioning"]}));
    Ok(())
}

#[tokio::test]
async fn default_archive_location_uses_target_syntax_and_unknown_readback_is_not_retried(
) -> TestResult {
    for malformed in [false, true] {
        let mut actual = original();
        actual["versioning"]["fsPath"] = r"D:\Chosen Archive".into();
        if malformed {
            actual["versioning"] = "invalid".into();
        }
        let server = ScriptedServer::start(vec![
            version(),
            identity(),
            identity(),
            Reply::json(original()),
            Reply::json(serde_json::json!({})),
            Reply::json(actual),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let result = client
            .set_folder_default_archive_location(&VersionArchiveLocation::BasicDirectory(
                TargetPath::remote(PathStyle::Windows, r"D:\Chosen Archive")?,
            ))
            .await;
        if malformed {
            assert!(matches!(result, Err(Error::MutationOutcomeUnknown { .. })));
        } else {
            let receipt = result?;
            assert!(receipt.requested_fields_match);
            assert_eq!(receipt.configuration.filesystem_path, r"D:\Chosen Archive");
        }
        assert_eq!(
            server
                .finish()
                .await?
                .iter()
                .filter(|r| r.starts_with("PATCH "))
                .count(),
            1
        );
    }
    Ok(())
}

#[tokio::test]
async fn invalid_default_archive_and_policy_inputs_do_not_send_requests() -> TestResult {
    let server = ScriptedServer::start(vec![version(), identity()]).await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client
            .set_folder_default_versioning(FolderVersioningPolicy::Simple {
                keep: 0,
                cleanout_days: 0,
                cleanup_interval_seconds: 3600
            })
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        client
            .set_folder_default_archive_location(&VersionArchiveLocation::BasicDirectory(
                TargetPath::remote(PathStyle::Unix, "/wrong-target-syntax")?
            ))
            .await,
        Err(Error::InvalidPath { .. })
    ));
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}
