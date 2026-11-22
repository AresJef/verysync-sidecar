use super::*;
use verysync_sidecar::{
    DirectoryVersionOrder, FileVersionRestore, FolderId, PathStyle, TargetPath, VersionedDirectory,
};

#[tokio::test]
async fn both_archive_restores_use_the_last_target_clock_before_the_only_write() -> TestResult {
    const ARCHIVE: &str = "2026-11-14T08:00:00.125+08:00";
    const INITIAL: &str = "2026-11-14T00:00:05Z";
    for (label, clock, allowed) in [
        (
            "equivalent offset and same second",
            Some("2026-11-14T00:00:00.800Z"),
            false,
        ),
        (
            "earlier target second after clock rollback",
            Some("2026-11-13T23:59:59.999Z"),
            false,
        ),
        ("missing final clock", None, false),
        ("invalid final clock", Some("unverified clock"), false),
        (
            "unverified leap second",
            Some("2026-11-14T00:00:60Z"),
            false,
        ),
        (
            "strictly earlier archive second",
            Some("2026-11-14T00:00:01Z"),
            true,
        ),
    ] {
        for directory in [false, true] {
            let final_status = match clock {
                Some(clock) => serde_json::json!({"myID": ID, "nowTime": clock}),
                None => serde_json::json!({"myID": ID}),
            };
            let initial = || Reply::json(serde_json::json!({"myID": ID, "nowTime": INITIAL}));
            let folder = || {
                Reply::json(serde_json::json!({"folders": [
                    {"id":"review-archive","label":"","path":"/fixture","paused":false}
                ]}))
            };
            let mut replies = vec![
                Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
                initial(),
                initial(),
                folder(),
            ];
            if directory {
                replies.extend([
                    initial(),
                    folder(),
                    Reply::json(serde_json::json!({"file.txt": [{
                        "versionTime": ARCHIVE, "modTime": ARCHIVE, "size": 9,
                    }]})),
                ]);
            }
            replies.push(Reply::json(final_status));
            if allowed {
                replies.push(Reply::json(serde_json::json!({})));
            }

            let server = ScriptedServer::start(replies).await?;
            let client = Client::connect(server.options()?).await?;
            let id = FolderId::parse("review-archive")?;
            let result = if directory {
                client
                    .restore_directory_versions(
                        &id,
                        &VersionedDirectory::FolderRoot,
                        DirectoryVersionOrder::Oldest,
                    )
                    .await
                    .map(|_| ())
            } else {
                let item = FileVersionRestore::new(
                    TargetPath::remote(PathStyle::Unix, "file.txt")?,
                    ARCHIVE,
                )?;
                client.restore_file_versions(&id, &[item]).await.map(|_| ())
            };
            if allowed {
                result?;
            } else {
                assert!(
                    matches!(result, Err(Error::ArchiveRestorePrecondition { .. })),
                    "{label}, directory={directory}: {result:?}"
                );
            }

            let requests = server.finish().await?;
            let count = if directory { 8 } else { 5 };
            assert_eq!(requests.len(), count + usize::from(allowed));
            assert!(requests[count - 1].starts_with("GET /prefix/rest/system/status "));
            let writes: Vec<_> = requests
                .iter()
                .filter(|line| line.starts_with("POST "))
                .collect();
            assert_eq!(
                writes.len(),
                usize::from(allowed),
                "{label}, directory={directory}"
            );
            if let Some(request) = writes.first() {
                let (route, expected) = if directory {
                    (
                        "POST /prefix/rest/folder/versions/restore?folder=review-archive ",
                        serde_json::json!({"items":[{"path":".","action":"oldest"}]}),
                    )
                } else {
                    (
                        "POST /prefix/rest/folder/versions?folder=review-archive ",
                        serde_json::json!({"file.txt": ARCHIVE}),
                    )
                };
                assert!(request.starts_with(route));
                let body = request
                    .split_once("\r\n\r\n")
                    .ok_or("restore body absent")?
                    .1;
                assert_eq!(serde_json::from_str::<serde_json::Value>(body)?, expected);
            }
        }
    }
    Ok(())
}
