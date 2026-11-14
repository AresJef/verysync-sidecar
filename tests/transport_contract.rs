//! Synthetic transport evidence, separate from real-engine acceptance.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, Error, ManagementEndpoint, VersionCompatibility, VersionPolicy,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const KEY: &str = "synthetic-transport-key";
const ID: &str = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";

#[tokio::test]
async fn index_reset_requires_explicit_scope_and_exact_native_ack_without_readback() -> TestResult {
    use verysync_sidecar::{FolderId, IndexResetScope};
    for all in [false, true] {
        let identity = || Reply::json(serde_json::json!({"myID":ID}));
        let mut replies = vec![
            Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
            identity(),
            identity(),
        ];
        let scope = if all {
            IndexResetScope::AllFolders
        } else {
            IndexResetScope::Folder(FolderId::parse(KEY)?)
        };
        if !all {
            replies.push(Reply::json(serde_json::json!({"folders":[{"id":KEY,"label":"","path":"/synthetic","paused":true}]})));
        }
        let message = if all {
            "resetting database".to_owned()
        } else {
            format!("resetting folder {KEY}")
        };
        replies.push(Reply::json(serde_json::json!({"ok":message,"private":KEY})));
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let ack = client.request_index_reset(&scope).await?;
        assert_eq!(ack.scope, scope);
        assert!(ack.restart_expected);
        assert_eq!(ack.native_message(), message);
        assert_eq!(ack.extra["private"], KEY);
        assert!(!format!("{ack:?}").contains(KEY));
        let requests = server.finish().await?;
        let posts = requests
            .iter()
            .filter(|r| r.starts_with("POST "))
            .collect::<Vec<_>>();
        assert_eq!(posts.len(), 1);
        let target = if all {
            "POST /prefix/rest/system/reset ".to_owned()
        } else {
            format!("POST /prefix/rest/system/reset?folder={KEY} ")
        };
        assert!(posts[0].starts_with(&target));
        assert!(requests.last().is_some_and(|r| r.starts_with("POST ")));
    }
    Ok(())
}

#[tokio::test]
async fn index_reset_unknown_ack_is_unknown_once_and_missing_folder_never_resets_all() -> TestResult
{
    use verysync_sidecar::{FolderId, IndexResetScope};
    for body in [
        serde_json::json!({}),
        serde_json::json!({"ok":"other native action","private":KEY}),
    ] {
        let identity = || Reply::json(serde_json::json!({"myID":ID}));
        let server = ScriptedServer::start(vec![
            Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
            identity(),
            identity(),
            Reply::json(body),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let error = client
            .request_index_reset(&IndexResetScope::AllFolders)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
        assert!(!format!("{error:?} {error}").contains(KEY));
        assert_eq!(
            server
                .finish()
                .await?
                .iter()
                .filter(|r| r.starts_with("POST "))
                .count(),
            1
        );
    }
    let identity = || Reply::json(serde_json::json!({"myID":ID}));
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        identity(),
        identity(),
        Reply::json(serde_json::json!({"folders":[]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client
            .request_index_reset(&IndexResetScope::Folder(FolderId::parse("absent")?))
            .await,
        Err(Error::FolderNotFound { .. })
    ));
    assert!(!server
        .finish()
        .await?
        .iter()
        .any(|r| r.starts_with("POST ")));
    Ok(())
}

#[tokio::test]
async fn archive_restore_refuses_same_future_missing_or_unknown_target_clock_without_post(
) -> TestResult {
    use verysync_sidecar::{FileVersionRestore, FolderId, PathStyle, TargetPath};
    for clock in [
        Some("2026-11-14T08:00:00+08:00"),
        Some("2026-11-13T23:59:59Z"),
        None,
        Some("unknown native clock"),
    ] {
        let identity = || Reply::json(serde_json::json!({"myID":ID}));
        let mut now = serde_json::json!({"myID":ID,"private":KEY});
        if let Some(clock) = clock {
            now["nowTime"] = clock.into();
        }
        let server=ScriptedServer::start(vec![
            Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),identity(),identity(),
            Reply::json(serde_json::json!({"folders":[{"id":"private-restore","label":"","path":"/synthetic","paused":false}]})),Reply::json(now),
        ]).await?;
        let client = Client::connect(server.options()?).await?;
        let item = FileVersionRestore::new(
            TargetPath::remote(PathStyle::Unix, "file.txt")?,
            "2026-11-14T00:00:00Z",
        )?;
        let error = client
            .restore_file_versions(&FolderId::parse("private-restore")?, &[item])
            .await
            .unwrap_err();
        assert!(matches!(error, Error::ArchiveRestorePrecondition { .. }));
        assert!(!format!("{error:?} {error}").contains(KEY));
        let requests = server.finish().await?;
        assert_eq!(requests.len(), 5);
        assert!(!requests.iter().any(|r| r.starts_with("POST ")));
    }
    Ok(())
}

#[tokio::test]
async fn directory_preflight_refuses_file_scope_and_oversized_inventory_without_post() -> TestResult
{
    use verysync_sidecar::{
        DirectoryVersionOrder, FolderId, PathStyle, TargetPath, VersionedDirectory,
    };
    let id = FolderId::parse("bounded-native-restore")?;
    let version = serde_json::json!({"versionTime":"2026-11-14T00:00:00Z","modTime":"2026-11-13T00:00:00Z","size":3});
    let mut oversized = serde_json::Map::new();
    for i in 0..513 {
        oversized.insert(format!("f{i}.txt"), serde_json::json!([version.clone()]));
    }
    for (scope, listing) in [
        (
            VersionedDirectory::Path(TargetPath::remote(PathStyle::Unix, "file.txt")?),
            serde_json::json!({"file.txt":[version]}),
        ),
        (
            VersionedDirectory::FolderRoot,
            serde_json::Value::Object(oversized),
        ),
    ] {
        let identity =
            || Reply::json(serde_json::json!({"myID":ID,"nowTime":"2026-11-15T00:00:00Z"}));
        let folder = || {
            Reply::json(
                serde_json::json!({"folders":[{"id":id.as_str(),"label":"","path":"/synthetic","paused":false}]}),
            )
        };
        let server = ScriptedServer::start(vec![
            Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
            identity(),
            identity(),
            folder(),
            identity(),
            folder(),
            Reply::json(listing),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        assert!(matches!(
            client
                .restore_directory_versions(&id, &scope, DirectoryVersionOrder::Oldest)
                .await,
            Err(Error::ArchiveRestorePrecondition { .. })
        ));
        let requests = server.finish().await?;
        assert_eq!(requests.len(), 7);
        assert!(!requests.iter().any(|r| r.starts_with("POST ")));
    }
    Ok(())
}

#[tokio::test]
async fn profiles_validate_duration_preserve_native_bytes_and_metrics_base_path() -> TestResult {
    use verysync_sidecar::CoreProfileRequest;
    let gzip = vec![
        31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 43, 174, 204, 43, 201, 72, 45, 201, 76, 214, 45, 41, 74,
        204, 43, 46, 200, 47, 42, 209, 205, 78, 173, 4, 0, 65, 73, 34, 84, 23, 0, 0, 0,
    ];
    let identity = || Reply::json(serde_json::json!({"myID":ID}));
    let metrics = format!("# HELP synthetic private {KEY}\n# TYPE synthetic gauge\nsynthetic 1\n");
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        identity(),
        identity(),
        Reply {
            body: gzip.clone(),
            ..Reply::json(serde_json::Value::Null)
        },
        identity(),
        Reply {
            body: metrics.as_bytes().to_vec(),
            ..Reply::json(serde_json::Value::Null)
        },
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    for duration_seconds in [0, 31, 255] {
        assert!(matches!(
            client
                .collect_core_profile(CoreProfileRequest::Cpu { duration_seconds })
                .await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    let profile = client
        .collect_core_profile(CoreProfileRequest::Cpu {
            duration_seconds: 1,
        })
        .await?;
    assert_eq!(profile.body_bytes(), gzip);
    assert!(!format!("{profile:?}").contains(KEY));
    assert_eq!(profile.into_body_bytes(), gzip);
    let snapshot = client.core_metrics().await?;
    assert_eq!(snapshot.native_text(), metrics);
    assert!(!format!("{snapshot:?}").contains(KEY));
    assert_eq!(snapshot.into_native_text(), metrics);
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 6);
    assert!(requests[3].starts_with("GET /prefix/rest/debug/cpuprof?duration=1s "));
    assert!(requests[5].starts_with("GET /prefix/metrics "));
    assert!(requests[5]
        .to_ascii_lowercase()
        .contains("x-api-key: synthetic-transport-key"));
    Ok(())
}

#[tokio::test]
async fn invalid_profile_success_is_unknown_once_and_metrics_html_is_not_a_snapshot() -> TestResult
{
    let identity = || Reply::json(serde_json::json!({"myID":ID}));
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        identity(),
        identity(),
        Reply {
            body: KEY.as_bytes().to_vec(),
            ..Reply::json(serde_json::Value::Null)
        },
        identity(),
        Reply {
            body: b"<html>not metrics</html>".to_vec(),
            ..Reply::json(serde_json::Value::Null)
        },
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let error = client
        .collect_core_profile(verysync_sidecar::CoreProfileRequest::Heap)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    assert!(!format!("{error:?} {error}").contains(KEY));
    assert!(matches!(
        client.core_metrics().await,
        Err(Error::InvalidResponse { .. })
    ));
    let requests = server.finish().await?;
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("GET /prefix/rest/debug/heapprof "))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn changed_profile_identity_prevents_native_profiling_request() -> TestResult {
    let server=ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":"BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB"})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client
            .collect_core_profile(verysync_sidecar::CoreProfileRequest::Heap)
            .await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert_eq!(server.finish().await?.len(), 3);
    Ok(())
}

#[test]
fn maintenance_schema_preserves_null_unknown_levels_and_redacts_private_data() -> TestResult {
    use verysync_sidecar::{CoreErrorLog, CoreLogLevel, CoreLogLevels, CoreLogSnapshot};
    let empty: CoreErrorLog =
        serde_json::from_value(serde_json::json!({"errors":null,"private":KEY}))?;
    assert!(empty.is_empty());
    for value in [
        serde_json::json!({}),
        serde_json::json!({"errors":{}}),
        serde_json::json!({"errors":[{"message":KEY}]}),
    ] {
        assert!(serde_json::from_value::<CoreErrorLog>(value).is_err());
    }
    assert!(serde_json::from_value::<CoreLogSnapshot>(serde_json::json!({})).is_err());
    let log: CoreLogSnapshot = serde_json::from_value(
        serde_json::json!({"messages":[{"when":KEY,"level":"UNMODELED","message":KEY,"unknown":KEY}],"private":KEY}),
    )?;
    let entry = &log.messages.as_ref().ok_or("entry absent")?[0];
    assert_eq!(entry.level, "UNMODELED");
    assert_eq!(entry.extra["unknown"], KEY);
    let levels: CoreLogLevels = serde_json::from_value(
        serde_json::json!({"levels":{"main":KEY},"packages":{"main":KEY},"private":KEY}),
    )?;
    assert_eq!(
        levels.levels.get("main"),
        Some(&CoreLogLevel::Other(KEY.to_owned()))
    );
    assert!(!format!(
        "{empty:?} {log:?} {entry:?} {levels:?} {:?}",
        levels.levels["main"]
    )
    .contains(KEY));
    Ok(())
}

#[tokio::test]
async fn maintenance_invalid_inputs_issue_no_requests() -> TestResult {
    use verysync_sidecar::CoreLogLevel;
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    for message in ["".to_owned(), "bad\0message".to_owned(), "x".repeat(8193)] {
        assert!(matches!(
            client.record_core_error(&message).await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    for stamp in ["", "bad\nvalue"] {
        assert!(matches!(
            client.core_log(Some(stamp)).await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    for levels in [
        std::collections::BTreeMap::new(),
        std::collections::BTreeMap::from([(
            "main".to_owned(),
            CoreLogLevel::Other("TRACE".to_owned()),
        )]),
    ] {
        assert!(matches!(
            client.set_core_log_levels(&levels).await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn maintenance_diagnostics_keep_remote_windows_paths_and_log_timestamp_query() -> TestResult {
    let stamp = "2026-11-14T04:00:00.123+08:00";
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"windows","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"databaseSize":12,"locations":{"confdir":"Q:\\private\\二 %"},"private":KEY})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"messages":null})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let diagnostic = client.core_diagnostics().await?;
    let path = &diagnostic.locations["confdir"];
    assert_eq!(path.style(), verysync_sidecar::PathStyle::Windows);
    assert_eq!(path.to_protocol()?, "Q:\\private\\二 %");
    assert!(path.local_path().is_none());
    assert_eq!(diagnostic.extra["private"], KEY);
    assert!(!format!("{diagnostic:?}").contains("Q:"));
    assert!(client.core_log(Some(stamp)).await?.messages.is_none());
    let requests = server.finish().await?;
    let expected = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("since", stamp)
        .finish();
    assert!(requests
        .last()
        .ok_or("last request absent")?
        .starts_with(&format!("GET /prefix/rest/system/log?{expected} ")));
    Ok(())
}

#[tokio::test]
async fn maintenance_nonempty_ack_or_failed_readback_is_unknown_without_retry() -> TestResult {
    for invalid_ack in [true, false] {
        let identity = || Reply::json(serde_json::json!({"myID":ID}));
        let mut replies = vec![
            Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
            identity(),
            identity(),
        ];
        if invalid_ack {
            replies.push(Reply::json(serde_json::json!({"unexpected":KEY})));
        } else {
            replies.push(Reply {
                body: Vec::new(),
                ..Reply::json(serde_json::Value::Null)
            });
            replies.push(identity());
            replies.push(Reply {
                status: 500,
                body: KEY.as_bytes().to_vec(),
                ..Reply::json(serde_json::Value::Null)
            });
        }
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let error = client
            .record_core_error("explicit synthetic message")
            .await
            .unwrap_err();
        assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
        assert!(!format!("{error:?} {error}").contains(KEY));
        let requests = server.finish().await?;
        let writes = requests
            .iter()
            .filter(|r| r.starts_with("POST "))
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), 1);
        assert!(writes[0].starts_with("POST /prefix/rest/system/error "));
        assert_eq!(
            writes[0].split("\r\n\r\n").nth(1),
            Some("explicit synthetic message")
        );
    }
    Ok(())
}

#[tokio::test]
async fn maintenance_invalid_diagnostics_are_not_successful_empty_metadata() -> TestResult {
    let identity = || Reply::json(serde_json::json!({"myID":ID}));
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        identity(),
        identity(), Reply::json(serde_json::json!({"locations":{},"private":KEY})),
        identity(), Reply::json(serde_json::json!({"databaseSize":0,"locations":{"confdir":"/bad\0path"},"private":KEY})),
        identity(), Reply::json(serde_json::json!({"databaseSize":-1,"locations":{},"private":KEY})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    for _ in 0..3 {
        let error = client.core_diagnostics().await.unwrap_err();
        assert!(matches!(error, Error::InvalidResponse { .. }));
        assert!(!format!("{error:?} {error}").contains(KEY));
    }
    assert_eq!(server.finish().await?.len(), 8);
    Ok(())
}

#[tokio::test]
async fn maintenance_level_update_is_partial_and_returns_actual_ignored_readback() -> TestResult {
    use verysync_sidecar::CoreLogLevel;
    let identity = || Reply::json(serde_json::json!({"myID":ID}));
    let levels = || {
        Reply::json(
            serde_json::json!({"levels":{"main":"INFO","other":"WARN"},"packages":{"main":"Main","other":KEY}}),
        )
    };
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        identity(),
        identity(),
        levels(),
        Reply {
            body: Vec::new(),
            ..Reply::json(serde_json::Value::Null)
        },
        identity(),
        levels(),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let update = client
        .set_core_log_levels(&std::collections::BTreeMap::from([(
            "main".to_owned(),
            CoreLogLevel::Debug,
        )]))
        .await?;
    assert!(!update.requested_levels_match);
    assert_eq!(
        update.configuration.levels.get("main"),
        Some(&CoreLogLevel::Info)
    );
    assert_eq!(
        update.configuration.levels.get("other"),
        Some(&CoreLogLevel::Warn)
    );
    assert!(!format!("{update:?}").contains(KEY));
    let requests = server.finish().await?;
    let writes = requests
        .iter()
        .filter(|r| r.starts_with("POST "))
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 1);
    assert!(writes[0].starts_with("POST /prefix/rest/system/loglevels "));
    let body: serde_json::Value =
        serde_json::from_str(writes[0].split("\r\n\r\n").nth(1).ok_or("body absent")?)?;
    assert_eq!(body, serde_json::json!({"main":"DEBUG"}));
    Ok(())
}

#[tokio::test]
async fn directory_version_restore_requires_explicit_root_and_native_items_body() -> TestResult {
    use verysync_sidecar::{
        DirectoryVersionOrder, FolderId, PathStyle, TargetPath, VersionedDirectory,
    };
    let identity = || Reply::json(serde_json::json!({"myID":ID,"nowTime":"2026-11-15T00:00:00Z"}));
    let id = FolderId::parse("directory versions")?;
    let folder = || {
        Reply::json(
            serde_json::json!({"folders":[{"id":id.as_str(),"path":"/synthetic","label":"","paused":false}]}),
        )
    };
    let version = serde_json::json!({"versionTime":"2026-11-14T00:00:00Z","modTime":"2026-11-13T00:00:00Z","size":12});
    let mut replies = vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        identity(),
    ];
    replies.extend([
        identity(),
        folder(),
        identity(),
        folder(),
        Reply::json(serde_json::json!({"root.txt":[version.clone()]})),
        identity(),
        Reply::json(serde_json::json!({})),
    ]);
    replies.extend([identity(), folder()]);
    for listing in [
        serde_json::json!({"nested":[]}),
        serde_json::json!({"nested/二 %":[]}),
        serde_json::json!({"nested/二 %/file.txt":[version]}),
    ] {
        replies.extend([identity(), folder(), Reply::json(listing)]);
    }
    replies.extend([
        identity(),
        Reply::json(serde_json::json!({"native-path":KEY})),
    ]);
    let server = ScriptedServer::start(replies).await?;
    let client = Client::connect(server.options()?).await?;
    for path in [".", "..", "/absolute", "nested/../escape"] {
        let scope = VersionedDirectory::Path(TargetPath::remote(PathStyle::Unix, path)?);
        assert!(matches!(
            client
                .restore_directory_versions(&id, &scope, DirectoryVersionOrder::Oldest)
                .await,
            Err(Error::InvalidPath { .. })
        ));
    }
    let root = client
        .restore_directory_versions(
            &id,
            &VersionedDirectory::FolderRoot,
            DirectoryVersionOrder::Oldest,
        )
        .await?;
    assert_eq!(root.error_count(), 0);
    let scope = VersionedDirectory::Path(TargetPath::remote(PathStyle::Unix, "nested/二 %")?);
    assert!(!format!("{scope:?}").contains("nested"));
    let result = client
        .restore_directory_versions(&id, &scope, DirectoryVersionOrder::Newest)
        .await?;
    assert_eq!(result.error_count(), 1);
    assert!(!format!("{result:?}").contains(KEY));
    let requests = server.finish().await?;
    let writes = requests
        .iter()
        .filter(|r| r.starts_with("POST "))
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 2);
    let mut bodies = Vec::new();
    for request in &writes {
        let text = request.split("\r\n\r\n").nth(1).ok_or("body")?;
        bodies.push(serde_json::from_str::<serde_json::Value>(text)?);
    }
    assert!(writes
        .iter()
        .all(|r| r
            .starts_with("POST /prefix/rest/folder/versions/restore?folder=directory+versions ")));
    assert_eq!(
        bodies[0],
        serde_json::json!({"items":[{"path":".","action":"oldest"}]})
    );
    assert_eq!(
        bodies[1],
        serde_json::json!({"items":[{"path":"nested/二 %","action":"latest"}]})
    );
    Ok(())
}

#[tokio::test]
async fn audit_settings_report_ignored_enable_and_preserve_null_pages() -> TestResult {
    use verysync_sidecar::AuditHistorySettings;
    let identity = || Reply::json(serde_json::json!({"myID":ID}));
    let server=ScriptedServer::start(vec![Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),identity(),identity(),Reply::json(serde_json::json!({})),Reply::json(serde_json::json!({"folderHistoryEnabled":false,"folderHistoryMaxRecords":100000,"private":KEY})),identity(),Reply::json(serde_json::json!({"data":null,"error":null,"total":0}))]).await?;
    let client = Client::connect(server.options()?).await?;
    let update = client
        .set_audit_history_settings(AuditHistorySettings {
            enabled: true,
            maximum_records: 100000,
        })
        .await?;
    assert!(!update.requested_fields_match && !update.configuration.enabled);
    for (page, size) in [(0, 10), (1, 0), (1, 1001)] {
        assert!(matches!(
            client.audit_history(page, size).await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    let page = client.audit_history(2, 10).await?;
    assert!(page.records.is_none() && page.error.is_none() && page.total == 0);
    assert!(!format!("{page:?} {update:?}").contains(KEY));
    let requests = server.finish().await?;
    assert!(requests
        .last()
        .is_some_and(|r| r.starts_with("GET /prefix/rest/history/list?page=2&perpage=10 ")));
    let patch = requests
        .iter()
        .find(|r| r.starts_with("PATCH "))
        .ok_or("patch")?;
    let body: serde_json::Value =
        serde_json::from_str(patch.split("\r\n\r\n").nth(1).ok_or("body")?)?;
    assert_eq!(
        body,
        serde_json::json!({"folderHistoryEnabled":true,"folderHistoryMaxRecords":100000})
    );
    Ok(())
}

#[tokio::test]
async fn audit_reset_get_requires_identity_explicit_error_field_and_no_retry() -> TestResult {
    for reply in [
        serde_json::json!({"error":null}),
        serde_json::json!({}),
        serde_json::json!({"error":KEY}),
    ] {
        let valid = reply.get("error").is_some_and(serde_json::Value::is_null);
        let server = ScriptedServer::start(vec![
            Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
            Reply::json(serde_json::json!({"myID":ID})),
            Reply::json(serde_json::json!({"myID":ID})),
            Reply::json(reply),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let result = client.reset_audit_history().await;
        assert_eq!(result.is_ok(), valid);
        if let Err(error) = result {
            assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
            assert!(!format!("{error:?} {error}").contains(KEY));
        }
        assert_eq!(
            server
                .finish()
                .await?
                .iter()
                .filter(|r| r.starts_with("GET /prefix/rest/history/reset "))
                .count(),
            1
        );
    }
    Ok(())
}

#[tokio::test]
async fn version_policy_preserves_unknown_archive_settings_and_reports_stale_readback() -> TestResult
{
    use verysync_sidecar::{FolderId, FolderVersioningPolicy};
    let id = FolderId::parse("version folder %")?;
    let versioning = serde_json::json!({"type":"simple","params":{"keep":"9","cleanoutDays":"7","vendor":KEY},"cleanupIntervalS":3600,"fsPath":KEY,"fsType":"basic","vendorSecret":KEY});
    let folder = |v: serde_json::Value| {
        Reply::json(
            serde_json::json!({"folders":[{"id":id.as_str(),"path":"/synthetic","label":"","paused":false,"versioning":v}]}),
        )
    };
    let identity = || Reply::json(serde_json::json!({"myID":ID}));
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        identity(),
        identity(),
        folder(versioning.clone()),
        Reply::json(serde_json::json!({})),
        folder(versioning),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let result = client
        .set_folder_versioning(
            &id,
            FolderVersioningPolicy::Trashcan {
                cleanout_days: 0,
                cleanup_interval_seconds: 7200,
            },
        )
        .await?;
    assert!(!result.requested_fields_match);
    assert_eq!(result.configuration.filesystem_path, KEY);
    assert!(!format!("{result:?}").contains(KEY));
    assert!(matches!(
        client
            .set_folder_versioning(
                &id,
                FolderVersioningPolicy::Simple {
                    keep: 0,
                    cleanout_days: 0,
                    cleanup_interval_seconds: 3600
                }
            )
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    let requests = server.finish().await?;
    let patches = requests
        .iter()
        .filter(|r| r.starts_with("PATCH "))
        .collect::<Vec<_>>();
    assert_eq!(patches.len(), 1);
    let body: serde_json::Value =
        serde_json::from_str(patches[0].split("\r\n\r\n").nth(1).ok_or("body")?)?;
    assert_eq!(body["versioning"]["type"], "trashcan");
    assert_eq!(body["versioning"]["params"]["keep"], "9");
    assert_eq!(body["versioning"]["params"]["cleanoutDays"], "0");
    assert_eq!(body["versioning"]["params"]["vendor"], KEY);
    assert_eq!(body["versioning"]["fsPath"], KEY);
    assert_eq!(body["versioning"]["vendorSecret"], KEY);
    assert_eq!(body["versioning"]["cleanupIntervalS"], 7200);
    Ok(())
}

#[tokio::test]
async fn extended_versioners_and_remote_archive_location_keep_unknowns_and_unknown_outcomes(
) -> TestResult {
    use verysync_sidecar::{
        ExternalVersioningCommand, FolderId, FolderVersioningPolicy, PathStyle, TargetPath,
        VersionArchiveLocation,
    };
    let id = FolderId::parse("archive-policy")?;
    let identity = || Reply::json(serde_json::json!({"myID":ID}));
    let folder = |versioning| {
        Reply::json(
            serde_json::json!({"folders":[{"id":id.as_str(),"label":"","path":"C:\\data","paused":false,"versioning":versioning}]}),
        )
    };
    let before = serde_json::json!({"type":"simple","params":{"keep":"9","native":KEY},"cleanupIntervalS":3600,"fsPath":"C:\\old","fsType":"basic","nativeSecret":KEY});
    let mut staggered = before.clone();
    staggered["type"] = "staggered".into();
    staggered["params"]["maxAge"] = "0".into();
    staggered["cleanupIntervalS"] = 7.into();
    let command = format!("\"target-program\" \"%FOLDER_PATH%\" \"%FILE_PATH%\" {KEY}");
    let mut external = staggered.clone();
    external["type"] = "external".into();
    external["params"]["command"] = command.clone().into();
    let archive = "\\\\owned-host\\share\\档案 %.bak";
    let mut located = external.clone();
    located["fsPath"] = archive.into();
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"windows","arch":"amd64"})),
        identity(),
        identity(),
        folder(before),
        Reply::json(serde_json::json!({})),
        folder(staggered.clone()),
        identity(),
        folder(staggered),
        Reply::json(serde_json::json!({})),
        folder(external.clone()),
        identity(),
        folder(external),
        Reply::json(serde_json::json!({})),
        folder(located.clone()),
        identity(),
        folder(located),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"folders":[]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let update = client
        .set_folder_versioning(
            &id,
            FolderVersioningPolicy::Staggered {
                max_age_seconds: 0,
                cleanup_interval_seconds: 7,
            },
        )
        .await?;
    assert!(update.requested_fields_match);
    let native = ExternalVersioningCommand::new(command.clone())?;
    assert_eq!(native.native_command(), command);
    assert!(!format!("{native:?}").contains(KEY));
    let update = client
        .set_folder_versioning(&id, FolderVersioningPolicy::External { command: native })
        .await?;
    assert!(update.requested_fields_match);
    let location =
        VersionArchiveLocation::BasicDirectory(TargetPath::remote(PathStyle::Windows, archive)?);
    let update = client.set_version_archive_location(&id, &location).await?;
    assert!(update.requested_fields_match);
    assert!(!format!("{update:?} {location:?}").contains(KEY));
    assert!(matches!(
        client
            .set_version_archive_location(&id, &VersionArchiveLocation::FolderDefault)
            .await,
        Err(Error::MutationOutcomeUnknown { .. })
    ));
    assert!(matches!(
        client
            .set_version_archive_location(
                &id,
                &VersionArchiveLocation::BasicDirectory(TargetPath::remote(
                    PathStyle::Unix,
                    "/wrong-style"
                )?)
            )
            .await,
        Err(Error::InvalidPath { .. })
    ));
    for text in [
        "".to_owned(),
        "   ".to_owned(),
        "bad\ncommand".to_owned(),
        "x".repeat(8193),
    ] {
        assert!(ExternalVersioningCommand::new(text).is_err());
    }
    assert!(client
        .set_folder_versioning(
            &id,
            FolderVersioningPolicy::Staggered {
                max_age_seconds: 0,
                cleanup_interval_seconds: 0
            }
        )
        .await
        .is_err());
    let requests = server.finish().await?;
    let writes = requests
        .iter()
        .filter(|r| r.starts_with("PATCH "))
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 4);
    for (index, request) in writes.iter().enumerate() {
        let body: serde_json::Value =
            serde_json::from_str(request.split("\r\n\r\n").nth(1).ok_or("body")?)?;
        assert_eq!(body["versioning"]["params"]["keep"], "9");
        assert_eq!(body["versioning"]["params"]["native"], KEY);
        assert_eq!(body["versioning"]["nativeSecret"], KEY);
        match index {
            0 => {
                assert_eq!(body["versioning"]["params"]["maxAge"], "0");
                assert_eq!(body["versioning"]["cleanupIntervalS"], 7);
            }
            1 => assert_eq!(body["versioning"]["params"]["command"], command),
            2 => assert_eq!(body["versioning"]["fsPath"], archive),
            3 => assert_eq!(body["versioning"]["fsPath"], ""),
            _ => unreachable!(),
        }
    }
    Ok(())
}

#[tokio::test]
async fn exact_version_restore_encodes_native_map_and_retains_partial_errors() -> TestResult {
    use verysync_sidecar::{FileVersionRestore, FolderId, PathStyle, TargetPath};
    let identity = || Reply::json(serde_json::json!({"myID":ID,"nowTime":"2026-11-15T00:00:00Z"}));
    let id = FolderId::parse("versions 中文")?;
    let server=ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),identity(),identity(),
        Reply::json(serde_json::json!({"folders":[{"id":id.as_str(),"label":"","path":"/synthetic","paused":false}]})),
        identity(),
        Reply::json(serde_json::json!({"nested/a 二 %.txt":null,"other.txt":KEY})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let timestamp = "2026-11-14T02:20:15+08:00";
    let item = FileVersionRestore::new(
        TargetPath::remote(PathStyle::Unix, "nested/a 二 %.txt")?,
        timestamp,
    )?;
    assert!(!format!("{item:?}").contains("nested"));
    for items in [vec![], vec![item.clone(), item.clone()]] {
        assert!(matches!(
            client.restore_file_versions(&id, &items).await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    let bad =
        FileVersionRestore::new(TargetPath::remote(PathStyle::Unix, "../escape")?, timestamp)?;
    assert!(matches!(
        client.restore_file_versions(&id, &[bad]).await,
        Err(Error::InvalidPath { .. })
    ));
    let result = client.restore_file_versions(&id, &[item]).await?;
    assert_eq!(result.error_count(), 1);
    assert_eq!(result.0["other.txt"].as_deref(), Some(KEY));
    assert!(!format!("{result:?}").contains(KEY));
    let requests = server.finish().await?;
    let posts = requests
        .iter()
        .filter(|r| r.starts_with("POST "))
        .collect::<Vec<_>>();
    assert_eq!(posts.len(), 1);
    assert!(posts[0]
        .starts_with("POST /prefix/rest/folder/versions?folder=versions+%E4%B8%AD%E6%96%87 "));
    let body: serde_json::Value =
        serde_json::from_str(posts[0].split("\r\n\r\n").nth(1).ok_or("body")?)?;
    assert_eq!(body, serde_json::json!({"nested/a 二 %.txt":timestamp}));
    Ok(())
}

#[tokio::test]
async fn malformed_version_restore_ack_is_unknown_and_is_never_retried() -> TestResult {
    use verysync_sidecar::{FileVersionRestore, FolderId, PathStyle, TargetPath};
    let identity = || Reply::json(serde_json::json!({"myID":ID,"nowTime":"2026-11-15T00:00:00Z"}));
    let id = FolderId::parse("versioned")?;
    let server=ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),identity(),identity(),
        Reply::json(serde_json::json!({"folders":[{"id":id.as_str(),"label":"","path":"/synthetic","paused":false}]})),
        identity(),
        Reply::json(serde_json::json!([KEY])),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let item = FileVersionRestore::new(
        TargetPath::remote(PathStyle::Unix, "version.txt")?,
        "2026-11-14T00:00:00Z",
    )?;
    let error = client
        .restore_file_versions(&id, &[item])
        .await
        .unwrap_err();
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    assert!(!format!("{error:?} {error}").contains(KEY));
    assert_eq!(
        server
            .finish()
            .await?
            .iter()
            .filter(|r| r.starts_with("POST "))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn version_prefix_null_is_empty_while_malformed_shapes_and_timestamps_are_rejected(
) -> TestResult {
    use verysync_sidecar::{
        ArchivedFileVersion, FileVersionRestore, FolderId, FolderVersionHistory, PathStyle,
        TargetPath,
    };
    assert!(
        serde_json::from_value::<FolderVersionHistory>(serde_json::Value::Null)?
            .0
            .is_empty()
    );
    assert!(serde_json::from_value::<FolderVersionHistory>(serde_json::json!([KEY])).is_err());
    assert!(serde_json::from_value::<ArchivedFileVersion>(
        serde_json::json!({"versionTime":"t","modTime":"m","size":-1})
    )
    .is_err());
    assert!(
        FileVersionRestore::new(TargetPath::remote(PathStyle::Unix, "file")?, "bad\nvalue")
            .is_err()
    );
    let identity = || Reply::json(serde_json::json!({"myID":ID}));
    let id = FolderId::parse("versioned")?;
    let server=ScriptedServer::start(vec![Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),identity(),identity(),Reply::json(serde_json::json!({"folders":[{"id":id.as_str(),"path":"/synthetic","label":"","paused":false}]})),Reply::json(serde_json::Value::Null)]).await?;
    let client = Client::connect(server.options()?).await?;
    assert!(client
        .folder_versions(&id, Some(&TargetPath::remote(PathStyle::Unix, "a 二%")?))
        .await?
        .0
        .is_empty());
    let requests = server.finish().await?;
    assert!(requests.last().is_some_and(|r| r.starts_with(
        "GET /prefix/rest/folder/versions/browse?folder=versioned&prefix=a+%E4%BA%8C%25 "
    )));
    Ok(())
}

#[tokio::test]
async fn native_preview_preserves_binary_media_and_rejects_empty_or_non_image_success() -> TestResult
{
    use verysync_sidecar::{PathStyle, ResourcePath, ResourceVolumeId};
    let reply = |body: Vec<u8>, headers: String| Reply {
        status: 200,
        body,
        headers,
        delay: Duration::ZERO,
    };
    let image = b"\x89PNG\r\n\x1a\nsynthetic-contract-bytes".to_vec();
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        reply(
            image.clone(),
            format!("Content-Type: image/png; private={KEY}\r\n"),
        ),
        Reply::json(serde_json::json!({"myID":ID})),
        reply(Vec::new(), "Content-Type: image/png\r\n".into()),
        Reply::json(serde_json::json!({"myID":ID})),
        reply(
            KEY.as_bytes().to_vec(),
            "Content-Type: text/plain\r\n".into(),
        ),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let path = ResourcePath::root(ResourceVolumeId::parse("image-volume")?, PathStyle::Unix)
        .child("preview %.png")?;
    let result = client.resource_thumbnail(&path).await?;
    assert_eq!(result.body_bytes(), image);
    assert!(result.media_type().contains(KEY));
    assert!(!format!("{result:?}").contains(KEY));
    assert!(matches!(
        client.resource_thumbnail(&path).await,
        Err(Error::InvalidResponse { .. })
    ));
    let error = client.resource_thumbnail(&path).await.unwrap_err();
    assert!(!format!("{error:?} {error}").contains(KEY));
    assert!(matches!(error, Error::InvalidResponse { .. }));
    let requests = server.finish().await?;
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with(
                "GET /prefix/rest/f/api/preview/thumb/image-volume/preview%20%25.png?inline=true "
            ))
            .count(),
        3
    );
    Ok(())
}

#[tokio::test]
async fn unix_newline_resource_name_is_percent_encoded_without_normalization() -> TestResult {
    use verysync_sidecar::{PathStyle, ResourcePath, ResourceVolumeId};
    let server=ScriptedServer::start(vec![Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),Reply::json(serde_json::json!({"myID":ID})),Reply::json(serde_json::json!({"myID":ID})),Reply::json(serde_json::json!({"path":"line\nbreak.txt","name":"line\nbreak.txt","size":4,"mode":420,"modified":"opaque","isDir":false}))]).await?;
    let client = Client::connect(server.options()?).await?;
    let path = ResourcePath::root(ResourceVolumeId::parse("mount")?, PathStyle::Unix)
        .child("line\nbreak.txt")?;
    client.resource_info(&path).await?;
    assert!(server
        .finish()
        .await?
        .last()
        .unwrap()
        .starts_with("GET /prefix/rest/f/api/resources/mount/line%0Abreak.txt "));
    Ok(())
}

#[tokio::test]
async fn known_provider_release_absence_is_typed_without_retry_or_erasing_other_failures(
) -> TestResult {
    let missing = b"couldn't find a release to download\n".to_vec();
    let http = |body: Vec<u8>| Reply {
        status: 500,
        body,
        headers: String::new(),
        delay: Duration::ZERO,
    };
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"windows","arch":"arm64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        http(missing.clone()),
        Reply::json(serde_json::json!({"myID":ID})),
        http(missing.clone()),
        Reply::json(serde_json::json!({"myID":ID})),
        http(format!("couldn't find a release to download but unknown: {KEY}").into_bytes()),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(
        matches!(client.check_kernel_upgrade().await,Err(Error::UpgradeReleaseUnavailable{response})if response.body_bytes()==missing)
    );
    assert!(
        matches!(client.request_server_selected_upgrade().await,Err(Error::UpgradeReleaseUnavailable{response})if response.status()==500)
    );
    let error = client.request_server_selected_upgrade().await.unwrap_err();
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    assert!(!format!("{error:?} {error}").contains(KEY));
    assert_eq!(
        server
            .finish()
            .await?
            .iter()
            .filter(|r| r.starts_with("POST "))
            .count(),
        2
    );
    Ok(())
}

#[tokio::test]
async fn resource_paths_are_encoded_once_and_missing_checksums_keep_private_diagnostics(
) -> TestResult {
    use verysync_sidecar::{PathStyle, ResourceChecksum, ResourcePath, ResourceVolumeId};
    let node = serde_json::json!({"path":"nested/二 ?%2e%2e.txt","name":"二 ?%2e%2e.txt","size":4,"mode":420,"modified":"unparsed-private-time","isDir":false,"checksums":{"sha256":"bad"},"private":KEY});
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(node),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let path = ResourcePath::root(ResourceVolumeId::parse("mount ?%")?, PathStyle::Unix)
        .child("nested")?
        .child("二 ?%2e%2e.txt")?;
    let error = client
        .resource_checksum(&path, ResourceChecksum::Sha256)
        .await
        .unwrap_err();
    assert!(!format!("{error:?} {error}").contains(KEY));
    assert!(
        matches!(error,Error::InvalidResponse{response,..}if response.body_bytes().windows(KEY.len()).any(|s|s==KEY.as_bytes()))
    );
    let requests = server.finish().await?;
    assert!(requests.last().unwrap().starts_with("GET /prefix/rest/f/api/resources/mount%20%3F%25/nested/%E4%BA%8C%20%3F%252e%252e.txt?checksum=sha256 "));
    Ok(())
}

#[tokio::test]
async fn upgrade_metadata_requires_flags_and_redacts_unknown_values() -> TestResult {
    let mut replies = vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
    ];
    for response in [
        serde_json::json!({"running":"v2.33.2","latest":"v2.33.2","newer":false}),
        serde_json::json!({"running":"","latest":"v2.33.2","newer":false,"majorNewer":false}),
        serde_json::json!({"running":"v2.33.2","latest":"v2.33.2","newer":false,"majorNewer":false,"private":KEY}),
    ] {
        replies.push(Reply::json(serde_json::json!({"myID":ID})));
        replies.push(Reply::json(response));
    }
    let server = ScriptedServer::start(replies).await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client.check_kernel_upgrade().await,
        Err(Error::InvalidResponse { .. })
    ));
    assert!(matches!(
        client.check_kernel_upgrade().await,
        Err(Error::InvalidResponse { .. })
    ));
    let result = client.check_kernel_upgrade().await?;
    assert_eq!(result.extra["private"], KEY);
    assert!(!result.newer && !result.major_newer && !format!("{result:?}").contains(KEY));
    let requests = server.finish().await?;
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("GET /prefix/rest/system/upgrade "))
            .count(),
        3
    );
    Ok(())
}
#[tokio::test]
async fn kernel_upgrade_unknown_ack_is_not_retried_and_fixed_ack_is_recognized() -> TestResult {
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"ok":KEY})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"ok":"restarting"})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let error = client.request_server_selected_upgrade().await.unwrap_err();
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    assert!(!format!("{error:?} {error}").contains(KEY));
    client.request_server_selected_upgrade().await?;
    let requests = server.finish().await?;
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("POST /prefix/rest/system/upgrade "))
            .count(),
        2
    );
    Ok(())
}
#[tokio::test]
async fn invalid_fixed_archive_is_rejected_before_any_modifying_or_identity_request() -> TestResult
{
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let asset = verysync_sidecar::official_programs()?
        .into_iter()
        .next()
        .ok_or("fixed asset missing")?;
    let root = tempfile::tempdir()?;
    let path = root.path().join("bad-archive");
    let file = std::fs::File::create(&path)?;
    file.set_len(asset.archive_bytes())?;
    drop(file);
    assert!(matches!(
        client.upload_kernel_upgrade(&path, &asset).await,
        Err(Error::ProgramRejected { .. })
    ));
    assert!(matches!(
        client
            .upload_kernel_upgrade("relative-archive", &asset)
            .await,
        Err(Error::InvalidPath { .. })
    ));
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn recovery_nonempty_ack_is_unknown_without_retry_and_pause_is_not_resumed() -> TestResult {
    use verysync_sidecar::FolderId;
    let folder = serde_json::json!({"id":"recovery","label":"synthetic","path":"/synthetic","paused":false,"type":"sendonly"});
    let mut paused = folder.clone();
    paused["paused"] = true.into();
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[folder]})),
        Reply::json(serde_json::json!({"unexpected_private_body":KEY})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[paused]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let folder = FolderId::parse("recovery")?;
    let error = client
        .request_override_remote_changes(&folder)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    assert!(!format!("{error:?} {error}").contains(KEY));
    assert!(matches!(
        client.request_override_remote_changes(&folder).await,
        Err(Error::FolderPaused { .. })
    ));
    let requests = server.finish().await?;
    let writes: Vec<_> = requests
        .iter()
        .filter(|r| r.starts_with("POST ") || r.starts_with("PATCH "))
        .collect();
    assert_eq!(writes.len(), 1);
    assert!(writes[0].starts_with("POST /prefix/rest/db/override?folder=recovery "));
    Ok(())
}

#[tokio::test]
async fn recovery_guards_modes_and_marker_body_failure_is_not_success() -> TestResult {
    use verysync_sidecar::FolderId;
    let folder = serde_json::json!({"id":"recovery ?%","label":"synthetic","path":"/synthetic","paused":false,"type":"receiveonly"});
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[folder.clone()]})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[folder.clone()]})),
        Reply {
            status: 200,
            body: Vec::new(),
            headers: String::new(),
            delay: Duration::ZERO,
        },
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[folder]})),
        Reply::json(serde_json::json!({"success":false,"error":KEY})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let folder = FolderId::parse("recovery ?%")?;
    assert!(matches!(
        client.request_override_remote_changes(&folder).await,
        Err(Error::InvalidConfiguration { .. })
    ));
    client.request_revert_local_changes(&folder).await?;
    let error = client.request_marker_repair(&folder).await.unwrap_err();
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    assert!(!format!("{error:?} {error}").contains(KEY));
    let requests = server.finish().await?;
    let posts: Vec<_> = requests.iter().filter(|r| r.starts_with("POST ")).collect();
    assert_eq!(posts.len(), 2);
    assert!(posts[0].starts_with("POST /prefix/rest/db/revert?folder=recovery+%3F%25 "));
    assert!(posts[1].starts_with("POST /prefix/rest/folder/marker/repair?folder=recovery+%3F%25 "));
    Ok(())
}

#[tokio::test]
async fn selective_browse_presence_flags_opaque_cursor_and_destructive_intent_are_exact(
) -> TestResult {
    use verysync_sidecar::{
        FolderId, PathStyle, SelectiveAction, SelectiveBrowseOptions, SelectiveScope,
        SelectiveSearchOptions, TargetPath,
    };
    let folder =
        serde_json::json!({"id":"scope ?%","label":"synthetic","path":"/synthetic","paused":false});
    let node = serde_json::json!({"name":"private-name","isdir":false,"size":15,"selectived":false,"exists":false});
    let mut replies = vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
    ];
    for response in [
        serde_json::json!({"private-name":node}),
        serde_json::json!({"search":true,"items":[],"hasMore":true,"nextCursor":format!("opaque /?% {KEY}")}),
        serde_json::json!({"search":false,"items":[],"hasMore":false}),
        serde_json::json!({"code":3000,"error":KEY}),
        serde_json::json!({}),
    ] {
        replies.push(Reply::json(serde_json::json!({"myID":ID})));
        replies.push(Reply::json(serde_json::json!({"folders":[folder.clone()]})));
        replies.push(Reply::json(response));
    }
    let server = ScriptedServer::start(replies).await?;
    let client = Client::connect(server.options()?).await?;
    let folder = FolderId::parse("scope ?%")?;
    let tree = client
        .browse_selective(
            &folder,
            &SelectiveBrowseOptions::new(SelectiveScope::FolderRoot).levels(2),
        )
        .await?;
    assert_eq!(tree.entries.len(), 1);
    let options = SelectiveSearchOptions::new(format!("needle {KEY}"))?.limit(1);
    let first = client.search_selective(&folder, &options).await?;
    let error = client
        .search_selective(&folder, &options.after_cursor(first.next_cursor.unwrap()))
        .await
        .unwrap_err();
    assert!(matches!(error, Error::InvalidResponse { .. }));
    assert!(!format!("{error:?} {error}").contains(KEY));
    let target = SelectiveScope::Path(TargetPath::remote(PathStyle::Unix, "nested/二 ?%.bin")?);
    let error = client
        .request_selection(&folder, &target, SelectiveAction::RemoveFromAll)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::LicenseRequired { code: 3000, .. }));
    client
        .browse_selective(
            &folder,
            &SelectiveBrowseOptions::new(SelectiveScope::FolderRoot).directories_only(true),
        )
        .await?;
    for options in [
        SelectiveBrowseOptions::new(SelectiveScope::FolderRoot).levels(0),
        SelectiveBrowseOptions::new(SelectiveScope::Path(TargetPath::remote(
            PathStyle::Unix,
            "../escape",
        )?)),
    ] {
        assert!(client.browse_selective(&folder, &options).await.is_err());
    }
    let requests = server.finish().await?;
    let targets: Vec<_> = requests
        .iter()
        .filter(|r| r.contains("/db/browse/selective?") || r.starts_with("POST "))
        .map(|r| {
            url::Url::parse(&format!(
                "http://synthetic.invalid{}",
                r.split_whitespace().nth(1).unwrap()
            ))
            .unwrap()
        })
        .collect();
    assert_eq!(targets.len(), 5);
    assert!(!targets[0].query_pairs().any(|(k, _)| k == "dirsonly"));
    assert!(targets[2]
        .query_pairs()
        .any(|(k, v)| k == "cursor" && v == format!("opaque /?% {KEY}")));
    let change: Vec<_> = targets[3].query_pairs().collect();
    assert_eq!(
        change,
        vec![
            ("folder".into(), "scope ?%".into()),
            ("path".into(), "nested/二 ?%.bin".into()),
            ("selected".into(), "false".into()),
            ("removefromall".into(), "true".into())
        ]
    );
    assert!(targets[4]
        .query_pairs()
        .any(|(k, v)| k == "dirsonly" && v == "true"));
    Ok(())
}

#[tokio::test]
async fn known_license_envelope_is_not_http_success_and_raw_response_remains_explicit() -> TestResult
{
    use verysync_sidecar::{FolderId, RawMethod, RawRequest, RequestEffect};
    let folder =
        serde_json::json!({"id":"scope","label":"synthetic","path":"/synthetic","paused":false});
    let license = serde_json::json!({"code":3000,"error":KEY});
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[folder]})),
        Reply::json(license.clone()),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(license.clone()),
        Reply::json(license),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    for error in [
        client
            .request_scan(&FolderId::parse("scope")?)
            .await
            .unwrap_err(),
        client.bandwidth_configuration().await.unwrap_err(),
    ] {
        assert!(!format!("{error:?} {error}").contains(KEY));
        let Error::LicenseRequired { code, response } = error else {
            return Err("expected known license rejection".into());
        };
        assert_eq!(code, 3000);
        assert_eq!(response.status(), 200);
        assert!(std::str::from_utf8(response.body_bytes())?.contains(KEY));
    }
    let raw = client
        .raw_request(&RawRequest::new(
            RawMethod::Get,
            ["rest", "synthetic"],
            RequestEffect::ReadOnly,
        )?)
        .await?;
    assert_eq!(raw.status(), 200);
    assert!(std::str::from_utf8(raw.body_bytes())?.contains(KEY));
    let requests = server.finish().await?;
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("POST ")).count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn scheduling_partial_bandwidth_and_priority_scope_preserve_protocol_and_failures(
) -> TestResult {
    use verysync_sidecar::{
        BandwidthPatch, FolderId, FolderPullOrder, ListPage, PathStyle, TargetPath,
    };
    let folder = serde_json::json!({"id":"scope /?%","label":"synthetic","path":"/synthetic","paused":false,"order":"alphabetic","secret":KEY});
    let options = serde_json::json!({"maxSendKbps":0,"maxRecvKbps":0,"limitBandwidthInLan":false,"secret":KEY});
    let server=ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),Reply::json(serde_json::json!({})),Reply::json(serde_json::json!({"myID":ID})),Reply::json(serde_json::json!({"options":options})),
        Reply::json(serde_json::json!({"myID":ID})),Reply::json(serde_json::json!({"folders":[folder.clone()]})),Reply::json(serde_json::json!({})),Reply::json(serde_json::json!({"myID":ID})),Reply::json(serde_json::json!({"folders":[folder.clone()]})),
        Reply::json(serde_json::json!({"myID":ID})),Reply::json(serde_json::json!({"folders":[folder.clone()]})),Reply::json(serde_json::json!({"progress":[],"queued":[{"name":"last ?%.bin","type":"FILE_INFO_TYPE_FILE","size":1}],"rest":[],"page":2,"perpage":3})),
        Reply::json(serde_json::json!({"myID":ID})),Reply::json(serde_json::json!({"folders":[folder]})),Reply::json(serde_json::json!({"queued":[]})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let folder = FolderId::parse("scope /?%")?;
    let result = client
        .update_bandwidth_configuration(&BandwidthPatch::default().max_send_kib_per_second(64))
        .await?;
    assert!(!result.requested_fields_match && result.configuration.max_send_kib_per_second == 0);
    assert!(!format!("{result:?}").contains(KEY));
    let order = client
        .set_folder_pull_order(&folder, &FolderPullOrder::LargestFirst)
        .await?;
    assert!(!order.requested_order_match);
    assert_eq!(order.configuration.extra["secret"], KEY);
    assert!(!format!("{order:?}").contains(KEY));
    assert!(client
        .set_folder_pull_order(&folder, &FolderPullOrder::Unknown(KEY.into()))
        .await
        .is_err());
    for patch in [
        BandwidthPatch::default(),
        BandwidthPatch::default().max_receive_kib_per_second(u32::MAX),
    ] {
        assert!(client.update_bandwidth_configuration(&patch).await.is_err());
    }
    let file = TargetPath::remote(PathStyle::Unix, "last ?%.bin")?;
    let page = ListPage::new(2, 3)?;
    let need = client.prioritize_file(&folder, &file, page).await?;
    assert_eq!(need.queued[0].name, "last ?%.bin");
    let error = client
        .prioritize_file(&folder, &file, page)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    let requests = server.finish().await?;
    let writes: Vec<_> = requests
        .iter()
        .filter(|r| r.starts_with("POST ") || r.starts_with("PATCH "))
        .collect();
    assert_eq!(writes.len(), 4);
    assert!(writes[0].starts_with("PATCH /prefix/rest/config/options "));
    let body: serde_json::Value =
        serde_json::from_str(writes[0].split_once("\r\n\r\n").unwrap().1)?;
    assert_eq!(body, serde_json::json!({"maxSendKbps":64}));
    let target = writes[2]
        .split_whitespace()
        .nth(1)
        .ok_or("priority target missing")?;
    let url = url::Url::parse(&format!("http://synthetic.invalid{target}"))?;
    assert_eq!(
        url.query_pairs().collect::<Vec<_>>(),
        vec![
            ("folder".into(), "scope /?%".into()),
            ("file".into(), "last ?%.bin".into()),
            ("page".into(), "2".into()),
            ("perpage".into(), "3".into())
        ]
    );
    Ok(())
}

#[tokio::test]
async fn priority_refuses_paused_or_changed_targets_and_device_rates_do_not_overflow() -> TestResult
{
    use verysync_sidecar::{DeviceId, DevicePatch, FolderId, ListPage, TargetPath};
    let remote = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    let server=ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),Reply::json(serde_json::json!({"folders":[{"id":"scope","label":"synthetic","path":"/synthetic","paused":true}]})),
        Reply::json(serde_json::json!({"myID":remote})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let file = TargetPath::remote(verysync_sidecar::PathStyle::Unix, "relative.bin")?;
    let folder = FolderId::parse("scope")?;
    let page = ListPage::new(1, 10)?;
    assert!(matches!(
        client.prioritize_file(&folder, &file, page).await,
        Err(Error::FolderPaused { .. })
    ));
    assert!(matches!(
        client.prioritize_file(&folder, &file, page).await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert!(client
        .update_device(
            &DeviceId::parse(remote)?,
            &DevicePatch::default().max_send_kib_per_second(u32::MAX)
        )
        .await
        .is_err());
    let requests = server.finish().await?;
    assert!(requests
        .iter()
        .all(|r| !r.starts_with("POST ") && !r.starts_with("PATCH ")));
    Ok(())
}

#[tokio::test]
async fn ignore_http_success_parse_rejection_is_typed_and_get_preserves_stored_error() -> TestResult
{
    use verysync_sidecar::{FolderId, IgnorePatterns};
    let folder = serde_json::json!({"id":"ignore ?%","label":"synthetic","path":"/synthetic","paused":false});
    let invalid = serde_json::json!({"ignore":[format!("[{KEY}")],"expanded":[],"error":format!("private parser {KEY}"),"future":KEY});
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[folder.clone()]})),
        Reply::json(invalid.clone()),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[folder]})),
        Reply::json(invalid),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let folder = FolderId::parse("ignore ?%")?;
    let rules = IgnorePatterns::new(vec![format!("[{KEY}")])?;
    let error = client
        .set_ignore_patterns(&folder, &rules)
        .await
        .unwrap_err();
    assert!(!format!("{error:?} {error}").contains(KEY));
    let Error::IgnorePatternsRejected { snapshot } = error else {
        return Err("expected parse rejection".into());
    };
    assert_eq!(snapshot.patterns.as_deref(), Some(rules.patterns()));
    assert!(snapshot.parse_error.as_ref().unwrap().contains(KEY));
    let actual = client.ignore_patterns(&folder).await?;
    assert_eq!(actual.patterns.as_deref(), Some(rules.patterns()));
    assert!(actual.parse_error.is_some());
    assert!(!format!("{actual:?}").contains(KEY));
    let requests = server.finish().await?;
    let posts: Vec<_> = requests.iter().filter(|r| r.starts_with("POST ")).collect();
    assert_eq!(posts.len(), 1);
    assert!(posts[0].starts_with("POST /prefix/rest/db/ignores?folder=ignore+%3F%25 "));
    Ok(())
}

#[tokio::test]
async fn ignore_failed_readback_is_unknown_and_reset_restores_defaults_without_empty_body(
) -> TestResult {
    use verysync_sidecar::{FolderId, IgnorePatterns};
    let folder =
        serde_json::json!({"id":"scope","label":"synthetic","path":"/synthetic","paused":false});
    let empty = serde_json::json!({"ignore":null,"expanded":[],"error":null});
    let defaults = serde_json::json!({"ignore":["*.tmp"],"expanded":["*.tmp"],"error":null});
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[folder.clone()]})),
        Reply::json(empty),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[folder.clone()]})),
        Reply {
            status: 500,
            body: KEY.as_bytes().to_vec(),
            headers: String::new(),
            delay: Duration::ZERO,
        },
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[folder.clone()]})),
        Reply::json(defaults.clone()),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[folder]})),
        Reply::json(defaults),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let folder = FolderId::parse("scope")?;
    let error = client
        .set_ignore_patterns(&folder, &IgnorePatterns::new(Vec::new())?)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    assert!(!format!("{error:?} {error}").contains(KEY));
    let reset = client.reset_ignore_patterns(&folder).await?;
    assert_eq!(reset.patterns.unwrap(), vec!["*.tmp"]);
    let requests = server.finish().await?;
    let posts: Vec<_> = requests.iter().filter(|r| r.starts_with("POST ")).collect();
    assert_eq!(posts.len(), 2);
    let submitted: serde_json::Value =
        serde_json::from_str(posts[0].split_once("\r\n\r\n").ok_or("body missing")?.1)?;
    assert_eq!(submitted, serde_json::json!({"ignore":[]}));
    assert!(posts[1].starts_with("POST /prefix/rest/db/resetIgnores?folder=scope "));
    assert_eq!(posts[1].split_once("\r\n\r\n").ok_or("body missing")?.1, "");
    Ok(())
}

#[tokio::test]
async fn scan_scopes_encode_repeated_subpaths_and_refuse_invalid_or_changed_targets() -> TestResult
{
    use verysync_sidecar::{FolderId, FolderScanPatch, PathStyle, TargetPath};
    let folder = serde_json::json!({"id":"scope /?%","label":"synthetic","path":"/synthetic","paused":false});
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[folder]})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"myID":"BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB"})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let folder = FolderId::parse("scope /?%")?;
    for paths in [
        vec![],
        vec![TargetPath::remote(PathStyle::Unix, "../escape")?],
        vec![TargetPath::remote(PathStyle::Unix, "/absolute")?],
        vec![TargetPath::remote(PathStyle::Windows, "relative")?],
    ] {
        assert!(matches!(
            client.request_scan_subpaths(&folder, &paths).await,
            Err(Error::InvalidPath { .. })
        ));
    }
    for patch in [
        FolderScanPatch::default(),
        FolderScanPatch::default().watcher_delay_seconds(f64::NAN),
        FolderScanPatch::default().watcher_delay_seconds(-1.0),
        FolderScanPatch::default().progress_interval_seconds(-2),
        FolderScanPatch::default().rescan_interval_seconds(u32::MAX),
    ] {
        assert!(matches!(
            client
                .update_folder_scan_configuration(&folder, &patch)
                .await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    assert!(client
        .update_folder_scan_configuration(
            &FolderId::parse("..")?,
            &FolderScanPatch::default().watcher(false)
        )
        .await
        .is_err());
    client
        .request_scan_subpaths(
            &folder,
            &[
                TargetPath::remote(PathStyle::Unix, "one/二 ?%.bin")?,
                TargetPath::remote(PathStyle::Unix, "two.bin")?,
            ],
        )
        .await?;
    client.request_all_scans().await?;
    assert!(matches!(
        client.request_all_scans().await,
        Err(Error::IdentityMismatch { .. })
    ));
    let requests = server.finish().await?;
    let scans: Vec<_> = requests.iter().filter(|r| r.starts_with("POST ")).collect();
    assert_eq!(scans.len(), 2);
    let url = url::Url::parse(&format!(
        "http://synthetic.invalid{}",
        scans[0].split_whitespace().nth(1).ok_or("target missing")?
    ))?;
    assert_eq!(
        url.query_pairs().collect::<Vec<_>>(),
        vec![
            ("folder".into(), "scope /?%".into()),
            ("sub".into(), "one/二 ?%.bin".into()),
            ("sub".into(), "two.bin".into())
        ]
    );
    assert!(scans[1].starts_with("POST /prefix/rest/db/scan "));
    Ok(())
}

#[tokio::test]
async fn scan_partial_patch_preserves_fields_and_unknown_outcome_is_not_retried() -> TestResult {
    use verysync_sidecar::{FolderId, FolderScanPatch};
    let folder = serde_json::json!({"id":"scope /?%","label":"synthetic","path":"/synthetic","paused":false,"rescanIntervalS":0,"fsWatcherEnabled":false,"fsWatcherDelayS":1.5,"fsWatcherTimeoutS":2,"scanProgressIntervalS":-1,"disableInitialScan":false,"futureSecret":KEY});
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[folder.clone()]})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[folder.clone()]})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[folder]})),
        Reply {
            status: 500,
            body: KEY.as_bytes().to_vec(),
            headers: String::new(),
            delay: Duration::ZERO,
        },
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let folder = FolderId::parse("scope /?%")?;
    let changed = client
        .update_folder_scan_configuration(&folder, &FolderScanPatch::default().watcher(true))
        .await?;
    assert!(!changed.requested_fields_match && !changed.configuration.watcher_enabled);
    assert_eq!(changed.configuration.extra["futureSecret"], KEY);
    assert!(!format!("{changed:?}").contains(KEY));
    let error = client
        .update_folder_scan_configuration(
            &folder,
            &FolderScanPatch::default().rescan_interval_seconds(1),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    assert!(!format!("{error:?} {error}").contains(KEY));
    let requests = server.finish().await?;
    let patches: Vec<_> = requests
        .iter()
        .filter(|r| r.starts_with("PATCH "))
        .collect();
    assert_eq!(patches.len(), 2);
    assert!(patches[0].starts_with("PATCH /prefix/rest/config/folders/scope%20%2F%3F%25 "));
    let body: serde_json::Value =
        serde_json::from_str(patches[0].split_once("\r\n\r\n").ok_or("body missing")?.1)?;
    assert_eq!(body, serde_json::json!({"fsWatcherEnabled":true}));
    Ok(())
}

#[tokio::test]
async fn scan_remote_windows_scope_uses_target_syntax_without_host_rewriting() -> TestResult {
    use verysync_sidecar::{FolderId, PathStyle, TargetPath};
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"windows","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[{"id":"scope","label":"synthetic","path":"C:\\synthetic","paused":false}]})),
        Reply::json(serde_json::json!({})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let folder = FolderId::parse("scope")?;
    for path in [
        r"C:relative",
        r"C:\absolute",
        r"\\host\share",
        r"a\..\escape",
        "/root",
        "a/../escape",
        ".",
    ] {
        assert!(matches!(
            client
                .request_scan_subpaths(&folder, &[TargetPath::remote(PathStyle::Windows, path)?])
                .await,
            Err(Error::InvalidPath { .. })
        ));
    }
    client
        .request_scan_subpaths(
            &folder,
            &[TargetPath::remote(PathStyle::Windows, r"folder\二 %.bin")?],
        )
        .await?;
    let requests = server.finish().await?;
    let target = requests[4]
        .split_whitespace()
        .nth(1)
        .ok_or("target missing")?;
    let url = url::Url::parse(&format!("http://synthetic.invalid{target}"))?;
    assert_eq!(url.query_pairs().last().unwrap().1, r"folder\二 %.bin");
    Ok(())
}

#[tokio::test]
async fn sync_missing_folder_and_changed_target_do_not_return_empty_data() -> TestResult {
    use verysync_sidecar::{FolderId, ListPage};
    let different = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[]})),
        Reply::json(serde_json::json!({"myID":different})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client
            .folder_need(&FolderId::parse("missing")?, ListPage::new(1, 2)?)
            .await,
        Err(Error::FolderNotFound { .. })
    ));
    assert!(matches!(
        client.batch_folder_status().await,
        Err(Error::IdentityMismatch { .. })
    ));
    let requests = server.finish().await?;
    assert!(!requests
        .iter()
        .any(|r| r.contains("/db/need") || r.contains("/batch/db/status")));
    Ok(())
}

#[tokio::test]
async fn sync_pages_encode_exact_scope_and_reject_wrong_folder_or_malformed_lists() -> TestResult {
    use verysync_sidecar::{FolderId, ListPage};
    let id = FolderId::parse(&format!("scope 中文 /?% {KEY}"))?;
    let folder = serde_json::json!({"id":id.as_str(),"label":"synthetic","path":"/synthetic","paused":false});
    let server=ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),Reply::json(serde_json::json!({"folders":[folder.clone()]})),
        Reply::json(serde_json::json!({"folder":format!("different-{KEY}"),"errors":[],"page":2,"perpage":3})),
        Reply::json(serde_json::json!({"myID":ID})),Reply::json(serde_json::json!({"folders":[folder]})),
        Reply::json(serde_json::json!({"progress":null,"queued":[],"rest":[]})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let error = client
        .folder_errors(&id, ListPage::new(2, 3)?)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::FolderIdentityMismatch { .. }));
    assert!(!format!("{error:?} {error}").contains(KEY));
    assert!(matches!(
        client.folder_need(&id, ListPage::new(1, 2)?).await,
        Err(Error::InvalidResponse { .. })
    ));
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 8);
    let target = requests[4].lines().next().ok_or("missing encoded target")?;
    assert!(target.starts_with("GET /prefix/rest/folder/errors?folder="));
    assert!(target.contains("%E4%B8%AD%E6%96%87") && target.contains("%2F%3F%25"));
    assert!(target.contains("&page=2&perpage=3"));
    Ok(())
}

#[tokio::test]
async fn transport_partial_settings_and_relay_unknown_write_are_separate_receipts() -> TestResult {
    use verysync_sidecar::{RelayServerPatch, TransportPatch};
    let options = serde_json::json!({"trackerEnabled":false,"udpEnabled":false,"udpPort":12345,"natEnabled":false,"relaysEnabled":false,"tcpPunchEnabled":false,"stunServers":[],"customRelayAddresses":[],"natLeaseMinutes":60,"natRenewalMinutes":30,"natTimeoutSeconds":10,"futureSecret":KEY});
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"options":options})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply {
            status: 500,
            body: KEY.as_bytes().to_vec(),
            headers: String::new(),
            delay: Duration::ZERO,
        },
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let changed = client
        .update_transport_configuration(&TransportPatch::default().udp(true))
        .await?;
    assert!(!changed.requested_fields_match && !changed.configuration.udp_enabled);
    assert_eq!(changed.configuration.extra["futureSecret"], KEY);
    assert!(!format!("{changed:?}").contains(KEY));
    let error = client
        .update_relay_server_configuration(&RelayServerPatch::default().enabled(true))
        .await
        .unwrap_err();
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    assert!(!format!("{error:?}").contains(KEY));
    for patch in [
        TransportPatch::default(),
        TransportPatch::default().udp_port(0),
        TransportPatch::default().stun_servers(vec!["bad\naddress".into()]),
    ] {
        assert!(matches!(
            client.update_transport_configuration(&patch).await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    let requests = server.finish().await?;
    let patches: Vec<_> = requests
        .iter()
        .filter(|r| r.starts_with("PATCH "))
        .collect();
    assert_eq!(patches.len(), 2);
    assert!(patches[0].starts_with("PATCH /prefix/rest/config/options "));
    assert!(patches[1].starts_with("PATCH /prefix/rest/config/relayserver "));
    for (request, expected) in [
        (patches[0], serde_json::json!({"udpEnabled":true})),
        (patches[1], serde_json::json!({"enabled":true})),
    ] {
        let body: serde_json::Value =
            serde_json::from_str(request.split_once("\r\n\r\n").ok_or("body missing")?.1)?;
        assert_eq!(body, expected);
    }
    Ok(())
}

#[tokio::test]
async fn relay_changed_readback_is_unknown_and_probe_never_follows_changed_identity() -> TestResult
{
    use verysync_sidecar::RelayServerPatch;
    let different = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"relayServer":null})),
        Reply::json(serde_json::json!({"myID":different})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client
            .update_relay_server_configuration(&RelayServerPatch::default().enabled(false))
            .await,
        Err(Error::MutationOutcomeUnknown { .. })
    ));
    assert!(matches!(
        client.probe_relay("relay://127.0.0.1:12345/").await,
        Err(Error::IdentityMismatch { .. })
    ));
    let requests = server.finish().await?;
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("PATCH ")).count(),
        1
    );
    assert!(!requests.iter().any(|r| r.contains("svc/test/relay")));
    Ok(())
}

#[tokio::test]
async fn explicit_relay_probe_preserves_unknown_result_and_redacts_sensitive_url() -> TestResult {
    use verysync_sidecar::RelayProbeResult;
    let address = format!("relay://127.0.0.1:12345/?token={KEY}&id=synthetic-id");
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"result":KEY,"error":KEY,"futureSecret":KEY})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    for invalid in [
        "https://example.invalid/",
        "relay://127.0.0.1:0/",
        "relay://user:password@127.0.0.1:12345/",
        "relay://127.0.0.1:12345/#fragment",
    ] {
        assert!(matches!(
            client.probe_relay(invalid).await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    let probe = client.probe_relay(&address).await?;
    assert_eq!(probe.result, RelayProbeResult::Unknown(KEY.into()));
    assert_eq!(probe.error.as_deref(), Some(KEY));
    assert_eq!(probe.extra["futureSecret"], KEY);
    assert!(!format!("{probe:?}").contains(KEY));
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 4);
    let target = requests[3].lines().next().ok_or("probe target missing")?;
    assert!(target.starts_with("GET /prefix/rest/svc/test/relay?relay="));
    assert!(target.contains("relay%3A%2F%2F127.0.0.1%3A12345%2F%3Ftoken%3D"));
    Ok(())
}

#[tokio::test]
async fn network_patch_preserves_partial_body_and_distinguishes_stale_readback() -> TestResult {
    use verysync_sidecar::NetworkPatch;
    let config = serde_json::json!({"options":{
        "listenAddresses":["tcp://127.0.0.1:12345"], "globalAnnounceServers":[],
        "globalAnnounceEnabled":false, "localAnnounceEnabled":false,
        "localAnnouncePort":21027,"localAnnounceMCAddr":"[ff12::8384]:21027",
        "reconnectionIntervalS":5,"futureSecret":KEY
    }});
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({})),
        Reply::json(config),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let result = client
        .update_network_configuration(&NetworkPatch::default().global_discovery(true))
        .await?;
    assert!(!result.requested_fields_match);
    assert!(!result.configuration.global_announce_enabled);
    assert_eq!(result.configuration.extra["futureSecret"], KEY);
    assert!(!format!("{result:?}").contains(KEY));
    let requests = server.finish().await?;
    let patches: Vec<_> = requests
        .iter()
        .filter(|r| r.starts_with("PATCH "))
        .collect();
    assert_eq!(patches.len(), 1);
    assert!(patches[0].starts_with("PATCH /prefix/rest/config/options "));
    let body: serde_json::Value =
        serde_json::from_str(patches[0].split_once("\r\n\r\n").ok_or("missing body")?.1)?;
    assert_eq!(body, serde_json::json!({"globalAnnounceEnabled":true}));
    Ok(())
}

#[tokio::test]
async fn network_patch_rechecks_identity_and_never_retries_unknown_outcomes() -> TestResult {
    use verysync_sidecar::NetworkPatch;
    let different = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    for failure in ["identity", "write", "readback"] {
        let mut replies = vec![
            Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
            Reply::json(serde_json::json!({"myID":ID})),
            Reply::json(serde_json::json!({"myID":if failure=="identity" {different}else{ID}})),
        ];
        if failure != "identity" {
            replies.push(Reply {
                status: if failure == "write" { 500 } else { 200 },
                body: KEY.as_bytes().to_vec(),
                headers: String::new(),
                delay: Duration::ZERO,
            });
            if failure == "readback" {
                replies.push(Reply::json(serde_json::json!({"options":null})));
            }
        }
        let server = ScriptedServer::start(replies).await?;
        let client = Client::connect(server.options()?).await?;
        let error = client
            .update_network_configuration(&NetworkPatch::default().global_discovery(true))
            .await
            .unwrap_err();
        if failure == "identity" {
            assert!(matches!(error, Error::IdentityMismatch { .. }));
        } else {
            assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
        }
        assert!(!format!("{error:?}").contains(KEY));
        let requests = server.finish().await?;
        assert_eq!(
            requests.iter().filter(|r| r.starts_with("PATCH ")).count(),
            usize::from(failure != "identity")
        );
    }
    Ok(())
}

#[cfg(not(feature = "tls"))]
#[tokio::test]
async fn https_without_tls_is_rejected_before_network_io() -> TestResult {
    let options = ConnectOptions::new(
        ManagementEndpoint::http("https://synthetic.invalid/")?,
        ApiKey::new(KEY)?,
    );
    assert!(matches!(
        Client::connect(options).await,
        Err(Error::UnsupportedTransport { .. })
    ));
    Ok(())
}

struct Reply {
    status: u16,
    body: Vec<u8>,
    headers: String,
    delay: Duration,
}
impl Reply {
    fn json(value: serde_json::Value) -> Self {
        Self {
            status: 200,
            body: serde_json::to_vec(&value).unwrap(),
            headers: String::new(),
            delay: Duration::ZERO,
        }
    }
}

struct ScriptedServer {
    base: String,
    task: Option<JoinHandle<TestResult<Vec<String>>>>,
}
impl ScriptedServer {
    async fn start(replies: Vec<Reply>) -> TestResult<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let base = format!("http://{}/prefix", listener.local_addr()?);
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for reply in replies {
                let (mut stream, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
                let mut bytes = Vec::new();
                while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                    let mut buffer = [0; 1024];
                    let count =
                        tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
                            .await??;
                    if count == 0 || bytes.len() + count > 16 * 1024 {
                        return Err("invalid synthetic HTTP request".into());
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                }
                let header_end = bytes
                    .windows(4)
                    .position(|part| part == b"\r\n\r\n")
                    .ok_or("missing bounded header")?
                    + 4;
                let header = std::str::from_utf8(&bytes[..header_end])?;
                let length = header
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map(|(_, value)| value.trim().parse::<usize>())
                    .transpose()?
                    .unwrap_or(0);
                if header_end + length > 16 * 1024 {
                    return Err("synthetic request body too large".into());
                }
                while bytes.len() < header_end + length {
                    let mut buffer = [0; 1024];
                    let count =
                        tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
                            .await??;
                    if count == 0 {
                        return Err("synthetic body ended early".into());
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                }
                requests.push(String::from_utf8(bytes)?);
                tokio::time::sleep(reply.delay).await;
                let head = format!(
                    "HTTP/1.1 {} Test\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n",
                    reply.status,
                    reply.body.len(),
                    reply.headers
                );
                // A deliberate timeout may close the client before this write.
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&reply.body).await;
            }
            Ok(requests)
        });
        Ok(Self {
            base,
            task: Some(task),
        })
    }
    fn options(&self) -> verysync_sidecar::Result<ConnectOptions> {
        Ok(ConnectOptions::new(
            ManagementEndpoint::http(&self.base)?,
            ApiKey::new(KEY)?,
        ))
    }
    async fn finish(mut self) -> TestResult<Vec<String>> {
        self.task
            .take()
            .ok_or("synthetic server already joined")?
            .await?
    }
}
impl Drop for ScriptedServer {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn version(value: &str) -> Reply {
    Reply::json(
        serde_json::json!({"version":value,"os":"synthetic-os","arch":"synthetic-arch","vendorExtension":{"preserved":true}}),
    )
}

#[tokio::test]
async fn device_ignore_put_preserves_full_unknown_configuration_and_other_records() -> TestResult {
    use verysync_sidecar::DeviceId;
    let peer = DeviceId::parse("BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB")?;
    let other = serde_json::json!({"deviceID":"CCCCCCC-CCCCCCC-CCCCCCC-CCCCCCC-CCCCCCC-CCCCCCC-CCCCCCC-CCCCCCC","time":"2025-01-01T00:00:00Z","name":"private-name","address":"private-address","futureSecret":{"preserved":7}});
    let config = serde_json::json!({"version":54,"devices":[{"deviceID":ID,"futureDeviceField":{"keep":true}}],"remoteIgnoredDevices":[other.clone()],"gui":{"apiKey":KEY},"futureSetting":{"nested":[1,false,"private-value"]}});
    let mut readback = config.clone();
    readback["remoteIgnoredDevices"].as_array_mut().ok_or("missing ignore list")?.push(serde_json::json!({"deviceID":peer.as_str(),"time":"0001-01-01T00:00:00Z","name":"","address":""}));
    let server = ScriptedServer::start(vec![
        version("v2.33.2"),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(config.clone()),
        Reply::json(serde_json::Value::Null),
        Reply::json(readback),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(client.ignore_device(&peer).await?.is_ignored);
    let requests = server.finish().await?;
    let puts: Vec<_> = requests.iter().filter(|v| v.starts_with("PUT ")).collect();
    assert_eq!(puts.len(), 1);
    assert!(puts[0].starts_with("PUT /prefix/rest/config HTTP/1.1\r\n"));
    let mut body: serde_json::Value =
        serde_json::from_str(puts[0].split_once("\r\n\r\n").ok_or("missing body")?.1)?;
    assert_eq!(body["remoteIgnoredDevices"][0], other);
    assert_eq!(
        body["remoteIgnoredDevices"][1],
        serde_json::json!({"deviceID":peer.as_str()})
    );
    body["remoteIgnoredDevices"] = config["remoteIgnoredDevices"].clone();
    assert_eq!(body, config);
    Ok(())
}

#[tokio::test]
async fn device_ignore_failed_readback_is_unknown_and_does_not_retry_full_put() -> TestResult {
    use verysync_sidecar::DeviceId;
    let peer = DeviceId::parse("BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB")?;
    let config = serde_json::json!({"devices":[{"deviceID":ID}],"remoteIgnoredDevices":[],"gui":{"apiKey":KEY}});
    let server = ScriptedServer::start(vec![
        version("v2.33.2"),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(config),
        Reply::json(serde_json::Value::Null),
        Reply::json(serde_json::json!({"devices":[],"remoteIgnoredDevices":"malformed"})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let error = client.ignore_device(&peer).await.unwrap_err();
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    assert!(!format!("{error:?} {error}").contains(KEY));
    assert_eq!(
        server
            .finish()
            .await?
            .iter()
            .filter(|v| v.starts_with("PUT "))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn pending_route_http_and_schema_errors_are_never_empty_snapshots() -> TestResult {
    for reply in [
        Reply {
            status: 404,
            body: b"missing route".to_vec(),
            headers: String::new(),
            delay: Duration::ZERO,
        },
        Reply::json(serde_json::json!({"folder":{"offeredBy":"malformed"}})),
    ] {
        let server = ScriptedServer::start(vec![
            version("v2.33.2"),
            Reply::json(serde_json::json!({"myID":ID})),
            reply,
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        assert!(matches!(
            client.pending_folders(None).await,
            Err(Error::Http { .. }) | Err(Error::InvalidResponse { .. })
        ));
        assert_eq!(server.finish().await?.len(), 3);
    }
    Ok(())
}

#[tokio::test]
async fn candidate_pending_device_dismissal_is_exact_and_has_no_implicit_ignore() -> TestResult {
    use verysync_sidecar::DeviceId;
    let peer = DeviceId::parse("BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB")?;
    let pending = serde_json::json!({peer.as_str():{"time":"2026-01-01T00:00:00Z","name":"private pending name","address":"private.invalid:1234","futureSecret":"private future value"}});
    let server = ScriptedServer::start(vec![
        version("v2.33.2"),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(pending),
        Reply::json(serde_json::Value::Null),
        Reply::json(serde_json::json!({})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(client.dismiss_pending_device(&peer).await?.record_absent);
    let requests = server.finish().await?;
    let writes: Vec<_> = requests.iter().filter(|v| !v.starts_with("GET ")).collect();
    assert_eq!(writes.len(), 1);
    assert!(writes[0].starts_with(&format!(
        "DELETE /prefix/rest/cluster/pending/devices?device={} HTTP/1.1\r\n",
        peer.as_str()
    )));
    assert!(writes[0].ends_with("\r\n\r\n"));
    // Synthetic candidate wire evidence only; no nonempty native record claim.
    Ok(())
}

#[tokio::test]
async fn persistent_folder_ignore_preserves_other_entries_and_only_patches_that_field() -> TestResult
{
    use verysync_sidecar::{DeviceId, FolderId};
    let peer = DeviceId::parse("BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB")?;
    let folder = FolderId::parse("remote ?/#%")?;
    let other = serde_json::json!({"id":"other","label":"keep","time":"2025-01-01T00:00:00Z","unknown":{"preserved":7}});
    let new =
        serde_json::json!({"id":folder.as_str(),"label":"offered","time":"2026-01-01T00:00:00Z"});
    let server=ScriptedServer::start(vec![
        version("v2.33.2"),Reply::json(serde_json::json!({"myID":ID})),Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({folder.as_str():{"offeredBy":{peer.as_str():{"time":"2026-01-01T00:00:00Z","label":"offered","receiveEncrypted":false,"remoteEncrypted":false}}}})),
        Reply::json(serde_json::json!({"devices":[{"deviceID":peer.as_str(),"ignoredFolders":[other.clone()]}]})),
        Reply::json(serde_json::Value::Null),
        Reply::json(serde_json::json!({"devices":[{"deviceID":peer.as_str(),"ignoredFolders":[other.clone(),new.clone()]}]})),
        Reply::json(serde_json::json!({})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let result = client.ignore_folder_offer(&folder, &peer).await?;
    assert!(result.is_ignored && result.pending_offer_absent);
    let requests = server.finish().await?;
    let writes: Vec<_> = requests
        .iter()
        .filter(|v| v.starts_with("PATCH "))
        .collect();
    assert_eq!(writes.len(), 1);
    let body: serde_json::Value =
        serde_json::from_str(writes[0].split_once("\r\n\r\n").ok_or("missing body")?.1)?;
    assert_eq!(body, serde_json::json!({"ignoredFolders":[other,new]}));
    assert!(requests
        .iter()
        .filter(|v| v.contains("pending/folders?"))
        .all(|v| v.contains(&format!("device={}", peer.as_str()))));
    Ok(())
}

#[tokio::test]
async fn device_creation_preserves_unknown_defaults_and_rejects_cloned_duplicates() -> TestResult {
    use verysync_sidecar::{CreateDeviceOptions, DeviceId, DevicePatch};
    let peer = DeviceId::parse("BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB")?;
    let configured = serde_json::json!({"deviceID":peer.as_str(),"name":"Chosen peer","addresses":["dynamic"],"compression":"metadata","paused":true,"vendorDefault":{"retained":7}});
    let server = ScriptedServer::start(vec![
        version("v2.33.2"), Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"devices":[]})),
        Reply::json(serde_json::json!({"deviceID":"","name":"Default","addresses":["dynamic"],"compression":"metadata","paused":false,"vendorDefault":{"retained":7}})),
        Reply::json(serde_json::Value::Null),
        Reply::json(serde_json::json!({"devices":[configured.clone()]})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"devices":[configured]})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let options = CreateDeviceOptions::new(peer.clone())
        .settings(DevicePatch::default().name("Chosen peer").paused(true));
    assert!(client.create_device(&options).await?.requested_fields_match);
    assert!(matches!(
        client.clone().create_device(&options).await,
        Err(Error::DeviceAlreadyExists { .. })
    ));
    let requests = server.finish().await?;
    let posts: Vec<_> = requests.iter().filter(|v| v.starts_with("POST ")).collect();
    assert_eq!(posts.len(), 1);
    assert!(posts[0].starts_with("POST /prefix/rest/config/devices HTTP/1.1\r\n"));
    let body: serde_json::Value =
        serde_json::from_str(posts[0].split_once("\r\n\r\n").ok_or("missing body")?.1)?;
    assert_eq!(body["deviceID"], peer.as_str());
    assert_eq!(body["vendorDefault"]["retained"], 7);
    assert_eq!(body["addresses"], serde_json::json!(["dynamic"]));
    Ok(())
}

#[tokio::test]
async fn device_patch_reports_stale_values_and_rejects_wrong_target_before_write() -> TestResult {
    use verysync_sidecar::{DeviceId, DevicePatch};
    let peer = DeviceId::parse("BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB")?;
    let configured = serde_json::json!({"deviceID":peer.as_str(),"name":"Old","addresses":["dynamic"],"compression":"metadata","paused":false});
    let server = ScriptedServer::start(vec![
        version("v2.33.2"),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"devices":[configured.clone()]})),
        Reply::json(serde_json::Value::Null),
        Reply::json(serde_json::json!({"devices":[configured]})),
        Reply::json(serde_json::json!({"myID":peer.as_str()})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(
        !client
            .update_device(&peer, &DevicePatch::default().name("New"))
            .await?
            .requested_fields_match
    );
    assert!(matches!(
        client.remove_device(&peer).await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert!(matches!(
        client.remove_device(&DeviceId::parse(ID)?).await,
        Err(Error::LocalDeviceProtected)
    ));
    let requests = server.finish().await?;
    let patches: Vec<_> = requests
        .iter()
        .filter(|v| v.starts_with("PATCH "))
        .collect();
    assert_eq!(patches.len(), 1);
    assert!(patches[0].starts_with(&format!(
        "PATCH /prefix/rest/config/devices/{} HTTP/1.1\r\n",
        peer.as_str()
    )));
    let body: serde_json::Value =
        serde_json::from_str(patches[0].split_once("\r\n\r\n").ok_or("missing body")?.1)?;
    assert_eq!(body, serde_json::json!({"name":"New"}));
    assert!(!requests.iter().any(|v| v.starts_with("DELETE ")));
    Ok(())
}

#[tokio::test]
async fn device_delete_readback_failure_is_unknown_without_retry_or_file_flags() -> TestResult {
    use verysync_sidecar::DeviceId;
    let peer = DeviceId::parse("BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB")?;
    let configured = serde_json::json!({"deviceID":peer.as_str(),"name":"Peer","addresses":["dynamic"],"compression":"metadata","paused":false});
    let server = ScriptedServer::start(vec![
        version("v2.33.2"),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"devices":[configured]})),
        Reply::json(serde_json::Value::Null),
        Reply::json(
            serde_json::json!({"devices":[],"folders":[{"id":"sample","devices":"malformed"}]}),
        ),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(
        matches!(client.remove_device(&peer).await,Err(Error::MutationOutcomeUnknown { source,.. }) if matches!(*source,Error::InvalidResponse { .. }))
    );
    let requests = server.finish().await?;
    let deletes: Vec<_> = requests
        .iter()
        .filter(|v| v.starts_with("DELETE "))
        .collect();
    assert_eq!(deletes.len(), 1);
    assert!(deletes[0].starts_with(&format!(
        "DELETE /prefix/rest/config/devices/{} HTTP/1.1\r\n",
        peer.as_str()
    )));
    assert!(deletes[0].ends_with("\r\n\r\n"));
    assert!(!deletes[0].to_ascii_lowercase().contains("content-type:"));
    Ok(())
}

#[tokio::test]
async fn unverified_version_requires_explicit_policy_and_retains_unknown_metadata() -> TestResult {
    let server = ScriptedServer::start(vec![version("v99.0.0")]).await?;
    let error = Client::connect(server.options()?).await.unwrap_err();
    assert!(matches!(error, Error::IncompatibleVersion { actual } if actual == "v99.0.0"));
    assert_eq!(server.finish().await?.len(), 1);

    let server = ScriptedServer::start(vec![
        version("v99.0.0"),
        Reply::json(serde_json::json!({"myID":ID})),
    ])
    .await?;
    let client = Client::connect(
        server
            .options()?
            .version_policy(VersionPolicy::AllowUnverified),
    )
    .await?;
    assert_eq!(
        client.instance().compatibility,
        VersionCompatibility::Unverified
    );
    assert_eq!(
        client.instance().version.extra["vendorExtension"]["preserved"],
        true
    );
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /prefix/rest/system/version HTTP/1.1\r\n"));
    assert!(requests[1].starts_with("GET /prefix/rest/system/status HTTP/1.1\r\n"));
    assert!(requests.iter().all(|request| request
        .to_ascii_lowercase()
        .contains(&format!("x-api-key: {KEY}\r\n"))));
    Ok(())
}

#[tokio::test]
async fn reflected_credentials_are_redacted_in_version_errors_and_client_debug() -> TestResult {
    let reflected = format!("v99.0.0+{KEY}");
    let server = ScriptedServer::start(vec![version(&reflected)]).await?;
    let error = Client::connect(server.options()?).await.unwrap_err();
    assert!(!format!("{error:?} {error}").contains(KEY));
    server.finish().await?;

    let server = ScriptedServer::start(vec![
        version(&reflected),
        Reply::json(serde_json::json!({"myID":ID})),
    ])
    .await?;
    let client = Client::connect(
        server
            .options()?
            .version_policy(VersionPolicy::AllowUnverified),
    )
    .await?;
    assert!(!format!("{client:?}").contains(KEY));
    server.finish().await?;
    Ok(())
}

#[tokio::test]
async fn redirects_are_not_followed_and_response_diagnostics_are_not_logged() -> TestResult {
    let destination = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    destination.set_nonblocking(true)?;
    let redirect = Reply {
        status: 302,
        body: KEY.as_bytes().to_vec(),
        headers: format!(
            "Location: http://{}/owned-redirect-target\r\n",
            destination.local_addr()?
        ),
        delay: Duration::ZERO,
    };
    let server = ScriptedServer::start(vec![redirect]).await?;
    let error = Client::connect(server.options()?).await.unwrap_err();
    assert!(!format!("{error:?} {error}").contains(KEY));
    match error {
        Error::Http { response } => {
            assert_eq!(response.status(), 302);
            assert_eq!(response.body_bytes(), KEY.as_bytes());
        }
        other => return Err(format!("unexpected synthetic redirect result: {other}").into()),
    }
    assert_eq!(
        destination.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(server.finish().await?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn malformed_metadata_or_identity_is_not_a_successful_connection() -> TestResult {
    for body in [
        serde_json::json!({}),
        serde_json::json!({"version":"","os":"linux","arch":"amd64"}),
    ] {
        let server = ScriptedServer::start(vec![Reply::json(body)]).await?;
        assert!(matches!(
            Client::connect(server.options()?).await,
            Err(Error::InvalidResponse {
                operation: "read version",
                ..
            })
        ));
        server.finish().await?;
    }
    let server = ScriptedServer::start(vec![
        version(verysync_sidecar::BASELINE_ENGINE_VERSION),
        Reply::json(serde_json::json!({"myID":"invalid-identity"})),
    ])
    .await?;
    assert!(matches!(
        Client::connect(server.options()?).await,
        Err(Error::InvalidResponse {
            operation: "read identity",
            ..
        })
    ));
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn management_reads_enforce_response_size_and_deadlines() -> TestResult {
    let mut large = version(verysync_sidecar::BASELINE_ENGINE_VERSION);
    large.body = vec![b'x'; 1024];
    let server = ScriptedServer::start(vec![large]).await?;
    assert!(matches!(
        Client::connect(server.options()?.response_limit(64)?).await,
        Err(Error::ResponseTooLarge { limit: 64 })
    ));
    server.finish().await?;

    let mut delayed = version(verysync_sidecar::BASELINE_ENGINE_VERSION);
    delayed.delay = Duration::from_secs(2);
    let server = ScriptedServer::start(vec![delayed]).await?;
    assert!(matches!(
        Client::connect(server.options()?.request_timeout(Duration::from_secs(1))?).await,
        Err(Error::Timeout {
            operation: "read version"
        })
    ));
    server.finish().await?;
    Ok(())
}

#[tokio::test]
async fn status_reads_are_fresh_preserve_unknowns_and_encode_folder_ids() -> TestResult {
    use verysync_sidecar::{FolderId, FolderState};
    let server=ScriptedServer::start(vec![
        version(verysync_sidecar::BASELINE_ENGINE_VERSION),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"synthetic-os","arch":"synthetic-arch","freshVendor":true})),
        Reply::json(serde_json::json!({"myID":ID,"vendorStatus":{"value":"sensitive-vendor-status"}})),
        Reply::json(serde_json::json!({"myID":ID,"uptime":7,"alloc":0,"cpuPercent":0,"goroutines":4})),
        Reply::json(serde_json::json!({"state":"future-hashing","localBytes":5,"vendorFolder":{"retained":true}})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let fresh_version = client.version().await?;
    assert_eq!(fresh_version.extra["freshVendor"], true);
    assert!(!client.instance().version.extra.contains_key("freshVendor"));
    let unknown = client.system_status().await?;
    assert_eq!(unknown.device_id.as_str(), ID);
    assert_eq!(unknown.uptime_seconds, None);
    assert_eq!(unknown.memory_allocated_bytes, None);
    assert_eq!(unknown.cpu_percent, None);
    assert_eq!(
        unknown.extra["vendorStatus"]["value"],
        "sensitive-vendor-status"
    );
    assert!(!format!("{unknown:?}").contains("sensitive-vendor-status"));
    let reported_zero = client.system_status().await?;
    assert_eq!(reported_zero.uptime_seconds, Some(7));
    assert_eq!(reported_zero.memory_allocated_bytes, Some(0));
    assert_eq!(reported_zero.cpu_percent, Some(0.0));
    let id = FolderId::parse("folder /?&中文")?;
    let status = client.folder_status(&id).await?;
    assert_eq!(
        status.state,
        Some(FolderState::Unknown("future-hashing".to_owned()))
    );
    assert_eq!(status.local_bytes, Some(5));
    assert_eq!(status.need_bytes, None);
    assert_eq!(status.extra["vendorFolder"]["retained"], true);
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 6);
    let path = requests[5].lines().next().ok_or("missing request line")?;
    assert!(path.starts_with("GET /prefix/rest/db/status?folder="));
    assert!(path.contains("folder+%2F%3F%26%E4%B8%AD%E6%96%87"));
    Ok(())
}

#[tokio::test]
async fn fresh_status_rejects_invalid_metrics_and_changed_identity() -> TestResult {
    let other = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    let server = ScriptedServer::start(vec![
        version(verysync_sidecar::BASELINE_ENGINE_VERSION),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID,"alloc":-1})),
        Reply::json(serde_json::json!({"myID":other,"uptime":9})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client.system_status().await,
        Err(Error::InvalidResponse { .. })
    ));
    assert!(matches!(
        client.system_status().await,
        Err(Error::IdentityMismatch { .. })
    ));
    server.finish().await?;
    Ok(())
}

#[tokio::test]
async fn create_folder_preserves_defaults_and_never_posts_over_an_existing_id() -> TestResult {
    use verysync_sidecar::{CreateFolderOptions, FolderId, PathStyle, TargetPath};
    let configured = serde_json::json!({"id":"test-folder","label":"New label","path":"/synthetic/folder","paused":true,"vendorDefault":{"retained":7},"secret":"sensitive-folder-secret"});
    let server=ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[]})),
        Reply::json(serde_json::json!({"id":"","path":"","label":"Default","paused":false,"vendorDefault":{"retained":7},"secret":"sensitive-folder-secret"})),
        Reply { status:200,body:vec![],headers:String::new(),delay:Duration::ZERO },
        Reply::json(serde_json::json!({"folders":[configured.clone()]})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[configured]})),
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let options = CreateFolderOptions::new(
        FolderId::parse("test-folder")?,
        TargetPath::remote(PathStyle::Unix, "/synthetic/folder")?,
    )
    .label("New label")
    .paused(true);
    let created = client.create_folder(&options).await?;
    assert_eq!(created.id, *options.id());
    assert_eq!(created.extra["vendorDefault"]["retained"], 7);
    assert!(!format!("{created:?}").contains("sensitive-folder-secret"));
    assert!(matches!(
        client.create_folder(&options).await,
        Err(Error::FolderAlreadyExists { .. })
    ));
    let requests = server.finish().await?;
    let posts: Vec<_> = requests
        .iter()
        .filter(|request| request.starts_with("POST "))
        .collect();
    assert_eq!(posts.len(), 1);
    let body: serde_json::Value =
        serde_json::from_str(posts[0].split_once("\r\n\r\n").ok_or("missing body")?.1)?;
    assert_eq!(body["label"], "New label");
    assert_eq!(body["paused"], true);
    assert_eq!(body["vendorDefault"]["retained"], 7);
    assert_eq!(body["secret"], "sensitive-folder-secret");
    Ok(())
}

#[tokio::test]
async fn modifying_request_failure_has_an_explicit_unknown_outcome_without_retry() -> TestResult {
    use verysync_sidecar::{CreateFolderOptions, FolderId, PathStyle, TargetPath};
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[]})),
        Reply::json(serde_json::json!({"vendorDefault":true})),
        Reply {
            status: 500,
            body: KEY.as_bytes().to_vec(),
            headers: String::new(),
            delay: Duration::ZERO,
        },
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let options = CreateFolderOptions::new(
        FolderId::parse("uncertain-folder")?,
        TargetPath::remote(PathStyle::Unix, "/synthetic/uncertain")?,
    );
    let error = client.create_folder(&options).await.unwrap_err();
    assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
    assert!(!format!("{error:?}").contains(KEY));
    assert!(!error.to_string().contains(KEY));
    assert_eq!(
        server
            .finish()
            .await?
            .iter()
            .filter(|request| request.starts_with("POST "))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn folder_update_sends_only_requested_fields_and_reports_stale_readback() -> TestResult {
    use verysync_sidecar::{FolderId, FolderPatch};
    let id = FolderId::parse("folder 中文 /?#%")?;
    let before = serde_json::json!({"id":id.as_str(),"label":"Before","path":"/synthetic","paused":false,"unknown":{"keep":[1,2]},"secret":"synthetic-folder-key"});
    let mut after = before.clone();
    after["label"] = serde_json::json!("After");
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[before]})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"folders":[after.clone()]})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[after.clone()]})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"folders":[after]})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let result = client
        .update_folder(&id, &FolderPatch::default().label("After"))
        .await?;
    assert!(result.requested_fields_match);
    assert_eq!(
        result.configuration.extra["unknown"]["keep"],
        serde_json::json!([1, 2])
    );
    assert!(!format!("{result:?}").contains("synthetic-folder-key"));
    let pending = client.pause_folder(&id).await?;
    assert!(!pending.requested_fields_match);
    assert!(!pending.configuration.paused);
    assert!(matches!(
        client.resume_folder(&id).await,
        Err(Error::FolderNotFound { .. })
    ));
    assert!(matches!(
        client.update_folder(&id, &FolderPatch::default()).await,
        Err(Error::InvalidConfiguration { .. })
    ));
    for unsafe_segment in [".", ".."] {
        assert!(matches!(
            client.pause_folder(&FolderId::parse(unsafe_segment)?).await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    let requests = server.finish().await?;
    let patches: Vec<_> = requests
        .iter()
        .filter(|r| r.starts_with("PATCH "))
        .collect();
    assert_eq!(patches.len(), 2);
    let target = patches[0].lines().next().ok_or("missing request target")?;
    assert!(target.starts_with("PATCH /prefix/rest/config/folders/folder%20"));
    assert!(target.contains("%2F%3F%23%25"));
    let body = |r: &str| -> TestResult<serde_json::Value> {
        Ok(serde_json::from_str(
            r.split_once("\r\n\r\n").ok_or("missing body")?.1,
        )?)
    };
    assert_eq!(body(patches[0])?, serde_json::json!({"label":"After"}));
    assert_eq!(body(patches[1])?, serde_json::json!({"paused":true}));
    Ok(())
}

#[tokio::test]
async fn folder_remove_keep_files_checks_identity_existence_and_absence_readback() -> TestResult {
    use verysync_sidecar::FolderId;
    let id = FolderId::parse("remove 中文?#%")?;
    let other = serde_json::json!({"id":"other","label":"Retained","path":"/synthetic/other","paused":true});
    let target = serde_json::json!({"id":id.as_str(),"label":"Target","path":"/synthetic/target","paused":false,"unknown":{"keep":7}});
    let different = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[target,other.clone()]})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"folders":[other.clone()]})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[other]})),
        Reply::json(serde_json::json!({"myID":different})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let removed = client.remove_folder_keep_files(&id).await?;
    assert!(removed.configuration_absent);
    assert_eq!(removed.previous_configuration.id, id);
    assert_eq!(removed.previous_configuration.extra["unknown"]["keep"], 7);
    assert!(matches!(
        client.remove_folder_keep_files(&id).await,
        Err(Error::FolderNotFound { .. })
    ));
    assert!(matches!(
        client
            .remove_folder_keep_files(&FolderId::parse("other")?)
            .await,
        Err(Error::IdentityMismatch { .. })
    ));
    let requests = server.finish().await?;
    let deletes: Vec<_> = requests
        .iter()
        .filter(|r| r.starts_with("DELETE "))
        .collect();
    assert_eq!(deletes.len(), 1);
    let line = deletes[0].lines().next().ok_or("missing target")?;
    assert!(line.starts_with("DELETE /prefix/rest/config/folders/remove%20"));
    assert!(line.contains("%3F%23%25"));
    assert!(!line.contains('?'));
    assert_eq!(
        deletes[0]
            .split_once("\r\n\r\n")
            .ok_or("missing body boundary")?
            .1,
        ""
    );
    Ok(())
}

#[tokio::test]
async fn unregister_acknowledgment_does_not_invent_absence_when_id_is_still_visible() -> TestResult
{
    let target = serde_json::json!({"id":"still-visible","label":"Concurrent writer","path":"/synthetic","paused":true});
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[target.clone()]})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"folders":[target]})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let result = client
        .remove_folder_keep_files(&verysync_sidecar::FolderId::parse("still-visible")?)
        .await?;
    assert!(!result.configuration_absent);
    assert_eq!(
        server
            .finish()
            .await?
            .iter()
            .filter(|r| r.starts_with("DELETE "))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn error_contract_distinguishes_authentication_forbidden_and_body_failure() -> TestResult {
    for status in [401, 403] {
        let server = ScriptedServer::start(vec![Reply {
            status,
            body: KEY.as_bytes().to_vec(),
            headers: String::new(),
            delay: Duration::ZERO,
        }])
        .await?;
        let error = Client::connect(server.options()?).await.unwrap_err();
        assert!(!format!("{error:?} {error}").contains(KEY));
        match (status, error) {
            (401, Error::Authentication { status: 401 }) => (),
            (403, Error::AccessDenied { response }) => {
                assert_eq!(response.status(), 403);
                assert_eq!(response.body_bytes(), KEY.as_bytes());
            }
            _ => return Err("access denial classification was incorrect".into()),
        }
        server.finish().await?;
    }
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"error":KEY})),
        Reply::json(
            serde_json::json!({"state":"error","error":"legitimate status detail","localFiles":0}),
        ),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let id = verysync_sidecar::FolderId::parse("synthetic-error-folder")?;
    let error = client.folder_status(&id).await.unwrap_err();
    assert!(matches!(error, Error::Api { .. }));
    assert!(!format!("{error:?} {error}").contains(KEY));
    let status = client.folder_status(&id).await?;
    assert_eq!(status.state, Some(verysync_sidecar::FolderState::Error));
    assert_eq!(status.extra["error"], "legitimate status detail");
    server.finish().await?;
    Ok(())
}

#[tokio::test]
async fn body_deadline_and_post_write_readback_failure_are_not_success_or_retry() -> TestResult {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let base = format!("http://{}/", listener.local_addr()?);
    let task = tokio::spawn(async move {
        let (mut stream, _) =
            tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
        let mut request = [0; 4096];
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut request)).await??;
        stream
            .write_all(b"HTTP/1.1 200 Test\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{")
            .await?;
        let mut tail = [0; 1];
        let closed =
            tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tail)).await?? == 0;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(closed)
    });
    let options = ConnectOptions::new(ManagementEndpoint::http(&base)?, ApiKey::new(KEY)?)
        .request_timeout(Duration::from_secs(1))?;
    assert!(matches!(
        Client::connect(options).await,
        Err(Error::Timeout { .. })
    ));
    assert!(task.await??, "timed-out response connection must close");

    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"folders":[]})),
        Reply::json(serde_json::json!({"vendorDefault":true})),
        Reply::json(serde_json::json!({})),
        Reply::json(serde_json::json!({"unexpected":"instead of folders"})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let options = verysync_sidecar::CreateFolderOptions::new(
        verysync_sidecar::FolderId::parse("uncertain-readback")?,
        verysync_sidecar::TargetPath::remote(
            verysync_sidecar::PathStyle::Unix,
            "/synthetic/readback",
        )?,
    );
    assert!(
        matches!(client.create_folder(&options).await,Err(Error::MutationOutcomeUnknown { source,.. }) if matches!(*source,Error::InvalidResponse{..}))
    );
    assert_eq!(
        server
            .finish()
            .await?
            .iter()
            .filter(|r| r.starts_with("POST "))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn raw_request_preserves_error_binary_headers_and_selected_origin() -> TestResult {
    use verysync_sidecar::{RawMethod, RawRequest, RequestEffect};
    let destination = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    destination.set_nonblocking(true)?;
    let mut binary = vec![0, 255, 1];
    binary.extend_from_slice(KEY.as_bytes());
    let location = format!("http://{}/must-not-receive-key", destination.local_addr()?);
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply {
            status: 418,
            body: binary.clone(),
            headers: format!("X-Vendor: one\r\nX-Vendor: {KEY}\r\n"),
            delay: Duration::ZERO,
        },
        Reply {
            status: 302,
            body: Vec::new(),
            headers: format!("Location: {location}\r\n"),
            delay: Duration::ZERO,
        },
        Reply::json(serde_json::json!({"error":KEY})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let request = RawRequest::new(
        RawMethod::Get,
        ["rest", "https://synthetic.invalid", "../slash"],
        RequestEffect::ReadOnly,
    )?
    .query("name", "/ ?#%中文")
    .header("X-Business", "synthetic-business-value")?
    .body(b"explicit synthetic body".to_vec());
    let raw = client.raw_request(&request).await?;
    assert_eq!(raw.status(), 418);
    assert_eq!(raw.body_bytes(), binary);
    assert_eq!(
        raw.headers()
            .filter(|(name, _)| *name == "x-vendor")
            .count(),
        2
    );
    assert!(!format!("{raw:?}").contains(KEY));
    let redirect = client
        .raw_request(&RawRequest::new(
            RawMethod::Get,
            ["rest", "redirect"],
            RequestEffect::ReadOnly,
        )?)
        .await?;
    assert_eq!(redirect.status(), 302);
    assert!(redirect
        .headers()
        .any(|(name, value)| name == "location" && value == location.as_bytes()));
    assert_eq!(
        destination.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let body_error = client
        .raw_request(&RawRequest::new(
            RawMethod::Get,
            ["rest", "unmodeled"],
            RequestEffect::ReadOnly,
        )?)
        .await?;
    assert_eq!(body_error.status(), 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(body_error.body_bytes())?["error"],
        KEY
    );
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 5);
    let first = &requests[2];
    let target = first.lines().next().ok_or("missing raw target")?;
    assert!(target.starts_with("GET /prefix/rest/https:%2F%2Fsynthetic.invalid/..%2Fslash?name="));
    assert!(target.contains("%23%25%E4%B8%AD%E6%96%87"));
    assert!(first
        .to_ascii_lowercase()
        .contains(&format!("x-api-key: {KEY}\r\n")));
    assert!(first.ends_with("explicit synthetic body"));
    Ok(())
}

#[tokio::test]
async fn raw_state_changing_get_requires_fresh_identity_before_sending() -> TestResult {
    use verysync_sidecar::{RawMethod, RawRequest, RequestEffect};
    let different = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":different})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let request = RawRequest::new(
        RawMethod::Get,
        ["rest", "account", "logout"],
        RequestEffect::MayModify,
    )?;
    assert!(matches!(
        client.raw_request(&request).await,
        Err(Error::IdentityMismatch { .. })
    ));
    let requests = server.finish().await?;
    assert_eq!(requests.len(), 3);
    assert!(!requests
        .iter()
        .any(|request| request.contains("account/logout")));
    Ok(())
}

#[tokio::test]
async fn capabilities_report_is_a_snapshot_without_optional_feature_probes() -> TestResult {
    use verysync_sidecar::{InstanceObservation, TargetValidation};
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"arm64"})),
        Reply::json(serde_json::json!({"myID":ID})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let report = client.capabilities();
    assert_eq!(report.target.engine_os, "linux");
    assert_eq!(report.target.engine_arch, "arm64");
    assert_eq!(
        report.target_validation,
        TargetValidation::OutsideNativeEvidence
    );
    assert_eq!(
        report.instance.authentication,
        InstanceObservation::ObservedAtHandshake
    );
    assert_eq!(
        report.instance.commercial_license,
        InstanceObservation::Unknown
    );
    assert_eq!(
        report.instance.operation_authorization,
        InstanceObservation::Unknown
    );
    assert!(!format!("{report:?}").contains(KEY));
    assert_eq!(
        server.finish().await?.len(),
        2,
        "report must not add management or license probes"
    );
    Ok(())
}

#[tokio::test]
async fn resource_download_rejects_wrong_ranges_and_preserves_partial_and_error_semantics(
) -> TestResult {
    use verysync_sidecar::{
        PathStyle, ResourceByteRange, ResourcePath, ResourceTransferOptions, ResourceVolumeId,
    };
    let body = |status, bytes: &[u8], headers: &str| Reply {
        status,
        body: bytes.to_vec(),
        headers: headers.into(),
        delay: Duration::ZERO,
    };
    let pairs = vec![
        body(200, b"abc", ""),
        body(206, b"bc", "Content-Range: bytes 0-1/3\r\n"),
        body(206, b"b", "Content-Range: bytes 1-2/3\r\n"),
        body(
            200,
            b"{\"error\":\"literal file bytes\"}",
            "Content-Type: application/json\r\n",
        ),
        body(401, KEY.as_bytes(), ""),
        body(403, KEY.as_bytes(), ""),
        body(404, KEY.as_bytes(), ""),
        body(206, b"abc", "Content-Range: bytes 0-2/3\r\n"),
        body(200, b"abcd", ""),
    ];
    let mut replies = vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
    ];
    for reply in pairs {
        replies.push(Reply::json(serde_json::json!({"myID":ID})));
        replies.push(reply);
    }
    let server = ScriptedServer::start(replies).await?;
    let client = Client::connect(server.options()?).await?;
    let path = ResourcePath::root(ResourceVolumeId::parse("private-volume")?, PathStyle::Unix)
        .child("literal %.bin")?;
    let root = tempfile::tempdir()?;
    let options = ResourceTransferOptions {
        max_bytes: 1024,
        deadline: Duration::from_secs(2),
    };
    for case in 0..9 {
        let output = root.path().join(format!("result-{case}.bin"));
        let range = if case < 3 {
            Some(ResourceByteRange::new(1, 2)?)
        } else {
            None
        };
        let opts = if case == 8 {
            ResourceTransferOptions {
                max_bytes: 2,
                ..options.clone()
            }
        } else {
            options.clone()
        };
        let result = client.download_resource(&path, &output, range, &opts).await;
        if case == 3 {
            assert_eq!(
                std::fs::read(&output)?,
                b"{\"error\":\"literal file bytes\"}"
            );
            assert_eq!(result?.bytes, 30);
        } else {
            let error = result.unwrap_err();
            assert!(!format!("{error:?} {error}").contains(KEY));
            match case {
                0 | 1 | 2 | 7 | 8 => {
                    assert!(matches!(error, Error::ResourceTransferRejected { .. }))
                }
                4 => assert!(matches!(error, Error::Authentication { status: 401 })),
                5 => assert!(
                    matches!(error,Error::AccessDenied{response} if response.status()==403 && response.body_bytes()==KEY.as_bytes())
                ),
                6 => assert!(
                    matches!(error,Error::Http{response} if response.status()==404 && response.body_bytes()==KEY.as_bytes())
                ),
                _ => unreachable!(),
            }
            // A contradictory Content-Length is rejected before local creation.
            assert!(!output.exists());
        }
    }
    let requests = server.finish().await?;
    assert_eq!(
        requests
            .iter()
            .filter(
                |r| r.starts_with("GET /prefix/rest/f/api/raw/private-volume/literal%20%25.bin ")
            )
            .count(),
        9
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.to_ascii_lowercase().contains("range: bytes=1-2\r\n"))
            .count(),
        3
    );
    Ok(())
}

#[tokio::test]
async fn resource_upload_keeps_unknown_ack_or_digest_outcomes_and_preflight_timeout_separate(
) -> TestResult {
    use verysync_sidecar::{
        PathStyle, ResourcePath, ResourceTransferOptions, ResourceUploadConflict, ResourceVolumeId,
    };
    let ack = |bytes: &[u8]| Reply {
        status: 200,
        body: bytes.to_vec(),
        headers: String::new(),
        delay: Duration::ZERO,
    };
    let mut slow = Reply::json(serde_json::json!({"myID":ID}));
    slow.delay = Duration::from_millis(100);
    let server=ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"myID":ID})),ack(b"200 OK\n"),Reply::json(serde_json::json!({"myID":ID})),
        Reply::json(serde_json::json!({"path":"/private/target","name":"target","size":5,"mode":420,"modified":"native-value","isDir":false,"checksums":{"sha256":"00".repeat(32)}})),
        Reply::json(serde_json::json!({"myID":ID})),ack(KEY.as_bytes()),slow,
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let path = ResourcePath::root(ResourceVolumeId::parse("private-volume")?, PathStyle::Unix)
        .child("target")?;
    let root = tempfile::tempdir()?;
    let input = root.path().join("source.bin");
    std::fs::write(&input, b"hello")?;
    let options = ResourceTransferOptions {
        max_bytes: 5,
        deadline: Duration::from_secs(2),
    };
    assert!(
        matches!(client.upload_resource(&path,&input,ResourceUploadConflict::RejectExisting,&options).await,
        Err(Error::MutationOutcomeUnknown{source,..}) if matches!(*source,Error::ResourceTransferRejected{..}))
    );
    let error = client
        .upload_resource(&path, &input, ResourceUploadConflict::Replace, &options)
        .await
        .unwrap_err();
    assert!(!format!("{error:?} {error}").contains(KEY));
    assert!(
        matches!(error,Error::MutationOutcomeUnknown{source,..} if matches!(source.as_ref(),Error::InvalidResponse{response,..} if response.body_bytes()==KEY.as_bytes()))
    );
    assert!(matches!(
        client
            .upload_resource(
                &path,
                &input,
                ResourceUploadConflict::Replace,
                &ResourceTransferOptions {
                    deadline: Duration::from_millis(20),
                    ..options
                }
            )
            .await,
        Err(Error::Timeout { .. })
    ));
    assert_eq!(std::fs::read(&input)?, b"hello");
    let requests = server.finish().await?;
    let writes = requests
        .iter()
        .filter(|r| r.starts_with("POST "))
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 2);
    assert!(writes[0]
        .starts_with("POST /prefix/rest/f/api/resources/private-volume/target?override=false "));
    assert!(writes[1]
        .starts_with("POST /prefix/rest/f/api/resources/private-volume/target?override=true "));
    for request in writes {
        assert!(request
            .to_ascii_lowercase()
            .contains("content-length: 5\r\n"));
        assert!(request.ends_with("hello"));
    }
    Ok(())
}

#[tokio::test]
async fn streamed_download_retains_real_partial_files_after_chunk_limit_and_transport_failure(
) -> TestResult {
    use verysync_sidecar::{PathStyle, ResourcePath, ResourceTransferOptions, ResourceVolumeId};
    for chunked in [false, true] {
        let root = tempfile::tempdir()?;
        let output = root.path().join("partial.bin");
        let observed = output.clone();
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let endpoint = ManagementEndpoint::http(&format!("http://{}/", listener.local_addr()?))?;
        let server = tokio::spawn(async move {
            for stage in 0..4 {
                let (mut stream, _) =
                    tokio::time::timeout(Duration::from_secs(3), listener.accept()).await??;
                let mut request = Vec::new();
                while !request.windows(4).any(|v| v == b"\r\n\r\n") {
                    let mut block = [0; 1024];
                    let n = stream.read(&mut block).await?;
                    if n == 0 || request.len() + n > 16384 {
                        return Err("invalid stream fixture request".into());
                    }
                    request.extend_from_slice(&block[..n]);
                }
                if stage < 3 {
                    let body = if stage == 0 {
                        serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})
                    } else {
                        serde_json::json!({"myID":ID})
                    };
                    let bytes = serde_json::to_vec(&body)?;
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).as_bytes()).await?;
                    stream.write_all(&bytes).await?;
                } else if chunked {
                    stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n").await?;
                    tokio::time::timeout(Duration::from_secs(2), async {
                        loop {
                            if tokio::fs::metadata(&observed)
                                .await
                                .is_ok_and(|m| m.len() == 3)
                            {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    })
                    .await?;
                    let _ = stream.write_all(b"3\r\ndef\r\n0\r\n\r\n").await;
                } else {
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nabc").await?;
                }
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        let client = Client::connect(ConnectOptions::new(endpoint, ApiKey::new(KEY)?)).await?;
        let path = ResourcePath::root(ResourceVolumeId::parse("volume")?, PathStyle::Unix)
            .child("file")?;
        let error = client
            .download_resource(
                &path,
                &output,
                None,
                &ResourceTransferOptions {
                    max_bytes: if chunked { 4 } else { 1024 },
                    deadline: Duration::from_secs(3),
                },
            )
            .await
            .unwrap_err();
        if chunked {
            assert!(matches!(error, Error::ResourceTransferRejected { .. }));
        } else {
            assert!(matches!(error, Error::Transport { .. }));
        }
        assert_eq!(tokio::fs::read(&output).await?, b"abc");
        server.await??;
    }
    Ok(())
}

#[tokio::test]
async fn resource_selection_uses_root_route_and_nested_escaped_volume_relative_uris() -> TestResult
{
    use verysync_sidecar::{
        PathStyle, ResourceArchiveFormat, ResourcePath, ResourceTransferOptions, ResourceVolumeId,
        TargetPath,
    };
    let identity = || Reply::json(serde_json::json!({"myID":ID}));
    let archive = b"PK synthetic opaque archive payload";
    let server=ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),identity(),
        identity(),Reply::json(serde_json::json!({"path":"/base","name":"base","size":0,"mode":493,"modified":"native-value","isDir":true,"items":[]})),
        identity(),Reply{status:200,body:archive.to_vec(),headers:"Content-Type: application/zip\r\n".into(),delay:Duration::ZERO},
    ]).await?;
    let client = Client::connect(server.options()?).await?;
    let base = ResourcePath::root(ResourceVolumeId::parse("volume")?, PathStyle::Unix)
        .child("base 二 %,dir")?;
    let output = tempfile::tempdir()?.keep().join("selection.zip");
    let result = client
        .download_selected_resources(
            &base,
            &[
                TargetPath::remote(PathStyle::Unix, "reports/二%,x.txt")?,
                TargetPath::remote(PathStyle::Unix, "line\nbreak.txt")?,
            ],
            ResourceArchiveFormat::Zip,
            &output,
            &ResourceTransferOptions::default(),
        )
        .await?;
    assert_eq!(std::fs::read(&output)?, archive);
    assert_eq!(result.bytes, archive.len() as u64);
    std::fs::remove_dir_all(output.parent().ok_or("output parent absent")?)?;
    let requests = server.finish().await?;
    let target = requests
        .last()
        .ok_or("missing selection request")?
        .split_whitespace()
        .nth(1)
        .ok_or("missing target")?;
    let uri = url::Url::parse(&format!("http://synthetic.invalid{target}"))?;
    assert_eq!(uri.path(), "/prefix/rest/f/api/raw/volume/");
    let query = uri
        .query_pairs()
        .into_owned()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(query.get("files").map(String::as_str),Some("base%20%E4%BA%8C%20%25%2Cdir/reports/%E4%BA%8C%25%2Cx.txt,base%20%E4%BA%8C%20%25%2Cdir/line%0Abreak.txt"));
    Ok(())
}

#[tokio::test]
async fn resource_mutation_roots_and_cross_volume_ids_are_rejected_before_requests() -> TestResult {
    use verysync_sidecar::{
        PathStyle, ResourceConflictPolicy, ResourceDeleteScope, ResourcePath, ResourceVolumeId,
    };
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let root = ResourcePath::root(ResourceVolumeId::parse("source-volume")?, PathStyle::Unix);
    let child = root.clone().child("file")?;
    let other = ResourcePath::root(ResourceVolumeId::parse("other-volume")?, PathStyle::Unix)
        .child("file")?;
    assert!(matches!(
        client.create_resource_directory(&root).await,
        Err(Error::InvalidPath { .. })
    ));
    assert!(matches!(
        client
            .delete_resource(&root, ResourceDeleteScope::RecursiveDirectory)
            .await,
        Err(Error::InvalidPath { .. })
    ));
    assert!(matches!(
        client.write_resource_text(&root, "refused").await,
        Err(Error::InvalidPath { .. })
    ));
    assert!(matches!(
        client
            .copy_resource(&root, &child, ResourceConflictPolicy::RejectExisting)
            .await,
        Err(Error::InvalidPath { .. })
    ));
    assert!(matches!(
        client
            .move_resource(&child, &root, ResourceConflictPolicy::RejectExisting)
            .await,
        Err(Error::InvalidPath { .. })
    ));
    assert!(matches!(
        client
            .copy_resource(&child, &other, ResourceConflictPolicy::RejectExisting)
            .await,
        Err(Error::ResourceMutationRejected { .. })
    ));
    assert!(matches!(
        client
            .move_resource(&child, &other, ResourceConflictPolicy::OverwriteAndMerge)
            .await,
        Err(Error::ResourceMutationRejected { .. })
    ));
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn resource_copy_encodes_native_destination_uri_inside_query_and_reads_both_resources(
) -> TestResult {
    use verysync_sidecar::{PathStyle, ResourceConflictPolicy, ResourcePath, ResourceVolumeId};
    let identity = || Reply::json(serde_json::json!({"myID":ID}));
    let metadata = |name: &str| {
        Reply::json(
            serde_json::json!({"path":"/private/metadata","name":name,"size":5,"mode":420,"modified":"native-value","isDir":false}),
        )
    };
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        identity(),
        identity(),
        identity(),
        metadata("from %.bin"),
        identity(),
        Reply {
            status: 404,
            body: b"not found".to_vec(),
            headers: String::new(),
            delay: Duration::ZERO,
        },
        Reply {
            status: 200,
            body: b"200 OK\n".to_vec(),
            headers: String::new(),
            delay: Duration::ZERO,
        },
        identity(),
        metadata("to 二 %.bin"),
        identity(),
        metadata("from %.bin"),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let root = ResourcePath::root(ResourceVolumeId::parse("volume")?, PathStyle::Unix);
    let result = client
        .copy_resource(
            &root.clone().child("from %.bin")?,
            &root.child("to 二 %.bin")?,
            ResourceConflictPolicy::RejectExisting,
        )
        .await?;
    assert_eq!(result.metadata.name, "to 二 %.bin");
    assert!(!result.generated_name);
    assert!(!format!("{result:?}").contains("from %"));
    assert!(!format!("{result:?}").contains("to 二"));
    let requests = server.finish().await?;
    let writes = requests
        .iter()
        .filter(|r| r.starts_with("PATCH "))
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 1);
    let request = writes[0].lines().next().ok_or("missing request line")?;
    let target = request.split_whitespace().nth(1).ok_or("missing target")?;
    let uri = url::Url::parse(&format!("http://synthetic.invalid{target}"))?;
    assert_eq!(
        uri.path(),
        "/prefix/rest/f/api/resources/volume/from%20%25.bin"
    );
    let query = uri
        .query_pairs()
        .into_owned()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        query.get("destination").map(String::as_str),
        Some("/volume/to%20%E4%BA%8C%20%25.bin")
    );
    assert_eq!(query.get("action").map(String::as_str), Some("copy"));
    assert_eq!(query.get("override").map(String::as_str), Some("false"));
    assert_eq!(query.get("rename").map(String::as_str), Some("false"));
    Ok(())
}

#[tokio::test]
async fn resource_keep_both_ambiguous_parent_changes_are_unknown_without_retries() -> TestResult {
    use verysync_sidecar::{PathStyle, ResourceConflictPolicy, ResourcePath, ResourceVolumeId};
    let identity = || Reply::json(serde_json::json!({"myID":ID}));
    let file = |name: &str| serde_json::json!({"path":"/private/metadata","name":name,"size":5,"mode":420,"modified":"native-value","isDir":false});
    let parent = |new: bool| {
        let mut items = vec![file("source.bin"), file("target.bin")];
        if new {
            items.push(file("target(1).bin"));
            items.push(file("concurrent.bin"));
        }
        Reply::json(
            serde_json::json!({"path":"/","name":"root","size":0,"mode":493,"modified":"native-value","isDir":true,"items":items}),
        )
    };
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        identity(),
        identity(),
        identity(),
        Reply::json(file("source.bin")),
        identity(),
        Reply::json(file("target.bin")),
        identity(),
        parent(false),
        Reply {
            status: 200,
            body: b"200 OK\n".to_vec(),
            headers: String::new(),
            delay: Duration::ZERO,
        },
        identity(),
        parent(true),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let root = ResourcePath::root(ResourceVolumeId::parse("volume")?, PathStyle::Unix);
    assert!(
        matches!(client.copy_resource(&root.clone().child("source.bin")?,&root.child("target.bin")?,ResourceConflictPolicy::KeepBoth).await,Err(Error::MutationOutcomeUnknown{source,..})if matches!(source.as_ref(),Error::ResourceMutationRejected{..}))
    );
    assert_eq!(
        server
            .finish()
            .await?
            .iter()
            .filter(|r| r.starts_with("PATCH "))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn local_sync_target_syntax_subpaths_and_unbounded_pages_are_refused_before_requests(
) -> TestResult {
    use verysync_sidecar::{
        CreateLocalSyncJob, LocalSyncJobId, LocalSyncJobPatch, LocalSyncMode, LocalSyncPreviewId,
        PathStyle, StorageEndpoint, TargetPath,
    };
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        Reply::json(serde_json::json!({"myID":ID})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let unix = StorageEndpoint::local(TargetPath::remote(PathStyle::Unix, "/synthetic/source")?)?;
    let windows = StorageEndpoint::local(TargetPath::remote(
        PathStyle::Windows,
        r"C:\synthetic\source",
    )?)?;
    for label in ["", "   ", "\t"] {
        assert!(CreateLocalSyncJob::new(
            label,
            unix.clone(),
            unix.clone(),
            LocalSyncMode::MirrorAToB
        )
        .is_err());
        assert!(LocalSyncJobPatch::default().label(label).is_err());
    }
    let options = CreateLocalSyncJob::new(
        "explicit synthetic label",
        windows,
        unix.clone(),
        LocalSyncMode::MirrorAToB,
    )?;
    assert!(matches!(
        client.create_local_sync_job(&options).await,
        Err(Error::InvalidConfiguration { .. })
    ));
    for path in ["../escape", "/absolute", "a//b", "a/./b", r"a\b"] {
        assert!(matches!(
            client.browse_storage_endpoint(&unix, path).await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    for name in ["", "..", "a/b"] {
        assert!(matches!(
            client.create_storage_directory(&unix, "", name).await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    let job = LocalSyncJobId::parse("synthetic-job")?;
    let preview = LocalSyncPreviewId::parse("synthetic-preview")?;
    for limit in [0, 1001] {
        assert!(matches!(
            client
                .local_sync_preview_actions(&job, &preview, 0, limit)
                .await,
            Err(Error::InvalidConfiguration { .. })
        ));
    }
    assert!(matches!(
        client.local_sync_history(None, 0, 100).await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        client
            .update_local_sync_job(&job, &LocalSyncJobPatch::default())
            .await,
        Err(Error::InvalidConfiguration { .. })
    ));
    assert!(CreateLocalSyncJob::new(
        "explicit two-way job",
        unix.clone(),
        unix.clone(),
        LocalSyncMode::Bidirectional
    )?
    .delete_extraneous(true)
    .is_err());
    assert_eq!(server.finish().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn local_sync_scoped_put_preserves_credentials_unknown_fields_and_exact_item_encoding(
) -> TestResult {
    use verysync_sidecar::{LocalSyncJobId, LocalSyncJobPatch};
    let id = LocalSyncJobId::parse("private /?% job")?;
    let original = serde_json::json!({"jobId":id.as_str(),"label":"old private label","group":"retained group",
        "sideA":{"fsType":"basic","uri":"/private/source","transfers":2,"unknownEndpoint":{"value":7}},
        "sideB":{"fsType":"sftp","uri":"sftp://private.invalid/target","transfers":4,"password":"retained synthetic password"},
        "mode":"mirror_a_to_b","enabled":true,"syncOnStartup":false,"deleteExtraneous":false,
        "unknownSetting":{"future":true},"scheduleMode":"off"});
    let mut updated = original.clone();
    updated["label"] = serde_json::json!("new private label");
    let identity = || Reply::json(serde_json::json!({"myID":ID}));
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        identity(),
        identity(),
        Reply::json(original),
        identity(),
        Reply::json(updated.clone()),
        identity(),
        Reply::json(updated.clone()),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let result = client
        .update_local_sync_job(
            &id,
            &LocalSyncJobPatch::default().label("new private label")?,
        )
        .await?;
    assert!(result.requested_fields_match);
    assert_eq!(serde_json::to_value(&result.configuration)?, updated);
    let debug = format!("{result:?}");
    assert!(
        !debug.contains("password")
            && !debug.contains("private.invalid")
            && !debug.contains("private label")
    );
    let requests = server.finish().await?;
    let writes = requests
        .iter()
        .filter(|r| r.starts_with("PUT "))
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 1);
    assert!(writes[0]
        .starts_with("PUT /prefix/rest/localsync/jobs/private%20%2F%3F%25%20job HTTP/1.1\r\n"));
    let body: serde_json::Value = serde_json::from_str(
        writes[0]
            .split_once("\r\n\r\n")
            .ok_or("request body absent")?
            .1,
    )?;
    assert_eq!(body, updated);
    Ok(())
}

#[tokio::test]
async fn local_sync_http_success_error_envelope_is_unknown_once_and_changed_identity_prevents_probe(
) -> TestResult {
    use verysync_sidecar::{PathStyle, StorageEndpoint, TargetPath};
    let endpoint =
        StorageEndpoint::local(TargetPath::remote(PathStyle::Unix, "/synthetic/source")?)?;
    let identity = || Reply::json(serde_json::json!({"myID":ID}));
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        identity(),
        identity(),
        Reply::json(
            serde_json::json!({"error":"synthetic invalid endpoint","code":"future_native_code"}),
        ),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(
        matches!(client.probe_storage_endpoint(&endpoint).await,Err(Error::MutationOutcomeUnknown{source,..})if matches!(source.as_ref(),Error::Api{response,..}if response.status()==200))
    );
    let requests = server.finish().await?;
    let writes = requests
        .iter()
        .filter(|r| r.starts_with("POST "))
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 1);
    let body: serde_json::Value = serde_json::from_str(
        writes[0]
            .split_once("\r\n\r\n")
            .ok_or("request body absent")?
            .1,
    )?;
    assert_eq!(
        body,
        serde_json::json!({"fsType":"basic","uri":"/synthetic/source","transfers":2})
    );
    let other = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        identity(),
        Reply::json(serde_json::json!({"myID":other})),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    assert!(matches!(
        client.probe_storage_endpoint(&endpoint).await,
        Err(Error::IdentityMismatch { .. })
    ));
    assert_eq!(server.finish().await?.len(), 3);
    Ok(())
}

#[tokio::test]
async fn local_sync_selection_and_resolution_keep_native_shapes_and_exact_preview_identities(
) -> TestResult {
    use verysync_sidecar::{
        LocalSyncActionRange, LocalSyncConflictResolution, LocalSyncConflictSide, LocalSyncJobId,
        LocalSyncPreviewId, LocalSyncSelection,
    };
    let identity = || Reply::json(serde_json::json!({"myID":ID}));
    let id = LocalSyncJobId::parse("job /%")?;
    let preview = LocalSyncPreviewId::parse("preview /%")?;
    let snapshot = |name: &str| serde_json::json!({"id":name,"jobId":id,"operationId":"operation","count":3,"expiresAt":"native-time","scanIssueCount":0});
    let old = snapshot(preview.as_str());
    let resolved = snapshot("replacement-preview");
    let totals = serde_json::json!({"resolvedConflicts":0,"permissionFiles":0,"copyFiles":1,"deleteFiles":0,"createDirectories":0,"deleteDirectories":0,"conflicts":0,"copyBytes":5});
    let receipt = serde_json::json!({"id":"run-identity","jobId":id,"started":"native-time","finished":"0001-01-01T00:00:00Z","count":1,"summary":{"completed":0,"failed":0,"skipped":0}});
    let server = ScriptedServer::start(vec![
        Reply::json(serde_json::json!({"version":"v2.33.2","os":"linux","arch":"amd64"})),
        identity(),
        identity(),
        Reply::json(old.clone()),
        identity(),
        Reply::json(totals),
        identity(),
        Reply::json(old.clone()),
        identity(),
        Reply::json(receipt),
        identity(),
        Reply::json(old),
        identity(),
        Reply::json(resolved.clone()),
        identity(),
        Reply::json(resolved),
    ])
    .await?;
    let client = Client::connect(server.options()?).await?;
    let selection = LocalSyncSelection::including(vec![LocalSyncActionRange::single(0)])?;
    assert_eq!(
        client
            .local_sync_selection_summary(&id, &preview, &selection)
            .await?
            .copy_bytes,
        5
    );
    assert_eq!(
        client
            .run_local_sync_preview(&id, &preview, &selection)
            .await?
            .count,
        1
    );
    let resolution =
        LocalSyncConflictResolution::at_path("private/中文 %.txt", LocalSyncConflictSide::B)?;
    assert!(!format!("{resolution:?}").contains("private"));
    let replaced = client
        .resolve_local_sync_conflict(&id, &preview, &resolution)
        .await?;
    assert_eq!(replaced.id.as_str(), "replacement-preview");
    let requests = server.finish().await?;
    let posts = requests
        .iter()
        .filter(|r| r.starts_with("POST "))
        .collect::<Vec<_>>();
    assert_eq!(posts.len(), 3);
    assert!(posts[0].starts_with("POST /prefix/rest/localsync/jobs/job%20%2F%25/previews/preview%20%2F%25/selection-summary "));
    let body = |request: &String| -> TestResult<serde_json::Value> {
        Ok(serde_json::from_str(
            request.split_once("\r\n\r\n").ok_or("missing body")?.1,
        )?)
    };
    assert_eq!(
        body(posts[0])?,
        serde_json::json!({"all":false,"include":[[0,0]]})
    );
    assert_eq!(
        body(posts[1])?,
        serde_json::json!({"previewId":preview,"selection":{"all":false,"include":[[0,0]]}})
    );
    assert_eq!(
        body(posts[2])?,
        serde_json::json!({"path":"private/中文 %.txt","recursive":false,"side":"b"})
    );
    Ok(())
}
