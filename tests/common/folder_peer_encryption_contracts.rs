//! A folder encryption edit preserves the entire list apart from one peer field.
use super::*;
use serde_json::{json, Value};
use verysync_sidecar::{DeviceId, FolderId};

const FOLDER: &str = "synthetic-encrypted-folder";
const PASSWORD: &str = "synthetic phrase with whitespace  空格 ";

fn version() -> Reply {
    Reply::json(json!({"version":"v2.33.2","os":"linux","arch":"amd64"}))
}

fn identity() -> Reply {
    Reply::json(json!({"myID":ID}))
}

fn devices(peer: &str) -> Reply {
    Reply::json(
        json!({"devices":[{"deviceID":peer,"name":"peer","addresses":["dynamic"],
        "compression":"metadata","paused":true}]}),
    )
}

fn folder(peers: &Value) -> Reply {
    Reply::json(
        json!({"folders":[{"id":FOLDER,"label":"fixture","path":"/private-fixture",
        "paused":true,"devices":peers}]}),
    )
}

#[tokio::test]
async fn folder_peer_encryption_preserves_other_settings_and_reports_actual_password_state(
) -> TestResult {
    let peer = ID.replacen('A', "B", 1);
    let other = ID.replacen('A', "C", 1);
    let before = json!([
        {"deviceID":peer,"introducedBy":other,"unknown":{"keep":true}},
        {"deviceID":other,"encryptionPassword":"synthetic other secret","futureField":[1,2]},
    ]);
    for (requested, observed, expected_state, expected_match) in [
        (Some(PASSWORD), Some(PASSWORD), Some(true), true),
        (None, Some(""), Some(false), true),
        (
            Some(PASSWORD),
            Some("different synthetic password"),
            Some(true),
            false,
        ),
        (Some(PASSWORD), None, None, false),
    ] {
        let mut actual = before.clone();
        if let Some(value) = observed {
            actual[0]["encryptionPassword"] = value.into();
        }
        let server = ScriptedServer::start(vec![
            version(),
            identity(),
            identity(),
            devices(&peer),
            folder(&before),
            Reply::json(json!({})),
            folder(&actual),
            identity(),
            folder(&actual),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let folder_id = FolderId::parse(FOLDER)?;
        let peer_id = DeviceId::parse(&peer)?;
        let update = client
            .set_folder_peer_encryption_password(&folder_id, &peer_id, requested)
            .await?;
        assert_eq!(update.password_is_set, expected_state);
        assert_eq!(update.requested_password_matches, expected_match);
        assert_eq!(
            client
                .folder_peer_encryption_password_is_set(&folder_id, &peer_id)
                .await?,
            expected_state
        );
        assert!(!format!("{update:?}").contains(PASSWORD));
        let requests = server.finish().await?;
        let mut patches = requests.iter().filter(|line| line.starts_with("PATCH "));
        let patch = patches.next().ok_or("missing sole mutation")?;
        assert!(patches.next().is_none());
        assert!(patch.starts_with(&format!("PATCH /prefix/rest/config/folders/{FOLDER} ")));
        let written: Value =
            serde_json::from_str(patch.split_once("\r\n\r\n").ok_or("body absent")?.1)?;
        let mut expected = before.clone();
        expected[0]["encryptionPassword"] = requested.unwrap_or("").into();
        assert_eq!(written, json!({"devices":expected}));
    }
    Ok(())
}

#[tokio::test]
async fn folder_peer_encryption_requires_a_unique_existing_association_before_writing() -> TestResult
{
    let peer = ID.replacen('A', "B", 1);
    for (members, duplicate) in [
        (json!([]), false),
        (json!([{"deviceID":peer},{"deviceID":peer}]), true),
    ] {
        let server = ScriptedServer::start(vec![
            version(),
            identity(),
            identity(),
            devices(&peer),
            folder(&members),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let result = client
            .set_folder_peer_encryption_password(
                &FolderId::parse(FOLDER)?,
                &DeviceId::parse(&peer)?,
                Some(PASSWORD),
            )
            .await;
        if duplicate {
            assert!(matches!(result, Err(Error::InvalidResponse { .. })));
        } else {
            assert!(matches!(result, Err(Error::FolderPeerNotAssociated)));
        }
        assert!(server
            .finish()
            .await?
            .iter()
            .all(|request| request.starts_with("GET ")));
    }
    Ok(())
}

#[tokio::test]
async fn folder_peer_encryption_invalid_post_write_readback_is_uncertain_and_redacted() -> TestResult
{
    let peer = ID.replacen('A', "B", 1);
    for actual in [
        json!([]),
        json!([{"deviceID":peer,"encryptionPassword":{"private":PASSWORD}}]),
    ] {
        let server = ScriptedServer::start(vec![
            version(),
            identity(),
            identity(),
            devices(&peer),
            folder(&json!([{"deviceID":peer}])),
            Reply::json(json!({})),
            folder(&actual),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let error = client
            .set_folder_peer_encryption_password(
                &FolderId::parse(FOLDER)?,
                &DeviceId::parse(&peer)?,
                Some(PASSWORD),
            )
            .await
            .expect_err("write outcome must stay uncertain");
        assert!(matches!(error, Error::MutationOutcomeUnknown { .. }));
        assert!(!format!("{error:?} {error}").contains(PASSWORD));
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
