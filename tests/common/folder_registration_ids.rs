use super::*;
use serde_json::json;
use verysync_sidecar::{
    CreateFolderOptions, FolderId, JoinFolderOptions, PathStyle, ShareKey, TargetPath,
};

#[tokio::test]
async fn dot_ids_in_create_options_and_native_share_preparation_send_no_registration() -> TestResult
{
    let version = || Reply::json(json!({"version":"v2.33.2","os":"linux","arch":"amd64"}));
    let identity = || Reply::json(json!({"myID":ID}));
    let path = TargetPath::remote(PathStyle::Unix, "/synthetic/private-folder")?;
    let rejected = |error| {
        matches!(
            error,
            Error::InvalidConfiguration {
                reason: "dot-segment folder IDs cannot be addressed by an item URL"
            }
        )
    };
    for id in [".", ".."] {
        let key = ShareKey::new("synthetic-read-only-share-key")?;
        let server = ScriptedServer::start(vec![
            version(),
            identity(),
            identity(),
            Reply::json(
                json!({"validate":true,"id":id,"perm":"ro","readOnlySecret":key.expose_secret()}),
            ),
        ])
        .await?;
        let client = Client::connect(server.options()?).await?;
        let share = client.validate_share_key(&key).await?;
        assert_eq!(share.registration_id().as_str(), id);
        let join = JoinFolderOptions::new(share, path.clone());
        assert!(rejected(client.join_folder(&join).await.unwrap_err()));
        let create = CreateFolderOptions::new(FolderId::parse(id)?, path.clone());
        assert!(rejected(client.create_folder(&create).await.unwrap_err()));
        let requests = server.finish().await?;
        assert_eq!(requests.len(), 4);
        assert!(requests[3].starts_with("GET /prefix/rest/svc/folder/secret_validate?"));
        assert!(requests.iter().all(|request| request.starts_with("GET ")));
        println!(
            "folder ID evidence: id={id} native_preparation_preserved=true registration_writes=0"
        );
    }
    Ok(())
}
