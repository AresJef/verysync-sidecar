//! Actual management credential changes and explicit owned-client recovery.
#[path = "common/managed_fixture.rs"]
mod managed_fixture;
use managed_fixture::{options, TestResult};
use std::time::Duration;
use verysync_sidecar::*;

#[tokio::test]
async fn gui_password_sessions_logout_and_api_key_management_are_independent() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-gui-auth-")
        .tempdir()?
        .keep();
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let endpoint = core.client().endpoint().clone();
    let identity = core.client().instance().device_id.clone();
    let mut entropy = [0u8; 24];
    getrandom::fill(&mut entropy)?;
    let password: String = entropy.iter().map(|b| format!("{b:02x}")).collect();
    let credentials = GuiCredentials::new("synthetic-gui-user", password.clone())?;
    let changed = core
        .set_local_gui_credentials(&credentials, Duration::from_secs(10))
        .await?;
    assert!(changed.username_matches && changed.configuration.password_is_set());
    assert!(matches!(changed.configuration.mode, GuiAuthMode::Static));
    let configured = core.client().configuration().await?;
    assert!(configured.native_document()["gui"]["password"]
        .as_str()
        .is_some_and(|s| s.starts_with("$2") && s != password));
    let login =
        GuiLoginOptions::new(endpoint.clone(), credentials).expected_device_id(identity.clone());
    let session = GuiSession::login(login.clone()).await?;
    let second = GuiSession::login(login).await?;
    assert_eq!(session.system_status().await?.device_id, identity);
    assert_eq!(session.version().await?.version, "v2.33.2");
    let obtained = session.gui_authentication().await?.api_key()?;
    assert_eq!(
        Client::connect(
            ConnectOptions::new(endpoint.clone(), obtained).expected_device_id(identity.clone())
        )
        .await?
        .instance()
        .device_id,
        identity
    );
    let wrong = GuiSession::login(
        GuiLoginOptions::new(
            endpoint,
            GuiCredentials::new("synthetic-gui-user", "wrong-private-test-password")?,
        )
        .expected_device_id(identity.clone()),
    )
    .await;
    assert!(
        matches!(&wrong,Err(Error::AccessDenied{response}) if response.status()==403)
            || matches!(&wrong, Err(Error::Authentication { status: 401 }))
    );
    let stale = session.clone();
    assert!(session.logout().await?.session_rejected);
    let denied = stale.system_status().await;
    assert!(
        matches!(&denied,Err(Error::AccessDenied{response}) if response.status()==403)
            || matches!(&denied, Err(Error::Authentication { status: 401 }))
    );
    assert_eq!(second.system_status().await?.device_id, identity);
    assert_eq!(core.client().system_status().await?.device_id, identity);
    assert!(second.logout().await?.session_rejected);
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    println!("native_gui_authentication_effects=14");
    Ok(())
}

#[tokio::test]
async fn key_rotation_reauthenticates_owner_retains_files_and_rejects_old_key() -> TestResult {
    let root = tempfile::Builder::new()
        .prefix("vs-auth-")
        .tempdir()?
        .keep();
    let mut core = ManagedInstance::start(options(&root.join("core"))?).await?;
    let mut other = ManagedInstance::start(options(&root.join("other"))?).await?;
    let identity = core.client().instance().device_id.clone();
    let other_identity = other.client().instance().device_id.clone();
    let other_gui = other.client().configuration().await?.native_document()["gui"].clone();
    let gui_before = core.client().configuration().await?.native_document()["gui"].clone();
    let pid = core.process_id();
    let old_client = core.client().clone();
    let old_key = core.client().gui_authentication().await?.api_key()?;
    let new_key = ApiKey::generate()?;
    let data = root.join("synthetic-data");
    std::fs::create_dir(&data)?;
    let sentinel = data.join("retained.txt");
    std::fs::write(&sentinel, b"credential change retains synthetic bytes")?;
    let folder = FolderId::parse("synthetic-authentication")?;
    core.client()
        .create_folder(
            &CreateFolderOptions::new(folder.clone(), TargetPath::local(data)).paused(true),
        )
        .await?;
    let rotated = core
        .rotate_api_key(new_key.clone(), Duration::from_secs(10))
        .await?;
    assert!(rotated.requested_key_matches && rotated.previous_key_rejected);
    assert_eq!(rotated.client.system_status().await?.device_id, identity);
    assert_eq!(core.client().system_status().await?.device_id, identity);
    assert_eq!(core.process_id(), pid);
    let mut gui_after = core.client().configuration().await?.native_document()["gui"].clone();
    gui_after["apiKey"] = gui_before["apiKey"].clone();
    assert!(gui_after == gui_before, "unrelated GUI settings changed");
    let denied = old_client.reconnect_with_api_key(old_key.clone()).await;
    assert!(
        matches!(&denied, Err(Error::AccessDenied { response }) if response.status() == 403)
            || matches!(&denied, Err(Error::Authentication { status: 401 }))
    );
    let exit = core.shutdown(Duration::from_secs(10)).await?;
    assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    core.restart(Duration::from_secs(30)).await?;
    assert_eq!(core.client().instance().device_id, identity);
    assert!(core.client().folder(&folder).await?.paused);
    assert!(core
        .client()
        .reconnect_with_api_key(new_key.clone())
        .await
        .is_ok());
    let denied = old_client.reconnect_with_api_key(old_key).await;
    assert!(
        matches!(&denied, Err(Error::AccessDenied { response }) if response.status() == 403)
            || matches!(&denied, Err(Error::Authentication { status: 401 }))
    );
    assert_eq!(
        other.client().system_status().await?.device_id,
        other_identity
    );
    assert!(
        other.client().configuration().await?.native_document()["gui"] == other_gui,
        "other instance GUI settings changed"
    );
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"credential change retains synthetic bytes"
    );
    // A separately borrowed client can rotate; the owner explicitly adopts the
    // supplied new key before using its own subsequent lifecycle operations.
    let borrowed = core.client().clone();
    let next_key = ApiKey::generate()?;
    let rotation = borrowed
        .rotate_api_key(next_key.clone(), Duration::from_secs(10))
        .await?;
    assert!(rotation.requested_key_matches && rotation.previous_key_rejected);
    core.reconnect_with_api_key(next_key).await?;
    assert_eq!(core.client().system_status().await?.device_id, identity);
    assert!(
        core.client()
            .remove_folder_keep_files(&folder)
            .await?
            .configuration_absent
    );
    assert_eq!(
        std::fs::read(&sentinel)?,
        b"credential change retains synthetic bytes"
    );
    for owned in [&mut core, &mut other] {
        let exit = owned.shutdown(Duration::from_secs(10)).await?;
        assert!(exit.tree_stopped && !exit.forced && exit.code == Some(0));
    }
    println!("management_key_rotation_effects=20");
    Ok(())
}
