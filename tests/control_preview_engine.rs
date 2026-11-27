//! Exercise the settings preview against a privately owned fixed native program.
#![cfg(feature = "engine-tests")]

#[path = "common/managed_fixture.rs"]
mod managed_fixture;

use managed_fixture::TestResult;
use std::{
    net::{Ipv4Addr, TcpListener},
    path::Path,
    time::{Duration, Instant},
};
use verysync_sidecar::{
    Client, ConnectOptions, ControlSubmission, CreateFolderOptions, DeviceId, Error, FolderId,
    FolderPatch, GuiListenAddress, GuiListenerPatch, ManagedInstance, ManagedOptions,
    ManagementEndpoint, SettingsChange, SettingsFieldState as State, SettingsValue, TargetPath,
};

const WAIT: Duration = Duration::from_secs(10);
const SAMPLE: &[u8] = b"the synthetic file remains byte-for-byte unchanged\n";

fn loopback_listener() -> std::io::Result<TcpListener> {
    loop {
        let binding = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        if binding.local_addr()?.port() != 18886 {
            return Ok(binding);
        }
    }
}

async fn await_listener(options: ConnectOptions) -> TestResult<ConnectOptions> {
    let deadline = Instant::now() + WAIT;
    loop {
        match Client::connect(options.clone()).await {
            Ok(_) => return Ok(options),
            Err(Error::IdentityMismatch { .. }) => {
                return Err("isolated listener selected a different device".into())
            }
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn verify(core: &mut ManagedInstance, root: &Path, alternate_bind: &str) -> TestResult {
    let folder_path = root.join("sample");
    std::fs::create_dir(&folder_path)?;
    let data = folder_path.join("retained.bin");
    std::fs::write(&data, SAMPLE)?;
    let id = FolderId::parse("private-preview-resource")?;
    let client = core.client().clone();
    let expected: DeviceId = client.instance().device_id.clone();
    let key = client.gui_authentication().await?.api_key()?;
    let writer = Client::connect(
        ConnectOptions::new(client.endpoint().clone(), key.clone())
            .expected_device_id(expected.clone()),
    )
    .await?;
    client
        .create_folder(
            &CreateFolderOptions::new(id.clone(), TargetPath::local(&folder_path))
                .label("Before preview")
                .paused(true),
        )
        .await?;

    let folder_patch = FolderPatch::default().label("After preview");
    let preview = client
        .preview_settings_changes(&[SettingsChange::Folder {
            id: &id,
            patch: &folder_patch,
        }])
        .await?;
    assert_eq!(client.folder(&id).await?.label, "Before preview");
    assert!(
        matches!(&preview.steps()[0].fields()[0].previous, SettingsValue::Text(value) if value == "Before preview")
    );
    writer
        .update_folder(&id, &FolderPatch::default().paused(false))
        .await?;
    let report = client.commit_settings_preview(preview).await;
    assert_eq!(report.steps[0].fields[0].state, State::Confirmed);
    assert!(report.steps[0].error.is_none());
    let after = client.folder(&id).await?;
    assert_eq!(after.label, "After preview");
    assert!(!after.paused);
    assert_eq!(
        after.path.to_protocol()?,
        TargetPath::local(&folder_path).to_protocol()?
    );

    let patch = FolderPatch::default().label("Stale requested label");
    let preview = client
        .preview_settings_changes(&[SettingsChange::Folder {
            id: &id,
            patch: &patch,
        }])
        .await?;
    writer
        .update_folder(&id, &FolderPatch::default().label("Independent label"))
        .await?;
    let report = client.commit_settings_preview(preview).await;
    assert!(matches!(
        report.steps[0].error,
        Some(Error::ConfigurationChanged)
    ));
    assert_eq!(report.steps[0].submission, ControlSubmission::NotSubmitted);
    assert_eq!(report.steps[0].fields[0].state, State::Conflict);
    assert_eq!(client.folder(&id).await?.label, "Independent label");

    let engine = client.observe_control_identity().await?;
    assert_eq!(
        engine.engine_version().version,
        verysync_sidecar::BASELINE_ENGINE_VERSION
    );
    let previous = client.gui_listener().await?;
    let gui_patch = GuiListenerPatch::default().address(GuiListenAddress::tcp(alternate_bind)?);
    let preview = client
        .preview_settings_changes(&[SettingsChange::GuiListener { patch: &gui_patch }])
        .await?;
    assert!(preview.steps()[0].may_interrupt_management());
    assert_eq!(client.gui_listener().await?.address, previous.address);

    let pid = core.process_id();
    let mut report = client.commit_settings_preview(preview).await;
    assert!(matches!(
        report.steps[0].submission,
        ControlSubmission::Acknowledged { .. } | ControlSubmission::PossiblySubmitted
    ));
    assert_eq!(report.steps[0].fields[0].state, State::Unknown);
    let new_endpoint = ManagementEndpoint::http(&format!("http://{alternate_bind}/"))?;
    let options = await_listener(
        ConnectOptions::new(new_endpoint, key)
            .expected_device_id(expected.clone())
            .request_timeout(Duration::from_millis(250))?,
    )
    .await?;
    core.reconnect_management(options.clone()).await?;
    report.steps[0].observe_listener(options).await?;
    assert_eq!(report.steps[0].fields[0].state, State::Confirmed);
    assert_eq!(
        report.steps[0].observation.as_ref().unwrap().device_id(),
        &expected
    );
    assert_eq!(core.process_id(), pid);
    let confirmed = core.client().gui_listener().await?;
    assert_eq!(confirmed.address.tcp_authority(), Some(alternate_bind));
    assert_eq!(confirmed.enabled, previous.enabled);
    assert_eq!(confirmed.use_tls, previous.use_tls);
    assert_eq!(core.client().folder(&id).await?.label, "Independent label");
    assert_eq!(std::fs::read(data)?, SAMPLE);
    println!("p4 native: selected folder values verified, unrelated pause preserved, independent edit retained, listener moved to trusted endpoint, device and process retained, sample matched");
    Ok(())
}

#[tokio::test]
async fn native_settings_preview_retains_unrelated_state_and_moves_the_listener() -> TestResult {
    #[cfg(unix)]
    let root = tempfile::Builder::new()
        .prefix("vss-preview-")
        .tempdir_in("/tmp")?;
    #[cfg(windows)]
    let root = tempfile::Builder::new().prefix("vss-preview-").tempdir()?;
    let primary = loopback_listener()?;
    let alternate = loopback_listener()?;
    let first = primary.local_addr()?;
    let second = alternate.local_addr()?.to_string();
    let fixture = managed_fixture::options(&root.path().join("state"))?;
    let options = ManagedOptions::new(
        fixture.program().clone(),
        fixture.state_directory(),
        ManagementEndpoint::http(&format!("http://{first}/"))?,
    )?
    .startup_timeout(Duration::from_secs(25))?;
    drop(primary);
    let mut core = ManagedInstance::start(options).await?;
    drop(alternate);

    let result = verify(&mut core, root.path(), &second).await;
    let cleanup = core.shutdown(WAIT).await;
    if cleanup.is_err() {
        let forced = core.force_stop(WAIT).await?;
        assert!(forced.tree_stopped && forced.state_released);
    }
    result?;
    let exit = cleanup?;
    assert_eq!(exit.code, Some(0));
    assert!(exit.tree_stopped && exit.state_released && !exit.forced);
    root.close()?;
    println!("p4 native cleanup: normal owned exit, released state, removed test directory");
    Ok(())
}
