//! Run a complete configuration workflow against one explicitly chosen instance.

use std::path::PathBuf;
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, CreateFolderOptions, DeviceId, FolderId, FolderPatch,
    ManagementEndpoint, RawMethod, RawRequest, RequestEffect, TargetPath,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let mode=args.next().ok_or("usage: manage_existing <http|socket> <address> <expected-device-id> <new-folder-id> <absolute-local-target-path>")?;
    let address = args.next().ok_or("explicit management address required")?;
    let endpoint = match mode.to_str() {
        Some("http") => {
            ManagementEndpoint::http(address.to_str().ok_or("HTTP URL must be UTF-8")?)?
        }
        Some("socket") => ManagementEndpoint::unix_socket(PathBuf::from(address))?,
        _ => return Err("transport must be http or socket".into()),
    };
    let expected = args.next().ok_or("expected device ID required")?;
    let expected = DeviceId::parse(expected.to_str().ok_or("device ID must be ASCII")?)?;
    let id = args.next().ok_or("explicit new folder ID required")?;
    let id = FolderId::parse(id.to_str().ok_or("folder ID must be UTF-8")?)?;
    let path = PathBuf::from(args.next().ok_or("absolute local target path required")?);
    if !path.is_absolute() || args.next().is_some() {
        return Err("supply one absolute local target path and no extra arguments".into());
    }
    let key = std::env::var("VERYSYNC_EXAMPLE_API_KEY")
        .map_err(|_| "VERYSYNC_EXAMPLE_API_KEY must contain the dedicated instance's key")?;
    let client = Client::connect(
        ConnectOptions::new(endpoint, ApiKey::new(&key)?).expected_device_id(expected),
    )
    .await?;
    let system = client.system_status().await?;
    let raw = client
        .raw_request(&RawRequest::new(
            RawMethod::Get,
            ["rest", "system", "version"],
            RequestEffect::ReadOnly,
        )?)
        .await?;
    if raw.status() != 200 {
        return Err("raw version response was not HTTP 200".into());
    }
    let report = client.capabilities();
    let created = client
        .create_folder(
            &CreateFolderOptions::new(id.clone(), TargetPath::local(path))
                .label("Example initial label")
                .paused(true),
        )
        .await?;
    if !created.paused {
        return Err("creation readback is not paused; inspect the folder before retrying".into());
    }
    let updated = client
        .update_folder(&id, &FolderPatch::default().label("Example updated label"))
        .await?;
    if !updated.requested_fields_match {
        return Err(
            "label change is pending or changed by another writer; reconcile before retrying"
                .into(),
        );
    }
    let resumed = client.resume_folder(&id).await?;
    if !resumed.requested_fields_match {
        return Err("resume readback is pending or changed; reconcile before retrying".into());
    }
    let paused = client.pause_folder(&id).await?;
    if !paused.requested_fields_match {
        return Err("pause readback is pending or changed; reconcile before retrying".into());
    }
    let removed = client.remove_folder_keep_files(&id).await?;
    if !removed.configuration_absent {
        return Err("folder remains configured; reconcile before retrying".into());
    }
    println!("Managed configuration workflow: identity={}, version={}, coordinate_scope={:?}, registered=true, label_updated=true, resume_readback=true, pause_readback=true, unregistered=true",system.device_id,client.instance().version.version,report.target_validation);
    println!("Only configuration readbacks were confirmed; inspect runtime activity separately. Local file deletion was never requested.");
    Ok(())
}
