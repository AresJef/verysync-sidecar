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
    let address = args
        .next()
        .ok_or("Supply the address of the selected VerySync instance.")?;
    let endpoint = match mode.to_str() {
        Some("http") => {
            ManagementEndpoint::http(address.to_str().ok_or("HTTP URL must be UTF-8")?)?
        }
        Some("socket") => ManagementEndpoint::unix_socket(PathBuf::from(address))?,
        _ => return Err("transport must be http or socket".into()),
    };
    let expected = args
        .next()
        .ok_or("Supply the expected device ID before changing settings.")?;
    let expected = DeviceId::parse(expected.to_str().ok_or("device ID must be ASCII")?)?;
    let id = args
        .next()
        .ok_or("Supply a new folder ID for this example.")?;
    let id = FolderId::parse(id.to_str().ok_or("folder ID must be UTF-8")?)?;
    let path = PathBuf::from(
        args.next()
            .ok_or("Supply the absolute folder path on the selected local instance.")?,
    );
    if !path.is_absolute() || args.next().is_some() {
        return Err("supply one absolute local target path and no extra arguments".into());
    }
    let key = std::env::var("VERYSYNC_EXAMPLE_API_KEY")
        .map_err(|_| "VERYSYNC_EXAMPLE_API_KEY must contain the dedicated instance's key")?;
    let client = Client::connect(
        ConnectOptions::new(endpoint, ApiKey::new(&key)?).expected_device_id(expected),
    )
    .await?;
    client.system_status().await?;
    let raw = client
        .raw_request(&RawRequest::new(
            RawMethod::Get,
            ["rest", "system", "version"],
            RequestEffect::ReadOnly,
        )?)
        .await?;
    if raw.status() != 200 {
        return Err(
            "The version request failed. Check the selected instance before changing its settings."
                .into(),
        );
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
        return Err("VerySync has a folder registration. It did not report the requested pause. Check the folder before repeating the request.".into());
    }
    let updated = client
        .update_folder(&id, &FolderPatch::default().label("Example updated label"))
        .await?;
    if !updated.requested_fields_match {
        return Err(
            "The folder did not report the requested label. Read the current label before trying again."
                .into(),
        );
    }
    let resumed = client.resume_folder(&id).await?;
    if !resumed.requested_fields_match {
        return Err("The folder did not report that it resumed. Check its current pause setting before trying again.".into());
    }
    let paused = client.pause_folder(&id).await?;
    if !paused.requested_fields_match {
        return Err("The folder did not report the requested pause. Check its current pause setting before continuing.".into());
    }
    let removed = client.remove_folder_keep_files(&id).await?;
    if !removed.configuration_absent {
        return Err("The folder is still registered. Check its current registration before requesting removal again.".into());
    }
    println!(
        "Managed configuration workflow: verified the selected device on VerySync {}.",
        client.instance().version.version,
    );
    println!("VerySync reported the new folder, the updated label, and the change from resumed to paused.");
    println!("The final read showed the registration was removed. The example requested that local files be kept.");
    if matches!(
        report.target_validation,
        verysync_sidecar::TargetValidation::OutsideNativeEvidence
    ) {
        println!("This system or connection is outside the recorded native test coverage.");
    }
    println!("Read folder and peer status separately to check synchronization activity.");
    Ok(())
}
