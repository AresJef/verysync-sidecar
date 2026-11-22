//! Register a paused folder only on an explicitly chosen dedicated instance.
use std::path::PathBuf;
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, CreateFolderOptions, DeviceId, FolderId, ManagementEndpoint,
    TargetPath,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let mode=args.next().ok_or("usage: create_folder <http|socket> <address> <expected-device-id> <folder-id> <absolute-local-target-path>")?;
    let address = args
        .next()
        .ok_or("Supply the address of the selected VerySync instance.")?;
    let endpoint = match mode.to_str() {
        Some("http") => {
            ManagementEndpoint::http(address.to_str().ok_or("HTTP URL must be UTF-8")?)?
        }
        Some("socket") => ManagementEndpoint::unix_socket(PathBuf::from(address))?,
        _ => return Err("Choose http for a URL or socket for a Unix socket path.".into()),
    };
    let expected = args
        .next()
        .ok_or("Supply the expected device ID before registering a folder.")?;
    let expected = DeviceId::parse(expected.to_str().ok_or("device ID must be ASCII")?)?;
    let id = args
        .next()
        .ok_or("Supply a new folder ID for the selected instance.")?;
    let id = FolderId::parse(id.to_str().ok_or("folder ID must be UTF-8")?)?;
    let path = PathBuf::from(
        args.next()
            .ok_or("Supply the folder's absolute path on the selected local instance.")?,
    );
    if !path.is_absolute() || args.next().is_some() {
        return Err("Supply one absolute local folder path and no extra arguments.".into());
    }
    let key = std::env::var("VERYSYNC_EXAMPLE_API_KEY")
        .map_err(|_| "VERYSYNC_EXAMPLE_API_KEY must contain the dedicated instance's key")?;
    let client = Client::connect(
        ConnectOptions::new(endpoint, ApiKey::new(&key)?).expected_device_id(expected),
    )
    .await?;
    let options = CreateFolderOptions::new(id, TargetPath::local(path)).paused(true);
    let configured = client.create_folder(&options).await?;
    if configured.paused {
        println!("Registered paused folder: {}", configured.id.as_str());
        println!("VerySync reports the folder is paused. Read folder status before checking for synchronization activity.");
    } else {
        println!("VerySync registered the folder and currently reports it as active. Check the folder settings before continuing.");
    }
    Ok(())
}
