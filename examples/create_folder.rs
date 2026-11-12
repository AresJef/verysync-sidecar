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
    let address = args.next().ok_or("explicit management address required")?;
    let endpoint = match mode.to_str() {
        Some("http") => {
            ManagementEndpoint::http(address.to_str().ok_or("HTTP URL must be UTF-8")?)?
        }
        Some("socket") => ManagementEndpoint::unix_socket(PathBuf::from(address))?,
        _ => return Err("transport must be http or socket".into()),
    };
    let expected = args
        .next()
        .ok_or("explicit expected device ID required for this write example")?;
    let expected = DeviceId::parse(expected.to_str().ok_or("device ID must be ASCII")?)?;
    let id = args.next().ok_or("explicit new folder ID required")?;
    let id = FolderId::parse(id.to_str().ok_or("folder ID must be UTF-8")?)?;
    let path = PathBuf::from(
        args.next()
            .ok_or("explicit absolute local target path required")?,
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
    let options = CreateFolderOptions::new(id, TargetPath::local(path)).paused(true);
    let configured = client.create_folder(&options).await?;
    println!("Registered paused folder: {configured:?}");
    println!("This is configuration readback; inspect folder status for later activity.");
    Ok(())
}
