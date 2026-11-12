//! Connect only to an explicitly supplied dedicated instance; never discover one.

use std::path::PathBuf;
use verysync_sidecar::{ApiKey, Client, ConnectOptions, DeviceId, FolderId, ManagementEndpoint};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let mode = args.next().ok_or(
        "usage: connect_existing <http|socket> <address> [expected-device-id] [folder-id]",
    )?;
    let address = args
        .next()
        .ok_or("an explicit management address is required")?;
    let endpoint = match mode.to_str() {
        Some("http") => {
            ManagementEndpoint::http(address.to_str().ok_or("HTTP URL must be UTF-8")?)?
        }
        Some("socket") => ManagementEndpoint::unix_socket(PathBuf::from(address))?,
        _ => return Err("transport must be http or socket".into()),
    };
    let key = std::env::var("VERYSYNC_EXAMPLE_API_KEY")
        .map_err(|_| "VERYSYNC_EXAMPLE_API_KEY must contain the dedicated instance's API key")?;
    let mut options = ConnectOptions::new(endpoint, ApiKey::new(&key)?);
    if let Some(expected) = args.next() {
        options = options.expected_device_id(DeviceId::parse(
            expected.to_str().ok_or("device ID must be ASCII")?,
        )?);
    }
    let folder = if let Some(id) = args.next() {
        Some(FolderId::parse(
            id.to_str().ok_or("folder ID must be UTF-8")?,
        )?)
    } else {
        None
    };
    if args.next().is_some() {
        return Err("too many arguments".into());
    }
    let client = Client::connect(options).await?;
    let info = client.instance();
    println!(
        "Connected: {} {} {} {}",
        info.device_id, info.version.version, info.version.os, info.version.arch
    );
    let system = client.system_status().await?;
    match system.uptime_seconds {
        Some(seconds) => println!("Reported engine uptime: {seconds} seconds"),
        None => println!("Reported engine uptime: unknown"),
    }
    if let Some(folder) = folder {
        println!(
            "Folder snapshot: {:?}",
            client.folder_status(&folder).await?
        );
    }
    Ok(())
}
