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
        .ok_or("Supply the address of the VerySync test instance you want to read.")?;
    let endpoint = match mode.to_str() {
        Some("http") => {
            ManagementEndpoint::http(address.to_str().ok_or("HTTP URL must be UTF-8")?)?
        }
        Some("socket") => ManagementEndpoint::unix_socket(PathBuf::from(address))?,
        _ => return Err("Choose http for a URL or socket for a Unix socket path.".into()),
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
        return Err(
            "Use at most one expected device ID and one folder ID after the address.".into(),
        );
    }
    let client = Client::connect(options).await?;
    let info = client.instance();
    println!(
        "Connected: {} {} {} {}",
        info.device_id, info.version.version, info.version.os, info.version.arch
    );
    let system = client.system_status().await?;
    match system.uptime_seconds {
        Some(seconds) => println!("VerySync reports it has been running for {seconds} seconds."),
        None => println!("VerySync did not report its running time."),
    }
    if let Some(folder) = folder {
        use verysync_sidecar::FolderState;
        let status = client.folder_status(&folder).await?;
        let activity = match status.state {
            Some(FolderState::Idle) => "VerySync reports the folder is idle.",
            Some(FolderState::Scanning) => "VerySync is scanning the folder.",
            Some(FolderState::ScanWaiting) => "The folder is waiting to be scanned.",
            Some(FolderState::Syncing) => "VerySync is applying changes to the folder.",
            Some(FolderState::SyncWaiting) => "The folder is waiting to synchronize.",
            Some(FolderState::Cleaning) => "VerySync is cleaning up the folder.",
            Some(FolderState::CleanWaiting) => "The folder is waiting for cleanup.",
            Some(FolderState::Paused) => "VerySync reports the folder is paused.",
            Some(FolderState::Error) => {
                "VerySync reports a folder error. Check the folder on the selected instance."
            }
            Some(_) => "VerySync reported a folder state this client does not recognize.",
            None => "VerySync did not report a folder state.",
        };
        println!("{activity}");
        if let Some(files) = status.need_files {
            println!("VerySync reports {files} files still needed.");
        }
    }
    Ok(())
}
