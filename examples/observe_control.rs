//! Save and resume a folder observation without starting or changing the engine.

use serde::Deserialize;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, DeviceId, EndpointKind, Error, EventOptions, EventStreamItem,
    FolderId, FolderObservationPosition, FolderObservationRefresh, ManagementEndpoint,
    ManagementTransport,
};

const USAGE: &str = "Usage\n  observe_control start NEW_POSITION\n  observe_control resume SAVED_POSITION NEW_POSITION\n\
Send one private JSON object on standard input. Include endpoint, api_key and expected_device_id. \
For start, include folder_id and optionally peer_id. Set wait_ms to choose how long to wait for one update. \
For HTTPS, ca_pem can add a trust root. Keep both position files in a private directory.";
const MAX_PAYLOAD: u64 = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    endpoint: String,
    api_key: String,
    expected_device_id: DeviceId,
    folder_id: Option<FolderId>,
    peer_id: Option<DeviceId>,
    ca_pem: Option<String>,
    wait_ms: Option<u64>,
}

struct PositionPaths {
    previous: Option<PathBuf>,
    next: PathBuf,
}

fn paths() -> Result<Option<PositionPaths>, &'static str> {
    let mut args = std::env::args_os().skip(1);
    let mode = args.next().ok_or("Choose start or resume. See --help.")?;
    let old = match mode.to_str() {
        Some("--help") if args.next().is_none() => return Ok(None),
        Some("start") => None,
        Some("resume") => Some(args.next().ok_or("Choose a saved position file.")?.into()),
        _ => return Err("Choose start or resume. See --help."),
    };
    let new = args.next().ok_or("Choose a new position file.")?.into();
    if args.next().is_some() {
        return Err("Too many file arguments. See --help.");
    }
    Ok(Some(PositionPaths {
        previous: old,
        next: new,
    }))
}

fn read_json<T: serde::de::DeserializeOwned>(source: impl Read) -> Result<T, &'static str> {
    let mut bytes = Vec::new();
    source
        .take(MAX_PAYLOAD + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Could not read the private input.")?;
    if bytes.len() as u64 > MAX_PAYLOAD {
        return Err("The private input exceeds 64 KiB.");
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| "The private input has invalid fields or JSON. Check the selected input.")
}

fn write_position(path: &Path, position: &FolderObservationPosition) -> Result<(), &'static str> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let bytes = serde_json::to_vec(position).map_err(|_| "Could not encode the position.")?;
    let mut file = options.open(path).map_err(|_| {
        "Could not create a new position file. Choose an unused path in your private directory."
    })?;
    file.write_all(&bytes).and_then(|()| file.sync_all())
        .map_err(|_| "Could not finish saving the new position file. Keep your previous position and choose a new path.")
}

impl Input {
    fn connect(&self) -> verysync_sidecar::Result<ConnectOptions> {
        let endpoint = ManagementEndpoint::http(&self.endpoint)?;
        if endpoint.kind() == EndpointKind::RemoteHttp
            && endpoint
                .http_url()
                .is_some_and(|url| url.scheme() != "https")
        {
            return Err(Error::InvalidConfiguration {
                reason: "choose HTTPS for a remote management endpoint",
            });
        }
        let mut transport = ManagementTransport::default();
        if let Some(pem) = &self.ca_pem {
            transport = transport.trusted_certificates_pem(pem.as_bytes())?;
        }
        Ok(ConnectOptions::new(endpoint, ApiKey::new(&self.api_key)?)
            .expected_device_id(self.expected_device_id.clone())
            .transport(transport))
    }
}

async fn observe(old: Option<PathBuf>, new: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let input: Input = read_json(io::stdin().lock())?;
    let wait_ms = input.wait_ms.unwrap_or(1000);
    if !(1..=60_000).contains(&wait_ms) {
        return Err("Choose a wait_ms value between 1 and 60,000.".into());
    }
    let saved = match old {
        Some(path) => {
            if input.folder_id.is_some() || input.peer_id.is_some() {
                return Err("The saved position selects the folder and peer. Omit folder_id and peer_id when resuming.".into());
            }
            Some(read_json::<FolderObservationPosition>(
                File::open(path).map_err(|_| "Could not open the saved position file.")?,
            )?)
        }
        None => None,
    };
    let client = Client::connect(input.connect()?).await?;
    let options = EventOptions::default().queue_capacity(4)?;
    let mut observation = match saved {
        Some(position) => client.resume_folder_observation(position, options).await?,
        None => {
            let folder = input
                .folder_id
                .as_ref()
                .ok_or("Supply folder_id when starting an observation.")?;
            client
                .observe_folder(folder, input.peer_id.as_ref(), options)
                .await?
        }
    };
    println!("Read the selected folder's current status. VerySync supplied no task ID.");
    let result = observation
        .next_within(Duration::from_millis(wait_ms))
        .await;
    match &result {
        Ok(Some(update)) => {
            if let EventStreamItem::Gap(gap) = &update.item {
                println!("{}", gap.reason);
            }
            match update.refresh {
                FolderObservationRefresh::Read => println!("Read the selected folder's current status again."),
                FolderObservationRefresh::Failed(_) => println!("Could not refresh the folder snapshot. The last successful snapshot is still available."),
                FolderObservationRefresh::NotNeeded => println!("Received an update outside the selected folder."),
                _ => (),
            }
        }
        Ok(None) => println!("The update stream ended."),
        Err(Error::Timeout { .. }) => println!("The wait ended before another update was ready."),
        Err(_) => (),
    }
    let position = observation.position().clone();
    observation.close().await?;
    if !matches!(result, Err(Error::Timeout { .. })) {
        result?;
    }
    write_position(&new, &position)?;
    println!("Stopped watching. No folder settings or engine controls were changed.");
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let arguments = match paths() {
        Ok(Some(arguments)) => arguments,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    match observe(arguments.previous, arguments.next).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
