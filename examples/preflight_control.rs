//! Inspect one control operation on an explicitly selected device.

use serde::Deserialize;
use std::io::Read;
use std::process::ExitCode;
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, DeviceId, FolderId, LocalApiClient, LocalApiConnectOptions,
    ManagementEndpoint, OperationPreflightReport, PreflightLicense, PreflightReadAccess,
    PreflightReads, TargetValidation, UpgradePreflightSource, UpgradeSourceEvidence,
    VersionCompatibility, VersionPolicy,
};

const HELP: &str = "\
Usage: preflight_control <gui|provider|url|local-need> [--read]\n\
\n\
Provide one JSON object on standard input with the selected endpoint.\n\
Use api_key for gui, provider or url. Use folder_id for local-need.\n\
Set expected_device_id to verify the intended device during connection.\n\
Set allow_unverified to inspect a version outside the recorded baseline.\n\
Add --read to run the selected read-only checks. The provider check can contact\n\
the release feed configured on the engine.";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    endpoint: String,
    expected_device_id: Option<String>,
    api_key: Option<String>,
    folder_id: Option<String>,
    #[serde(default)]
    allow_unverified: bool,
}

async fn report(
    selected: &str,
    input: Input,
    reads: PreflightReads,
) -> Result<OperationPreflightReport, Box<dyn std::error::Error>> {
    let endpoint = ManagementEndpoint::http(&input.endpoint)?;
    let expected = input
        .expected_device_id
        .as_deref()
        .map(DeviceId::parse)
        .transpose()?;
    let policy = if input.allow_unverified {
        VersionPolicy::AllowUnverified
    } else {
        VersionPolicy::ValidatedOnly
    };
    if selected == "local-need" {
        if input.api_key.is_some() {
            return Err(
                "Local-API preflight takes the folder ID and its separate endpoint.".into(),
            );
        }
        let folder = FolderId::parse(
            input
                .folder_id
                .as_deref()
                .ok_or("Provide folder_id for the selected Local-API need check.")?,
        )?;
        let mut connection = LocalApiConnectOptions::new(endpoint)?.version_policy(policy);
        if let Some(identity) = expected {
            connection = connection.expected_device_id(identity);
        }
        let local = LocalApiClient::connect(connection).await?;
        return Ok(local.preflight_folder_need(&folder, reads).await);
    }
    let key = ApiKey::new(
        input
            .api_key
            .as_deref()
            .ok_or("Provide api_key for the management connection.")?,
    )?;
    let mut connection = ConnectOptions::new(endpoint, key).version_policy(policy);
    if let Some(identity) = expected {
        connection = connection.expected_device_id(identity);
    }
    let client = Client::connect(connection).await?;
    Ok(match selected {
        "provider" => {
            client
                .preflight_upgrade(UpgradePreflightSource::ServerProvider, reads)
                .await?
        }
        "url" => {
            client
                .preflight_upgrade(UpgradePreflightSource::ExplicitUrl, reads)
                .await?
        }
        _ => client.preflight_gui_listener(reads).await,
    })
}

fn present(report: OperationPreflightReport, selected: &str) {
    match report.version {
        VersionCompatibility::ValidatedBaseline => {
            println!("The connection reported the validated engine version.");
        }
        VersionCompatibility::Unverified => {
            println!("The engine version is outside the recorded baseline.");
        }
    }
    match report.static_evidence.target_validation {
        TargetValidation::MatchesRecordedCoordinates => {
            println!("This connection matches the recorded platform and transport coordinates.");
        }
        TargetValidation::OutsideNativeEvidence => {
            println!("This connection falls outside the recorded platform and transport scope.");
        }
    }
    if let Some(UpgradeSourceEvidence::ServerProvider {
        recorded_windows_arm64_gap: true,
        ..
    }) = &report.upgrade_source
    {
        println!("The recorded provider feed omitted a Windows ARM64 release. Check the current provider or select a fixed official archive.");
    }
    let Some(current) = report.observation else {
        println!("Only the connection snapshot and recorded evidence were inspected. Current operation access is unknown.");
        return;
    };
    match current.permission {
        PreflightReadAccess::Observed if selected == "local-need" => {
            println!("VerySync returned the selected need page. Other Local-API permissions remain unknown.");
        }
        PreflightReadAccess::Observed if selected == "gui" => {
            println!("VerySync returned the current listener settings. Permission to change them remains unknown.");
        }
        PreflightReadAccess::Observed if selected == "provider" => {
            println!("The provider returned release metadata. Installation remains a separate operation.");
        }
        PreflightReadAccess::Observed => {
            println!("The selected device responded. The upgrade source has yet to be inspected.");
        }
        PreflightReadAccess::AuthenticationRequired { .. } => {
            println!("The endpoint requested authentication. Check the management connection and its credentials.");
        }
        PreflightReadAccess::Denied { .. } => {
            println!("The endpoint refused the read. The required license remains unknown.");
        }
        PreflightReadAccess::LicenseDenied => {
            if let PreflightLicense::ExplicitlyDenied { native_code, .. } = current.license {
                println!("VerySync reported that this need page requires a Local-API entitlement (code {native_code}).");
            }
        }
        _ => match current.issue {
            Some(error) => println!("The selected check could not be confirmed. {error}"),
            None => println!("The selected check could not be confirmed."),
        },
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }
    let Some(selected @ ("gui" | "provider" | "url" | "local-need")) =
        args.first().map(String::as_str)
    else {
        eprintln!("{HELP}");
        return ExitCode::from(2);
    };
    let reads = match args.get(1..).unwrap_or_default() {
        [] => PreflightReads::None,
        [flag] if flag == "--read" => PreflightReads::SelectedOperation,
        _ => {
            eprintln!("{HELP}");
            return ExitCode::from(2);
        }
    };
    let mut bytes = Vec::new();
    let input = std::io::stdin()
        .take(8193)
        .read_to_end(&mut bytes)
        .ok()
        .filter(|count| *count <= 8192)
        .and_then(|_| serde_json::from_slice::<Input>(&bytes).ok());
    let Some(input) = input else {
        eprintln!("Provide a valid JSON object of at most 8 KiB on standard input.");
        return ExitCode::from(2);
    };
    match report(selected, input, reads).await {
        Ok(report) => {
            present(report, selected);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("The selected connection could not be checked. {error}");
            ExitCode::FAILURE
        }
    }
}
