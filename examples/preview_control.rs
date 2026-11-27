//! Preview configuration in one process, then commit only after explicit approval.

use serde::Deserialize;
use std::io::{self, BufRead, Read, Write};
use std::process::ExitCode;
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, ControlSubmission, DeviceId, Error, FolderId, FolderPatch,
    GuiListenAddress, GuiListenerPatch, ManagementEndpoint, ManagementTransport, SettingsChange,
    SettingsField, SettingsFieldState, SettingsStepResult, SettingsTarget, SettingsValue,
};

const USAGE: &str = "Usage: preview_control [--help]\n\
Send a single JSON line over a private input stream. Supply connection with \
endpoint, api_key and expected_device_id, plus ca_pem if you need an HTTPS trust root. \
Include folder with id and label or paused, folders for additional ordered folders, \
or listener with bind. Supply readback \
with separate trusted connection settings if you want to check a listener change. \
After inspecting the redacted preview, enter apply on a second line to submit it.";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Connection {
    endpoint: String,
    api_key: String,
    expected_device_id: DeviceId,
    ca_pem: Option<String>,
}

impl Connection {
    fn options(&self) -> verysync_sidecar::Result<ConnectOptions> {
        let mut transport = ManagementTransport::default();
        if let Some(ca) = &self.ca_pem {
            transport = transport.trusted_certificates_pem(ca.as_bytes())?;
        }
        Ok(ConnectOptions::new(
            ManagementEndpoint::http(&self.endpoint)?,
            ApiKey::new(&self.api_key)?,
        )
        .expected_device_id(self.expected_device_id.clone())
        .transport(transport))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    connection: Connection,
    folder: Option<Folder>,
    #[serde(default)]
    folders: Vec<Folder>,
    listener: Option<Listener>,
    readback: Option<Connection>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Folder {
    id: FolderId,
    label: Option<String>,
    paused: Option<bool>,
}

impl Folder {
    fn patch(&self) -> FolderPatch {
        let mut patch = FolderPatch::default();
        if let Some(label) = &self.label {
            patch = patch.label(label);
        }
        if let Some(paused) = self.paused {
            patch = patch.paused(paused);
        }
        patch
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Listener {
    bind: String,
}

fn read_line(reader: &mut impl BufRead, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_until(b'\n', &mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other("the input line was too long"));
    }
    Ok(bytes)
}

fn describe_field(field: SettingsField) -> &'static str {
    match field {
        SettingsField::FolderLabel => "Folder label",
        SettingsField::FolderPaused => "Folder pause setting",
        SettingsField::ListenerAddress => "Management listener address",
        _ => "Selected setting",
    }
}

fn describe_value(value: &SettingsValue) -> &'static str {
    match value {
        SettingsValue::Text(_) => "a private label",
        SettingsValue::Flag(true) => "on",
        SettingsValue::Flag(false) => "off",
        SettingsValue::Address(_) => "a private address",
        _ => "a private value",
    }
}

fn report_submission(step: &SettingsStepResult) -> bool {
    let target = if step.target == SettingsTarget::GuiListener {
        "listener change"
    } else {
        "folder change"
    };
    match (step.submission, step.error.as_ref()) {
        (ControlSubmission::Acknowledged { .. }, error) => {
            println!("VerySync acknowledged the {target}.");
            if error.is_some() {
                println!("The current fields could not be checked after that acknowledgement.");
            }
            error.is_none()
        }
        (ControlSubmission::PossiblySubmitted, Some(Error::Authentication { status })) => {
            println!("VerySync could not authenticate this change (HTTP {status}).");
            false
        }
        (ControlSubmission::PossiblySubmitted, Some(Error::AccessDenied { response })) => {
            println!("VerySync refused this change (HTTP {}).", response.status());
            false
        }
        (ControlSubmission::PossiblySubmitted, Some(Error::MutationOutcomeUnknown { .. })) => {
            println!(
                "VerySync may have received the {target}. The acknowledgement is still unknown."
            );
            true
        }
        (ControlSubmission::PossiblySubmitted, _) => {
            println!("The {target} ended with an error. Check the current settings before sending another change.");
            false
        }
        (_, Some(_)) => {
            println!("No {target} was sent for this resource. Review a fresh preview.");
            false
        }
        _ => true,
    }
}

async fn run(reader: &mut impl BufRead) -> std::result::Result<bool, &'static str> {
    let input: Input = read_line(reader, 2 * 1024 * 1024)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or(
            "No settings were changed. Supply one valid input line. See --help for the fields.",
        )?;
    let connect = input
        .connection
        .options()
        .map_err(|_| "No settings were changed. Check the private connection settings.")?;
    let mut readback = input
        .readback
        .as_ref()
        .map(Connection::options)
        .transpose()
        .map_err(|_| "No settings were changed. Check the private readback settings.")?;
    let client = Client::connect(connect)
        .await
        .map_err(|_| "No settings were changed. Check the selected device and connection.")?;

    let folder_patches: Vec<_> = input
        .folder
        .iter()
        .chain(&input.folders)
        .map(|folder| (&folder.id, folder.patch()))
        .collect();
    let mut changes: Vec<_> = folder_patches
        .iter()
        .map(|(id, patch)| SettingsChange::Folder { id, patch })
        .collect();
    let listener_patch;
    if let Some(listener) = &input.listener {
        listener_patch = GuiListenerPatch::default().address(
            GuiListenAddress::tcp(&listener.bind)
                .map_err(|_| "No settings were changed. Check the native listener address.")?,
        );
        changes.push(SettingsChange::GuiListener {
            patch: &listener_patch,
        });
    }
    let preview = client
        .preview_settings_changes(&changes)
        .await
        .map_err(|_| "No settings were changed. Check that the selected resources can be read.")?;
    match preview.steps().len() {
        1 => println!("Previewed one resource. The preview sent no changes."),
        count => println!("Previewed {count} resources. The preview sent no changes."),
    }
    for step in preview.steps() {
        if step.may_interrupt_management() {
            println!("Changing the management listener can interrupt this connection.");
        }
        for setting in step.fields() {
            let field = describe_field(setting.field);
            if setting.is_change() {
                let previous = describe_value(&setting.previous);
                let requested = describe_value(&setting.requested);
                if previous == requested {
                    println!("{field} would change. The values are private.");
                } else {
                    println!("{field} would change from {previous} to {requested}.");
                }
            } else {
                println!("{field} already matches the requested value.");
            }
        }
    }
    println!("Enter apply to submit this preview.");
    io::stdout()
        .flush()
        .map_err(|_| "No settings were changed. The approval prompt could not be written.")?;
    let confirmation = read_line(reader, 64)
        .map_err(|_| "No settings were changed. The approval could not be read.")?;
    if !matches!(
        std::str::from_utf8(&confirmation).map(str::trim),
        Ok("apply")
    ) {
        println!("The preview was closed without sending any changes.");
        return Ok(true);
    }

    let committed = client.commit_settings_preview(preview).await;
    let multiple = committed.steps.len() > 1;
    let mut successful = true;
    for (index, mut step) in committed.steps.into_iter().enumerate() {
        if multiple {
            println!("Result for resource {}.", index + 1);
        }
        successful &= report_submission(&step);
        if step.target == SettingsTarget::GuiListener && step.listener_receipt.is_some() {
            if let Some(options) = readback.take() {
                if step.observe_listener(options).await.is_err() {
                    println!(
                        "The management listener could not be checked at the selected endpoint."
                    );
                }
            }
        }
        for field in step.fields {
            let message = match field.state {
                SettingsFieldState::Confirmed =>
                    "The device reports the requested value.",
                SettingsFieldState::Different =>
                    "The current value differs. Read the settings before submitting again.",
                SettingsFieldState::Conflict =>
                    "The value changed before submission. Review a fresh preview.",
                SettingsFieldState::NotExecuted =>
                    "No change was sent for this field.",
                _ => "This value is still unconfirmed. Read the selected device before sending another change.",
            };
            successful &= field.state == SettingsFieldState::Confirmed;
            println!("{}. {message}", describe_field(field.field));
        }
    }
    Ok(successful)
}

#[tokio::main]
async fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("--help") => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Some(_) => {
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
        None => {}
    }
    match run(&mut io::stdin().lock()).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
