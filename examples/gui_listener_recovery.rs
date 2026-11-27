//! Submit a listener change or peer removal and reopen its receipt from a separate process.

use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Mutex,
};
use std::time::{Duration, UNIX_EPOCH};
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, ControlOperationEvent, ControlOperationReceipt,
    ControlSubmission, DeviceId, Error, GuiListenAddress, GuiListenerPatch, ManagementEndpoint,
    ManagementTransport,
};

const USAGE: &str = "Usage: gui_listener_recovery <submit|observe|remove-device|observe-device> <private-operation-directory>\n\
Supply one JSON object on standard input. All commands require endpoint, api_key, and \
expected_device_id. Supply ca_pem for an additional HTTPS trust root, or timeout_ms \
to select the request deadline. Submit also requires bind and accepts use_tls. \
Remove-device requires peer_id. Add disconnect_timeout_ms to first pause the peer and confirm its disconnect. \
Set event_log to true on a submit or removal command to save separate progress diagnostics.";
const INPUT_LIMIT: u64 = 2 * 1024 * 1024;
const RECEIPT_LIMIT: u64 = 64 * 1024;
const RECEIPT_NAME: &str = "receipt.json";
const EVENT_LOG: &str = "events.jsonl";
const EVENT_LIMIT: usize = 8;
const EVENT_WAIT: Duration = Duration::from_millis(100);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    endpoint: String,
    api_key: String,
    expected_device_id: DeviceId,
    ca_pem: Option<String>,
    timeout_ms: Option<u64>,
    bind: Option<String>,
    use_tls: Option<bool>,
    peer_id: Option<DeviceId>,
    disconnect_timeout_ms: Option<u64>,
    #[serde(default)]
    event_log: bool,
}

impl Input {
    fn options(&self) -> verysync_sidecar::Result<ConnectOptions> {
        let endpoint = ManagementEndpoint::http(&self.endpoint)?;
        let mut transport = ManagementTransport::default();
        if let Some(pem) = &self.ca_pem {
            transport = transport.trusted_certificates_pem(pem.as_bytes())?;
        }
        ConnectOptions::new(endpoint, ApiKey::new(&self.api_key)?)
            .expected_device_id(self.expected_device_id.clone())
            .transport(transport)
            .request_timeout(Duration::from_millis(self.timeout_ms.unwrap_or(10_000)))
    }

    fn patch(&self) -> verysync_sidecar::Result<GuiListenerPatch> {
        if self.peer_id.is_some() || self.disconnect_timeout_ms.is_some() {
            return Err(Error::InvalidConfiguration {
                reason: "use the remove-device command for device removal settings",
            });
        }
        let bind = self.bind.as_deref().ok_or(Error::InvalidConfiguration {
            reason: "submit requires a native listener bind authority",
        })?;
        let mut patch = GuiListenerPatch::default().address(GuiListenAddress::tcp(bind)?);
        if let Some(use_tls) = self.use_tls {
            patch = patch.use_tls(use_tls);
        }
        Ok(patch)
    }
}

#[derive(Default)]
struct Events {
    entries: Vec<(ControlOperationEvent, usize)>,
    dropped: usize,
}

impl Events {
    fn record(&mut self, event: ControlOperationEvent) {
        if let Some(last) = self.entries.last_mut().filter(|last| {
            last.0.submission == event.submission && last.0.device_removal == event.device_removal
        }) {
            last.0 = event;
            last.1 += 1;
        } else if self.entries.len() < EVENT_LIMIT {
            self.entries.push((event, 1));
        } else {
            self.dropped += 1;
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        for (event, count) in &self.entries {
            output.extend_from_slice(
                json!({"event": event, "observations": count})
                    .to_string()
                    .as_bytes(),
            );
            output.push(b'\n');
        }
        output.extend_from_slice(json!({"dropped": self.dropped}).to_string().as_bytes());
        output.push(b'\n');
        output
    }
}

struct Journal {
    directory: PathBuf,
    prepared: AtomicBool,
    next_sequence: AtomicU64,
    committed_sequence: Mutex<u64>,
    events: Option<Mutex<Events>>,
}

impl Journal {
    fn new(directory: PathBuf, log_events: bool) -> Self {
        Self {
            directory,
            prepared: AtomicBool::new(false),
            next_sequence: AtomicU64::new(1),
            committed_sequence: Mutex::new(0),
            events: log_events.then(|| Mutex::new(Events::default())),
        }
    }

    async fn save(
        self: Arc<Self>,
        receipt: ControlOperationReceipt,
        initial: bool,
    ) -> io::Result<()> {
        // A cancelled async wait can leave its blocking storage worker running.
        let sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        tokio::task::spawn_blocking(move || {
            let bytes = receipt.encode().map_err(io::Error::other)?;
            let temporary = stage_file(&self.directory, &bytes)?;
            let mut committed = self
                .committed_sequence
                .lock()
                .map_err(|_| io::Error::other("the receipt commit lock is unavailable"))?;
            if sequence <= *committed {
                return Ok(());
            }
            replace_file(temporary, &self.directory.join(RECEIPT_NAME), initial)?;
            // Once replaced, no earlier worker can replace it, even if directory sync fails.
            *committed = sequence;
            sync_directory(&self.directory)?;
            if initial {
                self.prepared.store(true, Ordering::Release);
            }
            if let Some(mut events) = self.events.as_ref().and_then(|events| events.lock().ok()) {
                events.record(receipt.log_event());
            }
            Ok(())
        })
        .await
        .map_err(io::Error::other)?
    }

    async fn checkpoint(self: Arc<Self>, receipt: ControlOperationReceipt) -> io::Result<()> {
        let initial = !self.prepared.load(Ordering::Acquire);
        self.save(receipt, initial).await
    }

    async fn save_result(self: &Arc<Self>, receipt: &ControlOperationReceipt) -> bool {
        self.prepared.load(Ordering::Acquire)
            && Arc::clone(self).save(receipt.clone(), false).await.is_ok()
    }

    fn finish_event_log(&self) -> Option<&'static str> {
        let events = self.events.as_ref()?.lock().ok()?;
        if events.entries.is_empty() {
            return None;
        }
        let events = events.encode();
        let directory = self.directory.clone();
        let (ready, written) = mpsc::sync_channel(1);
        if std::thread::Builder::new()
            .spawn(move || {
                let _ = ready.send(store_file(&directory, EVENT_LOG, &events, false).is_ok());
            })
            .is_err()
        {
            return Some("unavailable");
        }
        Some(match written.recv_timeout(EVENT_WAIT) {
            Ok(true) => "written",
            Ok(false) | Err(mpsc::RecvTimeoutError::Disconnected) => "unavailable",
            Err(mpsc::RecvTimeoutError::Timeout) => "pending",
        })
    }
}

fn store_file(directory: &Path, name: &str, bytes: &[u8], initial: bool) -> io::Result<()> {
    replace_file(
        stage_file(directory, bytes)?,
        &directory.join(name),
        initial,
    )?;
    sync_directory(directory)
}

fn stage_file(directory: &Path, bytes: &[u8]) -> io::Result<tempfile::NamedTempFile> {
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    Ok(temporary)
}

fn replace_file(
    temporary: tempfile::NamedTempFile,
    destination: &Path,
    initial: bool,
) -> io::Result<()> {
    if initial {
        temporary.persist_noclobber(destination)?;
    } else {
        temporary.persist(destination)?;
    }
    Ok(())
}

fn sync_directory(directory: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(directory)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

fn private_directory(directory: PathBuf) -> io::Result<PathBuf> {
    let directory = std::path::absolute(directory)?;
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir() {
        return Err(io::Error::other(
            "the operation directory must be a real directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::other("the operation directory must be private"));
        }
    }
    Ok(directory)
}

fn bounded_bytes(reader: impl Read, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other("input exceeded the size limit"));
    }
    Ok(bytes)
}

fn open_receipt(directory: &Path) -> Option<ControlOperationReceipt> {
    let path = directory.join(RECEIPT_NAME);
    if !fs::symlink_metadata(&path).ok()?.is_file() {
        return None;
    }
    let bytes = bounded_bytes(File::open(path).ok()?, RECEIPT_LIMIT).ok()?;
    ControlOperationReceipt::decode(&bytes).ok()
}

fn submission_name(state: ControlSubmission) -> &'static str {
    match state {
        ControlSubmission::Prepared => "prepared",
        ControlSubmission::NotSubmitted => "not_submitted",
        ControlSubmission::PossiblySubmitted => "possibly_submitted",
        ControlSubmission::Acknowledged { .. } => "acknowledged",
        _ => "unknown",
    }
}

fn submission_report(command: &'static str, receipt: &ControlOperationReceipt) -> Value {
    let mut summary = json!({
        "command": command,
        "operation_id": receipt.id(),
        "submission": submission_name(receipt.submission()),
    });
    if let Some(progress) = receipt.device_removal_progress() {
        summary["device_removal_progress"] = json!(progress);
    }
    summary
}

fn error_label(error: &Error) -> &'static str {
    match error {
        Error::IdentityMismatch { .. } | Error::InvalidIdentity { .. } => "identity_mismatch",
        Error::Authentication { .. } | Error::AccessDenied { .. } => "authentication",
        Error::IncompatibleVersion { .. } => "incompatible_version",
        Error::InvalidConfiguration { .. } | Error::InvalidEndpoint { .. } => "invalid_input",
        Error::UnsupportedTransport { .. } => "unsupported_transport",
        Error::LocalIo { .. } => "receipt_storage",
        Error::TlsCertificateRejected { .. } => "tls_certificate_rejected",
        Error::Timeout { .. } | Error::Transport { .. } => "transport",
        Error::MutationOutcomeUnknown { .. } => "mutation_outcome_unknown",
        _ => "management_error",
    }
}

fn failure(report: &mut Value, label: &'static str, message: impl Into<String>) {
    report["failure"] = json!(label);
    report["message"] = json!(message.into());
}

fn complete_response_status(error: &Error) -> Option<u16> {
    match error {
        Error::Authentication { status } => Some(*status),
        Error::AccessDenied { response }
        | Error::Http { response }
        | Error::Api { response, .. }
        | Error::InvalidResponse { response, .. }
        | Error::LicenseRequired { response, .. } => Some(response.status()),
        Error::MutationOutcomeUnknown { source, .. } => complete_response_status(source),
        _ => None,
    }
}

fn read_failure(summary: &mut Value, stage: &'static str, error: &Error, message: &'static str) {
    summary["failure_stage"] = json!(stage);
    failure(summary, error_label(error), message);
    if let Some(status) = complete_response_status(error) {
        summary["read_http_status"] = json!(status);
        append_message(
            summary,
            &format!("VerySync returned HTTP {status} for this read."),
        );
    }
}

fn write_failure(
    summary: &mut Value,
    stage: &'static str,
    status: Option<u16>,
    error: Option<&Error>,
    request: &str,
    next: &str,
) -> u8 {
    let complete = status.is_some() && status == error.and_then(complete_response_status);
    summary["failure_stage"] = json!(stage);
    summary["response_complete"] = json!(complete);
    if let Some(status) = status {
        summary["http_status"] = json!(status);
    }
    if complete {
        let message = match status {
            Some(401) => Some(format!(
                "VerySync could not authenticate the {request} request (HTTP 401). Check the management credentials."
            )),
            Some(403) => Some(format!(
                "VerySync refused the {request} request (HTTP 403). Check access to the selected device."
            )),
            _ => None,
        };
        if let Some(message) = message {
            failure(summary, "authentication", message);
            return 1;
        }
    }
    let fact = match status {
        Some(status) if complete => {
            format!("VerySync returned HTTP {status}. The {request} outcome is still unknown.")
        }
        Some(status) => {
            format!("VerySync sent HTTP {status} headers, but the {request} reply did not finish.")
        }
        None => format!("No reply arrived for the {request} request. The outcome is unknown."),
    };
    failure(
        summary,
        "mutation_outcome_unknown",
        format!("{fact} {next}"),
    );
    2
}

fn append_message(summary: &mut Value, extra: &str) {
    if let Some(message) = summary["message"].as_str() {
        summary["message"] = json!(format!("{message} {extra}"));
    }
}

async fn submit(directory: PathBuf, input: Input) -> (u8, Value) {
    let mut summary = json!({"command": "submit", "submission": "not_submitted"});
    let (patch, options) = match input
        .patch()
        .and_then(|patch| input.options().map(|options| (patch, options)))
    {
        Ok(request) => request,
        Err(error) => {
            failure(&mut summary, error_label(&error), "No listener change was sent. Check the endpoint, bind address, and trust settings.");
            return (1, summary);
        }
    };
    let client = match Client::connect(options).await {
        Ok(client) => client,
        Err(error) => {
            read_failure(&mut summary, "pre_submit_read", &error, "The selected device could not be checked. No listener change was sent. Check the device, credentials, and connection.");
            return (1, summary);
        }
    };
    let operation = match client.prepare_gui_listener_change(&patch) {
        Ok(operation) => operation,
        Err(error) => {
            failure(
                &mut summary,
                error_label(&error),
                "No listener change was sent. The request could not be prepared.",
            );
            return (1, summary);
        }
    };
    let journal = Arc::new(Journal::new(directory, input.event_log));
    let checkpoints = Arc::clone(&journal);
    let report = client
        .execute_gui_listener_change_persisted(operation, move |receipt| {
            Arc::clone(&checkpoints).checkpoint(receipt)
        })
        .await;
    let result_saved = journal.save_result(&report.receipt).await;
    let mut summary = submission_report("submit", &report.receipt);
    summary["final_receipt_saved"] = json!(result_saved);
    if let Some(event_log) = journal.finish_event_log() {
        summary["event_log"] = json!(event_log);
    }
    match report.receipt.submission() {
        ControlSubmission::PossiblySubmitted => {
            let code = write_failure(
                &mut summary,
                "submit",
                report.receipt.response_status(),
                report.result.as_ref().err(),
                "listener change",
                "Use observe with a trusted endpoint to check the current listener settings.",
            );
            (code, summary)
        }
        ControlSubmission::Acknowledged { status } if report.result.is_ok() && result_saved => {
            summary["http_status"] = json!(status);
            summary["response_complete"] = json!(true);
            summary["message"] = json!("VerySync acknowledged the listener change. Use observe to check its current settings.");
            (0, summary)
        }
        ControlSubmission::Acknowledged { status } => {
            summary["http_status"] = json!(status);
            summary["response_complete"] = json!(true);
            failure(&mut summary, "receipt_storage", "VerySync acknowledged the listener change. The final receipt could not be saved. Keep the earlier checkpoint and use observe to check the settings.");
            (1, summary)
        }
        _ => {
            match report.result.as_ref().err() {
                Some(error) if complete_response_status(error).is_some() => read_failure(
                    &mut summary, "pre_submit_read", error,
                    "The listener settings could not be read. No listener change was sent. Check access to the selected device.",
                ),
                error => failure(
                    &mut summary, error.map_or("management_error", error_label),
                    "No listener change was sent. Check the selected device and the private receipt location.",
                ),
            }
            (1, summary)
        }
    }
}

async fn observe(directory: &Path, input: Input) -> (u8, Value) {
    let mut summary = json!({"command": "observe"});
    let Some(receipt) = open_receipt(directory) else {
        failure(&mut summary, "invalid_receipt", "The saved receipt could not be read. Use the original receipt from the submit process.");
        return (1, summary);
    };
    let mut summary = submission_report("observe", &receipt);
    if input.bind.is_some()
        || input.use_tls.is_some()
        || input.event_log
        || input.peer_id.is_some()
        || input.disconnect_timeout_ms.is_some()
    {
        failure(
            &mut summary,
            "invalid_input",
            "Observe accepts only connection settings and reads the existing receipt.",
        );
        return (1, summary);
    }
    let options = match input.options() {
        Ok(options) => options,
        Err(error) => {
            failure(
                &mut summary,
                error_label(&error),
                "The saved change is still unconfirmed. Check the endpoint and its trust settings.",
            );
            return (1, summary);
        }
    };
    match receipt.observe_gui_listener(options).await {
        Ok(observed) => {
            summary["requested_fields_match"] = json!(observed.requested_fields_match);
            summary["observed_at_unix_ms"] = json!(observed
                .identity
                .observed_at()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_millis()));
            let generation = if observed.identity.process_generation().is_some() {
                "observed"
            } else {
                "unknown"
            };
            summary["process_generation"] = json!(generation);
            summary["message"] = json!(if observed.requested_fields_match {
                "The selected device currently reports the requested listener settings."
            } else {
                "The selected device currently reports different listener settings."
            });
            (0, summary)
        }
        Err(error) => {
            let label = error_label(&error);
            let message = match label {
                "identity_mismatch" => "The selected device identity did not match the receipt. Verify the original device and trusted endpoint.",
                "tls_certificate_rejected" => "The HTTPS certificate was rejected. Verify the certificate and connection name before checking the listener again.",
                "transport" => "The selected endpoint could not be reached. Check that the original device is listening at an endpoint you trust.",
                _ => "The current listener settings could not be confirmed. Check the selected device and credentials.",
            };
            failure(&mut summary, label, message);
            (1, summary)
        }
    }
}

async fn remove_device(directory: PathBuf, input: Input) -> (u8, Value) {
    let mut summary = json!({"command":"remove-device","submission":"not_submitted"});
    let Some(peer) = input.peer_id.as_ref() else {
        failure(
            &mut summary,
            "invalid_input",
            "Supply the peer_id of the registration to remove.",
        );
        return (1, summary);
    };
    if input.bind.is_some() || input.use_tls.is_some() {
        failure(&mut summary, "invalid_input", "Remove-device accepts connection settings, a peer ID and an optional disconnect deadline.");
        return (1, summary);
    }
    let options = match input.options() {
        Ok(options) => options,
        Err(error) => {
            failure(
                &mut summary,
                error_label(&error),
                "Check the selected management address and trust settings.",
            );
            return (1, summary);
        }
    };
    let client = match Client::connect(options).await {
        Ok(client) => client,
        Err(error) => {
            read_failure(
                &mut summary,
                "pre_submit_read",
                &error,
                "The selected device could not be checked. No removal was requested. Check the device, credentials and connection.",
            );
            return (1, summary);
        }
    };
    let operation = match input.disconnect_timeout_ms {
        Some(timeout) => {
            client.prepare_device_disconnect_and_remove(peer, Duration::from_millis(timeout))
        }
        None => client.prepare_device_removal(peer),
    };
    let operation = match operation {
        Ok(operation) => operation,
        Err(error) => {
            failure(
                &mut summary,
                error_label(&error),
                "No removal was requested. Check the peer ID and any disconnect deadline.",
            );
            return (1, summary);
        }
    };
    let journal = Arc::new(Journal::new(directory, input.event_log));
    let checkpoints = Arc::clone(&journal);
    let report = client
        .execute_device_removal_persisted(operation, move |receipt| {
            Arc::clone(&checkpoints).checkpoint(receipt)
        })
        .await;
    let saved = journal.save_result(&report.receipt).await;
    let mut summary = submission_report("remove-device", &report.receipt);
    summary["final_receipt_saved"] = json!(saved);
    if let Some(event_log) = journal.finish_event_log() {
        summary["event_log"] = json!(event_log);
    }
    if let ControlSubmission::Acknowledged { status } = report.receipt.submission() {
        summary["http_status"] = json!(status);
        summary["response_complete"] = json!(true);
    }
    match report.result {
        Ok(observed) => {
            summary["configuration_absent"] = json!(observed.configuration_absent);
            summary["remaining_folder_count"] = json!(observed.remaining_folder_associations.len());
            if saved {
                summary["message"] = json!(if observed.configuration_absent {
                    "VerySync acknowledged the removal and the registration is now absent."
                } else {
                    "VerySync acknowledged the removal. The registration is currently present."
                });
                (0, summary)
            } else {
                failure(&mut summary, "receipt_storage", "The final receipt could not be saved. Keep the earlier checkpoint and use observe-device to check the current registration.");
                (1, summary)
            }
        }
        Err(error) => {
            let code = report_device_failure(&mut summary, &report.receipt, &error);
            (code, summary)
        }
    }
}

fn report_device_failure(
    summary: &mut Value,
    receipt: &ControlOperationReceipt,
    error: &Error,
) -> u8 {
    let progress = receipt.device_removal_progress();
    let prior_pause = progress.and_then(|progress| progress.pause_request);
    let pause_acknowledged = matches!(prior_pause, Some(ControlSubmission::Acknowledged { .. }));
    let code = match receipt.submission() {
        ControlSubmission::Acknowledged { .. } => {
            read_failure(summary, "post_submit_read", error,
                "VerySync acknowledged the removal request. The current registration could not be confirmed. Use observe-device to check it before sending another request.");
            2
        }
        ControlSubmission::PossiblySubmitted => write_failure(
            summary,
            "submit",
            receipt.response_status(),
            Some(error),
            "device removal",
            "Use observe-device to check the current registration before sending another request.",
        ),
        _ if prior_pause == Some(ControlSubmission::PossiblySubmitted) => {
            let code = write_failure(
                summary,
                "pause_submit",
                progress.and_then(|progress| progress.pause_response_status),
                Some(error),
                "peer pause",
                "Read the peer status before sending another request.",
            );
            append_message(summary, "No removal was requested.");
            code
        }
        _ if complete_response_status(error).is_some() => {
            let stage = if pause_acknowledged && progress.is_some_and(|p| !p.disconnection_observed)
            {
                "pause_read"
            } else {
                "pre_submit_read"
            };
            read_failure(summary, stage, error,
                "The selected device configuration could not be read. No removal was requested. Check access to the selected device.");
            if matches!(error, Error::MutationOutcomeUnknown { .. }) {
                2
            } else {
                1
            }
        }
        _ => {
            failure(
                summary,
                error_label(error),
                "No removal was requested. Check the selected peer and private receipt location.",
            );
            if matches!(error, Error::MutationOutcomeUnknown { .. }) {
                2
            } else {
                1
            }
        }
    };
    if pause_acknowledged {
        append_message(summary, "VerySync acknowledged the earlier peer pause.");
    }
    code
}

async fn observe_device(directory: &Path, input: Input) -> (u8, Value) {
    let mut summary = json!({"command":"observe-device"});
    if input.peer_id.is_some()
        || input.disconnect_timeout_ms.is_some()
        || input.event_log
        || input.use_tls.is_some()
        || input.bind.is_some()
    {
        failure(&mut summary, "invalid_input", "Observe-device accepts only connection settings. The saved receipt identifies the peer.");
        return (1, summary);
    }
    let Some(receipt) =
        open_receipt(directory).filter(|receipt| receipt.device_removal_progress().is_some())
    else {
        failure(&mut summary, "invalid_receipt", "The saved device-removal receipt could not be read. Use the original receipt directory.");
        return (1, summary);
    };
    let mut summary = submission_report("observe-device", &receipt);
    let options = match input.options() {
        Ok(options) => options,
        Err(error) => {
            failure(&mut summary, error_label(&error), "The current registration could not be checked. Verify the endpoint and its trust settings.");
            return (1, summary);
        }
    };
    match receipt.observe_device_removal(options).await {
        Ok(observed) => {
            summary["configuration_absent"] = json!(observed.configuration_absent);
            summary["remaining_folder_count"] = json!(observed.remaining_folder_associations.len());
            summary["observed_at_unix_ms"] = json!(observed
                .identity
                .observed_at()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|time| time.as_millis()));
            summary["process_generation"] = json!("unknown");
            summary["message"] = json!(if observed.configuration_absent {
                "The selected device no longer lists this registration. Sharing keys may still allow the peer to register again."
            } else {
                "The selected device currently lists this registration."
            });
            (0, summary)
        }
        Err(error) => {
            failure(&mut summary, error_label(&error), "The current registration could not be confirmed. Check the original device, trusted endpoint and credentials.");
            (1, summary)
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let mode = args.next();
    if mode.as_deref().and_then(|mode| mode.to_str()) == Some("--help") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let (
        Some(mode @ ("submit" | "observe" | "remove-device" | "observe-device")),
        Some(directory),
        None,
    ) = (
        mode.as_deref().and_then(|mode| mode.to_str()),
        args.next(),
        args.next(),
    )
    else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let directory = match private_directory(PathBuf::from(directory)) {
        Ok(directory) => directory,
        Err(_) => {
            println!(
                "{}",
                json!({"command": mode, "failure": "receipt_storage",
                "message": "The operation directory is unavailable or not private. Choose an existing private directory."})
            );
            return ExitCode::FAILURE;
        }
    };
    let input = bounded_bytes(io::stdin().lock(), INPUT_LIMIT)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Input>(&bytes).ok());
    let Some(input) = input else {
        println!(
            "{}",
            json!({"command": mode, "failure": "invalid_input",
            "message": "Supply one valid JSON object on standard input. Run with --help for the accepted fields."})
        );
        return ExitCode::FAILURE;
    };
    let (code, summary) = match mode {
        "submit" => submit(directory, input).await,
        "observe" => observe(&directory, input).await,
        "remove-device" => remove_device(directory, input).await,
        _ => observe_device(&directory, input).await,
    };
    let _ = writeln!(io::stdout().lock(), "{summary}");
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use verysync_sidecar::ControlOperationKind;

    fn event(submission: ControlSubmission) -> ControlOperationEvent {
        ControlOperationEvent {
            operation_id: "00000000000000000000000000000000".to_owned(),
            kind: ControlOperationKind::GuiListenerChange,
            submission,
            started_at_unix_millis: 40,
            elapsed_millis: 3,
            response_status: None,
            device_removal: None,
        }
    }

    #[test]
    fn event_buffer_coalesces_progress_and_counts_overflow() {
        let mut events = Events::default();
        events.record(event(ControlSubmission::Prepared));
        events.record(event(ControlSubmission::Prepared));
        for index in 1..=EVENT_LIMIT {
            let submission = if index % 2 == 0 {
                ControlSubmission::Prepared
            } else {
                ControlSubmission::PossiblySubmitted
            };
            events.record(event(submission));
        }
        assert_eq!(events.entries.len(), EVENT_LIMIT);
        assert_eq!(events.entries[0].1, 2);
        assert_eq!(events.dropped, 1);
    }

    #[test]
    fn a_new_operation_cannot_overwrite_an_existing_receipt() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path();
        store_file(path, RECEIPT_NAME, b"existing checkpoint", true)?;
        assert!(store_file(path, RECEIPT_NAME, b"other intent", true).is_err());
        assert_eq!(fs::read(path.join(RECEIPT_NAME))?, b"existing checkpoint");
        Ok(())
    }
}
