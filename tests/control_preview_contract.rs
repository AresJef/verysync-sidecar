//! Check settings previews using an independent witness at the request boundary.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use verysync_sidecar::{
    ApiKey, Client, ConnectOptions, ControlSubmission, DeviceId, Error, FolderId, FolderPatch,
    GuiListenAddress, GuiListenerPatch, ManagementEndpoint, SettingsChange, SettingsField,
    SettingsFieldState as State, SettingsValue,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const DEVICE: &str = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";
const OTHER: &str = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB";
const KEY: &str = "synthetic-private-fixture-key";
const WRITER: &str = "synthetic-private-independent-key";
const NEW_LABEL: &str = "synthetic-private-new-label";
const BEFORE: &str = "127.0.0.1:44121";
const AFTER: &str = "127.0.0.1:44122";
const GUI: &str = "/rest/config/gui";

struct Fixture {
    endpoint: ManagementEndpoint,
    state: Arc<Mutex<FixtureState>>,
    entered_write: Arc<Notify>,
    continue_write: Arc<Notify>,
    task: JoinHandle<()>,
}

struct FixtureState {
    device: &'static str,
    version: &'static str,
    folder_items: BTreeMap<&'static str, Value>,
    listener: Value,
    requests: Vec<(bool, String, String)>,
    drop_folder_reply: Option<&'static str>,
    acknowledge_then_fail_readback: Option<&'static str>,
    keep_old_pause: bool,
    gate_patch: bool,
    drop_gui_reply: bool,
    send_wrong_folder: bool,
}

impl Fixture {
    async fn start() -> TestResult<Self> {
        let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let endpoint = ManagementEndpoint::http(&format!("http://{}/", socket.local_addr()?))?;
        let state = Arc::new(Mutex::new(FixtureState {
            device: DEVICE,
            version: "v2.33.2",
            folder_items: ["test-a", "test-b", "test-c"].into_iter().map(|id| (
                id, json!({"id":id,"label":"Old label","paused":false,"path":"/synthetic","future":17})
            )).collect(),
            listener: json!({
                "enabled":true,"authMode":"static","user":"private-user","password":KEY,
                "apiKey":KEY,"address":BEFORE,"useTLS":false,"unixSocketPermissions":"",
                "future":17
            }),
            requests: Vec::new(),
            drop_folder_reply: None,
            acknowledge_then_fail_readback: None,
            keep_old_pause: false,
            gate_patch: false,
            drop_gui_reply: false,
            send_wrong_folder: false,
        }));
        let entered_write = Arc::new(Notify::new());
        let continue_write = Arc::new(Notify::new());
        let bound_state = Arc::clone(&state);
        let entered = Arc::clone(&entered_write);
        let proceed = Arc::clone(&continue_write);
        let task = tokio::spawn(async move {
            let mut children =
                tokio::task::JoinSet::<Result<TestResult, tokio::time::error::Elapsed>>::new();
            loop {
                tokio::select! {
                    reply = children.join_next(), if !children.is_empty() => {
                        if let Some(reply) = reply {
                            reply.expect("fixture task").expect("fixture deadline").expect("fixture request");
                        }
                    }
                    incoming = socket.accept() => {
                        let (stream, _) = incoming.unwrap();
                        children.spawn(tokio::time::timeout(Duration::from_secs(8), serve(
                            stream, Arc::clone(&bound_state), Arc::clone(&entered), Arc::clone(&proceed)
                        )));
                    }
                }
            }
        });
        Ok(Self {
            endpoint,
            state,
            entered_write,
            continue_write,
            task,
        })
    }

    fn options(&self, credential: &str) -> TestResult<ConnectOptions> {
        Ok(
            ConnectOptions::new(self.endpoint.clone(), ApiKey::new(credential)?)
                .expected_device_id(DeviceId::parse(DEVICE)?)
                .request_timeout(Duration::from_secs(3))?,
        )
    }

    async fn connect(&self, credential: &str) -> TestResult<Client> {
        Ok(Client::connect(self.options(credential)?).await?)
    }

    fn writes(&self, independent: bool) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|(writer, method, _)| *writer == independent && method != "GET")
            .map(|(_, _, path)| path.clone())
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    mut stream: TcpStream,
    state: Arc<Mutex<FixtureState>>,
    entered: Arc<Notify>,
    proceed: Arc<Notify>,
) -> TestResult<()> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 1024];
    let header = loop {
        if let Some(start) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break start + 4;
        }
        let amount = stream.read(&mut chunk).await?;
        assert!(amount != 0 && bytes.len() < 16384);
        bytes.extend_from_slice(&chunk[..amount]);
    };
    let mut lines = std::str::from_utf8(&bytes[..header])?.lines();
    let mut first = lines.next().ok_or("missing request")?.split(' ');
    let method = first.next().ok_or("missing method")?.to_owned();
    let path = first.next().ok_or("missing path")?.to_owned();
    let mut length = 0;
    let mut independent = None;
    for (name, value) in lines.filter_map(|line| line.split_once(':')) {
        if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse()?;
        }
        if name.eq_ignore_ascii_case("x-api-key") {
            assert!(
                matches!(value.trim(), KEY | WRITER),
                "synthetic authentication mismatch"
            );
            independent = Some(value.trim() == WRITER);
        }
    }
    let independent = independent.ok_or("no fixture credential")?;
    assert!(length < 4096);
    while bytes.len() < header + length {
        let amount = stream.read(&mut chunk).await?;
        assert!(amount != 0);
        bytes.extend_from_slice(&chunk[..amount]);
    }

    let stall = {
        let mut state = state.lock().unwrap();
        state
            .requests
            .push((independent, method.clone(), path.clone()));
        !independent && method == "PATCH" && state.gate_patch
    };
    if stall {
        entered.notify_one();
        proceed.notified().await;
    }
    let response = {
        let mut state = state.lock().unwrap();
        let item = path.strip_prefix("/rest/config/folders/");
        match (method.as_str(), path.as_str(), item) {
            ("GET", "/rest/system/version", _) => Some((
                200,
                json!({
                    "version":state.version, "os":"linux", "arch":"amd64"
                }),
            )),
            ("GET", "/rest/system/status", _) => Some((200, json!({"myID":state.device}))),
            ("GET", "/rest/config", _) => Some((
                200,
                json!({
                    "folders":state.folder_items.values().collect::<Vec<_>>()
                }),
            )),
            ("GET", GUI, _) => Some((200, state.listener.clone())),
            ("GET", _, Some(id)) if state.folder_items.contains_key(id) => {
                let mut folder = state.folder_items[id].clone();
                if state.send_wrong_folder {
                    folder["id"] = "unexpected-registration".into();
                }
                if state.acknowledge_then_fail_readback == Some(id)
                    && state
                        .requests
                        .iter()
                        .any(|(independent, method, request_path)| {
                            !independent && method == "PATCH" && request_path == &path
                        })
                {
                    Some((503, json!({})))
                } else {
                    Some((200, folder))
                }
            }
            ("PATCH", _, Some(id)) if state.folder_items.contains_key(id) => {
                let mut patch: BTreeMap<String, Value> =
                    serde_json::from_slice(&bytes[header..header + length])?;
                assert!(patch
                    .keys()
                    .all(|field| matches!(field.as_str(), "label" | "paused")));
                if state.keep_old_pause {
                    patch.remove("paused");
                }
                let folder = state
                    .folder_items
                    .get_mut(id)
                    .unwrap()
                    .as_object_mut()
                    .unwrap();
                folder.extend(patch);
                (state.drop_folder_reply != Some(id)).then(|| (200, json!({})))
            }
            ("PATCH", GUI, _) => {
                let patch: BTreeMap<String, Value> =
                    serde_json::from_slice(&bytes[header..header + length])?;
                assert!(patch.keys().all(|field| matches!(
                    field.as_str(),
                    "address" | "useTLS" | "enabled" | "unixSocketPermissions"
                )));
                state.listener.as_object_mut().unwrap().extend(patch);
                (!state.drop_gui_reply).then(|| (200, json!({})))
            }
            _ => panic!("unexpected fixture operation"),
        }
    };
    if let Some((status, body)) = response {
        let encoded = serde_json::to_vec(&body)?;
        let header = format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", encoded.len());
        stream.write_all(header.as_bytes()).await?;
        stream.write_all(&encoded).await?;
    }
    Ok(())
}

#[tokio::test]
async fn preview_is_read_only_and_commit_preserves_unselected_values() -> TestResult {
    let fixture = Fixture::start().await?;
    let client = fixture.connect(KEY).await?;
    let writer = fixture.connect(WRITER).await?;
    let id = FolderId::parse("test-a")?;
    let patch = FolderPatch::default().label(NEW_LABEL);
    let preview = client
        .preview_settings_changes(&[SettingsChange::Folder {
            id: &id,
            patch: &patch,
        }])
        .await?;
    assert!(fixture.writes(false).is_empty());
    assert!(fixture
        .state
        .lock()
        .unwrap()
        .requests
        .iter()
        .all(|(_, _, path)| path != "/rest/config"));
    assert_eq!(preview.identity().device_id().as_str(), DEVICE);
    let fields = preview.steps()[0].fields();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].field, SettingsField::FolderLabel);
    assert!(matches!(&fields[0].previous, SettingsValue::Text(value) if value == "Old label"));
    assert!(matches!(&fields[0].requested, SettingsValue::Text(value) if value == NEW_LABEL));
    let debug = format!("{preview:?}");
    for secret in [NEW_LABEL, DEVICE, "test-a", KEY, "Old label"] {
        assert!(!debug.contains(secret));
    }
    writer
        .update_folder(&id, &FolderPatch::default().paused(true))
        .await?;
    let report = client.commit_settings_preview(preview).await;
    assert_eq!(
        report.steps[0].submission,
        ControlSubmission::Acknowledged { status: 200 }
    );
    assert_eq!(report.steps[0].fields[0].state, State::Confirmed);
    assert!(report.steps[0].observation.is_some());
    assert!(report.steps[0].error.is_none());
    assert_eq!(fixture.writes(false), ["/rest/config/folders/test-a"]);
    assert_eq!(fixture.writes(true), ["/rest/config/folders/test-a"]);
    let state = fixture.state.lock().unwrap();
    assert_eq!(state.folder_items["test-a"]["paused"], true);
    assert_eq!(state.folder_items["test-a"]["future"], 17);
    assert_eq!(state.folder_items["test-b"]["label"], "Old label");
    Ok(())
}

#[tokio::test]
async fn a_preexisting_conflict_on_later_target_prevents_every_write() -> TestResult {
    let fixture = Fixture::start().await?;
    let client = fixture.connect(KEY).await?;
    let writer = fixture.connect(WRITER).await?;
    let a = FolderId::parse("test-a")?;
    let b = FolderId::parse("test-b")?;
    let patch = FolderPatch::default().label(NEW_LABEL).paused(true);
    let preview = client
        .preview_settings_changes(&[
            SettingsChange::Folder {
                id: &a,
                patch: &patch,
            },
            SettingsChange::Folder {
                id: &b,
                patch: &patch,
            },
        ])
        .await?;
    writer
        .update_folder(&b, &FolderPatch::default().label("Independent edit"))
        .await?;
    let report = client.commit_settings_preview(preview).await;
    assert!(report
        .steps
        .iter()
        .all(|step| step.submission == ControlSubmission::NotSubmitted));
    assert!(report.steps[0]
        .fields
        .iter()
        .all(|field| field.state == State::NotExecuted));
    assert!(matches!(
        report.steps[1].error,
        Some(Error::ConfigurationChanged)
    ));
    assert_eq!(report.steps[1].fields[0].state, State::Conflict);
    assert_eq!(report.steps[1].fields[1].state, State::NotExecuted);
    assert!(fixture.writes(false).is_empty());
    Ok(())
}

#[tokio::test]
async fn later_unknown_keeps_one_confirmation_and_one_unexecuted_step() -> TestResult {
    for ack_then_fail in [false, true] {
        let fixture = Fixture::start().await?;
        let client = fixture.connect(KEY).await?;
        let a = FolderId::parse("test-a")?;
        let b = FolderId::parse("test-b")?;
        let c = FolderId::parse("test-c")?;
        let patch = FolderPatch::default().label(NEW_LABEL);
        let preview = client
            .preview_settings_changes(&[
                SettingsChange::Folder {
                    id: &a,
                    patch: &patch,
                },
                SettingsChange::Folder {
                    id: &b,
                    patch: &patch,
                },
                SettingsChange::Folder {
                    id: &c,
                    patch: &patch,
                },
            ])
            .await?;
        if ack_then_fail {
            fixture.state.lock().unwrap().acknowledge_then_fail_readback = Some("test-b");
        } else {
            fixture.state.lock().unwrap().drop_folder_reply = Some("test-b");
        }
        let report = client.commit_settings_preview(preview).await;
        assert_eq!(report.steps[0].fields[0].state, State::Confirmed);
        assert_eq!(report.steps[1].fields[0].state, State::Unknown);
        assert!(matches!(
            report.steps[1].error,
            Some(Error::MutationOutcomeUnknown { .. })
        ));
        assert_eq!(
            report.steps[1].submission,
            if ack_then_fail {
                ControlSubmission::Acknowledged { status: 200 }
            } else {
                ControlSubmission::PossiblySubmitted
            }
        );
        assert_eq!(report.steps[2].fields[0].state, State::NotExecuted);
        assert_eq!(
            fixture.writes(false),
            ["/rest/config/folders/test-a", "/rest/config/folders/test-b"]
        );
        assert_eq!(
            fixture.state.lock().unwrap().folder_items["test-b"]["label"],
            NEW_LABEL
        );
    }
    Ok(())
}

#[tokio::test]
async fn one_acknowledgement_can_have_one_matching_and_one_different_field() -> TestResult {
    let fixture = Fixture::start().await?;
    let client = fixture.connect(KEY).await?;
    let a = FolderId::parse("test-a")?;
    let b = FolderId::parse("test-b")?;
    let patch = FolderPatch::default().label(NEW_LABEL).paused(true);
    let preview = client
        .preview_settings_changes(&[
            SettingsChange::Folder {
                id: &a,
                patch: &patch,
            },
            SettingsChange::Folder {
                id: &b,
                patch: &patch,
            },
        ])
        .await?;
    fixture.state.lock().unwrap().keep_old_pause = true;
    let report = client.commit_settings_preview(preview).await;
    assert_eq!(report.steps[0].fields[0].state, State::Confirmed);
    assert_eq!(report.steps[0].fields[1].state, State::Different);
    assert_eq!(report.steps[1].fields[1].state, State::NotExecuted);
    assert_eq!(fixture.writes(false), ["/rest/config/folders/test-a"]);
    Ok(())
}

#[tokio::test]
async fn independent_writer_can_interleave_between_precondition_and_application() -> TestResult {
    let fixture = Fixture::start().await?;
    let client = fixture.connect(KEY).await?;
    let writer = fixture.connect(WRITER).await?;
    let id = FolderId::parse("test-a")?;
    let patch = FolderPatch::default().label(NEW_LABEL);
    let preview = client
        .preview_settings_changes(&[SettingsChange::Folder {
            id: &id,
            patch: &patch,
        }])
        .await?;
    fixture.state.lock().unwrap().gate_patch = true;
    let submit = tokio::spawn(async move { client.commit_settings_preview(preview).await });
    tokio::time::timeout(Duration::from_secs(1), fixture.entered_write.notified()).await?;
    let independent = writer
        .update_folder(&id, &FolderPatch::default().label("Independent edit"))
        .await?;
    assert_eq!(independent.configuration.label, "Independent edit");
    fixture.continue_write.notify_one();
    let report = submit.await?;
    assert_eq!(report.steps[0].fields[0].state, State::Confirmed);
    assert_eq!(fixture.writes(false).len(), 1);
    assert_eq!(fixture.writes(true).len(), 1);
    Ok(())
}

#[tokio::test]
async fn mismatch_identity_version_or_folder_id_rejects_the_write() -> TestResult {
    for case in ["identity", "version", "resource"] {
        let fixture = Fixture::start().await?;
        let client = fixture.connect(KEY).await?;
        let id = FolderId::parse("test-a")?;
        let patch = FolderPatch::default().paused(true);
        let preview = client
            .preview_settings_changes(&[SettingsChange::Folder {
                id: &id,
                patch: &patch,
            }])
            .await?;
        {
            let mut state = fixture.state.lock().unwrap();
            match case {
                "identity" => state.device = OTHER,
                "version" => state.version = "v2.40.0",
                _ => state.send_wrong_folder = true,
            }
        }
        let report = client.commit_settings_preview(preview).await;
        assert_eq!(report.steps[0].fields[0].state, State::NotExecuted);
        assert!(match case {
            "identity" => matches!(report.steps[0].error, Some(Error::IdentityMismatch { .. })),
            "version" => matches!(
                report.steps[0].error,
                Some(Error::IncompatibleVersion { .. })
            ),
            _ => matches!(
                report.steps[0].error,
                Some(Error::InvalidConfiguration { .. })
            ),
        });
        assert!(fixture.writes(false).is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn listener_retains_original_submission_and_reads_back_through_explicit_trust() -> TestResult
{
    for drop in [false, true] {
        let fixture = Fixture::start().await?;
        let client = fixture.connect(KEY).await?;
        let patch = GuiListenerPatch::default().address(GuiListenAddress::tcp(AFTER)?);
        let preview = client
            .preview_settings_changes(&[SettingsChange::GuiListener { patch: &patch }])
            .await?;
        assert!(preview.steps()[0].may_interrupt_management());
        assert!(!format!("{preview:?}").contains(AFTER));
        assert!(fixture.writes(false).is_empty());
        fixture.state.lock().unwrap().drop_gui_reply = drop;
        let mut report = client.commit_settings_preview(preview).await;
        let row = &mut report.steps[0];
        let submission = if drop {
            ControlSubmission::PossiblySubmitted
        } else {
            ControlSubmission::Acknowledged { status: 200 }
        };
        assert_eq!(row.submission, submission);
        assert_eq!(row.fields[0].state, State::Unknown);
        assert_eq!(
            row.listener_receipt.as_ref().unwrap().submission(),
            submission
        );
        row.observe_listener(fixture.options(WRITER)?).await?;
        assert_eq!(row.submission, submission);
        assert_eq!(row.fields[0].state, State::Confirmed);
        assert_eq!(
            row.observation.as_ref().unwrap().device_id().as_str(),
            DEVICE
        );
        assert_eq!(fixture.writes(false), [GUI]);
        assert!(fixture.writes(true).is_empty());
        let state = fixture.state.lock().unwrap();
        assert_eq!(state.listener["future"], 17);
        assert_eq!(state.listener["password"], KEY);
        assert!(!format!("{row:?}").contains(AFTER));
    }
    Ok(())
}

#[tokio::test]
async fn changed_listener_and_different_connection_cannot_dispatch_a_preview() -> TestResult {
    let fixture = Fixture::start().await?;
    let client = fixture.connect(KEY).await?;
    let replacement = Fixture::start().await?;
    let replacement_client = replacement.connect(WRITER).await?;
    let patch = GuiListenerPatch::default().address(GuiListenAddress::tcp(AFTER)?);
    let input = [SettingsChange::GuiListener { patch: &patch }];

    let preview = client.preview_settings_changes(&input).await?;
    let before = replacement.state.lock().unwrap().requests.len();
    let report = replacement_client.commit_settings_preview(preview).await;
    assert_eq!(report.steps[0].submission, ControlSubmission::NotSubmitted);
    assert!(matches!(
        report.steps[0].error,
        Some(Error::InvalidConfiguration { .. })
    ));
    assert_eq!(before, replacement.state.lock().unwrap().requests.len());

    let preview = client.preview_settings_changes(&input).await?;
    let writer = fixture.connect(WRITER).await?;
    writer
        .update_gui_listener(
            &GuiListenerPatch::default().address(GuiListenAddress::tcp("127.0.0.1:44123")?),
        )
        .await?;
    let report = client.commit_settings_preview(preview).await;
    assert_eq!(report.steps[0].fields[0].state, State::Conflict);
    assert!(report.steps[0].listener_receipt.is_none());
    assert!(fixture.writes(false).is_empty());
    assert_eq!(fixture.writes(true), [GUI]);
    Ok(())
}

#[tokio::test]
async fn a_canceled_clone_waits_outside_the_shared_write_lock() -> TestResult {
    let fixture = Fixture::start().await?;
    let client = fixture.connect(KEY).await?;
    let clone = client.clone();
    let a = FolderId::parse("test-a")?;
    let b = FolderId::parse("test-b")?;
    let patch = FolderPatch::default().label(NEW_LABEL);
    let preview = client
        .preview_settings_changes(&[SettingsChange::Folder {
            id: &a,
            patch: &patch,
        }])
        .await?;
    fixture.state.lock().unwrap().gate_patch = true;
    let submit = tokio::spawn(async move { client.commit_settings_preview(preview).await });
    tokio::time::timeout(Duration::from_secs(1), fixture.entered_write.notified()).await?;
    let before = fixture.state.lock().unwrap().requests.len();

    assert!(
        tokio::time::timeout(Duration::ZERO, clone.update_folder(&b, &patch))
            .await
            .is_err()
    );
    assert_eq!(fixture.state.lock().unwrap().requests.len(), before);
    fixture.continue_write.notify_one();
    let report = submit.await?;
    assert_eq!(report.steps[0].fields[0].state, State::Confirmed);
    assert_eq!(fixture.writes(false), ["/rest/config/folders/test-a"]);
    Ok(())
}

#[tokio::test]
async fn package_consumer_requires_approval_before_one_scoped_write() -> TestResult {
    let Some(executable) = std::env::var_os("VERYSYNC_TEST_PREVIEW_EXAMPLE") else {
        println!("Package consumer not requested. Set VERYSYNC_TEST_PREVIEW_EXAMPLE to its absolute path.");
        return Ok(());
    };
    let executable = std::path::PathBuf::from(executable);
    assert!(executable.is_absolute() && executable.is_file());
    let fixture = Fixture::start().await?;
    let endpoint = fixture
        .endpoint
        .http_url()
        .ok_or("test HTTP endpoint absent")?
        .as_str();
    let input = json!({
        "connection": { "endpoint": endpoint, "api_key": KEY, "expected_device_id": DEVICE },
        "folder": { "id": "test-a", "label": NEW_LABEL, "paused": true }
    })
    .to_string();

    for (approval, expected_writes) in [(false, 0), (true, 1)] {
        let binary = executable.clone();
        let input = if approval {
            format!("{input}\napply\n")
        } else {
            format!("{input}\n")
        };
        let output = tokio::task::spawn_blocking(move || run_consumer(&binary, &input)).await??;
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let rendered = String::from_utf8(output.stdout)?;
        for private in [endpoint, DEVICE, KEY, NEW_LABEL, "test-a"] {
            assert!(!rendered.contains(private));
        }
        assert!(rendered.contains("The preview sent no changes."));
        assert_eq!(fixture.writes(false).len(), expected_writes);
        let state = fixture.state.lock().unwrap();
        let actual = &state.folder_items["test-a"];
        if approval {
            assert!(rendered.contains("The device reports the requested value."));
            assert_eq!(actual["label"], NEW_LABEL);
            assert_eq!(actual["paused"], true);
            assert_eq!(actual["future"], 17);
        } else {
            assert!(rendered.contains("closed without sending any changes"));
            assert_eq!(actual["label"], "Old label");
            assert_eq!(actual["paused"], false);
        }
        println!("p4 package consumer: approval={approval}, modifying_requests={expected_writes}, redacted_output=true");
    }
    Ok(())
}

fn run_consumer(executable: &std::path::Path, input: &str) -> TestResult<std::process::Output> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let mut child = Command::new(executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("the package consumer's standard input was unavailable".into());
    };
    let written = stdin.write_all(input.as_bytes());
    drop(stdin);
    if let Err(error) = written {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error.into());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(child.wait_with_output()?),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            outcome => {
                let _ = child.kill();
                let _ = child.wait();
                outcome?;
                return Err("the package consumer did not close within the test deadline".into());
            }
        }
    }
}
