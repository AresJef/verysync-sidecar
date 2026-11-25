//! The released client sends its real requests against a private loopback model.

use super::*;
use std::{
    io::{BufRead, BufReader, Read},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{SystemTime, UNIX_EPOCH},
};

const DEVICE: &str = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";
const PREFIX: &str = "/rest/localapi/";

#[derive(Default)]
struct State {
    folders: BTreeMap<String, Value>,
    writes: Vec<String>,
    substituted_identity: bool,
    uncertain_patch: bool,
    revoke_after_create: Option<PathBuf>,
}

impl State {
    fn request(&mut self, verb: &str, target: &str, body: Value) -> (u16, Value) {
        let route = target
            .strip_prefix(PREFIX)
            .expect("fixture receives only Local-API routes");
        match (verb, route) {
            ("GET", "system/version") => (
                200,
                json!({"version":"v2.33.2","os":"linux","arch":"amd64"}),
            ),
            ("GET", "system/status") => (200, json!({"myID":DEVICE})),
            ("GET", "config/folders") => (200, json!(self.folders.values().collect::<Vec<_>>())),
            ("POST", "config/folders") => {
                self.writes.push("create".to_owned());
                self.folders
                    .insert(body["id"].as_str().unwrap().to_owned(), body);
                if let Some(path) = self.revoke_after_create.take() {
                    fs::write(path, b"").unwrap();
                }
                (200, Value::Null)
            }
            ("PUT", "config/folders") => {
                self.writes.push("collection".to_owned());
                self.folders = body
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|item| (item["id"].as_str().unwrap().to_owned(), item.clone()))
                    .collect();
                (200, Value::Null)
            }
            (_, item) if item.starts_with("config/folders/") => {
                let id = &item["config/folders/".len()..];
                match verb {
                    "GET" => {
                        let Some(mut config) = self.folders.get(id).cloned() else {
                            return (404, Value::Null);
                        };
                        if self.substituted_identity {
                            config["id"] = json!("wrong-readback");
                        }
                        (200, config)
                    }
                    "PATCH" => {
                        self.writes.push("patch".into());
                        self.folders.get_mut(id).unwrap()["label"] = body["label"].clone();
                        if self.uncertain_patch {
                            return (503, Value::Null);
                        }
                        (200, Value::Null)
                    }
                    "PUT" => {
                        self.writes.push("replace".into());
                        self.folders.insert(id.into(), body);
                        (200, Value::Null)
                    }
                    "DELETE" => {
                        self.writes.push("remove".into());
                        self.folders.remove(id).expect("owned test folder");
                        (200, Value::Null)
                    }
                    _ => (404, Value::Null),
                }
            }
            _ => (404, Value::Null),
        }
    }
}

fn serve(stream: &mut TcpStream, state: &Mutex<State>) {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut reader = BufReader::new(&mut *stream);
    let mut request = String::new();
    assert!(reader.read_line(&mut request).unwrap() > 0);
    let mut fields = request.split_ascii_whitespace();
    let (verb, target) = (fields.next().unwrap(), fields.next().unwrap());
    let mut content_length = 0;
    loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        if line == "\r\n" {
            break;
        }
        let lower = line.to_ascii_lowercase();
        assert!(!lower.starts_with("x-api-key:"));
        if let Some(value) = lower.strip_prefix("content-length:") {
            content_length = value.trim().parse().unwrap();
        }
    }
    assert!(content_length <= 100_000);
    let mut encoded = vec![0; content_length];
    reader.read_exact(&mut encoded).unwrap();
    let body = if encoded.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&encoded).unwrap()
    };
    let (status, reply) = state.lock().unwrap().request(verb, target, body);
    let bytes = serde_json::to_vec(&reply).unwrap();
    write!(
        stream,
        "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        bytes.len(),
    ).unwrap();
    stream.write_all(&bytes).unwrap();
}

struct Fixture {
    root: PathBuf,
    endpoint: ManagementEndpoint,
    state: Arc<Mutex<State>>,
    close: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    original: FolderTarget,
    selected: FolderTarget,
}

impl Fixture {
    fn start() -> Self {
        let marker = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("r33-cfg-{}-{marker}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let original = FolderTarget::new(FIRST_ID, root.join("original")).unwrap();
        let selected = FolderTarget::new(SECOND_ID, root.join("selected")).unwrap();
        let mut state = State::default();
        state.folders.insert(
            FIRST_ID.to_owned(),
            json!({
                "id":FIRST_ID,"label":"Fixture baseline","path":original.path,"paused":true,
                "rescanIntervalS":600,"fsWatcherEnabled":false,"testExtension":"preserved"
            }),
        );
        let state = Arc::new(Mutex::new(state));
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("private loopback test port");
        listener.set_nonblocking(true).unwrap();
        let endpoint =
            ManagementEndpoint::http(&format!("http://{}/", listener.local_addr().unwrap()))
                .unwrap();
        let close = Arc::new(AtomicBool::new(false));
        let worker_close = Arc::clone(&close);
        let worker_state = Arc::clone(&state);
        let thread = thread::spawn(move || {
            while !worker_close.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => serve(&mut stream, &worker_state),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                }
            }
        });
        Self {
            root,
            endpoint,
            state,
            close,
            thread: Some(thread),
            original,
            selected,
        }
    }

    async fn client(&self) -> LocalApiClient {
        open(self.endpoint.clone(), &DeviceId::parse(DEVICE).unwrap())
            .await
            .unwrap()
    }

    async fn change(&self, local: &LocalApiClient) -> Stage<BTreeMap<&'static str, bool>> {
        let template = serde_json::from_value(json!({
            "label":"Fixture default","paused":false,"fsWatcherEnabled":false,"rescanIntervalS":600,
            "testExtension":"selected-preserved"
        }))
        .unwrap();
        change_configurations(&self.root, local, &self.original, &self.selected, &template).await
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.close.store(true, Ordering::Release);
        let worker = self.thread.take().unwrap().join();
        let deleted = fs::remove_dir_all(&self.root);
        if !thread::panicking() {
            worker.unwrap();
            deleted.unwrap();
        }
    }
}

#[tokio::test]
async fn admitted_lifecycle_mutates_each_route_once_and_unregisters_the_selected_folder() {
    let fixture = Fixture::start();
    fs::create_dir(&fixture.selected.path).unwrap();
    let sample = fixture.selected.path.join("sample.txt");
    let witness = fixture.root.join("untouched.txt");
    fs::write(&sample, b"ordinary owned sample").unwrap();
    fs::write(&witness, b"unrelated file").unwrap();
    let files = [sample, witness];
    let before = snapshot(&files).unwrap();
    let local = fixture.client().await;
    let result = fixture.change(&local).await.unwrap();
    assert_eq!(
        result,
        BTreeMap::from([
            ("LA-010", true),
            ("LA-011", true),
            ("LA-013", true),
            ("LA-014", true)
        ])
    );
    assert!(
        unregister_second(&fixture.root, &local, &fixture.original, &fixture.selected)
            .await
            .unwrap()
    );
    let state = fixture.state.lock().unwrap();
    assert_eq!(
        state.writes,
        ["create", "patch", "replace", "collection", "remove"]
    );
    assert_eq!(state.folders[FIRST_ID]["testExtension"], "preserved");
    assert!(!state.folders.contains_key(SECOND_ID));
    assert_eq!(snapshot(&files).unwrap(), before);
}

#[tokio::test]
async fn substituted_native_readback_stops_before_any_write() {
    let fixture = Fixture::start();
    fixture.state.lock().unwrap().substituted_identity = true;
    let local = fixture.client().await;
    assert_eq!(
        fixture.change(&local).await.unwrap_err(),
        "local-api-exact-configuration-target-mismatch"
    );
    assert!(fixture.state.lock().unwrap().writes.is_empty());
}

#[tokio::test]
async fn confirmed_readback_reconciles_one_patch_whose_response_was_uncertain() {
    let fixture = Fixture::start();
    fixture.state.lock().unwrap().uncertain_patch = true;
    let local = fixture.client().await;
    let result = fixture.change(&local).await.unwrap();
    assert!(!result["LA-014"]);
    assert_eq!(
        fixture.state.lock().unwrap().writes,
        ["create", "patch", "replace", "collection"]
    );
}

#[tokio::test]
async fn revoked_fixture_allows_observation_and_refuses_a_new_write() {
    let fixture = Fixture::start();
    fs::write(fixture.root.join("local-grant-revoked"), b"").unwrap();
    let local = fixture.client().await;
    assert_eq!(
        fixture.change(&local).await.unwrap_err(),
        "local-api-grant-unavailable"
    );
    assert!(fixture.state.lock().unwrap().writes.is_empty());
}

#[tokio::test]
async fn a_revocation_after_create_prevents_the_following_patch() {
    let fixture = Fixture::start();
    fixture.state.lock().unwrap().revoke_after_create =
        Some(fixture.root.join("local-grant-revoked"));
    let local = fixture.client().await;
    assert_eq!(
        fixture.change(&local).await.unwrap_err(),
        "local-api-grant-unavailable"
    );
    assert_eq!(fixture.state.lock().unwrap().writes, ["create"]);
}
