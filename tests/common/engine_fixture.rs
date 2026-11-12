//! Private integration-test infrastructure for the fixed upstream baseline.
//!
//! No fixture operation is public-library acceptance evidence. Only an explicit
//! test invocation with a supplied executable and digest can start an engine.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use reqwest::header::HeaderValue;
use reqwest::{Method, RequestBuilder};
use rmpv::Value;
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[cfg(windows)]
#[path = "windows_fixture.rs"]
mod windows_fixture;

pub struct TestBinary {
    path: PathBuf,
    sha256: String,
}

impl TestBinary {
    pub fn new(path: Option<PathBuf>, sha256: Option<String>) -> TestResult<Self> {
        let path = path.ok_or("VERYSYNC_TEST_BINARY is required for engine tests")?;
        let sha256 = sha256.ok_or("VERYSYNC_TEST_BINARY_SHA256 is required for engine tests")?;
        if !path.is_absolute() {
            return Err("test executable must have an explicit absolute path".into());
        }
        if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("test executable checksum must be a SHA-256 hex digest".into());
        }
        Ok(Self {
            path,
            sha256: sha256.to_ascii_lowercase(),
        })
    }

    pub fn from_env() -> TestResult<Self> {
        Self::new(
            std::env::var_os("VERYSYNC_TEST_BINARY").map(PathBuf::from),
            std::env::var("VERYSYNC_TEST_BINARY_SHA256").ok(),
        )
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn verify(&self) -> TestResult {
        let mut file = File::open(&self.path)?;
        let mut digest = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        if format!("{:x}", digest.finalize()) != self.sha256 {
            return Err("test executable checksum mismatch; engine not started".into());
        }
        Ok(())
    }
}

/// An exact child handle, retained before any asynchronous wait.
struct OwnedChild {
    child: Option<Child>,
    #[cfg(windows)]
    job: windows_fixture::Job,
}

impl OwnedChild {
    fn spawn(command: &mut Command) -> TestResult<Self> {
        #[cfg(windows)]
        let job = {
            use std::os::windows::process::CommandExt;
            use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};
            command.creation_flags(CREATE_NO_WINDOW | CREATE_SUSPENDED);
            windows_fixture::Job::new()?
        };
        let owned = Self {
            child: Some(command.spawn()?),
            #[cfg(windows)]
            job,
        };
        #[cfg(windows)]
        owned
            .job
            .assign_and_resume(owned.child.as_ref().ok_or("missing new child")?)?;
        Ok(owned)
    }

    fn confirm_tree_stopped(&self) -> TestResult {
        #[cfg(windows)]
        self.job.wait_empty(Duration::from_secs(10))?;
        Ok(())
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Err(error) = self.job.terminate_and_wait() {
            eprintln!("private fixture job cleanup failed: {error}");
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub struct EngineFixture {
    child: OwnedChild,
    state: TempDir,
    client: reqwest::Client,
    base: String,
    management_address: String,
    api_key: String,
    device_id: String,
    pid: u32,
    reaped: bool,
}

impl EngineFixture {
    pub async fn start() -> TestResult<Self> {
        Self::start_from(TestBinary::from_env()?).await
    }

    pub async fn start_from(binary: TestBinary) -> TestResult<Self> {
        binary.verify()?;
        let state = tempfile::Builder::new().prefix("vs-test-").tempdir()?;
        protect_directory(state.path())?;
        fs::write(state.path().join("appconf.yaml"), "auto_startup: false\n")?;
        protect_file(&state.path().join("appconf.yaml"))?;
        for directory in ["roaming", "local", "profile", "tmp"] {
            fs::create_dir(state.path().join(directory))?;
        }
        let version = run_tool(&binary.path, state.path(), &["version"], None).await?;
        if !baseline_version_output(&version) {
            return Err("fixture requires the verified VerySync v2.33.2 baseline".into());
        }
        let mut entropy = [0; 32];
        getrandom::fill(&mut entropy).map_err(|e| io::Error::other(e.to_string()))?;
        let password: String = entropy.iter().map(|b| format!("{b:02x}")).collect();
        run_tool(
            &binary.path,
            state.path(),
            &[
                "generate",
                "--no-port-probing",
                "--gui-user",
                "sidecar-test",
                "--gui-password",
                "-",
            ],
            Some(&password),
        )
        .await?;
        let device_output = run_tool(&binary.path, state.path(), &["device-id"], None).await?;
        let device_id = device_id_output(&device_output)
            .ok_or("fixture generated no unambiguous device identity")?
            .to_owned();

        let builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5));
        #[cfg(unix)]
        let (builder, management_address, base) = {
            let socket = state.path().join("gui.sock");
            use std::os::unix::ffi::OsStrExt;
            if socket.as_os_str().as_bytes().len() >= 104 {
                return Err("private test socket path exceeds the portable Unix limit".into());
            }
            let builder = builder.unix_socket(socket.as_path());
            (
                builder,
                path_string(&socket)?,
                "http://localhost".to_owned(),
            )
        };
        #[cfg(windows)]
        let (builder, management_address, base) = {
            let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            let address = listener.local_addr()?;
            // The engine cannot inherit this listener. Verify the generated device
            // identity before issuing any mutating request after this reservation.
            drop(listener);
            (builder, address.to_string(), format!("http://{address}"))
        };
        let client = builder.build()?;
        let api_key = configure_state(state.path(), &management_address)?;
        let log = File::create(state.path().join("engine.log"))?;
        protect_file(&state.path().join("engine.log"))?;
        let mut command = engine_command(&binary.path, state.path())?;
        command
            .arg("serve")
            .arg("--home")
            .arg(state.path())
            .args(["--no-browser", "--no-restart", "--no-upgrade"])
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        let child = OwnedChild::spawn(&mut command)?;
        let pid = child.child.as_ref().ok_or("missing fixture child")?.id();
        let mut fixture = Self {
            child,
            state,
            client,
            base,
            management_address,
            api_key,
            device_id,
            pid,
            reaped: false,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = fixture
                .child
                .child
                .as_mut()
                .ok_or("lost fixture process ownership")?
                .try_wait()?
            {
                return Err(format!(
                    "isolated engine exited before authenticated readiness ({status}): {}",
                    fixture.startup_diagnostic(&password)
                )
                .into());
            }
            if let Ok(status) = fixture.read_json("/rest/system/status").await {
                if status["myID"].as_str() != Some(fixture.device_id.as_str()) {
                    return Err(
                        "management endpoint identity does not belong to the fixture".into(),
                    );
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err(format!("isolated engine did not become authenticated and ready before its deadline: {}", fixture.startup_diagnostic(&password)).into());
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        Ok(fixture)
    }

    pub fn state_dir(&self) -> &Path {
        self.state.path()
    }
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
    pub fn api_key(&self) -> &str {
        &self.api_key
    }
    pub fn management_address(&self) -> &str {
        &self.management_address
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn has_reaped_process(&self) -> bool {
        self.reaped
    }

    fn startup_diagnostic(&self, password: &str) -> String {
        let read_tail = || -> io::Result<Vec<u8>> {
            let mut file = File::open(self.state.path().join("engine.log"))?;
            let length = file.metadata()?.len();
            file.seek(SeekFrom::Start(length.saturating_sub(8192)))?;
            let mut bytes = Vec::new();
            file.take(8192).read_to_end(&mut bytes)?;
            Ok(bytes)
        };
        let Ok(bytes) = read_tail() else {
            return "private startup log unavailable".to_owned();
        };
        let mut text = String::from_utf8_lossy(&bytes).into_owned();
        if text.contains("PRIVATE KEY") {
            return "private key material suppressed".to_owned();
        }
        for secret in [&self.api_key, password] {
            if !secret.is_empty() {
                text = text.replace(secret, "[REDACTED]");
            }
        }
        if let Ok(bytes) = fs::read(self.state.path().join("setting.dat")) {
            if let Ok(value) = rmpv::decode::read_value(&mut io::Cursor::new(bytes)) {
                if let Some(hash) = value["4"]["4"].as_str().filter(|s| !s.is_empty()) {
                    text = text.replace(hash, "[REDACTED]");
                }
            }
        }
        text
    }

    pub fn request_with_key(
        &self,
        method: Method,
        route: &str,
        key: &str,
    ) -> TestResult<RequestBuilder> {
        if !route.starts_with("/rest/") || route.contains(['#', '?']) {
            return Err("fixture request must use an explicit local REST path".into());
        }
        let mut header = HeaderValue::from_str(key)?;
        header.set_sensitive(true);
        Ok(self
            .client
            .request(method, format!("{}{route}", self.base))
            .header("X-API-Key", header))
    }

    pub fn request(&self, method: Method, route: &str) -> TestResult<RequestBuilder> {
        self.request_with_key(method, route, &self.api_key)
    }

    pub async fn read_json(&self, route: &str) -> TestResult<Json> {
        let mut response = self.request(Method::GET, route)?.send().await?;
        if !response.status().is_success() {
            return Err("fixture management read rejected".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > 1024 * 1024 {
                return Err("fixture response limit exceeded".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub async fn shutdown(&mut self) -> TestResult<ExitStatus> {
        let acknowledged = self
            .request(Method::POST, "/rest/system/shutdown")?
            .send()
            .await?
            .status()
            .is_success();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let child = self.child.child.as_mut().ok_or("fixture already stopped")?;
            if let Some(status) = child.try_wait()? {
                self.child.confirm_tree_stopped()?;
                self.reaped = true;
                self.child.child.take();
                if !acknowledged {
                    return Err("fixture shutdown was not acknowledged".into());
                }
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err("owned fixture process did not stop before deadline".into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub fn private_resources_are_protected(&self) -> TestResult<bool> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [
                self.state.path().to_owned(),
                self.state.path().join("setting.dat"),
                self.state.path().join("key.pem"),
            ] {
                if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        #[cfg(windows)]
        {
            for (path, require_protected) in [
                (self.state.path().to_owned(), true),
                (self.state.path().join("setting.dat"), false),
                (self.state.path().join("key.pem"), false),
            ] {
                if !protected_windows_acl(&path, require_protected)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }
}

fn command(program: &Path) -> Command {
    let command = Command::new(program);
    #[cfg(windows)]
    let command = {
        use std::os::windows::process::CommandExt;
        let mut command = command;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW for test helpers.
        command
    };
    command
}

fn engine_command(program: &Path, home: &Path) -> TestResult<Command> {
    #[cfg(target_os = "macos")]
    let mut c = {
        let mut c = command(Path::new("/usr/bin/sandbox-exec"));
        let canonical_home = fs::canonicalize(home)?;
        let quoted_home = serde_json::to_string(&path_string(&canonical_home)?)?;
        let profile = format!("(version 1)(allow default)(deny network-outbound (require-all (remote ip) (require-not (remote ip \"localhost:*\"))))(deny network-inbound (require-all (local ip) (require-not (local ip \"localhost:*\"))))(deny file-write* (require-not (require-any (subpath {quoted_home}) (literal \"/dev/null\"))))");
        c.args(["-p", &profile]);
        c.arg(program);
        c
    };
    #[cfg(not(target_os = "macos"))]
    let mut c = command(program);
    c.current_dir(home).env("TMPDIR", home.join("tmp"));
    #[cfg(windows)]
    c.env("APPDATA", home.join("roaming"))
        .env("LOCALAPPDATA", home.join("local"))
        .env("USERPROFILE", home.join("profile"))
        .env("TEMP", home.join("tmp"))
        .env("TMP", home.join("tmp"));
    Ok(c)
}

async fn run_tool(
    program: &Path,
    home: &Path,
    args: &[&str],
    password: Option<&str>,
) -> TestResult<String> {
    let mut c = engine_command(program, home)?;
    c.args(args)
        .arg("--home")
        .arg(home)
        .stdin(if password.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut owned = OwnedChild::spawn(&mut c)?;
    if let Some(password) = password {
        let mut input = owned
            .child
            .as_mut()
            .and_then(|c| c.stdin.take())
            .ok_or("missing private credential input")?;
        writeln!(input, "{password}")?;
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if owned
            .child
            .as_mut()
            .ok_or("lost helper ownership")?
            .try_wait()?
            .is_some()
        {
            let output = owned
                .child
                .take()
                .ok_or("lost helper ownership")?
                .wait_with_output()?;
            if !output.status.success() {
                return Err(
                    "isolated engine helper failed; private output retained only in memory".into(),
                );
            }
            if output.stdout.len() > 64 * 1024 {
                return Err("engine helper output limit exceeded".into());
            }
            return Ok(String::from_utf8(output.stdout)?);
        }
        if Instant::now() >= deadline {
            return Err("engine helper exceeded its deadline".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(unix)]
fn path_string(path: &Path) -> TestResult<String> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        "test path cannot be represented without loss at the protocol boundary".into()
    })
}

fn field_mut<'a>(value: &'a mut Value, key: &str) -> TestResult<&'a mut Value> {
    let Value::Map(entries) = value else {
        return Err("unexpected baseline configuration map".into());
    };
    entries
        .iter_mut()
        .find(|(k, _)| k.as_str() == Some(key))
        .map(|(_, v)| v)
        .ok_or_else(|| format!("missing baseline configuration field {key}").into())
}

fn set(value: &mut Value, key: &str, replacement: Value) -> TestResult {
    let Value::Map(entries) = value else {
        return Err("unexpected baseline configuration map".into());
    };
    if let Some((_, v)) = entries.iter_mut().find(|(k, _)| k.as_str() == Some(key)) {
        *v = replacement;
    } else {
        entries.push((Value::from(key), replacement));
    }
    Ok(())
}

fn configure_state(home: &Path, address: &str) -> TestResult<String> {
    let path = home.join("setting.dat");
    let bytes = fs::read(&path)?;
    let mut cursor = io::Cursor::new(&bytes);
    let mut root = rmpv::decode::read_value(&mut cursor)?;
    if cursor.position() != bytes.len() as u64 || root["1"].as_i64() != Some(54) {
        return Err("unexpected v2.33.2 MessagePack configuration schema".into());
    }
    // These numeric wire tags are specific to the verified v2.33.2 baseline.
    // Preserve every unknown value and do not apply this schema to other versions.
    set(&mut root, "2", Value::Array(Vec::new()))?;
    let gui = field_mut(&mut root, "4")?;
    let api_key = gui["6"]
        .as_str()
        .ok_or("generated API key missing")?
        .to_owned();
    if api_key.len() < 20 || gui["4"].as_str().is_none_or(str::is_empty) {
        return Err("isolated GUI credentials were not generated".into());
    }
    for (key, value) in [("1", true), ("5", false), ("7", false), ("10", false)] {
        set(gui, key, Value::Boolean(value))?;
    }
    set(gui, "2", Value::from(address))?;
    let options = field_mut(&mut root, "5")?;
    set(
        options,
        "1",
        Value::Array(vec![Value::from("tcp://127.0.0.1:0")]),
    )?;
    set(options, "2", Value::Array(Vec::new()))?;
    for key in ["3", "4", "10", "12", "13", "59", "74", "79"] {
        set(options, key, Value::Boolean(false))?;
    }
    set(options, "17", Value::from(-1))?;
    set(options, "24", Value::from(0))?;
    set(field_mut(&mut root, "12")?, "0", Value::Boolean(false))?;
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &root)?;
    fs::write(&path, encoded)?;
    for name in ["setting.dat", "key.pem", "cert.pem"] {
        protect_file(&home.join(name))?;
    }
    Ok(api_key)
}

fn protect_file(path: &Path) -> TestResult {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    {
        let _ = path;
    } // Files inherit the private, protected directory DACL.
    Ok(())
}

fn protect_directory(path: &Path) -> TestResult {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    {
        let sid = windows_sid()?;
        // The new, empty directory may contain explicit permissions inherited
        // from its creation policy. Reset first; /inheritance:r alone removes
        // only inherited ACEs. No credentials exist in this directory yet.
        let reset = command(&windows_tool("icacls.exe")?)
            .arg(path)
            .arg("/reset")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !reset.success() {
            return Err("could not reset the new empty fixture DACL".into());
        }
        let status = command(&windows_tool("icacls.exe")?)
            .arg(path)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!("*{sid}:(OI)(CI)F"))
            .args(["/grant:r", "*S-1-5-18:(OI)(CI)F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !status.success() {
            return Err("could not protect the private fixture DACL".into());
        }
    }
    Ok(())
}

fn sid_from_csv(text: &str) -> Option<&str> {
    text.split(|c: char| c == '"' || c == ',' || c.is_whitespace())
        .find(|field| {
            field.strip_prefix("S-1-").is_some_and(|tail| {
                !tail.is_empty()
                    && tail
                        .split('-')
                        .all(|part| !part.is_empty() && part.bytes().all(|c| c.is_ascii_digit()))
            })
        })
}

#[cfg(windows)]
fn windows_tool(name: &str) -> TestResult<PathBuf> {
    let root = std::env::var_os("SystemRoot").ok_or("Windows SystemRoot missing")?;
    Ok(PathBuf::from(root).join("System32").join(name))
}

#[cfg(windows)]
fn windows_sid() -> TestResult<String> {
    let output = command(&windows_tool("whoami.exe")?)
        .args(["/user", "/fo", "csv", "/nh"])
        .output()?;
    if !output.status.success() {
        return Err("native Windows identity tool failed".into());
    }
    let text = String::from_utf8(output.stdout)?;
    sid_from_csv(&text)
        .map(str::to_owned)
        .ok_or_else(|| "could not determine the fixture owner's SID".into())
}

#[cfg(windows)]
fn protected_windows_acl(path: &Path, require_protected: bool) -> TestResult<bool> {
    let directory = if path.is_dir() {
        path
    } else {
        path.parent().ok_or("ACL path has no parent")?
    };
    let output_path = directory.join("acl-check.txt");
    let status = command(&windows_tool("icacls.exe")?)
        .arg(path)
        .arg("/save")
        .arg(&output_path)
        .arg("/q")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err("could not inspect the fixture directory DACL".into());
    }
    let bytes = fs::read(output_path)?;
    let text = decode_acl_export(&bytes)?;
    let sid = windows_sid()?;
    let Some(sddl) = text.lines().find(|s| s.starts_with("D:")) else {
        return Err("fixture ACL export contains no DACL record".into());
    };
    let entries: Vec<_> = sddl.split('(').skip(1).collect();
    let valid = (!require_protected || sddl.starts_with("D:P"))
        && entries.len() == 2
        && entries.iter().all(|e| {
            let fields: Vec<_> = e.trim_end_matches(')').split(';').collect();
            fields.len() == 6
                && fields[0] == "A"
                && fields[2] == "FA"
                && [sid.as_str(), "SY", "S-1-5-18"].contains(&fields[5])
        });
    if !valid {
        // Report structure, never the runner's account name or SID.
        let details: Vec<_> = entries
            .iter()
            .map(|entry| {
                let fields: Vec<_> = entry.trim_end_matches(')').split(';').collect();
                if fields.len() != 6 {
                    return "malformed ACE".to_owned();
                }
                let principal = if fields[5] == sid {
                    "owner"
                } else if ["SY", "S-1-5-18"].contains(&fields[5]) {
                    "system"
                } else {
                    "other"
                };
                format!(
                    "type={},flags={},rights={},principal={principal}",
                    fields[0], fields[1], fields[2]
                )
            })
            .collect();
        return Err(format!(
            "private fixture DACL mismatch: protected={}, entries={details:?}",
            sddl.starts_with("D:P")
        )
        .into());
    }
    Ok(true)
}

fn decode_acl_export(bytes: &[u8]) -> TestResult<String> {
    // icacls exports can be UTF-16LE without a BOM. Treating these bytes as
    // UTF-8 produces embedded NULs and falsely reports a missing DACL.
    let has_bom = bytes.starts_with(&[0xff, 0xfe]);
    Ok(if has_bom || bytes.contains(&0) {
        let wide = if has_bom { &bytes[2..] } else { bytes };
        if wide.len() % 2 != 0 {
            return Err("truncated UTF-16 fixture ACL export".into());
        }
        String::from_utf16(
            &wide
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        )?
    } else {
        String::from_utf8(bytes.to_vec())?
    })
}

fn baseline_version_output(text: &str) -> bool {
    // The verified Windows build emits console-init logs before the result.
    let mut versions = text
        .lines()
        .filter_map(|line| line.strip_prefix("verysync "));
    let version = versions
        .next()
        .and_then(|line| line.split_whitespace().next());
    version == Some(verysync_sidecar::BASELINE_ENGINE_VERSION) && versions.next().is_none()
}

fn device_id_output(text: &str) -> Option<&str> {
    let mut candidates = text.lines().map(str::trim).filter(|line| {
        let parts: Vec<_> = line.split('-').collect();
        parts.len() == 8
            && parts.iter().all(|part| {
                part.len() == 7
                    && part
                        .bytes()
                        .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c))
            })
    });
    let id = candidates.next()?;
    if candidates.next().is_some() {
        None
    } else {
        Some(id)
    }
}

#[cfg(test)]
mod fixture_unit_tests {
    #[cfg(windows)]
    #[tokio::test]
    async fn windows_panic_cleanup_terminates_the_entire_owned_job() -> super::TestResult {
        let fixture = super::EngineFixture::start().await?;
        let probe = fixture.child.job.try_clone()?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _owned = fixture;
            panic!("synthetic fixture failure exercises process-tree cleanup");
        }));
        assert!(result.is_err());
        probe.wait_empty(std::time::Duration::from_secs(5))?;
        Ok(())
    }

    #[test]
    fn acl_export_decodes_utf16_with_or_without_bom() -> super::TestResult {
        let expected = "state\r\nD:P(A;OICI;FA;;;SY)\r\n";
        let wide: Vec<_> = expected.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(super::decode_acl_export(&wide)?, expected);
        let mut with_bom = vec![0xff, 0xfe];
        with_bom.extend_from_slice(&wide);
        assert_eq!(super::decode_acl_export(&with_bom)?, expected);
        assert_eq!(super::decode_acl_export(expected.as_bytes())?, expected);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_child_can_write_its_state_but_not_an_outside_canary() -> super::TestResult {
        let state = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let allowed = state.path().join("allowed-canary");
        let denied = outside.path().join("outside-canary");
        let mut command =
            super::engine_command(std::path::Path::new("/usr/bin/touch"), state.path())?;
        assert!(command.arg(&allowed).output()?.status.success());
        assert!(allowed.exists());
        let mut command =
            super::engine_command(std::path::Path::new("/usr/bin/touch"), state.path())?;
        assert!(!command.arg(&denied).output()?.status.success());
        assert!(!denied.exists());
        Ok(())
    }

    #[test]
    fn device_id_probe_accepts_preamble_and_requires_a_unique_canonical_line() {
        let id = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";
        assert_eq!(
            super::device_id_output(&format!("INF console initialization\n{id}\n")),
            Some(id)
        );
        assert_eq!(super::device_id_output(&format!("{id}\n{id}\n")), None);
        assert_eq!(
            super::device_id_output("console output is not an identity"),
            None
        );
    }

    #[test]
    fn version_probe_accepts_preamble_but_rejects_other_or_ambiguous_versions() {
        let text = "2026-11-12 INF Failed allocConsole\n2026-11-12 WRN fixConsole\nverysync v2.33.2 \"Pigeon\" (go1.23.10 windows-amd64)\n";
        assert!(super::baseline_version_output(text));
        assert!(!super::baseline_version_output(
            "verysync v2.33.20 \"Other\"\n"
        ));
        assert!(!super::baseline_version_output(
            "verysync v2.33.2 x\nverysync v2.34.0 y\n"
        ));
    }

    #[test]
    fn windows_sid_csv_accepts_quoted_and_unquoted_fields() {
        for text in [
            "\"machine\\synthetic\",\"S-1-5-21-100-200-300-1001\"\r\n",
            "machine\\synthetic,S-1-5-21-100-200-300-1001\r\n",
        ] {
            assert_eq!(super::sid_from_csv(text), Some("S-1-5-21-100-200-300-1001"));
        }
        assert_eq!(super::sid_from_csv("command failed"), None);
        assert_eq!(super::sid_from_csv("name,S-1-5-invalid"), None);
    }
}
