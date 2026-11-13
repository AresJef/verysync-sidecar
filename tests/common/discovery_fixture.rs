//! Private HTTPS fixture with owned process and bounded native readiness/exit.
use serde_json::Value;
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub struct DiscoveryFixture {
    child: Option<Child>,
    root: tempfile::TempDir,
    port: u16,
}
fn bounded(path: &Path) -> TestResult<Value> {
    if std::fs::metadata(path)?.len() > 4096 {
        return Err("fixture record too large".into());
    }
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
impl DiscoveryFixture {
    pub async fn start(
        server: PathBuf,
        client: PathBuf,
        device: String,
        address: String,
    ) -> TestResult<Self> {
        tokio::task::spawn_blocking(move || -> TestResult<Self> {
            let root = tempfile::Builder::new().prefix("vsds-").tempdir()?;
            let mut command = Command::new(if cfg!(windows) { "python" } else { "python3" });
            command
                .arg(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("scripts")
                        .join("fixture-discovery-server.py"),
                )
                .arg("--server-state")
                .arg(server)
                .arg("--client-state")
                .arg(client)
                .arg("--device")
                .arg(device)
                .arg("--address")
                .arg(address)
                .arg("--output")
                .arg(root.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
            }
            let child = command.spawn()?;
            let mut fixture = Self {
                child: Some(child),
                root,
                port: 0,
            };
            let ready = fixture.root.path().join("ready.json");
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                if ready.try_exists()? {
                    break;
                }
                if fixture
                    .child
                    .as_mut()
                    .ok_or("fixture child missing")?
                    .try_wait()?
                    .is_some()
                {
                    eprintln!(
                        "private discovery startup diagnostic: {}",
                        bounded(&fixture.root.path().join("stage.json"))
                            .unwrap_or(serde_json::json!({"phase":"no-stage-file"}))
                    );
                    return Err("private discovery fixture exited before readiness".into());
                }
                if Instant::now() >= deadline {
                    eprintln!(
                        "private discovery startup diagnostic: {}",
                        bounded(&fixture.root.path().join("stage.json"))
                            .unwrap_or(serde_json::json!({"phase":"no-stage-file"}))
                    );
                    return Err("private discovery fixture readiness deadline".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let value = bounded(&ready)?;
            fixture.port = u16::try_from(
                value["loopback_https_port"]
                    .as_u64()
                    .ok_or("fixture port missing")?,
            )?;
            if fixture.port == 0 || fixture.port == 18886 {
                return Err("private fixture port invalid".into());
            }
            Ok(fixture)
        })
        .await?
    }
    pub fn enable_private_routing(&self) -> TestResult {
        let path = PathBuf::from(
            std::env::var_os("VERYSYNC_TEST_DISCOVERY_FORWARD_TARGET_FILE")
                .ok_or("network suite requires explicit private-discovery wrapper mode")?,
        );
        let token = std::env::var("VERYSYNC_TEST_DISCOVERY_FORWARD_TOKEN")?;
        if !path.is_absolute() || token.len() != 64 {
            return Err("invalid private discovery routing record".into());
        }
        let temporary = path.with_extension("tmp");
        let value = serde_json::json!({"port":self.port,"token":token});
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(&value)?)?;
        drop(file);
        std::fs::rename(temporary, path)?;
        Ok(())
    }
    pub async fn close(mut self) -> TestResult<Value> {
        tokio::task::spawn_blocking(move || -> TestResult<Value> {
            let child = self.child.as_mut().ok_or("fixture already stopped")?;
            child
                .stdin
                .as_mut()
                .ok_or("fixture input missing")?
                .write_all(b"stop\n")?;
            child.stdin.take();
            let deadline = Instant::now() + Duration::from_secs(8);
            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break status;
                }
                if Instant::now() >= deadline {
                    return Err("fixture exit deadline".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            if !status.success() {
                return Err("private discovery fixture failed".into());
            }
            self.child.take();
            bounded(&self.root.path().join("result.json"))
        })
        .await?
    }
}
impl Drop for DiscoveryFixture {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}
