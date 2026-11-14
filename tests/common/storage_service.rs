//! Explicit test-only protocol peer; never called by library code or Cargo build.
use std::{
    fs::File,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};
use verysync_sidecar::{StorageEndpoint, StorageProtocol};
type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct Service {
    child: Option<Child>,
    pub endpoint: StorageEndpoint,
    pub bad_endpoint: StorageEndpoint,
    pub share: PathBuf,
    pub python_platform: String,
}
impl Service {
    pub fn start(
        protocol: StorageProtocol,
        root: &Path,
        write_delay: Duration,
    ) -> TestResult<Self> {
        if write_delay.as_millis() > 100
            || (protocol != StorageProtocol::Sftp && !write_delay.is_zero())
        {
            return Err("bounded delay is test-only and requires SFTP".into());
        }
        let python = std::env::var_os("VERYSYNC_STORAGE_TEST_PYTHON")
            .ok_or("explicit private storage test interpreter required")?;
        let share = root.join("synthetic-share");
        std::fs::create_dir_all(&share)?;
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| "OS randomness unavailable")?;
        let user: String = random[..8].iter().map(|b| format!("{b:02x}")).collect();
        let password: String = random[8..].iter().map(|b| format!("{b:02x}")).collect();
        let name = match protocol {
            StorageProtocol::Ftp => "ftp",
            StorageProtocol::Sftp => "sftp",
            StorageProtocol::Smb => "smb",
            StorageProtocol::WebDav => "webdav",
        };
        let placeholder = StorageEndpoint::remote(
            protocol,
            &format!(
                "{}://127.0.0.1/",
                if protocol == StorageProtocol::WebDav {
                    "http"
                } else {
                    name
                }
            ),
        )?;
        let child = Command::new(python)
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/storage-test-services.py"))
            .args(["--protocol", name])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(File::create(root.join("private-service.log"))?)
            .spawn()?;
        let mut service = Self {
            child: Some(child),
            endpoint: placeholder.clone(),
            bad_endpoint: placeholder,
            share,
            python_platform: String::new(),
        };
        let child = service
            .child
            .as_mut()
            .ok_or("private service owner absent")?;
        let mut input = child.stdin.take().ok_or("private service stdin absent")?;
        serde_json::to_writer(
            &mut input,
            &serde_json::json!({"root":service.share,"user":user,"password":password,"write_delay_ms":write_delay.as_millis()}),
        )?;
        input.write_all(b"\n")?;
        drop(input);
        let output = child.stdout.take().ok_or("private service stdout absent")?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let mut line = Vec::new();
            let result = BufReader::new(output.take(8193))
                .read_until(b'\n', &mut line)
                .map(|_| line);
            let _ = sender.send(result);
        });
        let line = match receiver.recv_timeout(Duration::from_secs(12)) {
            Ok(result) => result?,
            Err(_) => {
                service.stop()?;
                let _ = reader.join();
                return Err("private service readiness timed out".into());
            }
        };
        reader
            .join()
            .map_err(|_| "private readiness reader panicked")?;
        if line.len() > 8192 || !line.ends_with(b"\n") {
            return Err("private service readiness exceeds bound".into());
        }
        let ready: serde_json::Value = serde_json::from_slice(&line)?;
        let port = ready["port"]
            .as_u64()
            .filter(|p| *p > 0 && *p <= 65535 && *p != 18886)
            .ok_or("invalid private service port")?;
        if ready["ready"] != true || ready["loopback_only"] != true {
            return Err("service has no explicit private readiness".into());
        }
        service.python_platform = ready["python_platform"]
            .as_str()
            .ok_or("helper platform classification absent")?
            .to_owned();
        let scheme = if protocol == StorageProtocol::WebDav {
            "http"
        } else {
            name
        };
        let path = if protocol == StorageProtocol::Smb {
            "/synthetic/"
        } else {
            "/"
        };
        let endpoint =
            StorageEndpoint::remote(protocol, &format!("{scheme}://127.0.0.1:{port}{path}"))?
                .connection_timeout_seconds(6);
        let endpoint = if protocol == StorageProtocol::Sftp {
            endpoint.insecure_tls(true)?
        } else {
            endpoint
        };
        service.endpoint = endpoint.clone().credentials(user.clone(), password)?;
        service.bad_endpoint =
            endpoint.credentials(user, "deliberately-incorrect-synthetic-password")?;
        Ok(service)
    }
    pub fn stop(&mut self) -> TestResult<()> {
        if let Some(child) = self.child.as_mut() {
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
            child.wait()?;
            self.child = None;
        }
        Ok(())
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
