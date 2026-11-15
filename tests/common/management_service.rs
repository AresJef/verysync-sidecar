//! Exact retained child for a test-only TLS origin and private authenticated proxies.
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};
use verysync_sidecar::{ManagementEndpoint, ManagementProxy};
type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct ManagementService {
    child: Option<Child>,
    root: PathBuf,
    origin_port: u16,
    proxy_port: u16,
    tls_proxy_port: u16,
    password: String,
    pub python_platform: String,
}
impl ManagementService {
    pub fn start(root: &Path, backend_port: u16) -> TestResult<Self> {
        std::fs::create_dir(root)?;
        let python = std::env::var_os("VERYSYNC_STORAGE_TEST_PYTHON")
            .ok_or("explicit private management test Python required")?;
        let mut random = [0; 24];
        getrandom::fill(&mut random).map_err(|_| "management fixture entropy failed")?;
        let password: String = random.iter().map(|v| format!("{v:02x}")).collect();
        let child = Command::new(python)
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/management-test-service.py"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(std::fs::File::create(
                root.join("private-management-peer.log"),
            )?)
            .spawn()?;
        let mut service = Self {
            child: Some(child),
            root: root.into(),
            origin_port: 0,
            proxy_port: 0,
            tls_proxy_port: 0,
            password,
            python_platform: String::new(),
        };
        let child = service
            .child
            .as_mut()
            .ok_or("management peer owner absent")?;
        let mut input = child.stdin.take().ok_or("management peer input absent")?;
        serde_json::to_writer(
            &mut input,
            &serde_json::json!({"root":root,"backend_port":backend_port,
            "username":"isolated-proxy-user","password":service.password}),
        )?;
        input.write_all(b"\n")?;
        drop(input);
        let output = child.stdout.take().ok_or("management peer output absent")?;
        let (sender, receiver) = mpsc::channel();
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
                eprintln!("{}", service.startup_diagnostic());
                service.stop()?;
                let _ = reader.join();
                return Err("management peer readiness timed out".into());
            }
        };
        reader
            .join()
            .map_err(|_| "management readiness reader failed")?;
        if line.len() > 8192 || !line.ends_with(b"\n") {
            return Err("bounded management readiness required".into());
        }
        let ready: serde_json::Value = serde_json::from_slice(&line)?;
        let port = |key| -> TestResult<u16> {
            Ok(ready[key]
                .as_u64()
                .filter(|v| *v > 0 && *v <= 65535 && *v != 18886)
                .ok_or("management fixture port invalid")? as u16)
        };
        if ready["ready"] != true || ready["loopback_only"] != true {
            return Err("management peer readiness differs".into());
        }
        service.python_platform = ready["python_platform"]
            .as_str()
            .ok_or("management peer platform absent")?
            .to_owned();
        service.origin_port = port("origin_port")?;
        service.proxy_port = port("proxy_port")?;
        service.tls_proxy_port = port("tls_proxy_port")?;
        Ok(service)
    }
    fn startup_diagnostic(&mut self) -> serde_json::Value {
        let mut bytes = Vec::new();
        let state = std::fs::File::open(self.root.join("management-startup.json"))
            .ok()
            .and_then(|file| file.take(1025).read_to_end(&mut bytes).ok())
            .filter(|_| bytes.len() <= 1024)
            .and_then(|_| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
        let phase = state
            .as_ref()
            .and_then(|value| value["phase"].as_str())
            .filter(|phase| {
                matches!(
                    *phase,
                    "loading_crypto"
                        | "creating_certificates"
                        | "certificates_ready"
                        | "binding_origin"
                        | "binding_http_proxy"
                        | "binding_https_proxy"
                        | "ready"
                )
            })
            .unwrap_or("unavailable");
        let elapsed_millis = state
            .as_ref()
            .and_then(|value| value["elapsed_millis"].as_u64());
        let child_exited = self
            .child
            .as_mut()
            .and_then(|child| child.try_wait().ok())
            .map(|status| status.is_some());
        let private_stderr_bytes = std::fs::metadata(self.root.join("private-management-peer.log"))
            .ok()
            .map(|metadata| metadata.len());
        serde_json::json!({"management_peer_startup_failure": {
            "phase": phase, "phase_elapsed_millis": elapsed_millis,
            "child_exited": child_exited, "private_stderr_bytes": private_stderr_bytes,
            "readiness_timeout_seconds": 12
        }})
    }
    pub fn endpoint(&self, correct_hostname: bool) -> TestResult<ManagementEndpoint> {
        let host = if correct_hostname {
            "localhost"
        } else {
            "127.0.0.1"
        };
        Ok(ManagementEndpoint::http(&format!(
            "https://{host}:{}/",
            self.origin_port
        ))?)
    }
    pub fn redirect_endpoint(&self) -> TestResult<ManagementEndpoint> {
        Ok(ManagementEndpoint::http(&format!(
            "https://localhost:{}/redirect/",
            self.origin_port
        ))?)
    }
    pub fn proxy(&self, tls: bool) -> TestResult<ManagementProxy> {
        let (scheme, port) = if tls {
            ("https", self.tls_proxy_port)
        } else {
            ("http", self.proxy_port)
        };
        Ok(
            ManagementProxy::new(&format!("{scheme}://localhost:{port}/"))?
                .basic_auth("isolated-proxy-user", &self.password)?,
        )
    }
    pub fn pem(&self) -> TestResult<Vec<u8>> {
        Ok(std::fs::read(self.root.join("ca.pem"))?)
    }
    pub fn der(&self) -> TestResult<Vec<u8>> {
        Ok(std::fs::read(self.root.join("ca.der"))?)
    }
    pub fn observations(&self) -> TestResult<Vec<serde_json::Value>> {
        std::fs::read_to_string(self.root.join("management-observations.jsonl"))?
            .lines()
            .map(|line| Ok(serde_json::from_str(line)?))
            .collect()
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
impl Drop for ManagementService {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
