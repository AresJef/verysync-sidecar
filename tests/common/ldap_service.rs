//! Explicit test-only LDAP peer with an exact retained child and private account.
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};
use verysync_sidecar::GuiCredentials;
type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub struct LdapService {
    child: Option<Child>,
    pub address: String,
    pub credentials: GuiCredentials,
    pub python_platform: String,
    observations: std::path::PathBuf,
    password: String,
}
impl LdapService {
    pub fn start(root: &Path) -> TestResult<Self> {
        Self::start_transport(root, "plain")
    }
    pub fn start_transport(root: &Path, transport: &str) -> TestResult<Self> {
        let python = std::env::var_os("VERYSYNC_STORAGE_TEST_PYTHON")
            .ok_or("explicit private LDAP test Python required")?;
        let mut random = [0; 24];
        getrandom::fill(&mut random).map_err(|_| "private LDAP randomness failed")?;
        let password: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let credentials = GuiCredentials::new("ldap-test-user", password.clone())?;
        let child = Command::new(python)
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/ldap-test-service.py"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(std::fs::File::create(root.join("private-ldap-peer.log"))?)
            .spawn()?;
        let mut service = Self {
            child: Some(child),
            address: String::new(),
            credentials,
            python_platform: String::new(),
            observations: root.join("ldap-observations.jsonl"),
            password,
        };
        let child = service.child.as_mut().ok_or("LDAP peer owner absent")?;
        let mut input = child.stdin.take().ok_or("LDAP peer input absent")?;
        serde_json::to_writer(
            &mut input,
            &serde_json::json!({"root":root,"dn":"uid=ldap-test-user,dc=example,dc=test","password":service.password,"transport":transport}),
        )?;
        input.write_all(b"\n")?;
        drop(input);
        let output = child.stdout.take().ok_or("LDAP peer readiness absent")?;
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
                service.stop()?;
                let _ = reader.join();
                return Err("private LDAP peer readiness timed out".into());
            }
        };
        reader.join().map_err(|_| "LDAP readiness reader failed")?;
        if line.len() > 8192 || !line.ends_with(b"\n") {
            return Err("bounded LDAP readiness required".into());
        }
        let ready: serde_json::Value = serde_json::from_slice(&line)?;
        let port = ready["port"]
            .as_u64()
            .filter(|p| *p > 0 && *p <= 65535 && *p != 18886)
            .ok_or("LDAP peer port invalid")?;
        if ready["ready"] != true
            || ready["loopback_only"] != true
            || ready["protocol"] != "ldap"
            || ready["transport"] != transport
        {
            return Err("private LDAP readiness contract failed".into());
        }
        service.address = format!("127.0.0.1:{port}");
        service.python_platform = ready["python_platform"]
            .as_str()
            .ok_or("LDAP helper platform absent")?
            .to_owned();
        Ok(service)
    }
    pub fn unknown_user(&self) -> TestResult<GuiCredentials> {
        Ok(GuiCredentials::new(
            "unrecognized-user",
            self.password.clone(),
        )?)
    }
    pub fn observations(&self) -> TestResult<Vec<serde_json::Value>> {
        let text = std::fs::read_to_string(&self.observations)?;
        text.lines()
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
impl Drop for LdapService {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
