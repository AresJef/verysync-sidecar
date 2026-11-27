//! CI-only observer for the standalone package consumer's exact native loopback socket.
use crate::control_fault_origin::TestResult;
use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

pub struct DirectCapture {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
}

impl DirectCapture {
    pub fn start(port: u16) -> TestResult<Option<Self>> {
        if std::env::var("VERYSYNC_TEST_REQUIRE_DIRECT_REQUEST_CAPTURE").as_deref() != Ok("1") {
            return Ok(None);
        }
        if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
            return Err(
                "direct request observation is confined to standard GitHub runner jobs".into(),
            );
        }
        let python = std::env::var_os("VERYSYNC_TEST_PYTHON")
            .ok_or("explicit CI Python is required for loopback observation")?;
        if !Path::new(&python).is_absolute() {
            return Err("the loopback observer requires an absolute Python path".into());
        }
        let mut child = Command::new("/usr/bin/sudo")
            .args(["-n", "--preserve-env=GITHUB_ACTIONS", "--"])
            .arg(python)
            .arg("-B")
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/common/control_loopback_capture.py"),
            )
            .arg("--port")
            .arg(port.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child.stdin.take();
        let output = BufReader::new(child.stdout.take().ok_or("observer stdout absent")?);
        let mut capture = Self {
            child,
            input,
            output,
        };
        let ready = capture.read()?;
        if ready["ready"] != true || ready["loopback_and_owned_port_only"] != true {
            return Err("direct request observation did not confirm its scope".into());
        }
        Ok(Some(capture))
    }

    fn read(&mut self) -> TestResult<Value> {
        let mut row = Vec::new();
        self.output
            .by_ref()
            .take(4097)
            .read_until(b'\n', &mut row)?;
        if row.len() > 4096 || !row.ends_with(b"\n") {
            return Err("direct witness response missing or oversized".into());
        }
        Ok(serde_json::from_slice(&row)?)
    }

    pub fn finish(mut self) -> TestResult<Value> {
        self.input
            .take()
            .ok_or("direct observer input absent")?
            .write_all(b"\x01")?;
        let evidence = self.read()?;
        if !self.child.wait()?.success()
            || evidence["normal_capture_exit"] != true
            || evidence["kernel_dropped_packets"] != 0
            || evidence["reads"] != serde_json::json!({"version": 2, "identity": 3, "gui": 1})
            || evidence["modifications"] != 0
            || evidence["all_routes_allowlisted"] != true
        {
            return Err("direct observer did not confirm six read-only native requests".into());
        }
        Ok(evidence)
    }
}

impl Drop for DirectCapture {
    fn drop(&mut self) {
        // EOF releases the exact observer with its own 30-second bound, even
        // if the test failed before it could report completion.
        self.input.take();
        let _ = self.child.wait();
    }
}
