//! Fixed-baseline preparation on the exclusive private owner thread.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

use rmpv::Value;
use sha2::{Digest, Sha256};

use super::{io_error, native, process::OwnedProcess, state::StateLease, ManagedOptions};
use crate::{ApiKey, DeviceId, Error, ProgramInfo, Result, BASELINE_ENGINE_VERSION};

pub(super) struct Prepared {
    pub(super) lease: StateLease,
    pub(super) binary: PathBuf,
    pub(super) info: ProgramInfo,
    pub(super) key: ApiKey,
    pub(super) identity: DeviceId,
}

pub(super) fn check_active(cancel: &Receiver<()>, deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(Error::Timeout {
            operation: "start managed instance",
        });
    }
    match cancel.try_recv() {
        Err(TryRecvError::Empty) => Ok(()),
        _ => Err(Error::ManagedFailure {
            reason: "startup or ownership was cancelled",
        }),
    }
}

pub(super) fn command(binary: &Path, state: &Path) -> Command {
    let mut command = Command::new(binary);
    command.current_dir(state).env("TMPDIR", state.join("tmp"));
    #[cfg(unix)]
    command
        .env("HOME", state.join("profile"))
        .env("XDG_CONFIG_HOME", state.join("roaming"))
        .env("XDG_CACHE_HOME", state.join("local"))
        .env("XDG_DATA_HOME", state.join("profile").join("data"));
    #[cfg(windows)]
    command
        .env("APPDATA", state.join("roaming"))
        .env("LOCALAPPDATA", state.join("local"))
        .env("USERPROFILE", state.join("profile"))
        .env("TEMP", state.join("tmp"))
        .env("TMP", state.join("tmp"));
    command
}

fn persisted_file(state: &Path, name: &str) -> Result<bool> {
    let path = state.join(name);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            // Inspect the entry itself, including dangling aliases. A followed
            // existence check must not turn a broken link into fresh state.
            native::open_private(&path, true)
                .map_err(|e| io_error("check persisted private resource", e))?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error("inspect persisted private resource", error)),
    }
}

pub(super) fn prepare(
    options: &ManagedOptions,
    cancel: &Receiver<()>,
    deadline: Instant,
) -> Result<Prepared> {
    check_active(cancel, deadline)?;
    let lease = StateLease::acquire(&options.state)?;
    let state = lease.path();
    let key_exists = persisted_file(state, "key.pem")?;
    let cert_exists = persisted_file(state, "cert.pem")?;
    let config_exists = persisted_file(state, "setting.dat")?;
    let identity_exists = persisted_file(state, ".verysync-sidecar-identity")?;
    let configured_exists = persisted_file(state, ".verysync-sidecar-configured")?;
    if key_exists != cert_exists || (!key_exists && (identity_exists || configured_exists)) {
        return Err(Error::ManagedFailure {
            reason: "persistent identity is incomplete; it was not regenerated",
        });
    }
    let fresh = !key_exists;
    if fresh && config_exists {
        return Err(Error::ManagedFailure {
            reason: "configuration exists without a complete identity; it was not reset",
        });
    }
    if !fresh && !config_exists {
        return Err(Error::ManagedFailure {
            reason: "persistent configuration is missing; it was not regenerated",
        });
    }
    let expected_id = state.join(".verysync-sidecar-identity");
    for name in ["tmp", "roaming", "local", "profile"] {
        let path = state.join(name);
        if path
            .try_exists()
            .map_err(|e| io_error("inspect private subdirectory", e))?
        {
            let metadata = fs::symlink_metadata(&path)
                .map_err(|e| io_error("inspect private subdirectory", e))?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(Error::UnmanagedState);
            }
            native::private_directory(&path, &metadata)
                .map_err(|e| io_error("check private subdirectory", e))?;
        } else {
            native::create_directory(&path)
                .map_err(|e| io_error("create private subdirectory", e))?;
        }
    }
    #[cfg(windows)]
    {
        let path = state.join("appconf.yaml");
        if path
            .try_exists()
            .map_err(|e| io_error("inspect app settings", e))?
        {
            let mut text = String::new();
            native::open_private(&path, true)
                .map_err(|e| io_error("read app settings", e))?
                .take(1024)
                .read_to_string(&mut text)
                .map_err(|e| io_error("read app settings", e))?;
            if text != "auto_startup: false\n" {
                return Err(Error::ManagedFailure {
                    reason:
                        "owned startup settings changed; automatic startup must remain disabled",
                });
            }
        } else {
            native::create_private(&path)
                .map_err(|e| io_error("create app settings", e))?
                .write_all(b"auto_startup: false\n")
                .map_err(|e| io_error("persist app settings", e))?;
        }
    }
    #[cfg(windows)]
    let resolved = dunce::canonicalize(&options.program.path);
    #[cfg(not(windows))]
    let resolved = fs::canonicalize(&options.program.path);
    let binary = resolved.map_err(|e| io_error("resolve selected executable", e))?;
    let mut input = File::open(&binary).map_err(|e| io_error("open selected executable", e))?;
    if !input
        .metadata()
        .map_err(|e| io_error("inspect executable", e))?
        .is_file()
    {
        return Err(Error::ProgramRejected {
            reason: "executable must be a regular file",
        });
    }
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        check_active(cancel, deadline)?;
        let count = input
            .read(&mut buffer)
            .map_err(|e| io_error("hash executable", e))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let sha256: [u8; 32] = digest.finalize().into();
    if options
        .program
        .expected_sha256
        .is_some_and(|expected| expected != sha256)
    {
        return Err(Error::ProgramRejected {
            reason: "executable SHA-256 differs",
        });
    }
    let version = cli(&binary, state, &["version"], None, cancel, deadline)?;
    let mut versions = version
        .lines()
        .filter_map(|line| line.strip_prefix("verysync "));
    if versions
        .next()
        .and_then(|line| line.split_whitespace().next())
        != Some(BASELINE_ENGINE_VERSION)
        || versions.next().is_some()
    {
        return Err(Error::ProgramRejected {
            reason: "the program does not report the exact v2.33.2 baseline",
        });
    }
    if fresh {
        let mut entropy = [0; 32];
        getrandom::fill(&mut entropy).map_err(|_| Error::ManagedFailure {
            reason: "secure credential generation failed",
        })?;
        let password: String = entropy.iter().map(|b| format!("{b:02x}")).collect();
        cli(
            &binary,
            state,
            &[
                "generate",
                "--no-port-probing",
                "--gui-user",
                "sidecar-managed",
                "--gui-password",
                "-",
            ],
            Some(&password),
            cancel,
            deadline,
        )?;
        for name in ["setting.dat", "key.pem", "cert.pem"] {
            native::protect_generated(&state.join(name))
                .map_err(|e| io_error("protect generated private resource", e))?;
        }
    }
    let output = cli(&binary, state, &["device-id"], None, cancel, deadline)?;
    let identities: Vec<_> = output
        .lines()
        .filter_map(|line| DeviceId::parse(line.trim()).ok())
        .collect();
    if identities.len() != 1 {
        return Err(Error::ProgramRejected {
            reason: "CLI did not return one unambiguous identity",
        });
    }
    let identity = identities.into_iter().next().ok_or(Error::ManagedFailure {
        reason: "identity missing",
    })?;
    if identity_exists {
        let mut text = String::new();
        native::open_private(&expected_id, true)
            .map_err(|e| io_error("read persisted identity", e))?
            .take(128)
            .read_to_string(&mut text)
            .map_err(|e| io_error("read persisted identity", e))?;
        let expected = DeviceId::parse(&text)?;
        if expected != identity {
            return Err(Error::IdentityMismatch {
                expected,
                actual: identity,
            });
        }
    } else {
        native::create_private(&expected_id)
            .map_err(|e| io_error("create persistent identity record", e))?
            .write_all(identity.as_str().as_bytes())
            .map_err(|e| io_error("persist identity record", e))?;
    }
    let ready = state.join(".verysync-sidecar-configured");
    let first_configuration = !configured_exists;
    if !first_configuration {
        let mut mark = Vec::new();
        native::open_private(&ready, true)
            .map_err(|e| io_error("read startup completion", e))?
            .take(2)
            .read_to_end(&mut mark)
            .map_err(|e| io_error("read startup completion", e))?;
        if mark != b"1" {
            return Err(Error::UnmanagedState);
        }
    }
    let key = configure(state, options, first_configuration)?;
    if first_configuration {
        native::create_private(&ready)
            .map_err(|e| io_error("record startup configuration", e))?
            .write_all(b"1")
            .map_err(|e| io_error("persist startup configuration", e))?;
    }
    check_active(cancel, deadline)?;
    Ok(Prepared {
        lease,
        binary,
        info: ProgramInfo {
            sha256,
            version: BASELINE_ENGINE_VERSION.to_owned(),
        },
        key,
        identity,
    })
}

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn cli(
    binary: &Path,
    state: &Path,
    args: &[&str],
    password: Option<&str>,
    cancel: &Receiver<()>,
    deadline: Instant,
) -> Result<String> {
    check_active(cancel, deadline)?;
    let mut entropy = [0; 16];
    getrandom::fill(&mut entropy).map_err(|_| Error::ManagedFailure {
        reason: "temporary capture identity failed",
    })?;
    let nonce: String = entropy.iter().map(|b| format!("{b:02x}")).collect();
    let scratch = Scratch(state.join(format!(".verysync-sidecar-cli-{nonce}.tmp")));
    let capture = native::create_private(&scratch.0)
        .map_err(|e| io_error("create private CLI capture", e))?;
    let mut command = command(binary, state);
    command
        .args(args)
        .arg("--home")
        .arg(state)
        .stdin(if password.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(
            capture
                .try_clone()
                .map_err(|e| io_error("attach private CLI capture", e))?,
        )
        .stderr(Stdio::null());
    #[cfg(windows)]
    command.stderr(
        capture
            .try_clone()
            .map_err(|e| io_error("attach private CLI diagnostics", e))?,
    );
    let mut process =
        OwnedProcess::spawn(command, true).map_err(|e| io_error("spawn metadata helper", e))?;
    if let Some(password) = password {
        let mut input = process
            .child_mut()
            .stdin
            .take()
            .ok_or(Error::ManagedFailure {
                reason: "private credential pipe missing",
            })?;
        writeln!(input, "{password}")
            .map_err(|e| io_error("supply private generated credential", e))?;
    }
    let status = loop {
        check_active(cancel, deadline)?;
        if capture
            .metadata()
            .map_err(|e| io_error("bound CLI capture", e))?
            .len()
            > 65536
        {
            return Err(Error::ProgramRejected {
                reason: "CLI output exceeds the metadata bound",
            });
        }
        if let Some(status) = process
            .try_wait()
            .map_err(|e| io_error("observe metadata helper", e))?
        {
            break status;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    process
        .finish()
        .map_err(|e| io_error("confirm helper tree exit", e))?;
    let mut bytes = Vec::new();
    native::open_private(&scratch.0, true)
        .map_err(|e| io_error("read private CLI result", e))?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error("read private CLI result", e))?;
    if bytes.len() > 65536 {
        return Err(Error::ProgramRejected {
            reason: "CLI metadata exceeds its bound",
        });
    }
    if !status.success() {
        let operation = match args.first().copied() {
            Some("version") => "inspect executable version",
            Some("generate") => "generate private identity",
            Some("device-id") => "read persistent device identity",
            _ => "run metadata helper",
        };
        if let Some(password) = password {
            bytes = String::from_utf8_lossy(&bytes)
                .replace(password, "[REDACTED]")
                .into_bytes();
        }
        return Err(Error::ManagedProcessExited {
            operation,
            code: status.code(),
            diagnostic: Some(crate::ProcessDiagnostic::new(bytes)),
        });
    }
    String::from_utf8(bytes).map_err(|_| Error::ProgramRejected {
        reason: "CLI metadata is not UTF-8",
    })
}

fn set(value: &mut Value, key: &str, replacement: Value) -> Result<()> {
    let Value::Map(entries) = value else {
        return Err(Error::ManagedFailure {
            reason: "unexpected fixed-baseline configuration map",
        });
    };
    if let Some((_, old)) = entries.iter_mut().find(|(k, _)| k.as_str() == Some(key)) {
        *old = replacement;
    } else {
        entries.push((Value::from(key), replacement));
    }
    Ok(())
}

fn field_mut<'a>(root: &'a mut Value, key: &str) -> Result<&'a mut Value> {
    let Value::Map(entries) = root else {
        return Err(Error::ManagedFailure {
            reason: "configuration root is not a map",
        });
    };
    entries
        .iter_mut()
        .find(|(field, _)| field.as_str() == Some(key))
        .map(|(_, value)| value)
        .ok_or(Error::ManagedFailure {
            reason: "required baseline configuration section is missing",
        })
}

fn configure(state: &Path, options: &ManagedOptions, fresh: bool) -> Result<ApiKey> {
    let path = state.join("setting.dat");
    let mut input =
        native::open_private(&path, true).map_err(|e| io_error("open private configuration", e))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut input)
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error("read private configuration", e))?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(Error::ManagedFailure {
            reason: "configuration exceeds its bound",
        });
    }
    let mut cursor = std::io::Cursor::new(&bytes);
    let mut root = rmpv::decode::read_value(&mut cursor).map_err(|_| Error::ManagedFailure {
        reason: "configuration is not baseline MessagePack",
    })?;
    if cursor.position() != bytes.len() as u64 || root["1"].as_i64() != Some(54) {
        return Err(Error::ManagedFailure {
            reason: "configuration does not match the verified baseline schema",
        });
    }
    let key = ApiKey::new(
        root["4"]["6"]
            .as_str()
            .filter(|key| key.len() >= 20)
            .ok_or(Error::ManagedFailure {
                reason: "persistent API credential missing",
            })?,
    )?;
    if root["4"]["4"].as_str().is_none_or(str::is_empty) {
        return Err(Error::ManagedFailure {
            reason: "persistent GUI authentication missing",
        });
    }
    let address = if let Some(socket) = options.endpoint.socket_path() {
        socket.to_str().ok_or(Error::PathEncoding)?.to_owned()
    } else {
        let url = options.endpoint.http_url().ok_or(Error::ManagedFailure {
            reason: "management address missing",
        })?;
        let host = url.host_str().ok_or(Error::ManagedFailure {
            reason: "management host missing",
        })?;
        format!(
            "{host}:{}",
            url.port_or_known_default().ok_or(Error::ManagedFailure {
                reason: "management port missing"
            })?
        )
    };
    for (key, value) in [("1", true), ("5", false), ("7", false), ("10", false)] {
        set(field_mut(&mut root, "4")?, key, Value::Boolean(value))?;
    }
    set(field_mut(&mut root, "4")?, "2", Value::from(address))?;
    set(field_mut(&mut root, "12")?, "0", Value::Boolean(false))?;
    if fresh {
        set(
            field_mut(&mut root, "5")?,
            "1",
            Value::Array(vec![Value::from("tcp://127.0.0.1:0")]),
        )?;
        set(field_mut(&mut root, "5")?, "2", Value::Array(Vec::new()))?;
        for key in ["3", "4", "10", "12", "13", "59", "74", "79"] {
            set(field_mut(&mut root, "5")?, key, Value::Boolean(false))?;
        }
        set(field_mut(&mut root, "5")?, "17", Value::from(-1))?;
        set(field_mut(&mut root, "5")?, "24", Value::from(0))?;
    }
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &root).map_err(|_| Error::ManagedFailure {
        reason: "configuration encoding failed",
    })?;
    drop(input);
    let mut entropy = [0; 16];
    getrandom::fill(&mut entropy).map_err(|_| Error::ManagedFailure {
        reason: "configuration temporary identity failed",
    })?;
    let nonce: String = entropy.iter().map(|b| format!("{b:02x}")).collect();
    let scratch = Scratch(state.join(format!(".verysync-sidecar-config-{nonce}.tmp")));
    let mut output = native::create_private(&scratch.0)
        .map_err(|e| io_error("create atomic configuration update", e))?;
    output
        .write_all(&encoded)
        .map_err(|e| io_error("write atomic configuration update", e))?;
    output
        .sync_all()
        .map_err(|e| io_error("persist atomic configuration update", e))?;
    drop(output);
    fs::rename(&scratch.0, &path)
        .map_err(|e| io_error("atomically replace owned configuration", e))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_sections_fail_without_replacing_configuration() -> Result<()> {
        let root = tempfile::tempdir().map_err(|e| io_error("create test root", e))?;
        let state = root.path().join("state");
        let lease = StateLease::acquire(&state)?;
        let settings = ManagedOptions::new(
            crate::LocalProgram::new(lease.path().join("not-executed"))?,
            lease.path(),
            crate::ManagementEndpoint::http("http://127.0.0.1:43219")?,
        )?;
        let mut config = Value::Map(vec![
            (Value::from("1"), Value::from(54)),
            (
                Value::from("4"),
                Value::Map(vec![
                    (Value::from("4"), Value::from("synthetic password hash")),
                    (
                        Value::from("6"),
                        Value::from("synthetic-key-of-sufficient-length"),
                    ),
                ]),
            ),
            (Value::from("12"), Value::Array(Vec::new())),
        ]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &config).map_err(|_| Error::ManagedFailure {
            reason: "test encoding failed",
        })?;
        let path = lease.path().join("setting.dat");
        native::create_private(&path)
            .map_err(|e| io_error("create sample configuration", e))?
            .write_all(&bytes)
            .map_err(|e| io_error("write sample configuration", e))?;
        assert!(configure(lease.path(), &settings, false).is_err());
        assert_eq!(
            fs::read(path).map_err(|e| io_error("read original configuration", e))?,
            bytes
        );
        assert!(field_mut(&mut config, "missing").is_err());
        Ok(())
    }
}
