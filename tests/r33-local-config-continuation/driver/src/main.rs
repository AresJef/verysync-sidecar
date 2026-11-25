//! Private driver for one Local-API entitlement check.

mod local_api_probe;

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{self, BufRead, ErrorKind, Read, Write},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use verysync_sidecar::{LicenseEntries, LicenseExpiry, ManagedInstance, OfficialAccountState};

const ENGINE_VERSION: &str = "2.33.2";
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const ENGINE_HASH: [u8; 32] = [
    0xf8, 0xe9, 0xbd, 0x67, 0xbe, 0x3f, 0xb1, 0xb4, 0x5e, 0xaf, 0xea, 0x79, 0x40, 0x08, 0xc4, 0xdf,
    0xae, 0x24, 0xae, 0xc4, 0xe1, 0x77, 0x61, 0x75, 0x78, 0xb2, 0x68, 0x59, 0x8b, 0xf1, 0x22, 0x74,
];
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const ENGINE_HASH: [u8; 32] = [
    0x77, 0x03, 0x24, 0xd3, 0x41, 0x1b, 0xf6, 0xff, 0x7d, 0x18, 0x10, 0x9b, 0xa5, 0xfa, 0x1e, 0x50,
    0x57, 0x05, 0x6b, 0x5e, 0x93, 0x44, 0x1f, 0x29, 0x18, 0x5b, 0x50, 0x89, 0x5f, 0x55, 0x69, 0x3a,
];
const START: Duration = Duration::from_secs(20);
const STOP: Duration = Duration::from_secs(10);
const RESTART: Duration = Duration::from_secs(32);
const FRAME_LIMIT: u64 = 4096;

type Stage<T> = Result<T, &'static str>;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Request {
    Login { username: String, password: String },
    Inspect,
    RefreshPaid,
    LocalApiQualify,
    LocalApiFileVerify,
    LocalApiConfigVerify,
    Logout,
    End,
}

fn check_authorization(root: &Path) -> Stage<()> {
    match fs::symlink_metadata(root.join("local-grant-revoked")) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        _ => Err("local-api-grant-unavailable"),
    }
}

fn record(result: Value) -> Stage<()> {
    let mut buffer = io::stdout().lock();
    serde_json::to_writer(&mut buffer, &result).map_err(|_| "receipt-unavailable")?;
    buffer.write_all(b"\n").map_err(|_| "receipt-unavailable")?;
    buffer.flush().map_err(|_| "receipt-unavailable")
}

fn private_input() -> mpsc::Receiver<Request> {
    let (tx, rx) = mpsc::channel(1);
    std::thread::spawn(move || {
        let mut reader = io::stdin().lock();
        loop {
            let mut line = Vec::new();
            let Ok(count) = reader
                .by_ref()
                .take(FRAME_LIMIT + 1)
                .read_until(b'\n', &mut line)
            else {
                return;
            };
            if count == 0 || count as u64 > FRAME_LIMIT || !line.ends_with(b"\n") {
                return;
            }
            let request = serde_json::from_slice(&line);
            line.fill(0);
            let Ok(request) = request else {
                return;
            };
            if tx.blocking_send(request).is_err() {
                return;
            }
        }
    });
    rx
}

async fn end(core: &mut ManagedInstance) -> bool {
    match core.shutdown(STOP).await {
        Ok(result) => {
            result.code == Some(0) && !result.forced && result.tree_stopped && result.state_released
        }
        Err(_) => {
            let _ = core.force_stop(STOP).await;
            false
        }
    }
}

fn device_alias(core: &ManagedInstance, run: &str) -> String {
    format!(
        "{:x}",
        Sha256::new()
            .chain_update(run.as_bytes())
            .chain_update(core.client().instance().device_id.to_string().as_bytes())
            .finalize(),
    )
}

async fn inspect(core: &ManagedInstance, run: &str) -> Stage<Value> {
    let client = core.client();
    let info = client.instance();
    let reported_version = &info.version.version;
    if reported_version != ENGINE_VERSION && reported_version != "v2.33.2" {
        return Err("unexpected-engine-version");
    }
    let device = device_alias(core, run);
    let account = client
        .official_account_status()
        .await
        .map_err(|_| "official-account-read-failed")?;
    let state = match account.state() {
        OfficialAccountState::LoggedIn => "logged-in",
        OfficialAccountState::LoggedOut => "logged-out",
        OfficialAccountState::Unknown => "unknown",
    };
    let mut licenses = Vec::new();
    if let Ok(status) = client.license_status().await {
        let observed = match status.licenses() {
            Some(LicenseEntries::List(items)) => Some(items.iter().collect::<Vec<_>>()),
            Some(LicenseEntries::Map(items)) => Some(items.values().collect::<Vec<_>>()),
            _ => None,
        };
        if let Some(items) = observed {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "clock-unavailable")?;
            let now = i64::try_from(now.as_secs()).map_err(|_| "clock-unavailable")?;
            for item in items.into_iter().filter(|item| item.is_pro()) {
                licenses.push(json!({
                    "reported_trial": item.trial(),
                    "reported_expiry_unix_seconds": item.expires_unix_seconds(),
                    "expiry_observation": match item.expiry_at(now) {
                        Some(LicenseExpiry::Perpetual) => "perpetual",
                        Some(LicenseExpiry::NotExpired) => "not-expired",
                        Some(LicenseExpiry::Expired) => "expired",
                        None => "unreported",
                    },
                }));
            }
        }
    }
    Ok(json!({
        "ok": true, "account": state, "device": device, "version": ENGINE_VERSION,
        "arch": env::consts::ARCH, "pro_observations": licenses,
    }))
}

async fn paid_native_permission(core: &ManagedInstance, run: &str) -> Stage<Value> {
    let observed = inspect(core, run).await?;
    if observed["account"] != "logged-in" {
        return Err("dedicated-official-session-not-confirmed");
    }
    let valid = observed["pro_observations"]
        .as_array()
        .is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry["reported_trial"] == false
                    && matches!(
                        entry["expiry_observation"].as_str(),
                        Some("perpetual" | "not-expired")
                    )
            })
        });
    if !valid {
        return Err("dedicated-paid-license-not-confirmed");
    }
    Ok(observed)
}

async fn refresh_paid(core: &ManagedInstance, root: &Path, run: &str) -> Stage<Value> {
    let before = inspect(core, run).await?;
    if before["account"] != "logged-in" {
        return Err("dedicated-paid-account-not-signed-in");
    }
    check_authorization(root)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("paid-fetch-submitted"))
        .and_then(|receipt| receipt.sync_all())
        .map_err(|_| "paid-refresh-already-submitted")?;
    let sentinel = b"R33 owned paid license persistence sample\\n";
    std::fs::write(root.join("paid-sentinel"), sentinel).map_err(|_| "sentinel-setup-failed")?;
    let acknowledged = core.client().fetch_licenses().await.is_ok();
    let after = inspect(core, run).await?;
    Ok(json!({"ok":acknowledged,"device":after["device"],
              "refresh_acknowledged":acknowledged,
              "previous_pro_observations":before["pro_observations"],
              "actual_pro_observations":after["pro_observations"],
              "native_fields_read_independently":true}))
}

async fn logout(core: &mut ManagedInstance) -> Stage<Value> {
    let device = core.client().instance().device_id.clone();
    let acknowledged = core
        .client()
        .logout_official_account()
        .await
        .is_ok_and(|change| change.expected_state_matches);
    let retained = if acknowledged && core.restart(RESTART).await.is_ok() {
        core.client().instance().device_id == device
            && core
                .client()
                .official_account_status()
                .await
                .is_ok_and(|status| status.state() == OfficialAccountState::LoggedOut)
    } else {
        false
    };
    Ok(json!({"ok": acknowledged && retained,
              "native_logout_readback": acknowledged, "persisted_after_restart": retained}))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let result = match arguments.as_slice() {
        [operation, engine, root, run]
            if operation == "serve-local-api" || operation == "check-local-api-scope" =>
        {
            match run.to_str() {
                Some(run)
                    if run.len() == 32 && run.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
                {
                    local_api_probe::serve_qualification(
                        Path::new(engine),
                        Path::new(root),
                        run,
                        operation == "check-local-api-scope",
                    )
                    .await
                }
                _ => Err("local-api-owned-run-invalid"),
            }
        }
        _ => Err("private-driver-arguments-invalid"),
    };
    if let Err(code) = result {
        let _ = record(json!({"ok":false,"code":code}));
        std::process::exit(2);
    }
}
