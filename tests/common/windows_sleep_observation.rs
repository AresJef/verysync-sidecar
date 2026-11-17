//! Powercfg attributes requests to the private image, not a fabricated PID.
use super::managed_fixture::TestResult;

pub(super) fn owned_system_request(text: &str, image: &str) -> TestResult<bool> {
    if text.len() > 1024 * 1024 || !image.starts_with(r"\Device\") || image.contains(['\r', '\n']) {
        return Err("bounded native image and power request snapshot required".into());
    }
    let mut in_system = false;
    let mut system_sections = 0;
    let mut closed = false;
    let mut entry_seen = false;
    let mut owned = false;
    for line in text.lines().map(str::trim) {
        if [
            "DISPLAY:",
            "SYSTEM:",
            "AWAYMODE:",
            "EXECUTION:",
            "PERFBOOST:",
            "ACTIVELOCKSCREEN:",
        ]
        .contains(&line)
        {
            if in_system {
                closed = true;
            }
            in_system = line == "SYSTEM:";
            if in_system {
                system_sections += 1;
            }
            continue;
        }
        if !in_system {
            continue;
        }
        if line == "None."
            || ["[PROCESS]", "[DRIVER]", "[SERVICE]"]
                .iter()
                .any(|p| line.starts_with(p))
        {
            entry_seen = true;
        }
        if let Some(path) = line.strip_prefix("[PROCESS]").map(str::trim) {
            owned |= path.eq_ignore_ascii_case(image);
        }
    }
    if system_sections != 1 || !closed || !entry_seen {
        return Err("missing or incomplete English SYSTEM power-request section".into());
    }
    Ok(owned)
}

#[test]
fn parser_attributes_only_the_exact_private_system_process_image() -> TestResult {
    let image = r"\Device\HarddiskVolume2\private\verysync.exe";
    let text = format!(
        "DISPLAY:\nNone.\nSYSTEM:\n[PROCESS] {image}\nVerysyncStayAwake\nAWAYMODE:\nNone.\n"
    );
    assert!(owned_system_request(&text, image)?);
    for text in [
        "DISPLAY:\nNone.\nSYSTEM:\nNone.\nAWAYMODE:\nNone.\n".to_owned(),
        format!("DISPLAY:\n[PROCESS] {image}\nSYSTEM:\n[DRIVER] Legacy Kernel Caller\nAWAYMODE:\nNone.\n"),
        "DISPLAY:\nNone.\nSYSTEM:\n[PROCESS] \\Device\\HarddiskVolume2\\other\\verysync.exe\nAWAYMODE:\nNone.\n".to_owned(),
    ] { assert!(!owned_system_request(&text, image)?); }
    Ok(())
}

#[test]
fn parser_refuses_missing_truncated_or_unattributable_snapshots() {
    for text in ["", "DISPLAY:\nNone.\n", "SYSTEM:\n", "SYSTEM:\nNone.\n"] {
        assert!(
            owned_system_request(text, r"\Device\HarddiskVolume2\private\verysync.exe").is_err()
        );
    }
    assert!(owned_system_request("SYSTEM:\nNone.\nAWAYMODE:\nNone.\n", "verysync.exe").is_err());
}

#[cfg(windows)]
pub(super) async fn powercfg(selector: &'static str) -> TestResult<String> {
    if !["/requests", "/query"].contains(&selector) {
        return Err("only read-only powercfg snapshots are allowed".into());
    }
    tokio::task::spawn_blocking(move || {
        let base = std::path::PathBuf::from(std::env::var_os("SystemRoot").ok_or("Windows directory absent")?);
        let shell = base.join("System32").join("WindowsPowerShell").join("v1.0").join("powershell.exe");
        // Decode native console output in PowerShell, then emit UTF-8 to our
        // pipe. No caller data is interpolated into this fixed read-only command.
        let script = format!("$ErrorActionPreference='Stop'; $p=Join-Path (Join-Path $env:SystemRoot 'System32') 'powercfg.exe'; $t=& $p {selector}; $c=$LASTEXITCODE; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); [Console]::Out.Write(($t -join \"`n\")); exit $c");
        let output = std::process::Command::new(shell).args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", &script]).output()?;
        if !output.status.success() || output.stdout.len() > 1024 * 1024 {
            return Err("read-only power request snapshot failed or exceeded bound".into());
        }
        Ok(String::from_utf8(output.stdout)?)
    }).await?
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn owned_native_image(pid: u32) -> TestResult<String> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SAFETY: Read-only access to the exact live ManagedInstance PID. The
    // returned handle has one owner and closes on every success/error path.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    let query = |flags| -> TestResult<String> {
        let mut buffer = [0_u16; 32768];
        let mut length = u32::try_from(buffer.len())?;
        // SAFETY: Live queried handle, native flags0/1, exact writable UTF-16
        // buffer and length. No process memory or execution state is modified.
        if unsafe {
            QueryFullProcessImageNameW(
                handle.as_raw_handle(),
                flags,
                buffer.as_mut_ptr(),
                &mut length,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(String::from_utf16(&buffer[..usize::try_from(length)?])?)
    };
    let win32 = query(0)?;
    let expected =
        std::env::var_os("VERYSYNC_TEST_BINARY").ok_or("private native program absent")?;
    if std::fs::canonicalize(win32)? != std::fs::canonicalize(expected)? {
        return Err("queried PID does not own the selected private native image".into());
    }
    query(1)
}

#[cfg(windows)]
pub(super) async fn observe(pid: u32) -> TestResult<(bool, String)> {
    let image = owned_native_image(pid)?;
    let snapshot = powercfg("/requests").await?;
    let active = owned_system_request(&snapshot, &image)
        .map_err(|e| format!("{e}; powercfg snapshot: {snapshot}"))?;
    Ok((active, snapshot))
}
