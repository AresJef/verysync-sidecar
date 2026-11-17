//! Powercfg attributes requests to the private image, not a fabricated PID.
use super::managed_fixture::TestResult;

fn decode_native_requests(raw: &[u8]) -> TestResult<String> {
    if raw.len() > 1024 * 1024 {
        return Err("native power request snapshot exceeded bound".into());
    }
    let wide = if let Some(unmarked) = raw.strip_prefix(&[0xff, 0xfe]) {
        Some(unmarked)
    } else if raw.starts_with(b"D\0I\0S\0P\0") {
        Some(raw)
    } else {
        None
    };
    if let Some(wide) = wide {
        if wide.len() % 2 != 0 {
            return Err("truncated native UTF-16 power request snapshot".into());
        }
        let units: Vec<_> = wide
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        return Ok(String::from_utf16(&units)?);
    }
    // ASCII is also UTF-8. Unknown legacy encodings must fail instead of
    // replacing characters in a device path or fabricating an empty request.
    Ok(std::str::from_utf8(raw)?.to_owned())
}

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

#[test]
fn native_request_decoder_preserves_unicode_and_refuses_unknown_or_truncated_bytes() -> TestResult {
    let expected = "DISPLAY:\r\nNone.\r\nSYSTEM:\r\n[PROCESS] \\Device\\private-二\\verysync.exe\r\nAWAYMODE:\r\nNone.\r\n";
    assert_eq!(decode_native_requests(expected.as_bytes())?, expected);
    let wide: Vec<u8> = expected.encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(decode_native_requests(&wide)?, expected);
    let mut marked = vec![0xff, 0xfe];
    marked.extend_from_slice(&wide);
    assert_eq!(decode_native_requests(&marked)?, expected);
    for malformed in [vec![0xff], vec![0xff, 0xfe, 1], vec![0xff, 0xfe, 0, 0xd8]] {
        assert!(decode_native_requests(&malformed).is_err());
    }
    Ok(())
}

#[cfg(windows)]
pub(super) async fn powercfg(selector: &'static str) -> TestResult<Vec<u8>> {
    if !["/requests", "/query"].contains(&selector) {
        return Err("only read-only powercfg snapshots are allowed".into());
    }
    tokio::task::spawn_blocking(move || {
        let base = std::path::PathBuf::from(
            std::env::var_os("SystemRoot").ok_or("Windows directory absent")?,
        );
        let native = base.join("System32").join("powercfg.exe");
        let started = std::time::Instant::now();
        let output = std::process::Command::new(native).arg(selector).output()?;
        let elapsed_ms = started.elapsed().as_millis();
        if selector == "/query" || elapsed_ms >= 1000 {
            eprintln!(
                "native powercfg command diagnostic: {}",
                serde_json::json!({
                    "selector":selector,"elapsed_ms":elapsed_ms,"shell_invoked":false,
                    "exit_code":output.status.code(),"stdout_bytes":output.stdout.len()
                })
            );
        }
        if !output.status.success() || output.stdout.len() > 1024 * 1024 {
            return Err("read-only power request snapshot failed or exceeded bound".into());
        }
        // /query is compared byte-for-byte; decoding must not normalize the
        // protected host power-plan snapshot.
        Ok(output.stdout)
    })
    .await?
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
    let snapshot = decode_native_requests(&powercfg("/requests").await?)?;
    let active = owned_system_request(&snapshot, &image)
        .map_err(|e| format!("{e}; powercfg snapshot: {snapshot}"))?;
    Ok((active, snapshot))
}
