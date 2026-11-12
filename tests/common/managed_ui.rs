//! Read-only native UI observations for explicitly owned test process trees.

use serde_json::Value;
use std::path::Path;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[cfg(target_os = "macos")]
pub fn observe(root_pid: Option<u32>, scratch: &Path) -> TestResult<Value> {
    use std::process::Command;
    let mut pids = Vec::new();
    if let Some(root) = root_pid {
        let output = Command::new("/bin/ps")
            .args(["-A", "-o", "pid=,pgid="])
            .output()?;
        if !output.status.success() {
            return Err("private process-group UI observation failed".into());
        }
        for row in String::from_utf8_lossy(&output.stdout).lines() {
            let fields: Vec<_> = row.split_whitespace().collect();
            if fields.len() == 2 && fields[1].parse::<u32>()? == root {
                pids.push(fields[0].parse::<u32>()?);
            }
        }
        if !pids.contains(&root) {
            return Err("owned root is absent during UI observation".into());
        }
    }
    let source = scratch.join("managed-ui.swift");
    let cache = scratch.join("swift-module-cache");
    std::fs::create_dir_all(&cache)?;
    std::fs::write(&source, MACOS)?;
    let output = Command::new("/usr/bin/swift")
        .arg("-module-cache-path")
        .arg(cache)
        .arg(source)
        .args(pids.iter().map(u32::to_string))
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "native UI query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[cfg(target_os = "macos")]
const MACOS: &str = r#"
import AppKit
import CoreGraphics
import Foundation

let owned = Set(CommandLine.arguments.dropFirst().compactMap(Int32.init))
guard let windows = CGWindowListCopyWindowInfo(.optionAll, kCGNullWindowID) as? [[String:Any]] else {
    fputs("No GUI security session/window server; observation unavailable\n", stderr)
    exit(2)
}
let ownWindows = windows.filter { owned.contains(($0[kCGWindowOwnerPID as String] as? NSNumber)?.int32Value ?? -1) }
var policies: [Int] = []
for pid in owned {
    if let app = NSRunningApplication(processIdentifier: pid) {
        policies.append(app.activationPolicy.rawValue)
    }
}
let browserNames: Set<String> = ["Safari", "Google Chrome", "Chromium", "Firefox", "Microsoft Edge", "Brave Browser", "Arc", "Opera"]
let browserWindows = windows.filter {
    browserNames.contains($0[kCGWindowOwnerName as String] as? String ?? "") &&
    (($0[kCGWindowLayer as String] as? NSNumber)?.intValue ?? -1) == 0 &&
    ($0[kCGWindowIsOnscreen as String] as? Bool ?? false)
}.compactMap { ($0[kCGWindowNumber as String] as? NSNumber)?.uint32Value }.sorted()
let result: [String:Any] = ["platform":"macos", "gui_session_observed":true,
    "owned_processes":owned.count, "owned_windows":ownWindows.count,
    "owned_application_policies":policies, "browser_windows":browserWindows,
    "scope":"CGWindow/AppKit current GUI session; no titles or window contents collected"]
let bytes = try JSONSerialization.data(withJSONObject: result, options:.sortedKeys)
print(String(decoding:bytes, as:UTF8.self))
"#;

#[cfg(windows)]
pub fn observe(root_pid: Option<u32>, scratch: &Path) -> TestResult<Value> {
    use std::os::windows::process::CommandExt;
    let script = scratch.join("managed-ui.ps1");
    std::fs::write(&script, WINDOWS)?;
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(script)
        .arg(root_pid.unwrap_or(0).to_string())
        .arg(std::process::id().to_string())
        .env("TEMP", scratch)
        .env("TMP", scratch)
        .creation_flags(0x08000000) // CREATE_NO_WINDOW applies only to this test query.
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "native UI query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[cfg(windows)]
const WINDOWS: &str = r#"
param([uint32]$OwnedRoot, [uint32]$CallerPid)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class ManagedUiQuery {
  public delegate bool Callback(IntPtr window, IntPtr data);
  [DllImport("user32.dll", SetLastError=true)] public static extern bool EnumWindows(Callback callback, IntPtr data);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr window);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool AttachConsole(uint process);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool FreeConsole();
  [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
  [DllImport("kernel32.dll", SetLastError=true)] public static extern uint GetConsoleProcessList([Out] uint[] processes, uint capacity);
  public static List<long[]> Windows() {
    var rows = new List<long[]>();
    if (!EnumWindows((window, data) => {
      uint pid; GetWindowThreadProcessId(window, out pid);
      rows.Add(new long[] {window.ToInt64(), pid, IsWindowVisible(window) ? 1 : 0});
      return true;
    }, IntPtr.Zero)) throw new System.ComponentModel.Win32Exception();
    return rows;
  }
  public static long[] ConsoleInfo(uint process) {
    FreeConsole();
    bool attached = AttachConsole(process);
    int error = Marshal.GetLastWin32Error();
    if (attached) {
      IntPtr window = GetConsoleWindow();
      bool visible = window != IntPtr.Zero && IsWindowVisible(window);
      var members = new uint[128];
      uint count = GetConsoleProcessList(members, (uint)members.Length);
      int listError = Marshal.GetLastWin32Error();
      FreeConsole();
      if (count > members.Length) throw new InvalidOperationException("Console membership observation truncated");
      var result = new List<long> {process, 1, window.ToInt64(), visible ? 1 : 0, count == 0 ? listError : 0, count};
      for (uint i=0; i<count; i++) result.Add(members[i]);
      return result.ToArray();
    }
    if (error == 6) return new long[] {process, 0, 0, 0, error, 0}; // Target has no console.
    throw new System.ComponentModel.Win32Exception(error);
  }
}
'@
$processes = @(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name)
$owned = [System.Collections.Generic.HashSet[uint32]]::new()
if ($OwnedRoot -ne 0) {
  if (-not ($processes | Where-Object ProcessId -eq $OwnedRoot)) { throw 'Owned root absent during UI observation' }
  [void]$owned.Add($OwnedRoot)
  do {
    $before = $owned.Count
    foreach ($process in $processes) {
      if ($owned.Contains([uint32]$process.ParentProcessId)) { [void]$owned.Add([uint32]$process.ProcessId) }
    }
  } while ($before -ne $owned.Count)
}
$rows = [ManagedUiQuery]::Windows()
$ownWindows = @($rows | Where-Object { $owned.Contains([uint32]$_[1]) })
$consoleInfo = @()
foreach ($processId in $owned) { $consoleInfo += ,([ManagedUiQuery]::ConsoleInfo($processId)) }
$consoles = @($consoleInfo | Where-Object { $_[1] -eq 1 }).Count
$visibleConsoles = @($consoleInfo | Where-Object { $_[3] -eq 1 }).Count
$callerConsole = [ManagedUiQuery]::ConsoleInfo($CallerPid)
$browserIds = @($processes | Where-Object { $_.Name -match '^(msedge|chrome|chromium|firefox|brave|opera|arc)\.exe$' } | ForEach-Object { [uint32]$_.ProcessId })
$browserWindows = @($rows | Where-Object { $_[2] -eq 1 -and $browserIds -contains [uint32]$_[1] } | ForEach-Object { $_[0] } | Sort-Object)
@{platform='windows';current_desktop_enumerated=$true;interactive_session=[Environment]::UserInteractive;session_id=[Diagnostics.Process]::GetCurrentProcess().SessionId;caller_pid=$CallerPid;caller_console=$callerConsole;owned_root=$OwnedRoot;owned_processes=$owned.Count;owned_windows=$ownWindows.Count;owned_console_processes=$consoles;owned_visible_consoles=$visibleConsoles;console_observations=$consoleInfo;browser_windows=$browserWindows;scope='Current desktop EnumWindows, owned descendants and separate-probe AttachConsole; no titles collected'} | ConvertTo-Json -Compress -Depth 5
"#;

#[cfg(target_os = "linux")]
pub fn observe(root_pid: Option<u32>, _scratch: &Path) -> TestResult<Value> {
    let headless =
        std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none();
    if !headless {
        return Err("Linux acceptance requires the explicit headless test environment".into());
    }
    if let Some(pid) = root_pid {
        std::fs::metadata(Path::new("/proc").join(pid.to_string()))?;
    }
    Ok(
        serde_json::json!({"platform":"linux","headless":true,"owned_root_observed":root_pid.is_some(),"scope":"No DISPLAY/Wayland session; GUI/tray widgets are not inspectable in this headless run"}),
    )
}

pub fn assert_background(baseline: &Value, observed: &Value) -> TestResult<()> {
    if observed["platform"] == "macos" || observed["platform"] == "windows" {
        if observed["owned_processes"].as_u64().unwrap_or(0) == 0 || observed["owned_windows"] != 0
        {
            return Err("owned native UI was present or could not be observed".into());
        }
        let before = baseline["browser_windows"]
            .as_array()
            .ok_or("browser baseline unavailable")?;
        let after = observed["browser_windows"]
            .as_array()
            .ok_or("browser observation unavailable")?;
        if after.iter().any(|window| !before.contains(window)) {
            return Err("a new visible browser window appeared during the controlled test".into());
        }
        if observed["platform"] == "macos"
            && observed["owned_application_policies"]
                .as_array()
                .ok_or("AppKit observation unavailable")?
                .iter()
                .any(|policy| policy != 2)
        {
            return Err(
                "owned process registered as an ordinary/accessory AppKit application".into(),
            );
        }
        if observed["platform"] == "windows" && observed["owned_console_processes"] != 0 {
            return Err("owned process acquired a console".into());
        }
    } else if observed["headless"] != true || observed["owned_root_observed"] != true {
        return Err("Linux headless observation unavailable".into());
    }
    Ok(())
}
