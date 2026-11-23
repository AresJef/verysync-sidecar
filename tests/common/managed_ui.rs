//! Native UI observations with calibration inside a separate test probe.

use serde_json::Value;
use std::path::Path;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub async fn observe(
    root_pid: Option<u32>,
    scratch: &Path,
    phase: &'static str,
) -> TestResult<Value> {
    let scratch = scratch.to_owned();
    // Native CLI/desktop probes can take seconds. Keep the test runtime's I/O
    // reactor/timers progressing while its management Client remains connected.
    let mut observation =
        tokio::task::spawn_blocking(move || observe_blocking(root_pid, &scratch)).await??;
    observation["observation_phase"] = phase.into();
    Ok(observation)
}

#[cfg(target_os = "macos")]
fn observe_blocking(root_pid: Option<u32>, scratch: &Path) -> TestResult<Value> {
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
fn observe_blocking(root_pid: Option<u32>, scratch: &Path) -> TestResult<Value> {
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
    let mut report = serde_json::from_slice(&output.stdout)?;
    calibrate_windows(&mut report)?;
    Ok(report)
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
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool AllocConsole();
  [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
  [DllImport("kernel32.dll")] public static extern uint GetCurrentProcessId();
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr window, int command);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr CreateWindowEx(
    uint exStyle, string className, string title, uint style, int x, int y, int width, int height,
    IntPtr parent, IntPtr menu, IntPtr instance, IntPtr parameter);
  [DllImport("user32.dll", SetLastError=true)] public static extern bool DestroyWindow(IntPtr window);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern uint GetConsoleProcessList([Out] uint[] processes, uint capacity);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  private static extern IntPtr OpenJobObject(uint access, bool inherit, string name);
  [DllImport("kernel32.dll", SetLastError=true)]
  private static extern bool QueryInformationJobObject(IntPtr job, int kind, IntPtr value, uint size, out uint used);
  [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

  public static uint[] JobPids(string name) {
    if (String.IsNullOrEmpty(name)) return new uint[0];
    const uint query = 4;
    const int processIdList = 3;
    const int capacity = 128;
    var job = OpenJobObject(query, false, name);
    if (job == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
    var size = 8 + IntPtr.Size * capacity;
    var buffer = Marshal.AllocHGlobal(size);
    try {
      uint used;
      if (!QueryInformationJobObject(job, processIdList, buffer, (uint)size, out used))
        throw new System.ComponentModel.Win32Exception();
      int assigned = Marshal.ReadInt32(buffer);
      int count = Marshal.ReadInt32(buffer, 4);
      if (count != assigned || count < 0 || count > capacity)
        throw new InvalidOperationException("Incomplete fixture Job process inventory.");
      var ids = new uint[count];
      for (int i = 0; i < count; i++)
        ids[i] = checked((uint)Marshal.ReadIntPtr(buffer, 8 + i * IntPtr.Size).ToInt64());
      return ids;
    } finally {
      Marshal.FreeHGlobal(buffer);
      CloseHandle(job);
    }
  }

  public static List<long[]> Windows() {
    var rows = new List<long[]>();
    if (!EnumWindows((window, data) => {
      uint pid; GetWindowThreadProcessId(window, out pid);
      rows.Add(new long[] {window.ToInt64(), pid, IsWindowVisible(window) ? 1 : 0});
      return true;
    }, IntPtr.Zero)) throw new System.ComponentModel.Win32Exception();
    return rows;
  }
  public static List<long[]> CalibrateWindows() {
    const uint popup = 0x80000000;
    const uint visible = 0x10000000;
    var zero = IntPtr.Zero;
    var hidden = CreateWindowEx(0, "STATIC", null, popup, 0, 0, 12, 12, zero, zero, zero, zero);
    if (hidden == zero) throw new System.ComponentModel.Win32Exception();
    IntPtr shown = zero;
    try {
      shown = CreateWindowEx(0, "STATIC", null, popup | visible, 0, 0, 12, 12, zero, zero, zero, zero);
      if (shown == zero) throw new System.ComponentModel.Win32Exception();
      var rows = Windows();
      var observedHidden = rows.Find(row => row[0] == hidden.ToInt64());
      var observedShown = rows.Find(row => row[0] == shown.ToInt64());
      uint pid = GetCurrentProcessId();
      if (observedHidden == null || observedShown == null ||
          observedHidden[1] != pid || observedShown[1] != pid ||
          observedHidden[2] != 0 || observedShown[2] != 1)
        throw new InvalidOperationException("The visible and hidden calibration windows were not distinguished.");
      return new List<long[]> {observedHidden, observedShown};
    } finally {
      bool shownDestroyed = shown == zero || DestroyWindow(shown);
      bool hiddenDestroyed = DestroyWindow(hidden);
      if (!shownDestroyed || !hiddenDestroyed)
        throw new System.ComponentModel.Win32Exception();
    }
  }
  public static long[] CurrentConsoleInfo(uint process) {
      IntPtr window = GetConsoleWindow();
      bool visible = window != IntPtr.Zero && IsWindowVisible(window);
      var members = new uint[128];
      uint count = GetConsoleProcessList(members, (uint)members.Length);
      int listError = Marshal.GetLastWin32Error();
      if (count > members.Length) throw new InvalidOperationException("Console membership observation truncated");
      var result = new List<long> {process, 1, window.ToInt64(), visible ? 1 : 0, count == 0 ? listError : 0, count};
      for (uint i=0; i<count; i++) result.Add(members[i]);
      return result.ToArray();
  }
  public static long[] ConsoleInfo(uint process) {
    FreeConsole();
    bool attached = AttachConsole(process);
    int error = Marshal.GetLastWin32Error();
    if (attached) {
      try { return CurrentConsoleInfo(process); }
      finally { FreeConsole(); }
    }
    if (error == 6) return new long[] {process, 0, 0, 0, error, 0}; // Target has no console.
    throw new System.ComponentModel.Win32Exception(error);
  }
  public static long[][] Calibrate() {
    uint self = GetCurrentProcessId();
    var none = ConsoleInfo(self);
    if (!AllocConsole()) throw new System.ComponentModel.Win32Exception();
    long[] independent;
    try {
      IntPtr window = GetConsoleWindow();
      if (window != IntPtr.Zero) ShowWindow(window, 0); // Only this probe's new console.
      independent = CurrentConsoleInfo(self);
    } finally { FreeConsole(); }
    return new long[][] {none, independent};
  }
}
'@
function Get-ProcessInventory {
  return @(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,CreationDate,Name)
}
function Get-BirthUtc($Process) {
  if ($null -ne $Process -and $null -ne $Process.CreationDate) {
    return $Process.CreationDate.ToUniversalTime().ToString('o')
  }
}
$processes = @(Get-ProcessInventory)
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
$sampleStart = [DateTime]::UtcNow.ToString('o')
$jobBefore = @([ManagedUiQuery]::JobPids($env:VERYSYNC_WINDOW_SAMPLE_JOB))
$rows = [ManagedUiQuery]::Windows()
$jobAfter = @([ManagedUiQuery]::JobPids($env:VERYSYNC_WINDOW_SAMPLE_JOB))
$sampleEnd = [DateTime]::UtcNow.ToString('o')
$ownWindows = @($rows | Where-Object { $owned.Contains([uint32]$_[1]) })
$after = @(Get-ProcessInventory)
$byPid = @{}
$detailsByPid = @{}
foreach ($process in $after) { $byPid[[uint32]$process.ProcessId] = $process }
$firstByPid = @{}
$stable = @{}
foreach ($process in $processes) {
  $processId = [uint32]$process.ProcessId
  $firstByPid[$processId] = $process
  $later = $byPid[$processId]
  if ($null -ne $process.CreationDate -and $null -ne $later -and
      $later.CreationDate -eq $process.CreationDate -and $later.ParentProcessId -eq $process.ParentProcessId) {
    $stable[$processId] = $process
  }
}
$ordered = [System.Collections.Generic.HashSet[uint32]]::new()
if ($OwnedRoot -ne 0 -and $stable.ContainsKey($OwnedRoot)) {
  [void]$ordered.Add($OwnedRoot)
  do {
    $priorSize = $ordered.Count
    foreach ($process in $stable.Values) {
      $parentId = [uint32]$process.ParentProcessId
      if ($ordered.Contains($parentId) -and $stable[$parentId].CreationDate -le $process.CreationDate) {
        [void]$ordered.Add([uint32]$process.ProcessId)
      }
    }
  } while ($priorSize -ne $ordered.Count)
}
$orderedWindows = @($rows | Where-Object { $ordered.Contains([uint32]$_[1]) })
$rootIdentityStable = ($OwnedRoot -eq 0 -or $stable.ContainsKey($OwnedRoot))
if ($OwnedRoot -ne 0 -and (-not $rootIdentityStable -or $jobBefore -notcontains $OwnedRoot -or $jobAfter -notcontains $OwnedRoot)) {
  throw 'Private root identity and fixture Job membership were not observed on both sides of enumeration.'
}
$ownedProcessDetails = @(
  foreach ($process in $processes) {
    $processId = [uint32]$process.ProcessId
    if (-not $owned.Contains($processId)) { continue }
    $afterProcess = $byPid[$processId]
    $birth = Get-BirthUtc $process
    $afterBirth = Get-BirthUtc $afterProcess
    $record = [ordered]@{
      pid = $processId
      image = $process.Name
      parent_pid = [uint32]$process.ParentProcessId
      created_utc = $birth
      created_after_utc = $afterBirth
      same_identity_after = ($null -ne $birth -and $birth -eq $afterBirth)
      relationship = $(if ($processId -eq $OwnedRoot) {'engine root'} else {'descendant by parent PID'})
      parent_created_before_utc = (Get-BirthUtc ($firstByPid[[uint32]$process.ParentProcessId]))
      parent_created_after_utc = (Get-BirthUtc ($byPid[[uint32]$process.ParentProcessId]))
      parent_after_pid = $afterProcess.ParentProcessId
      creation_order_selector = $ordered.Contains($processId)
      in_fixture_job_before = ($jobBefore -contains $processId)
      in_fixture_job_after = ($jobAfter -contains $processId)
    }
    $detailsByPid[$processId] = $record
    $record
  }
)
$ownedWindowDetails = @(
  foreach ($row in $ownWindows) {
    $detail = $detailsByPid[[uint32]$row[1]]
    [ordered]@{handle=[long]$row[0];pid=[uint32]$row[1];visible=($row[2] -eq 1);
      parent_pid=$detail.parent_pid;created_utc=$detail.created_utc;creation_time_confirmed=$detail.same_identity_after;
      relationship=$detail.relationship;sample_started_utc=$sampleStart;sample_ended_utc=$sampleEnd;
      parent_created_before_utc=$detail.parent_created_before_utc;parent_created_after_utc=$detail.parent_created_after_utc;
      creation_order_selector=$detail.creation_order_selector;
      in_fixture_job_before=$detail.in_fixture_job_before;in_fixture_job_after=$detail.in_fixture_job_after}
  }
)
$windowControls = @([ManagedUiQuery]::CalibrateWindows() | ForEach-Object {
  [ordered]@{handle=[long]$_[0];pid=[uint32]$_[1];visible=($_[2] -eq 1);
    created_utc=(Get-BirthUtc ($byPid[[uint32]$_[1]]));inside_selected_tree=$owned.Contains([uint32]$_[1])}
})
if ($windowControls.Count -ne 2 -or @($windowControls | Where-Object inside_selected_tree).Count -ne 0) {
  throw 'Window observation controls could not be distinguished from the selected process tree.'
}
$consoleInfo = @()
foreach ($processId in $owned) { $consoleInfo += ,([ManagedUiQuery]::ConsoleInfo($processId)) }
$consoles = @($consoleInfo | Where-Object { $_[1] -eq 1 }).Count
$visibleConsoles = @($consoleInfo | Where-Object { $_[3] -eq 1 }).Count
$callerConsole = [ManagedUiQuery]::ConsoleInfo($CallerPid)
$controls = [ManagedUiQuery]::Calibrate()
$browserIds = @($processes | Where-Object { $_.Name -match '^(msedge|chrome|chromium|firefox|brave|opera|arc)\.exe$' } | ForEach-Object { [uint32]$_.ProcessId })
$browserWindows = @($rows | Where-Object { $_[2] -eq 1 -and $browserIds -contains [uint32]$_[1] } | ForEach-Object { $_[0] } | Sort-Object)
@{platform='windows';current_desktop_enumerated=$true;interactive_session=[Environment]::UserInteractive;session_id=[Diagnostics.Process]::GetCurrentProcess().SessionId;caller_pid=$CallerPid;caller_console=$callerConsole;console_controls=@{without_console=$controls[0];independent_console=$controls[1]};owned_root=$OwnedRoot;owned_processes=$owned.Count;owned_windows=$ownWindows.Count;owned_console_processes=$consoles;owned_visible_consoles=$visibleConsoles;console_observations=$consoleInfo;browser_windows=$browserWindows;
sample_started_utc=$sampleStart;sample_ended_utc=$sampleEnd;owned_window_details=$ownedWindowDetails;owned_process_details=$ownedProcessDetails;window_controls=$windowControls;window_probe_calibrated=$true;
creation_order_windows=$orderedWindows.Count;fixture_job_before=$jobBefore;fixture_job_after=$jobAfter;root_identity_stable=$rootIdentityStable;
scope='Current desktop, owned descendants and separate-probe console and window calibration. Window titles and contents are excluded.'} | ConvertTo-Json -Compress -Depth 8
"#;

#[cfg(target_os = "linux")]
fn observe_blocking(root_pid: Option<u32>, _scratch: &Path) -> TestResult<Value> {
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
        if observed["platform"] == "windows" {
            if observed["window_probe_calibrated"] != true
                || observed["owned_window_details"]
                    .as_array()
                    .map(|rows| rows.len() as u64)
                    != observed["owned_windows"].as_u64()
            {
                return Err("owned window observation or calibration was incomplete".into());
            }
            if observed["console_probe_calibrated"] != true
                || observed["owned_additional_consoles"] != 0
            {
                return Err("owned process acquired an additional or unverified console".into());
            }
            for record in observed["console_observations"]
                .as_array()
                .ok_or("console observations unavailable")?
            {
                if record[3] == 1 && record[2] != baseline["caller_console"][2] {
                    return Err("a new visible console window appeared".into());
                }
            }
        }
    } else if observed["headless"] != true || observed["owned_root_observed"] != true {
        return Err("Linux headless observation unavailable".into());
    }
    Ok(())
}

#[cfg(windows)]
fn console_members(record: &Value) -> TestResult<Option<&[Value]>> {
    let fields = record.as_array().ok_or("console record unavailable")?;
    if fields.len() < 6 {
        return Err("console record incomplete".into());
    }
    if fields[1] == 0 && fields[4] == 6 && fields[5] == 0 && fields.len() == 6 {
        return Ok(None);
    }
    if fields[1] != 1 || fields[4] != 0 {
        return Err("console membership was not observable".into());
    }
    let count = fields[5].as_u64().ok_or("console count invalid")? as usize;
    if count == 0 || count > 128 || fields.len() != 6 + count || !fields[6..].contains(&fields[0]) {
        return Err("console membership incomplete or subject absent".into());
    }
    Ok(Some(&fields[6..]))
}

#[cfg(windows)]
fn shares_console(record: &Value, caller: &Value) -> TestResult<bool> {
    let Some(members) = console_members(record)? else {
        return Ok(false);
    };
    let Some(caller_members) = console_members(caller)? else {
        return Ok(false);
    };
    // Each native process can belong to at most one console. Mutual membership
    // proves sharing an existing caller console, not an additional allocation.
    Ok(members.contains(&caller[0]) && caller_members.contains(&record[0]))
}

#[cfg(windows)]
fn calibrate_windows(report: &mut Value) -> TestResult<()> {
    let caller = &report["caller_console"];
    let none = &report["console_controls"]["without_console"];
    let independent = &report["console_controls"]["independent_console"];
    if console_members(none)?.is_some()
        || console_members(independent)?.is_none()
        || shares_console(independent, caller)?
    {
        return Err("native absent/independent console controls failed".into());
    }
    let mut additional = 0_u64;
    let mut shared = 0_u64;
    for record in report["console_observations"]
        .as_array()
        .ok_or("console observations unavailable")?
    {
        if console_members(record)?.is_some() {
            if shares_console(record, caller)? {
                shared += 1;
            } else {
                additional += 1;
            }
        }
    }
    report["owned_additional_consoles"] = additional.into();
    report["owned_shared_console_processes"] = shared.into();
    report["console_probe_calibrated"] = true.into();
    Ok(())
}
