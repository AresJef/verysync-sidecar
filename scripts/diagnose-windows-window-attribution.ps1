# Scoped controls for the managed-instance desktop probe. The only windows
# retained in diagnostics are created by this fixture on its current desktop.
param(
    [ValidateSet('observe', 'root', 'window')]
    [string]$Mode = 'observe',
    [string]$Scratch,
    [ValidateSet('owned', 'sibling')]
    [string]$Role = 'owned'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Start-Control([string]$ChildMode, [string]$ChildRole) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $info.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Mode {1} -Scratch "{2}" -Role {3}' -f $PSCommandPath, $ChildMode, $Scratch, $ChildRole
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    return [Diagnostics.Process]::Start($info)
}

function Wait-ControlExit([Diagnostics.Process]$Control, [int]$Timeout = 15000) {
    if (-not $Control.WaitForExit($Timeout)) {
        # The live Process object belongs to a process launched by this fixture.
        $Control.Kill()
        [void]$Control.WaitForExit(5000)
        throw 'A fixture process failed to stop normally.'
    }
    if ($Control.ExitCode -ne 0) {
        throw "A fixture process exited with code $($Control.ExitCode)."
    }
}

if ($Mode -eq 'root') {
    $owned = Start-Control 'window' 'owned'
    try { Wait-ControlExit $owned 100000 } finally { $owned.Dispose() }
    exit 0
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

public static class WindowAttributionFixture {
  public delegate bool Callback(IntPtr window, IntPtr data);
  [DllImport("user32.dll", SetLastError=true)] public static extern bool EnumWindows(Callback callback, IntPtr data);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr window);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr CreateWindowEx(
    uint exStyle, string className, string title, uint style, int x, int y, int width, int height,
    IntPtr parent, IntPtr menu, IntPtr instance, IntPtr parameter);
  [DllImport("user32.dll", SetLastError=true)] public static extern bool DestroyWindow(IntPtr window);
  [StructLayout(LayoutKind.Sequential)]
  private struct Message {
    public IntPtr Window;
    public uint Id;
    public UIntPtr WParam;
    public IntPtr LParam;
    public uint Time;
    public int X;
    public int Y;
    public uint Private;
  }
  [DllImport("user32.dll")] private static extern bool PeekMessage(out Message message, IntPtr window, uint min, uint max, uint remove);
  [DllImport("user32.dll")] private static extern bool TranslateMessage(ref Message message);
  [DllImport("user32.dll")] private static extern IntPtr DispatchMessage(ref Message message);

  // Same enumeration callback and fields the RC2 probe used.
  public static List<long[]> Windows() {
    var rows = new List<long[]>();
    if (!EnumWindows((window, data) => {
      uint pid; GetWindowThreadProcessId(window, out pid);
      rows.Add(new long[] {window.ToInt64(), pid, IsWindowVisible(window) ? 1 : 0});
      return true;
    }, IntPtr.Zero)) throw new Win32Exception();
    return rows;
  }

  public static void HoldWindows(string ready, string stop) {
    const uint popup = 0x80000000;
    const uint visible = 0x10000000;
    const uint noActivate = 0x08000000;
    var zero = IntPtr.Zero;
    var hidden = CreateWindowEx(noActivate, "STATIC", null, popup, 0, 0, 12, 12, zero, zero, zero, zero);
    if (hidden == zero) throw new Win32Exception();
    IntPtr shown = zero;
    try {
      shown = CreateWindowEx(noActivate, "STATIC", null, popup | visible, 0, 0, 12, 12, zero, zero, zero, zero);
      if (shown == zero) throw new Win32Exception();
      var record = String.Format("{{\"pid\":{0},\"hidden\":{1},\"visible\":{2}}}",
        Process.GetCurrentProcess().Id, hidden.ToInt64(), shown.ToInt64());
      File.WriteAllText(ready + ".tmp", record);
      File.Move(ready + ".tmp", ready);
      var wait = Stopwatch.StartNew();
      while (!File.Exists(stop)) {
        if (wait.Elapsed > TimeSpan.FromSeconds(90)) throw new TimeoutException("Control release deadline.");
        Message message;
        while (PeekMessage(out message, zero, 0, 0, 1)) {
          TranslateMessage(ref message);
          DispatchMessage(ref message);
        }
        Thread.Sleep(15);
      }
    } finally {
      bool shownDestroyed = shown == zero || DestroyWindow(shown);
      bool hiddenDestroyed = DestroyWindow(hidden);
      if (!shownDestroyed || !hiddenDestroyed) throw new Win32Exception();
    }
  }
}
'@

if ($Mode -eq 'window') {
    [WindowAttributionFixture]::HoldWindows((Join-Path $Scratch "$Role.json"), (Join-Path $Scratch 'stop'))
    exit 0
}

function Read-Control([string]$ControlRole, [Diagnostics.Process]$Owner) {
    $file = Join-Path $Scratch "$ControlRole.json"
    $wait = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        if ($Owner.HasExited) { throw "The $ControlRole control exited before reporting its windows." }
        if ($wait.Elapsed.TotalSeconds -ge 45) { throw "The $ControlRole control did not report its windows." }
        Start-Sleep -Milliseconds 30
    }
    return Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
}

function Read-Inventory {
    return @(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,CreationDate,SessionId)
}

function Find-Identity($Inventory, [uint32]$ProcessId) {
    $found = @($Inventory | Where-Object ProcessId -eq $ProcessId)
    if ($found.Count -ne 1 -or $null -eq $found[0].CreationDate) {
        throw "Process identity $ProcessId could not be confirmed."
    }
    return $found[0]
}

function Select-Rc2Owners($Inventory, [uint32]$RootPid) {
    # Preserve RC2's closure over numeric parent PIDs for the comparison.
    $owned = [System.Collections.Generic.HashSet[uint32]]::new()
    [void]$owned.Add($RootPid)
    do {
        $before = $owned.Count
        foreach ($process in $Inventory) {
            if ($owned.Contains([uint32]$process.ParentProcessId)) { [void]$owned.Add([uint32]$process.ProcessId) }
        }
    } while ($before -ne $owned.Count)
    return ,$owned
}

function Select-CreationOrderedOwners($Inventory, $After, [uint32]$RootPid) {
    # Require each sampled identity and parent edge to survive both inventories.
    $stable = @{}
    $afterByPid = @{}
    foreach ($process in $After) { $afterByPid[[uint32]$process.ProcessId] = $process }
    foreach ($process in $Inventory) {
        $key = [uint32]$process.ProcessId
        $last = $afterByPid[$key]
        if ($null -ne $last -and $null -ne $process.CreationDate -and
            $last.CreationDate -eq $process.CreationDate -and
            $last.ParentProcessId -eq $process.ParentProcessId) {
            $stable[$key] = $process
        }
    }
    if (-not $stable.ContainsKey($RootPid)) { throw 'Selected root identity changed while taking the sample.' }
    $owned = [System.Collections.Generic.HashSet[uint32]]::new()
    [void]$owned.Add($RootPid)
    do {
        $count = $owned.Count
        foreach ($process in $stable.Values) {
            $parent = [uint32]$process.ParentProcessId
            if ($owned.Contains($parent) -and $stable[$parent].CreationDate -le $process.CreationDate) {
                [void]$owned.Add([uint32]$process.ProcessId)
            }
        }
    } while ($count -ne $owned.Count)
    return ,$owned
}

function Confirm-Window($Rows, $Repeat, [long]$Handle, $Process, [bool]$Visible, [string]$Relationship) {
    $expectedPid = [uint32]$Process.ProcessId
    $match = @($Rows | Where-Object { $_[0] -eq $Handle })
    $again = @($Repeat | Where-Object { $_[0] -eq $Handle })
    if ($match.Count -ne 1 -or $again.Count -ne 1 -or $match[0][1] -ne $expectedPid -or
        $again[0][1] -ne $expectedPid -or $match[0][2] -ne [int]$Visible -or
        $again[0][2] -ne [int]$Visible) {
        throw "Control window $Handle was absent or changed identity or visibility."
    }
    return [ordered]@{handle=$Handle;pid=$expectedPid;parent_pid=[uint32]$Process.ParentProcessId;
        created_utc=$Process.CreationDate.ToUniversalTime().ToString('o');visible=$Visible;relation=$Relationship}
}

function Find-ControlWindows($WindowRecords, $Owners) {
    return @($WindowRecords | Where-Object { $Owners.Contains([uint32]$_.pid) } | Sort-Object handle)
}

$Scratch = Join-Path ([IO.Path]::GetTempPath()) ('verysync-window-control-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($Scratch)
$root = $null
$sibling = $null
$evidence = $null
try {
    # Start the sibling first, so a numeric parent edge back to the later root
    # is demonstrably stale even with stable process identities after sampling.
    $sibling = Start-Control 'window' 'sibling'
    $siblingWindows = Read-Control 'sibling' $sibling
    $root = Start-Control 'root' 'owned'
    $ownedWindows = Read-Control 'owned' $root
    $inventory = @(Read-Inventory)
    $sampleStart = [DateTime]::UtcNow
    $rows = [WindowAttributionFixture]::Windows()
    $repeat = [WindowAttributionFixture]::Windows()
    $sampleEnd = [DateTime]::UtcNow
    $after = @(Read-Inventory)
    $rootIdentity = Find-Identity $inventory $root.Id
    $siblingIdentity = Find-Identity $inventory $sibling.Id
    $ownedIdentity = Find-Identity $inventory $ownedWindows.pid
    $session = [Diagnostics.Process]::GetCurrentProcess().SessionId
    if ($siblingWindows.pid -ne $sibling.Id -or $rootIdentity.ParentProcessId -ne $PID -or
        $siblingIdentity.ParentProcessId -ne $PID -or $ownedIdentity.ParentProcessId -ne $root.Id -or
        $siblingIdentity.CreationDate -ge $rootIdentity.CreationDate -or
        $rootIdentity.SessionId -ne $session -or $ownedIdentity.SessionId -ne $session -or
        $siblingIdentity.SessionId -ne $session) {
        throw 'The observed controls did not have the required parent relationships, birth order and session.'
    }
    $controlWindows = @(
        Confirm-Window $rows $repeat $ownedWindows.hidden $ownedIdentity $false 'root child'
        Confirm-Window $rows $repeat $ownedWindows.visible $ownedIdentity $true 'root child'
        Confirm-Window $rows $repeat $siblingWindows.hidden $siblingIdentity $false 'root sibling'
        Confirm-Window $rows $repeat $siblingWindows.visible $siblingIdentity $true 'root sibling'
    )
    $normalRc2 = @(Find-ControlWindows $controlWindows (Select-Rc2Owners $inventory $root.Id))
    $normalTimed = @(Find-ControlWindows $controlWindows (Select-CreationOrderedOwners $inventory $after $root.Id))
    if ($normalRc2.Count -ne 2 -or $normalTimed.Count -ne 2 -or
        @($normalRc2 + $normalTimed | Where-Object relation -ne 'root child').Count -ne 0) {
        throw 'The controls did not distinguish actual owned and sibling windows.'
    }

    # Change only the parent PID field in copies of both inventories, so stable
    # before/after PID and birth checks alone cannot reject this stale edge.
    $staleBefore = @($inventory | ForEach-Object {
        if ($_.ProcessId -eq $sibling.Id) {
            [pscustomobject]@{ProcessId=$_.ProcessId; ParentProcessId=$root.Id; CreationDate=$_.CreationDate; SessionId=$_.SessionId}
        } else { $_ }
    })
    $staleAfter = @($after | ForEach-Object {
        if ($_.ProcessId -eq $sibling.Id) {
            [pscustomobject]@{ProcessId=$_.ProcessId; ParentProcessId=$root.Id; CreationDate=$_.CreationDate; SessionId=$_.SessionId}
        } else { $_ }
    })
    $staleRc2 = @(Find-ControlWindows $controlWindows (Select-Rc2Owners $staleBefore $root.Id))
    $staleTimed = @(Find-ControlWindows $controlWindows (Select-CreationOrderedOwners $staleBefore $staleAfter $root.Id))
    if ($staleRc2.Count -ne 4 -or $staleTimed.Count -ne 2 -or
        @($staleTimed | Where-Object relation -ne 'root child').Count -ne 0) {
        throw 'The stale-parent control did not discriminate the RC2 selector from the creation-ordered selector.'
    }
    $evidence = [ordered]@{phase='isolated current desktop attribution controls';session_id=$session;
        sample_started_utc=$sampleStart.ToString('o');sample_ended_utc=$sampleEnd.ToString('o');caller_pid=$PID;
        root_pid=$root.Id;root_created_utc=$rootIdentity.CreationDate.ToUniversalTime().ToString('o');
        control_windows=$controlWindows;actual_rc2_handles=@($normalRc2.handle);
        actual_creation_ordered_handles=@($normalTimed.handle);injected_stale_parent_pid=$root.Id;
        stale_rc2_handles=@($staleRc2.handle);stale_creation_ordered_handles=@($staleTimed.handle);
        pid_reuse_was_simulated_by_changing_the_copied_parent_pid=$true}
} finally {
    [IO.File]::WriteAllText((Join-Path $Scratch 'stop'), '')
    try {
        if ($null -ne $root) { try { Wait-ControlExit $root } finally { $root.Dispose() } }
    } finally {
        try {
            if ($null -ne $sibling) { try { Wait-ControlExit $sibling } finally { $sibling.Dispose() } }
        } finally {
            Remove-Item -LiteralPath $Scratch -Recurse -Force
        }
    }
}
$gone = @([WindowAttributionFixture]::Windows() | Where-Object {
    $handle = $_[0]
    $owner = $_[1]
    @($evidence.control_windows | Where-Object { $_.handle -eq $handle -and $_.pid -eq $owner }).Count -ne 0
}).Count -eq 0
if (-not $gone) { throw 'A fixture window still belongs to its original process.' }
$evidence['controls_exited_and_no_owned_fixture_windows_remain'] = $true
$evidence | ConvertTo-Json -Compress -Depth 6
