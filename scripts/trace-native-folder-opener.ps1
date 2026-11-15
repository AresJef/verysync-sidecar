param(
    [Parameter(Mandatory=$true)][UInt32]$SourcePid,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory
)
# Read-only, short-lived diagnostics on a disposable Windows CI VM only.
# https://learn.microsoft.com/en-us/previous-versions/windows/desktop/krnlprov/win32-processstarttrace
# https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/register-cimindicationevent
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:VERYSYNC_TEST_OPENER_TRACE -ne '1') {
    throw 'Explicit Windows CI diagnostic scope is required'
}
$nativeDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
if (-not [IO.Directory]::Exists($nativeDirectory)) { throw 'Owned evidence directory is required' }
$nativeReady = [IO.Path]::Combine($nativeDirectory, 'ready')
$nativeStop = [IO.Path]::Combine($nativeDirectory, 'stop')
$nativeReport = [IO.Path]::Combine($nativeDirectory, 'report.json')
$nativeEncoding = [System.Text.UTF8Encoding]::new($false)
$nativeIdentifier = 'verysync-opener-' + [Guid]::NewGuid().ToString('N')
$nativeEvents = New-Object 'System.Collections.Generic.List[object]'
$nativeOmitted = 0
$nativeAvailable = $false
$nativeErrorType = $null
$nativeClosed = $false
try {
    Register-CimIndicationEvent -Namespace 'root/cimv2' -ClassName 'Win32_ProcessStartTrace' -SourceIdentifier $nativeIdentifier | Out-Null
    $nativeAvailable = $true
    [IO.File]::WriteAllText($nativeReady, 'ready', $nativeEncoding)
    $nativeEnd = [DateTime]::UtcNow.AddSeconds(15)
    $nativeDrain = $null
    while ([DateTime]::UtcNow -lt $nativeEnd) {
        if ([IO.File]::Exists($nativeStop) -and $null -eq $nativeDrain) {
            $nativeDrain = [DateTime]::UtcNow.AddSeconds(1)
        }
        if ($null -ne $nativeDrain -and [DateTime]::UtcNow -ge $nativeDrain) { break }
        $nativeEvent = Wait-Event -SourceIdentifier $nativeIdentifier -Timeout 1 | Select-Object -First 1
        if ($null -ne $nativeEvent) {
            $nativeNew = $nativeEvent.SourceEventArgs.NewEvent
            if ($nativeEvents.Count -lt 256) {
                $nativeName = [string]$nativeNew.ProcessName
                if ($nativeName.Length -gt 80) { $nativeName = $nativeName.Substring(0, 80) }
                $nativeEvents.Add([pscustomobject]@{
                    pid = [UInt32]$nativeNew.ProcessID
                    parent = [UInt32]$nativeNew.ParentProcessID
                    name = $nativeName
                })
            } else { $nativeOmitted++ }
            Remove-Event -EventIdentifier $nativeEvent.EventIdentifier
        }
    }
} catch {
    $nativeErrorType = $_.Exception.GetType().FullName
} finally {
    if ($nativeAvailable) {
        try {
            Unregister-Event -SourceIdentifier $nativeIdentifier
            Get-Event -SourceIdentifier $nativeIdentifier -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue
            $nativeClosed = $true
        } catch { $nativeErrorType = $_.Exception.GetType().FullName }
    }
}
$nativeKnown = @{}
$nativeKnown[[UInt32]$SourcePid] = $true
for ($nativeRound = 0; $nativeRound -lt 256; $nativeRound++) {
    $nativeChanged = $false
    foreach ($nativeRow in $nativeEvents) {
        if ($nativeKnown.ContainsKey($nativeRow.parent) -and -not $nativeKnown.ContainsKey($nativeRow.pid)) {
            $nativeKnown[$nativeRow.pid] = $true
            $nativeChanged = $true
        }
    }
    if (-not $nativeChanged) { break }
}
$nativeDescendants = @($nativeEvents | Where-Object { $nativeKnown.ContainsKey($_.parent) } | Select-Object -First 64)
$nativeNames = @{}
$nativeAllow = @('explorer.exe','cmd.exe','rundll32.exe','powershell.exe','msedge.exe','firefox.exe','chrome.exe','runtimebroker.exe','openwith.exe','dllhost.exe')
foreach ($nativeRow in $nativeEvents) {
    $nativeLower = $nativeRow.name.ToLowerInvariant()
    if ($nativeAllow -contains $nativeLower) {
        if (-not $nativeNames.ContainsKey($nativeLower)) { $nativeNames[$nativeLower] = 0 }
        $nativeNames[$nativeLower]++
    }
}
$nativeResult = @{
    scope = 'read-only Windows CI process-start metadata; not GUI success'
    available = $nativeAvailable
    subscription_removed = $nativeClosed
    error_type = $nativeErrorType
    source_pid = $SourcePid
    descendants = $nativeDescendants
    known_system_name_counts = $nativeNames
    events_omitted = $nativeOmitted
    event_limit = 256
    duration_limit_s = 15
    command_lines_or_titles_logged = $false
}
[IO.File]::WriteAllText($nativeReport, ($nativeResult | ConvertTo-Json -Depth 6 -Compress), $nativeEncoding)
