param([Parameter(Mandatory=$true)][string]$Directory)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Use the process subscriber only on the isolated GitHub Windows runner.'
}
$root = [IO.Path]::GetFullPath($Directory)
$encoding = [Text.UTF8Encoding]::new($false)
$source = 'upgrade-recovery-' + [Guid]::NewGuid().ToString('N')
$registered = $false
$closed = $false
$failure = $null
$omitted = 0
$events = [Collections.Generic.List[object]]::new()
try {
    Register-CimIndicationEvent -Namespace 'root/cimv2' -ClassName 'Win32_ProcessStartTrace' -SourceIdentifier $source | Out-Null
    $registered = $true
    [IO.File]::WriteAllText([IO.Path]::Combine($root, 'ready'), 'ready', $encoding)
    $until = [DateTime]::UtcNow.AddSeconds(180)
    $drain = $false
    while ([DateTime]::UtcNow -lt $until) {
        if (-not $drain -and [IO.File]::Exists([IO.Path]::Combine($root, 'stop'))) {
            $drain = $true
            $until = [DateTime]::UtcNow.AddSeconds(2)
        }
        $event = Wait-Event -SourceIdentifier $source -Timeout 1 | Select-Object -First 1
        if ($null -eq $event) { continue }
        $item = $event.SourceEventArgs.NewEvent
        if ($events.Count -lt 4096) {
            $events.Add(@{
                time = ([Int64]$item.TIME_CREATED - [Int64]116444736000000000) * 100
                pid = [UInt32]$item.ProcessID
                parent = [UInt32]$item.ParentProcessID
                event = 'create'
            })
        } else { $omitted++ }
        Remove-Event -EventIdentifier $event.EventIdentifier
    }
} catch {
    $failure = $_.Exception.GetType().FullName
} finally {
    if ($registered) {
        try {
            Unregister-Event -SourceIdentifier $source
            Get-Event -SourceIdentifier $source -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue
            $closed = $true
        } catch { $failure = $_.Exception.GetType().FullName }
    }
}
$result = @{events = $events; error = $failure; omitted = $omitted; closed = $closed}
[IO.File]::WriteAllText([IO.Path]::Combine($root, 'observer.local.json'), ($result | ConvertTo-Json -Depth 5 -Compress), $encoding)
