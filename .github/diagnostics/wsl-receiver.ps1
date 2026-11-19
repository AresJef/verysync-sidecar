param(
    [Parameter(Mandatory)][ValidateSet('x86_64','aarch64')][string]$GuestArch,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedDigest
)
$ErrorActionPreference = 'Stop'
$registry = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
$wsl = (Get-Command wsl.exe -ErrorAction Stop).Source
$owner = 'vs-receiver-' + [guid]::NewGuid().ToString('N')
$root = Join-Path $env:RUNNER_TEMP $owner
$storage = Join-Path $root 'distribution'

function Get-Registrations {
    if (Test-Path -LiteralPath $registry) {
        Get-ChildItem -LiteralPath $registry | ForEach-Object {
            $value = Get-ItemProperty -LiteralPath $_.PSPath
            if ($value.PSObject.Properties.Name -contains 'DistributionName') { $value }
        }
    }
}

function Invoke-WslLocal([string[]]$Argument, [int]$Seconds) {
    $info = [Diagnostics.ProcessStartInfo]::new($wsl)
    $info.UseShellExecute = $false
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($value in $Argument) { $info.ArgumentList.Add($value) }
    $process = [Diagnostics.Process]::Start($info)
    try {
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (!$process.WaitForExit($Seconds * 1000)) {
            $process.Kill()
            $process.WaitForExit()
            throw "The exact WSL invocation exceeded $Seconds seconds."
        }
        @{code=$process.ExitCode; out=($stdout.Result -replace '\x00','').Trim()
          err=($stderr.Result -replace '\x00','').Trim()}
    }
    finally { $process.Dispose() }
}

function Require-Wsl([string[]]$Argument, [int]$Seconds) {
    $result = Invoke-WslLocal $Argument $Seconds
    if ($result.code -ne 0) {
        $detail = ($result.err + ' ' + $result.out).Trim()
        throw "WSL exit $($result.code): $detail"
    }
    $result.out
}

if (@(Get-Registrations).Count -ne 0 -or (Test-Path -LiteralPath $root)) {
    throw 'A fresh and exclusive WSL fixture is required.'
}
$null = New-Item -ItemType Directory -Path $storage
try {
    $archiveName = "alpine-minirootfs-3.23.8-$GuestArch.tar.gz"
    $compressed = Join-Path $root $archiveName
    $tar = Join-Path $root 'alpine-rootfs.tar'
    $url = "https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/$GuestArch/$archiveName"
    curl.exe --fail --silent --show-error --max-time 30 --output $compressed $url
    if ($LASTEXITCODE -ne 0) { throw 'Official fixed Alpine download did not complete.' }
    $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $compressed).Hash.ToLowerInvariant()
    if ($digest -ne $ExpectedDigest) { throw 'Official pinned Alpine image hash mismatch.' }
    Write-Output "WSL_TEST_INPUT architecture=$GuestArch sha256=$digest"
    $archiveStream = [IO.File]::OpenRead($compressed)
    $tarStream = [IO.File]::Create($tar)
    try {
        $gzip = [IO.Compression.GzipStream]::new($archiveStream, [IO.Compression.CompressionMode]::Decompress)
        try { $gzip.CopyTo($tarStream) } finally { $gzip.Dispose() }
    }
    finally { $tarStream.Dispose(); $archiveStream.Dispose() }
    $null = Require-Wsl @('--import', $owner, $storage, $tar, '--version', '2') 90
    $hostArchitecture = (Require-Wsl @('-d', $owner, '-u', 'root', '--exec', '/bin/uname', '-m') 30)
    $kernel = (Require-Wsl @('-d', $owner, '-u', 'root', '--exec', '/bin/uname', '-r') 15)
    $null = Require-Wsl @('-d', $owner, '-u', 'root', '--exec', '/bin/sh', '-c', 'test -e /sys/class/net/eth0') 15
    if ($hostArchitecture -ne $GuestArch -or $kernel -notmatch '(?i)wsl2') {
        throw "Wrong active guest architecture or kernel: $hostArchitecture $kernel"
    }
    Write-Output "WSL_RECEIVER_BOOT guest_architecture=$hostArchitecture kernel=$kernel own_ethernet=true"
}
finally {
    $registrations = @(Get-Registrations)
    $owned = @($registrations | Where-Object { $_.DistributionName -eq $owner })
    if ($owned.Count -gt 0) {
        $base = [string]$owned[0].BasePath
        if ($base.StartsWith('\\?\')) { $base = $base.Substring(4) }
        if ($owned.Count -ne 1 -or [IO.Path]::GetFullPath($base) -ne [IO.Path]::GetFullPath($storage)) {
            throw 'Cannot confirm exact fixture ownership. WSL registration and storage were retained.'
        }
        $null = Require-Wsl @('--terminate', $owner) 30
        $null = Require-Wsl @('--unregister', $owner) 30
    }
    if (@(Get-Registrations).Count -ne 0) { throw 'Unexpected retained WSL registration.' }
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
    Write-Output 'WSL_RECEIVER_CLEANUP no_registration_changes_outside_fixture=true private_storage_removed=true'
}
