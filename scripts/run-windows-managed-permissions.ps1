param(
    [Parameter(Mandatory = $true)][string]$Toolchain
)

$ErrorActionPreference = 'Stop'
$caller = [Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$localService = [Security.Principal.SecurityIdentifier]::new('S-1-5-19')
if ($caller -eq $system) { throw 'Run the ordinary-caller controls outside LocalSystem.' }

$result = @(cargo "+$Toolchain" test --locked --offline --features download --lib --no-run --message-format=json |
    ForEach-Object { ConvertFrom-Json -InputObject $_ } |
    Where-Object { $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'verysync_sidecar' -and $_.profile.test -and $_.executable })
if ($LASTEXITCODE -ne 0 -or $result.Count -ne 1) { throw 'The native library test executable could not be selected.' }

$root = Join-Path $env:RUNNER_TEMP ("vss-managed-permissions-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$tasks = [Collections.Generic.List[string]]::new()
try {
    function Grant-Access([string]$Path, [Security.Principal.SecurityIdentifier]$Principal, [string]$Right) {
        $acl = Get-Acl -LiteralPath $Path
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $Principal, $Right, 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $acl
    }

    Grant-Access $root $localService 'ReadAndExecute'
    $foreign = Join-Path $root 'owner-fixture'
    New-Item -ItemType Directory -Path $foreign | Out-Null
    Grant-Access $foreign $localService 'FullControl'
    $test = Join-Path $root 'managed-permission-tests.exe'
    Copy-Item -LiteralPath $result[0].executable -Destination $test
    if ((Get-FileHash -LiteralPath $result[0].executable).Hash -ne (Get-FileHash -LiteralPath $test).Hash) {
        throw 'The isolated test executable differs from the compiled file.'
    }

    $script = Join-Path $root 'fixture.ps1'
    @'
param([string]$Root, [string]$Mode, [string]$Caller)
$ErrorActionPreference = 'Stop'
$exe = Join-Path $Root 'managed-permission-tests.exe'
$actual = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($Mode -eq 'system') {
    if ($actual -ne 'S-1-5-18') { throw 'The test token is not LocalSystem.' }
    $env:VSS_WINDOWS_REQUIRE_SYSTEM = '1'
    $log = Join-Path $Root 'system.log'
    & $exe windows_private_directories_and_controls_reopen_for_the_actual_caller --nocapture *> $log
    if ($LASTEXITCODE -ne 0) { throw 'The LocalSystem state test failed.' }
    & $exe windows_system_creates_and_reopens_the_real_cache_lease --ignored --nocapture *>> $log
    if ($LASTEXITCODE -ne 0) { throw 'The LocalSystem cache test failed.' }
    Write-Output "Actual test TokenUser $actual" *>> $log
    [IO.File]::WriteAllText((Join-Path $Root 'system.done'), $actual)
    exit 0
}
if ($Mode -ne 'foreign' -or $actual -ne 'S-1-5-19') { throw 'The foreign owner fixture has an unexpected token.' }
$drop = Join-Path $Root 'owner-fixture'
$dir = Join-Path $drop 'foreign-state'
$file = Join-Path $drop 'foreign-control.bin'
New-Item -ItemType Directory -Path $dir | Out-Null
[IO.File]::WriteAllText($file, 'synthetic foreign control')
[IO.File]::WriteAllText((Join-Path $dir 'sample.bin'), 'synthetic foreign state')
foreach ($entry in @(@{ Path = $dir; Flags = 'OICI' }, @{ Path = $file; Flags = '' })) {
    $acl = Get-Acl -LiteralPath $entry.Path
    $inherit = $entry.Flags
    $privateAcl = "D:P(A;$inherit;FA;;;SY)(A;$inherit;FA;;;$Caller)"
    $acl.SetSecurityDescriptorSddlForm($privateAcl, [Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -LiteralPath $entry.Path -AclObject $acl
}
[IO.File]::WriteAllText((Join-Path $drop 'foreign.done'), $actual)
'@ | Set-Content -LiteralPath $script -Encoding UTF8

    function Invoke-Fixture([string]$Mode, [string]$Identity, [string]$Receipt, [string]$Expected) {
        $task = [IO.Path]::GetFileName($root) + "-$Mode"
        $arguments = '-NoProfile -NonInteractive -File "{0}" -Root "{1}" -Mode {2} -Caller {3}' -f $script, $root, $Mode, $caller.Value
        $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments
        $principal = New-ScheduledTaskPrincipal -UserId $Identity -LogonType ServiceAccount
        Register-ScheduledTask -TaskName $task -Action $action -Principal $principal | Out-Null
        $tasks.Add($task)
        Start-ScheduledTask -TaskName $task
        $limit = [DateTime]::UtcNow.AddSeconds(45)
        do {
            Start-Sleep -Milliseconds 200
            $finished = (Test-Path -LiteralPath $Receipt) -and (Get-ScheduledTask -TaskName $task).State -eq 'Ready'
        } while (-not $finished -and [DateTime]::UtcNow -lt $limit)
        if (-not $finished -or (Get-Content -LiteralPath $Receipt -Raw) -ne $Expected -or
            (Get-ScheduledTaskInfo -TaskName $task).LastTaskResult -ne 0) {
            $systemLog = Join-Path $root 'system.log'
            if (Test-Path -LiteralPath $systemLog) { Get-Content -LiteralPath $systemLog }
            throw "The isolated $Mode task did not produce the expected receipt."
        }
    }

    & $test windows_private_directories_and_controls_reopen_for_the_actual_caller --nocapture
    if ($LASTEXITCODE -ne 0) { throw 'The ordinary-caller private state test failed.' }
    Invoke-Fixture 'system' 'NT AUTHORITY\SYSTEM' (Join-Path $root 'system.done') $system.Value
    Get-Content -LiteralPath (Join-Path $root 'system.log')
    Invoke-Fixture 'foreign' 'NT AUTHORITY\LOCAL SERVICE' (Join-Path $foreign 'foreign.done') $localService.Value
    $dir = Join-Path $foreign 'foreign-state'
    $file = Join-Path $foreign 'foreign-control.bin'
    function Read-FixtureSecurity([string]$Path) {
        $acl = Get-Acl -LiteralPath $Path
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $localService.Value) {
            throw 'The opened fixture does not belong to the foreign service account.'
        }
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        $principals = ($rules.IdentityReference.Value | Sort-Object) -join ','
        $expectedPrincipals = (@($caller.Value, $system.Value) | Sort-Object) -join ','
        if ($principals -ne $expectedPrincipals -or
            @($rules | Where-Object { $_.FileSystemRights -ne 'FullControl' -or $_.AccessControlType -ne 'Allow' }).Count -ne 0 -or
            -not $acl.AreAccessRulesProtected) {
            throw 'The foreign fixture does not have the expected two private access grants.'
        }
        $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Access,Owner')
    }
    $before = @((Read-FixtureSecurity $dir), (Read-FixtureSecurity $file))
    $digest = @((Get-FileHash -LiteralPath $file).Hash, (Get-FileHash -LiteralPath (Join-Path $dir 'sample.bin')).Hash)
    $env:VSS_WINDOWS_FOREIGN_FIXTURE = $foreign
    & $test windows_rejects_the_foreign_owner_before_mutating_directory_or_file --ignored --nocapture
    if ($LASTEXITCODE -ne 0) { throw 'The foreign-owner rejection test failed.' }
    $after = @((Read-FixtureSecurity $dir), (Read-FixtureSecurity $file))
    $readback = @((Get-FileHash -LiteralPath $file).Hash, (Get-FileHash -LiteralPath (Join-Path $dir 'sample.bin')).Hash)
    for ($index = 0; $index -lt $before.Count; $index++) {
        if ($before[$index] -cne $after[$index]) { throw 'The owner or DACL changed.' }
        if ($digest[$index] -cne $readback[$index]) { throw 'A protected sample changed.' }
    }
    Write-Output 'Directory and control retained their real LocalService owner, private DACL and original sample SHA-256.'
} finally {
    foreach ($task in $tasks) {
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
        if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) { throw 'An isolated fixture task remains.' }
    }
    Remove-Item Env:VSS_WINDOWS_FOREIGN_FIXTURE -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $root -Recurse -Force
}
if (Test-Path -LiteralPath $root) { throw 'The isolated Windows permission fixture remains.' }
Write-Output 'Both isolated Windows identity tasks and the private fixture were removed.'
