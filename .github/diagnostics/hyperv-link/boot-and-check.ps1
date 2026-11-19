param(
    [Parameter(Mandatory)][string]$FixtureDirectory
)
$ErrorActionPreference = 'Stop'
$iso = Join-Path (Resolve-Path $FixtureDirectory) 'receive.iso'
$checksums = Join-Path (Resolve-Path $FixtureDirectory) 'SHA256SUMS'
$expected = [regex]::Match((Get-Content -Raw -LiteralPath $checksums), '(?m)^([0-9a-f]{64})  receive\.iso$').Groups[1].Value
if ($expected.Length -ne 64 -or $expected -ne $env:EXPECTED_OWNED_ISO_SHA -or (Get-FileHash -LiteralPath $iso -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
    throw 'Owned test ISO SHA-256 did not match the producing job'
}
Write-Output "HYPERV_GUEST_INPUT iso_sha256=$expected"
$name = 'vs-receiver-' + [guid]::NewGuid().ToString('N').Substring(0, 16)
$root = Join-Path $env:RUNNER_TEMP $name
$beforeVM = @(Get-VM | ForEach-Object { $_.Id.ToString() } | Sort-Object)
$beforeSwitch = @(Get-VMSwitch | ForEach-Object { $_.Id.ToString() } | Sort-Object)
$prefixes = @('192.0.2.0/30','2001:db8:73f:43::/64')
if ((Test-Path -LiteralPath $root) -or (Get-VM -Name $name -ErrorAction SilentlyContinue) -or
    (Get-VMSwitch -Name $name -ErrorAction SilentlyContinue) -or
    (Get-NetRoute | Where-Object { $_.DestinationPrefix -in $prefixes })) {
    throw 'The temporary disk, VM, switch, and test routes must be fresh'
}
$null = New-Item -ItemType Directory -Path $root
$vmId = $null
$switchId = $null
$pipe = $null
$serial = $null
try {
    $link = New-VMSwitch -Name $name -SwitchType Internal
    $switchId = $link.Id
    $hostName = "vEthernet ($name)"
    $deadline = [DateTime]::UtcNow.AddSeconds(12)
    do {
        $interface = Get-NetAdapter -Name $hostName -ErrorAction SilentlyContinue
        if (!$interface) { Start-Sleep -Milliseconds 150 }
    } until ($interface -or [DateTime]::UtcNow -gt $deadline)
    if (!$interface -or $link.SwitchType -ne 'Internal') { throw 'No exclusively owned internal link' }
    $testInterface = $interface.ifIndex
    $null = New-NetIPAddress -InterfaceIndex $testInterface -AddressFamily IPv4 -IPAddress '192.0.2.1' -PrefixLength 30 -PolicyStore ActiveStore
    $null = New-NetIPAddress -InterfaceIndex $testInterface -AddressFamily IPv6 -IPAddress '2001:db8:73f:43::1' -PrefixLength 64 -PolicyStore ActiveStore
    if (Get-NetRoute -InterfaceIndex $testInterface | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') }) {
        throw 'No default route may use the isolated receiver link'
    }
    $vm = New-VM -Name $name -Path $root -MemoryStartupBytes 512MB -Generation 2 -NoVHD -SwitchName $name -Force
    $vmId = $vm.Id
    $network = @(Get-VMNetworkAdapter -VM $vm)
    if ($network.Count -ne 1 -or $network[0].SwitchId -ne $switchId -or (Get-VMHardDiskDrive -VM $vm)) {
        throw 'The fixture must have exactly its internal link and no writable disk'
    }
    $dvd = Add-VMDvdDrive -VM $vm -Path $iso -Passthru
    Set-VMFirmware -VM $vm -EnableSecureBoot Off -FirstBootDevice $dvd
    Set-VMComPort -VMName $name -Number 1 -Path ('\\.\pipe\' + $name)
    Start-VM -VM $vm
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', $name, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
    $pipe.Connect(5000)
    $serial = [IO.StreamReader]::new($pipe)
    $guestMessages = $serial.ReadToEndAsync()
    & python -B (Join-Path $PSScriptRoot 'windows-probe.py')
    if ($LASTEXITCODE -ne 0) { throw 'True dual-family native TCP transfer failed' }

    $limit = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $current = Get-VM -Id $vmId
        if ($current.State -ne 'Off') { Start-Sleep -Milliseconds 150 }
    } until ($current.State -eq 'Off' -or [DateTime]::UtcNow -gt $limit)
    if (!$guestMessages.Wait(5000)) { throw 'Owned guest console did not close' }
    $markers = @($guestMessages.Result -split '\r?\n' | Where-Object { $_ -match '^RECEIVER_GUEST_' })
    $markers | Write-Output
    if ($current.State -ne 'Off' -or -not ($markers -match '^RECEIVER_GUEST_BOOT kernel=6\.18\.60-0-virt architecture=x86_64$') -or
        -not ($markers -match '^RECEIVER_GUEST_LINK name=\w+ boot_driver=hv_netvsc no_default_ipv4_ipv6=true$') -or
        -not ($markers -match '^RECEIVER_GUEST_FINISH status=0$') -or
        @($markers -match '^RECEIVER_GUEST_DATA family=').Count -ne 2) {
        throw 'Guest identity, dedicated link, dual-family bytes, or own shutdown was incomplete'
    }
    Write-Output 'HYPERV_GUEST_ACTUAL no_external_route=true own_linux_shutdown=true'
}
finally {
    if ($serial) { $serial.Dispose() } elseif ($pipe) { $pipe.Dispose() }
    $found = Get-VM -Name $name -ErrorAction SilentlyContinue
    if ($found) {
        $path = [IO.Path]::GetFullPath([string]$found.ConfigurationLocation)
        $normal = [IO.Path]::GetFullPath($root).TrimEnd('\')
        if (($vmId -and $found.Id -ne $vmId) -or ($path -ne $normal -and !$path.StartsWith($normal + '\', [StringComparison]::OrdinalIgnoreCase))) {
            throw 'Refuse to remove a VM whose exact ownership is unavailable'
        }
        if ($found.State -ne 'Off') { Stop-VM -VM $found -TurnOff -Force }
        Remove-VM -VM $found -Force
    }
    $foundLink = Get-VMSwitch -Name $name -ErrorAction SilentlyContinue
    if ($foundLink) {
        if ($foundLink.Id -ne $switchId -or $foundLink.SwitchType -ne 'Internal') {
            throw 'Refuse to remove a switch whose exact ownership is unavailable'
        }
        Remove-VMSwitch -VMSwitch $foundLink -Force
    }
    $afterVM = @(Get-VM | ForEach-Object { $_.Id.ToString() } | Sort-Object)
    $afterSwitch = @(Get-VMSwitch | ForEach-Object { $_.Id.ToString() } | Sort-Object)
    if (($afterVM -join ',') -ne ($beforeVM -join ',') -or ($afterSwitch -join ',') -ne ($beforeSwitch -join ',') -or
        (Get-NetRoute | Where-Object { $_.DestinationPrefix -in $prefixes })) {
        throw 'Owned virtual machines, switch or routes were not fully restored'
    }
    Remove-Item -LiteralPath $root -Recurse -Force
    Write-Output 'HYPERV_GUEST_CLEANUP exact_vm=true exact_switch=true route_inventory_restored=true owned_storage_removed=true'
}
