param([string]$TcpPeer, [string]$Python)

$ErrorActionPreference = 'Stop'
$dataCalibration = ![string]::IsNullOrEmpty($TcpPeer)
$expectedRef = if ($dataCalibration) {
    'refs/heads/verify/r24/windows-arm64-tun-data'
} else {
    'refs/heads/verify/r24/windows-arm64-wintun-qualify'
}
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_REPOSITORY -cne 'AresJef/verysync-sidecar' -or
    $env:GITHUB_REF -cne $expectedRef -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'Arm64' -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'Arm64') {
    throw 'Run only on the assigned disposable native Windows ARM64 job'
}
if ($dataCalibration -and (!(Test-Path -LiteralPath $TcpPeer -PathType Leaf) -or
    !(Test-Path -LiteralPath $Python -PathType Leaf))) {
    throw 'The exact owned receiver and native Python sender are required'
}

function Get-WintunPackages {
    @(Get-WindowsDriver -Online | Where-Object { [IO.Path]::GetFileName($_.OriginalFileName) -ieq 'wintun.inf' })
}
function Get-WintunAdapters {
    @(Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceDescription -match 'Wintun' })
}
function Get-OwnedTestRoutes {
    @(Get-NetRoute | Where-Object { $_.DestinationPrefix -in @('192.0.2.0/30', '2001:db8:73f:43::/64') })
}
function Get-DefaultRouteSnapshot {
    @(Get-NetRoute | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') } |
        ForEach-Object { "$($_.DestinationPrefix)|$($_.InterfaceIndex)|$($_.NextHop)|$($_.RouteMetric)" } |
        Sort-Object)
}

if (@(Get-WintunPackages).Count -or @(Get-WintunAdapters).Count -or @(Get-OwnedTestRoutes).Count) {
    throw 'The isolated runner needs an unused driver and both unused documentation prefixes'
}
$defaults = Get-DefaultRouteSnapshot
$root = Join-Path $env:RUNNER_TEMP ('vs-owned-wintun-' + [guid]::NewGuid().ToString('N'))
$adapter = [IntPtr]::Zero
$session = [IntPtr]::Zero
$ownedPeer = $null
$attempted = $false
$dllLoaded = $false
$index = [uint32]0
New-Item -Path $root -ItemType Directory | Out-Null
try {
    $archive = Join-Path $root 'wintun-0.14.1.zip'
    $fixedHash = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
    Invoke-WebRequest -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $archive -TimeoutSec 30
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ine $fixedHash) {
        throw 'The pinned official Wintun archive did not match its published SHA-256'
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $root
    $dll = Join-Path $root 'wintun/bin/arm64/wintun.dll'
    $signature = Get-AuthenticodeSignature -LiteralPath $dll
    if ($signature.Status -ne 'Valid') {
        throw "The ARM64 DLL's Authenticode status was $($signature.Status)"
    }

    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

public static class OwnedTunQualification
{
    private static IntPtr library;

    [DllImport("wintun.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr WintunCreateAdapter(string name, string type, ref Guid id);

    [DllImport("wintun.dll", ExactSpelling = true)]
    public static extern void WintunCloseAdapter(IntPtr adapter);

    [DllImport("wintun.dll", ExactSpelling = true)]
    private static extern void WintunGetAdapterLUID(IntPtr adapter, out ulong luid);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint ConvertInterfaceLuidToIndex(ref ulong luid, out uint index);

    [DllImport("wintun.dll", ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr WintunStartSession(IntPtr adapter, uint capacity);

    [DllImport("wintun.dll", ExactSpelling = true)]
    public static extern void WintunEndSession(IntPtr session);

    [DllImport("wintun.dll", ExactSpelling = true, SetLastError = true)]
    public static extern uint WintunGetRunningDriverVersion();

    [DllImport("wintun.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WintunDeleteDriver();

    [DllImport("wintun.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr WintunReceivePacket(IntPtr session, out uint size);

    [DllImport("wintun.dll", ExactSpelling = true)]
    private static extern void WintunReleaseReceivePacket(IntPtr session, IntPtr packet);

    public static void LoadExactDll(string path)
    {
        library = NativeLibrary.Load(path);
        try
        {
            NativeLibrary.SetDllImportResolver(typeof(OwnedTunQualification).Assembly,
                (name, assembly, options) => name == "wintun.dll" ? library : IntPtr.Zero);
        }
        catch
        {
            NativeLibrary.Free(library);
            throw;
        }
    }

    public static void UnloadExactDll() => NativeLibrary.Free(library);

    public static uint InterfaceIndex(IntPtr adapter)
    {
        WintunGetAdapterLUID(adapter, out ulong luid);
        uint result = ConvertInterfaceLuidToIndex(ref luid, out uint index);
        if (result != 0) throw new Win32Exception((int)result);
        return index;
    }

    public static int ObserveSyn(IntPtr session, string local, string remote)
    {
        var source = IPAddress.Parse(local);
        var dest = IPAddress.Parse(remote);
        var v4 = source.AddressFamily == AddressFamily.InterNetwork;
        using var sender = new Socket(source.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        sender.Bind(new IPEndPoint(source, 0));
        int sourcePort = ((IPEndPoint)sender.LocalEndPoint).Port;
        var connect = sender.ConnectAsync(new IPEndPoint(dest, 47529));
        var clock = Stopwatch.StartNew();
        while (clock.Elapsed < TimeSpan.FromSeconds(5))
        {
            if (connect.IsFaulted || connect.IsCompletedSuccessfully)
                throw new InvalidOperationException("The controlled unanswered SYN could not be isolated", connect.Exception);
            var packet = WintunReceivePacket(session, out uint size);
            if (packet == IntPtr.Zero)
            {
                int code = Marshal.GetLastWin32Error();
                if (code != 259) throw new Win32Exception(code);
                System.Threading.Thread.Sleep(5);
                continue;
            }
            try
            {
                var header = new byte[Math.Min((int)size, 96)];
                Marshal.Copy(packet, header, 0, header.Length);
                int tcp = v4 && header.Length > 0 ? (header[0] & 15) * 4 : 40;
                int width = v4 ? 4 : 16;
                int start = v4 ? 12 : 8;
                if (tcp < (v4 ? 20 : 40) || header.Length < tcp + 20 ||
                    (header[0] >> 4) != (v4 ? 4 : 6) ||
                    header[v4 ? 9 : 6] != (byte)ProtocolType.Tcp ||
                    !new IPAddress(header.AsSpan(start, width)).Equals(source) ||
                    !new IPAddress(header.AsSpan(start + width, width)).Equals(dest) ||
                    ((header[tcp] << 8) | header[tcp + 1]) != sourcePort ||
                    ((header[tcp + 2] << 8) | header[tcp + 3]) != 47529 ||
                    (header[tcp + 13] & 0x12) != 2)
                    continue;
                return v4 ? header[1] : ((header[0] & 15) << 4) | (header[1] >> 4);
            }
            finally
            {
                WintunReleaseReceivePacket(session, packet);
            }
        }
        throw new TimeoutException("No test-owned native TCP SYN reached the layer-3 capture");
    }
}
'@
    [OwnedTunQualification]::LoadExactDll($dll)
    $dllLoaded = $true
    if ([OwnedTunQualification]::WintunGetRunningDriverVersion() -ne 0) {
        throw 'A Wintun driver became active outside this test'
    }
    $id = [guid]::NewGuid()
    $name = 'VS-Wintun-' + $id.ToString('N')
    $attempted = $true
    $adapter = [OwnedTunQualification]::WintunCreateAdapter($name, 'VerySync test Wintun', [ref]$id)
    if ($adapter -eq [IntPtr]::Zero) {
        $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "WintunCreateAdapter failed with Win32 code $code"
    }
    $index = [OwnedTunQualification]::InterfaceIndex($adapter)
    if ($dataCalibration) {
        # A running Wintun session brings the interface media up before routes appear.
        $peerStart = [Diagnostics.ProcessStartInfo]::new($TcpPeer)
        $peerStart.UseShellExecute = $false
        $peerStart.RedirectStandardOutput = $true
        $peerStart.RedirectStandardError = $true
        $peerStart.ArgumentList.Add($dll)
        $peerStart.ArgumentList.Add($name)
        $ownedPeer = [Diagnostics.Process]::Start($peerStart)
        $peerErrors = $ownedPeer.StandardError.ReadToEndAsync()
        $ready = $ownedPeer.StandardOutput.ReadLineAsync()
        if (!$ready.Wait(8000) -or $ready.Result -cne 'ARM64_TUN_TCP_READY') {
            if ($peerErrors.IsCompletedSuccessfully) { Write-Output $peerErrors.Result }
            throw 'The independent receiver did not become ready on the owned adapter'
        }
        $peerOutput = $ownedPeer.StandardOutput.ReadToEndAsync()
        Write-Output 'ARM64_TUN_TCP_READY'
    }
    if (!$dataCalibration) {
        $session = [OwnedTunQualification]::WintunStartSession($adapter, 4194304)
        if ($session -eq [IntPtr]::Zero) {
            $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "WintunStartSession failed with Win32 code $code"
        }
    }

    $cases = @(
        @{family=4; source='192.0.2.1'; peer='192.0.2.2'; length=30; prefix='192.0.2.0/30'},
        @{family=6; source='2001:db8:73f:43::1'; peer='2001:db8:73f:43::2'; length=64; prefix='2001:db8:73f:43::/64'}
    )
    foreach ($case in $cases) {
        New-NetIPAddress -InterfaceIndex $index -IPAddress $case.source -PrefixLength $case.length -PolicyStore ActiveStore | Out-Null
        $limit = (Get-Date).AddSeconds(8)
        do {
            $address = Get-NetIPAddress -IPAddress $case.source -InterfaceIndex $index
            if ($address.AddressState -eq 'Preferred') { break }
            Start-Sleep -Milliseconds 100
        } until ((Get-Date) -ge $limit)
        $onLink = [bool](Get-NetRoute -InterfaceIndex $index -DestinationPrefix $case.prefix -ErrorAction SilentlyContinue)
        Write-Output ("ARM64_TUN_LINK family=$($case.family) address_state=$($address.AddressState) owned_on_link=$onLink")
        if ($address.AddressState -ne 'Preferred' -or !$onLink) {
            throw 'The assigned test endpoint and its on-link route did not become active'
        }
        if (!$dataCalibration) {
            $octet = [OwnedTunQualification]::ObserveSyn($session, $case.source, $case.peer)
            Write-Output ("ARM64_TUN_SAMPLE " + (@{family=$case.family; observed_owned_syn=$true; octet=$octet} | ConvertTo-Json -Compress))
        }
    }
    if ($dataCalibration) {
        $env:OWNED_HYPERV_QOS_CONTROL = 'true'
        $env:OWNED_HYPERV_QOS_MECHANISM = 'qwave'
        $senderOutput = @(& $Python -B (Join-Path $PSScriptRoot 'hyperv-wire/qos_send.py'))
        $senderExit = $LASTEXITCODE
        $senderOutput | Write-Output
        if (!$ownedPeer.WaitForExit(10000)) { throw 'The independent receiver did not exit on time' }
        Write-Output $peerErrors.Result
        $receiverLines = @($peerOutput.Result -split '\r?\n')
        $receiverLines | Write-Output
        $senderApi = @($senderOutput | Where-Object { $_ -match '^QOS_API ' } |
            ForEach-Object { $_.Substring(8) | ConvertFrom-Json -AsHashtable })
        if ($senderExit -ne 0 -or $ownedPeer.ExitCode -ne 0 -or
            $senderApi.Count -ne 6 -or @($senderApi | Where-Object { $_.winerror -ne 0 }).Count -ne 0 -or
            @($receiverLines -match '^ARM64_TUN_QOS_DATA ').Count -ne 6 -or
            !($receiverLines -contains 'ARM64_TUN_QOS_COMPLETE six_native_tcp_data_cases=true')) {
            throw 'The complete six-case native TCP calibration did not pass'
        }
    } else {
        Write-Output 'ARM64_TUN_QUALIFICATION exact_official_archive=true native_arm64=true two_owned_synthetic_syn_packets=true'
    }
    if (((Get-DefaultRouteSnapshot) -join ',') -cne ($defaults -join ',')) {
        throw 'Default route inventory changed'
    }
}
finally {
    try {
        if ($null -ne $ownedPeer) {
            if (!$ownedPeer.HasExited) {
                $ownedPeer.Kill($true)
                if (!$ownedPeer.WaitForExit(5000)) { throw 'The exact owned receiver remains active' }
            }
            $ownedPeer.Dispose()
        }
        if ($session -ne [IntPtr]::Zero) { [OwnedTunQualification]::WintunEndSession($session) }
        if ($adapter -ne [IntPtr]::Zero) { [OwnedTunQualification]::WintunCloseAdapter($adapter) }
        if ($attempted -and @(Get-WintunPackages).Count -and ![OwnedTunQualification]::WintunDeleteDriver()) {
            $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "Owned Wintun driver did not unload (Win32 code $code)"
        }
        $limit = (Get-Date).AddSeconds(8)
        do {
            $residual = @(Get-WintunAdapters).Count + @(Get-OwnedTestRoutes).Count
            if ($residual -eq 0) { break }
            Start-Sleep -Milliseconds 150
        } until ((Get-Date) -ge $limit)
        if ($residual -or ($attempted -and @(Get-WintunPackages).Count) -or
            ((Get-DefaultRouteSnapshot) -join ',') -cne ($defaults -join ',')) {
            throw 'The isolated test did not restore the adapter, driver, and route inventory'
        }
        Write-Output 'ARM64_TUN_CLEANUP owned_adapter_and_driver_removed=true routes_restored=true'
    }
    finally {
        if ($dllLoaded) { [OwnedTunQualification]::UnloadExactDll() }
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
