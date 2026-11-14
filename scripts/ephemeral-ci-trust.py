#!/usr/bin/env python3
"""Explicit, fingerprint-scoped CA trust for disposable GitHub-hosted test VMs."""
import argparse
import base64
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def require_scope(certificate, enabled):
    if not enabled or any(os.environ.get(key) != value for key, value in {
        "CI": "true", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
    }.items()):
        raise ValueError("explicit disposable GitHub-hosted runner trust required")
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    path = Path(certificate)
    if path.name != "synthetic-ldap-ca.pem" or not path.is_absolute():
        raise ValueError("explicit generated LDAP CA path required")
    current = path
    child = None
    while True:
        if current.is_symlink() or current.is_junction() or current.parent == current:
            raise ValueError("test trust path must stay inside the runner directory without aliases")
        if current.samefile(temporary):
            break
        child = current
        current = current.parent
    if child is None or not child.name.startswith("vs-ldap-trusted-"):
        raise ValueError("dedicated trusted LDAP test directory required")
    if not path.is_file() or path.stat().st_size > 16384:
        raise ValueError("bounded generated CA certificate required")
    return path


def certificate_identity(path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID
    data = path.read_bytes()
    if data.count(b"-----BEGIN CERTIFICATE-----") != 1:
        raise ValueError("one generated CA certificate required")
    cert = x509.load_pem_x509_certificate(data)
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    now = datetime.datetime.now(datetime.timezone.utc)
    if (len(names) != 1 or not names[0].value.startswith("verysync-sidecar-ephemeral-ci-")
            or cert.subject != cert.issuer or not constraints.ca or constraints.path_length != 0
            or not usage.key_cert_sign or not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
            or cert.not_valid_after_utc - cert.not_valid_before_utc > datetime.timedelta(days=2)):
        raise ValueError("short-lived generated test CA identity differs")
    public = cert.public_key()
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 2048:
        raise ValueError("generated RSA CA required")
    public.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
    return {"sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "sha1": cert.fingerprint(hashes.SHA1()).hex(), "common_name": names[0].value,
            "pem_sha256": hashlib.sha256(data).hexdigest()}


WINDOWS = r'''
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Disposable runner required' }
$pem = [IO.File]::ReadAllText($env:VS_TEST_CA_CERTIFICATE)
$der = [Convert]::FromBase64String(($pem -replace '-----BEGIN CERTIFICATE-----','' -replace '-----END CERTIFICATE-----','').Trim())
$cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$der)
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Disposable VM administrator required' }
$stageLog = [IO.Path]::Combine([IO.Path]::GetDirectoryName($env:VS_TEST_CA_CERTIFICATE),'ephemeral-ca-windows-stages.jsonl')
function Stage($name) { [IO.File]::AppendAllText($stageLog,('{"phase":"' + $name + '"}' + [Environment]::NewLine)) }
# CurrentUser Root writes can prompt through CryptoAPI despite -NonInteractive.
# Only this explicit disposable VM uses its administrative LocalMachine Root.
$store = New-Object Security.Cryptography.X509Certificates.X509Store 'Root','LocalMachine'
Stage 'before-store-open'
$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
Stage 'after-store-open'
try {
  $found = $store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$cert.Thumbprint,$false)
  switch ($env:VS_TEST_CA_ACTION) {
    'probe' { if ($found.Count -gt 0) { exit 3 }; exit 0 }
    'install' {
      if ($found.Count -ne 0) { throw 'Preexisting CA refused' }
      Stage 'before-store-add'
      $store.Add($cert)
      Stage 'after-store-add'
    }
    'remove' { foreach ($item in $found) {
      if ([Convert]::ToBase64String($item.RawData) -ne [Convert]::ToBase64String($der)) { throw 'CA identity mismatch' }
      Stage 'before-store-remove'
      $store.Remove($item)
      Stage 'after-store-remove'
    } }
    default { throw 'Explicit trust action required' }
  }
} finally { $store.Close() }
'''


def run(arguments, path, extra=None):
    environment = os.environ.copy()
    environment.update(extra or {})
    log = path.parent / "private-ephemeral-trust.log"
    with log.open("ab") as output:
        os.chmod(log, 0o600)
        try:
            result = subprocess.run(arguments, env=environment, stdout=output,
                                    stderr=subprocess.STDOUT, timeout=25)
            code = result.returncode
        except subprocess.TimeoutExpired:
            record_command_result(arguments, path, "timeout")
            raise
    record_command_result(arguments, path, code)
    return code


def record_command_result(arguments, path, code):
    operations = {"find-certificate", "add-trusted-cert", "remove-trusted-cert",
                  "delete-certificate", "probe-admin-trust", "install", "rm", "update-ca-certificates"}
    operation = next((value for value in arguments if value in operations), "windows-root-store")
    with (path.parent / "ephemeral-ca-command-results.jsonl").open("a", encoding="utf-8") as output:
        output.write(json.dumps({"operation": operation, "exit": code}) + "\n")


def windows(action, path):
    encoded = base64.b64encode(WINDOWS.encode("utf-16-le")).decode("ascii")
    return run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], path,
               {"VS_TEST_CA_ACTION": action, "VS_TEST_CA_CERTIFICATE": str(path)})


def linux_path(identity):
    return Path("/usr/local/share/ca-certificates") / ("verysync-sidecar-ci-" + identity["sha256"] + ".crt")


def macos_admin_trust_status(path):
    """Read settings for this exact DER certificate; never mutate trust here.

    Apple's SecTrustSettings.h specifies domainAdmin=1 and errSecItemNotFound
    when this certificate has no settings. A successful empty array is PRESENT
    trust, not absence. No enumeration or import of unrelated settings occurs.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    der = x509.load_pem_x509_certificate(path.read_bytes()).public_bytes(Encoding.DER)
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
    pointer = ctypes.c_void_p
    cf.CFDataCreate.argtypes = [pointer, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_long]
    cf.CFDataCreate.restype = pointer
    cf.CFRelease.argtypes = [pointer]
    cf.CFRelease.restype = None
    security.SecCertificateCreateWithData.argtypes = [pointer, pointer]
    security.SecCertificateCreateWithData.restype = pointer
    security.SecTrustSettingsCopyTrustSettings.argtypes = [pointer, ctypes.c_uint32,
                                                        ctypes.POINTER(pointer)]
    security.SecTrustSettingsCopyTrustSettings.restype = ctypes.c_int32
    data = cf.CFDataCreate(None, (ctypes.c_ubyte * len(der)).from_buffer_copy(der), len(der))
    if not data:
        raise RuntimeError("native CA probe could not allocate certificate data")
    certificate = None
    settings = pointer()
    try:
        certificate = security.SecCertificateCreateWithData(None, data)
        if not certificate:
            raise RuntimeError("native CA probe rejected generated certificate")
        return security.SecTrustSettingsCopyTrustSettings(certificate, 1, ctypes.byref(settings))
    finally:
        if settings.value:
            cf.CFRelease(settings)
        if certificate:
            cf.CFRelease(certificate)
        cf.CFRelease(data)


def probe_macos_admin_trust(path):
    # Keep even a stalled native read inside the same 25s subprocess boundary.
    return run([sys.executable, str(Path(__file__).resolve()), "probe-admin-trust",
                "--certificate", str(path), "--allow-ephemeral-runner-system-trust"], path)


def macos_certificate_absent(path, identity):
    code = run(["security", "find-certificate", "-c", identity["common_name"], "-Z",
                "/Library/Keychains/System.keychain"], path)
    if code not in (0, 44):
        raise ValueError("generated macOS CA keychain state is unobservable")
    return code == 44


def ensure_absent(path, identity):
    if sys.platform == "win32":
        code = windows("probe", path)
        if code != 0:
            raise ValueError("preexisting or unobservable CA refused")
    elif sys.platform == "darwin":
        if not macos_certificate_absent(path, identity):
            raise ValueError("preexisting or unobservable CA refused")
        if probe_macos_admin_trust(path) != 0:
            raise ValueError("preexisting or unobservable administrative CA trust refused")
    elif sys.platform == "linux":
        if linux_path(identity).exists():
            raise ValueError("preexisting test CA file refused")
    else:
        raise ValueError("unsupported disposable runner system")


def mutate(action, path, identity):
    if sys.platform == "win32":
        codes = [windows(action, path)]
    elif sys.platform == "darwin":
        if action == "install":
            commands = [["sudo", "-n", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
                         "-k", "/Library/Keychains/System.keychain", str(path)]]
        else:
            # Removing trust before the keychain certificate hangs on hosted
            # macOS. The native diagnostic proves deletion alone leaves trust.
            # Reverse the order, then explicitly remove that exact remaining
            # record and verify both independent postconditions. Never import
            # a replacement trust store or change authorization policies.
            if not macos_certificate_absent(path, identity):
                code = run(["sudo", "-n", "security", "delete-certificate", "-Z", identity["sha256"],
                            "/Library/Keychains/System.keychain"], path)
                if code != 0:
                    raise RuntimeError("exact generated CA deletion failed; private lease retained")
            trust = probe_macos_admin_trust(path)
            if trust == 3:
                if run(["sudo", "-n", "security", "remove-trusted-cert", "-d", str(path)], path) != 0:
                    raise RuntimeError("exact administrative CA trust removal failed; private lease retained")
            elif trust != 0:
                raise RuntimeError("exact administrative CA trust is unobservable; private lease retained")
            if probe_macos_admin_trust(path) != 0:
                raise RuntimeError("exact macOS CA cleanup incomplete; private lease retained")
            return
        codes = [run(command, path) for command in commands]
    elif sys.platform == "linux":
        destination = linux_path(identity)
        if action == "install":
            first = ["sudo", "-n", "install", "-m", "0644", str(path), str(destination)]
        else:
            if destination.exists() and hashlib.sha256(destination.read_bytes()).hexdigest() != identity["pem_sha256"]:
                raise ValueError("owned CA file changed; removal refused")
            first = ["sudo", "-n", "rm", "-f", "--", str(destination)]
        codes = [run(first, path), run(["sudo", "-n", "update-ca-certificates"], path)]
    else:
        raise ValueError("unsupported disposable runner system")
    if any(code != 0 for code in codes):
        raise RuntimeError("ephemeral CA operation failed; inspect private test log")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["install", "remove", "probe-admin-trust"])
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--allow-ephemeral-runner-system-trust", action="store_true")
    arguments = parser.parse_args(argv)
    path = require_scope(arguments.certificate, arguments.allow_ephemeral_runner_system_trust)
    identity = certificate_identity(path)
    if arguments.action == "probe-admin-trust":
        if sys.platform != "darwin":
            raise ValueError("administrative trust probe requires macOS")
        status = macos_admin_trust_status(path)
        if status not in (0, -25300):
            raise RuntimeError(f"administrative CA trust read failed with status {status}")
        print(json.dumps({"ca_sha256": identity["sha256"],
                          "admin_trust_present": status == 0}), flush=True)
        return 3 if status == 0 else 0
    lease = path.parent / ".ephemeral-ci-ca-lease.json"
    if arguments.action == "install":
        ensure_absent(path, identity)
        with lease.open("x", encoding="utf-8") as output:
            os.chmod(lease, 0o600)
            json.dump(identity, output)
        try:
            mutate("install", path, identity)
        except BaseException:
            try:
                mutate("remove", path, identity)
                ensure_absent(path, identity)
                lease.unlink()
            except Exception:
                pass  # Original failure and private lease remain for exact recovery.
            raise
    else:
        if lease.stat().st_size > 4096 or lease.is_symlink():
            raise ValueError("bounded owned CA lease required")
        recorded = json.loads(lease.read_text(encoding="utf-8"))
        if recorded != identity:
            raise ValueError("generated CA identity changed before cleanup")
        mutate("remove", path, identity)
        ensure_absent(path, identity)
        lease.unlink()
    print(json.dumps({"action": arguments.action, "ca_sha256": identity["sha256"],
                      "ephemeral_runner_only": True, "completed": True}), flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
