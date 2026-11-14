#!/usr/bin/env python3
"""Explicit, fingerprint-scoped CA trust for disposable GitHub-hosted test VMs."""
import argparse
import base64
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
$store = New-Object Security.Cryptography.X509Certificates.X509Store 'Root','CurrentUser'
$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
try {
  $found = $store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$cert.Thumbprint,$false)
  switch ($env:VS_TEST_CA_ACTION) {
    'probe' { if ($found.Count -gt 0) { exit 3 }; exit 0 }
    'install' { if ($found.Count -ne 0) { throw 'Preexisting CA refused' }; $store.Add($cert) }
    'remove' { foreach ($item in $found) {
      if ([Convert]::ToBase64String($item.RawData) -ne [Convert]::ToBase64String($der)) { throw 'CA identity mismatch' }
      $store.Remove($item)
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
                  "delete-certificate", "install", "rm", "update-ca-certificates"}
    operation = next((value for value in arguments if value in operations), "windows-root-store")
    with (path.parent / "ephemeral-ca-command-results.jsonl").open("a", encoding="utf-8") as output:
        output.write(json.dumps({"operation": operation, "exit": code}) + "\n")


def windows(action, path):
    encoded = base64.b64encode(WINDOWS.encode("utf-16-le")).decode("ascii")
    return run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], path,
               {"VS_TEST_CA_ACTION": action, "VS_TEST_CA_CERTIFICATE": str(path)})


def linux_path(identity):
    return Path("/usr/local/share/ca-certificates") / ("verysync-sidecar-ci-" + identity["sha256"] + ".crt")


def ensure_absent(path, identity):
    if sys.platform == "win32":
        code = windows("probe", path)
        if code != 0:
            raise ValueError("preexisting or unobservable CA refused")
    elif sys.platform == "darwin":
        code = run(["security", "find-certificate", "-c", identity["common_name"], "-Z",
                    "/Library/Keychains/System.keychain"], path)
        if code != 44:
            raise ValueError("preexisting or unobservable CA refused")
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
            commands = [["sudo", "-n", "security", "remove-trusted-cert", "-d", str(path)],
                        ["sudo", "-n", "security", "delete-certificate", "-Z", identity["sha1"],
                         "/Library/Keychains/System.keychain"]]
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
    parser.add_argument("action", choices=["install", "remove"])
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--allow-ephemeral-runner-system-trust", action="store_true")
    arguments = parser.parse_args(argv)
    path = require_scope(arguments.certificate, arguments.allow_ephemeral_runner_system_trust)
    identity = certificate_identity(path)
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
    main()
