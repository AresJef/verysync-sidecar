"""Explicit, test-only public-CA loopback fixture; never changes system trust."""
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.request
import urllib.parse
import zipfile

HOSTNAME = "ldap.localhost.direct"
SOURCE = "https://github.com/Upinel/localhost.direct"
README_URL = "https://raw.githubusercontent.com/Upinel/localhost.direct/master/README.md"
README_SHA256 = "5fd457cf93ddc050df0584883257aeb000ec8565c968ba7104994d840d1110c8"
# Canonical destination of the publisher's documented short download link.
BUNDLE_URL = "https://get.localhost.direct/localhost.direct.OP.zip"
BUNDLE_SHA256 = "775a3517f5c7c1b62165d72dff98e092b432502d454a0dcd687b2463c2832ad8"
LEAF_SHA256 = "a747b1c21a3f5269462e0c005b41f32dbca8e5da59f20f879380e26bc03af2d7"
FILES = {"certificate-chain.pem", "private-key.pem", "manifest.json"}


def read_bounded(path, limit):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("bounded regular private fixture file required")
    with path.open("rb") as source:
        value = source.read(limit + 1)
    if len(value) > limit:
        raise ValueError("fixture grew beyond its bound")
    return value


def require_loopback(addresses):
    if not addresses or any(not ipaddress.ip_address(value).is_loopback for value in addresses):
        raise ValueError("every LDAP fixture DNS result must be loopback; no host or router changes are made")


def check_dns():
    # Name resolution can block in OS code. Bound the exact child, not a thread.
    code = ("import json,socket;print(json.dumps(sorted({x[4][0] for x in "
            "socket.getaddrinfo('ldap.localhost.direct',0,type=socket.SOCK_STREAM)})))")
    result = subprocess.run([sys.executable, "-c", code], capture_output=True,
                            check=True, timeout=8)
    if len(result.stdout) > 4096:
        raise ValueError("bounded DNS response required")
    addresses = json.loads(result.stdout)
    require_loopback(addresses)
    # The controlled peer listens on IPv4 only; do not rely on IPv6 fallback.
    if "127.0.0.1" not in addresses:
        raise ValueError("the controlled LDAP peer requires IPv4 loopback resolution")


class DownloadPolicy(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        parsed = urllib.parse.urlsplit(new_url)
        if parsed.scheme != "https" or parsed.hostname not in {"aka.re", "get.localhost.direct"}:
            raise ValueError("unexpected development-fixture redirect")
        return super().redirect_request(request, response, code, message, headers, new_url)


def download(url, digest, limit):
    opener = urllib.request.build_opener(DownloadPolicy())
    request = urllib.request.Request(url, headers={"User-Agent": "verysync-sidecar-ci-fixture/1.0"})
    with opener.open(request, timeout=20) as response:
        value = response.read(limit + 1)
    if len(value) > limit or hashlib.sha256(value).hexdigest() != digest:
        raise ValueError("pinned development fixture changed; review the publisher's current bundle explicitly")
    return value


def select_pair(bundle, password):
    from datetime import datetime, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    certificates, keys = [], []
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        entries = archive.infolist()
        if len(entries) > 16 or sum(entry.file_size for entry in entries) > 262144:
            raise ValueError("bounded development fixture archive required")
        for entry in entries:
            if entry.is_dir() or entry.file_size > 65536:
                raise ValueError("unexpected archive entry")
            content = archive.read(entry, pwd=password)
            if entry.filename.endswith(".crt"):
                certificates.append(x509.load_pem_x509_certificates(content))
            elif entry.filename.endswith(".key"):
                keys.append(serialization.load_pem_private_key(content, password=None))
            else:
                raise ValueError("unexpected development fixture format")
    public = lambda key: key.public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    now = datetime.now(timezone.utc)
    for chain in certificates:
        for leaf in chain:
            if leaf.fingerprint(hashes.SHA256()).hex() != LEAF_SHA256:
                continue
            if not leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc:
                raise ValueError("pinned LDAP development certificate expired or is not yet valid")
            names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            if "*.localhost.direct" not in names.get_values_for_type(x509.DNSName):
                raise ValueError("pinned LDAP development certificate hostname differs")
            for key in keys:
                if public(key.public_key()) == public(leaf.public_key()):
                    # The bundle contains leaf-only and chain-only files too.
                    # Assemble verified issuers across entries, not by filename.
                    ordered = [leaf]
                    pool = [item for group in certificates for item in group]
                    while ordered[-1].issuer != ordered[-1].subject:
                        candidates = [item for item in pool if item.subject == ordered[-1].issuer]
                        if not candidates:
                            break  # The platform must supply the root trust anchor.
                        issuer = candidates[0]
                        ordered[-1].verify_directly_issued_by(issuer)
                        if issuer in ordered or len(ordered) >= 6:
                            raise ValueError("unexpected development certificate chain")
                        if issuer.subject == issuer.issuer:
                            break
                        ordered.append(issuer)
                    if len(ordered) < 2:
                        raise ValueError("public CA intermediate chain is absent")
                    return (b"".join(item.public_bytes(serialization.Encoding.PEM) for item in ordered),
                            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()), leaf.not_valid_after_utc.isoformat())
    raise ValueError("pinned valid certificate and matching private key were not found")


def write_private(path, content):
    with Path(path).open("xb") as output:
        os.chmod(path, 0o600)
        output.write(content)


def load_manifest(path):
    path = Path(path)
    if not path.is_absolute() or path.name != "manifest.json" or path.parent.is_symlink():
        raise ValueError("explicit absolute private TLS manifest required")
    value = json.loads(read_bounded(path, 4096))
    expected = {"hostname": HOSTNAME, "certificate": "certificate-chain.pem",
                "private_key": "private-key.pem", "leaf_sha256": LEAF_SHA256,
                "bundle_sha256": BUNDLE_SHA256, "source": SOURCE}
    if any(value.get(key) != item for key, item in expected.items()):
        raise ValueError("private TLS fixture manifest identity differs")
    certificate = read_bounded(path.parent / expected["certificate"], 65536)
    private_key = read_bounded(path.parent / expected["private_key"], 16384)
    # Recheck the exact leaf, validity and key match on every peer launch.
    from datetime import datetime, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    leaf = x509.load_pem_x509_certificate(certificate)
    if leaf.fingerprint(hashes.SHA256()).hex() != LEAF_SHA256:
        raise ValueError("private TLS certificate identity differs")
    if not leaf.not_valid_before_utc <= datetime.now(timezone.utc) < leaf.not_valid_after_utc:
        raise ValueError("pinned TLS fixture is outside its validity interval")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(path.parent / expected["certificate"], path.parent / expected["private_key"])
    return value, certificate, private_key


def publisher_password(readme):
    section = re.search(r"(?ms)^### [^\n]*B\. Public CA Certificate[^\n]*\n(.*?)(?=^### |\Z)", readme)
    if section is None:
        raise ValueError("publisher's explicit public-CA section is absent")
    match = re.search(r"^Password:\s*(.+)$", section[1], re.MULTILINE)
    if match is None:
        raise ValueError("publisher's explicit development password is absent")
    return match[1].strip().strip("*`\"'").encode("utf-8")


def prepare(parent):
    print("private_ldap_tls_preparation_stage=dns", flush=True)
    check_dns()
    print("private_ldap_tls_preparation_stage=pinned_publisher_metadata", flush=True)
    readme = download(README_URL, README_SHA256, 32768).decode("utf-8")
    password = publisher_password(readme)
    print("private_ldap_tls_preparation_stage=pinned_certificate_bundle", flush=True)
    bundle = download(BUNDLE_URL, BUNDLE_SHA256, 1048576)
    certificate, private_key, expiry = select_pair(bundle, password)
    print("private_ldap_tls_preparation_stage=validated_certificate_and_key", flush=True)
    root = Path(tempfile.mkdtemp(prefix="vs-public-ldap-tls-", dir=Path(parent).resolve(strict=True)))
    os.chmod(root, 0o700)
    try:
        write_private(root / "certificate-chain.pem", certificate)
        write_private(root / "private-key.pem", private_key)
        manifest = {"hostname": HOSTNAME, "certificate": "certificate-chain.pem", "private_key": "private-key.pem",
                    "leaf_sha256": LEAF_SHA256, "bundle_sha256": BUNDLE_SHA256, "source": SOURCE,
                    "not_after": expiry, "scope": "synthetic loopback development only; never publish keys"}
        write_private(root / "manifest.json", (json.dumps(manifest) + "\n").encode())
        load_manifest(root / "manifest.json")
    except BaseException:
        for name in FILES:
            (root / name).unlink(missing_ok=True)
        root.rmdir()
        raise
    return root / "manifest.json"


def cleanup(manifest, parent):
    manifest = Path(manifest)
    root = manifest.parent
    if (not manifest.is_absolute() or manifest.name != "manifest.json" or root.is_symlink()
            or root.parent.resolve(strict=True) != Path(parent).resolve(strict=True)
            or not root.name.startswith("vs-public-ldap-tls-")):
        raise ValueError("cleanup is restricted to an exact prepared private fixture directory")
    load_manifest(manifest)
    if {item.name for item in root.iterdir()} != FILES:
        raise ValueError("unexpected private fixture content; refusing cleanup")
    for name in FILES:
        (root / name).unlink()
    root.rmdir()
