#!/usr/bin/env python3
"""Explicit test-only TLS origin and authenticated loopback proxies.

Every forward target is one exact supplied owned backend or this process's TLS
origin. This fixture never resolves or forwards arbitrary destinations.
"""
import base64
import datetime
import hmac
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import ssl
import sys
import sysconfig
import threading
import time
import urllib.parse

config = json.loads(sys.stdin.buffer.readline(32769))
root = Path(config["root"])
backend = config["backend_port"]
if not root.is_dir() or not isinstance(backend, int) or not 0 < backend <= 65535 or backend == 18886:
    raise ValueError("explicit owned backend and private directory required")
startup_started = time.monotonic()


def startup_phase(phase):
    temporary = root / ".management-startup.tmp"
    with temporary.open("x", encoding="utf-8") as output:
        os.chmod(temporary, 0o600)
        json.dump({"phase": phase, "elapsed_millis": int((time.monotonic() - startup_started) * 1000)}, output)
    os.replace(temporary, root / "management-startup.json")


startup_phase("loading_crypto")
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

startup_phase("creating_certificates")
observations = root / "management-observations.jsonl"
observations.touch(exist_ok=False)
lock = threading.Lock()


def record(**fields):
    with lock:
        with observations.open("a", encoding="utf-8") as output:
            output.write(json.dumps(fields) + "\n")


now = datetime.datetime.now(datetime.timezone.utc)
ca_key = ec.generate_private_key(ec.SECP256R1())
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Isolated management test CA")])
ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
      .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
      .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=2))
      .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
      .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                  key_encipherment=False, data_encipherment=False,
                                  key_agreement=False, key_cert_sign=True, crl_sign=True,
                                  encipher_only=None, decipher_only=None), critical=True)
      .sign(ca_key, hashes.SHA256()))
leaf_key = ec.generate_private_key(ec.SECP256R1())
leaf = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name).public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256()))
# A separate native-core certificate keeps the origin's localhost-only
# certificate available for the wrong-hostname test above.
native_leaf = (x509.CertificateBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "isolated-native-management")]))
    .issuer_name(ca_name).public_key(leaf_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=2))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    .sign(ca_key, hashes.SHA256()))
for name, data in [
    ("native-server.pem", native_leaf.public_bytes(serialization.Encoding.PEM)),
    ("ca.pem", ca.public_bytes(serialization.Encoding.PEM)),
    ("ca.der", ca.public_bytes(serialization.Encoding.DER)),
    ("server.pem", leaf.public_bytes(serialization.Encoding.PEM)),
    ("server.key", leaf_key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())),
]:
    path = root / name
    with path.open("xb") as output:
        output.write(data)
    os.chmod(path, 0o600)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(root / "server.pem", root / "server.key")
startup_phase("certificates_ready")
expected_auth = "Basic " + base64.b64encode(
    (config["username"] + ":" + config["password"]).encode()).decode()
HOP = {"connection", "proxy-connection", "proxy-authorization", "transfer-encoding",
       "keep-alive", "te", "trailer", "upgrade", "host", "content-length"}


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def server_bind(self):
        # HTTPServer otherwise performs getfqdn() even for this literal loopback
        # address. No hostname lookup is needed for the private fixed-name peer.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.server_address[1]

    def get_request(self):
        stream, address = super().get_request()
        stream.settimeout(8)
        if self.secure:
            try:
                stream = context.wrap_socket(stream, server_side=True)
            except ssl.SSLError:
                record(role=self.role, operation="tls_rejected")
                stream.close()
                raise
        return stream, address

    def handle_error(self, request, client_address):
        record(role=self.role, operation="handler_error")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reject(self, status):
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def authenticated(self):
        matched = hmac.compare_digest(self.headers.get("Proxy-Authorization", ""), expected_auth)
        record(role=self.server.role, operation="proxy_auth", matched=matched)
        if not matched:
            self.reject(407)
        return matched

    def forward(self, path):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 <= size <= 1024 * 1024:
            return self.reject(413)
        body = self.rfile.read(size) if size else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        headers["Connection"] = "close"
        record(role=self.server.role, operation="http_forward", method=self.command,
               received_proxy_authorization="Proxy-Authorization" in self.headers,
               forwarded_proxy_authorization=any(k.lower() == "proxy-authorization" for k in headers),
               target_authorization=any(k.lower() == "authorization" for k in headers),
               target_api_key=any(k.lower() == "x-api-key" for k in headers))
        upstream = http.client.HTTPConnection("127.0.0.1", backend, timeout=8)
        try:
            upstream.request(self.command, path, body, headers)
            response = upstream.getresponse()
            data = response.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                return self.reject(502)
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in HOP:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True
        finally:
            upstream.close()

    def dispatch(self):
        if self.server.role == "origin":
            if self.path.startswith("/redirect/"):
                record(role=self.server.role, operation="redirect")
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{backend}/rest/system/version")
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                return
            if not self.path.startswith("/") or self.path.startswith("//"):
                return self.reject(400)
            return self.forward(self.path)
        if not self.authenticated():
            return
        target = urllib.parse.urlsplit(self.path)
        if (target.scheme != "http" or target.hostname not in {"localhost", "127.0.0.1"}
                or target.port != backend or target.username or target.password or target.fragment):
            return self.reject(403)
        self.forward(urllib.parse.urlunsplit(("", "", target.path or "/", target.query, "")))

    do_GET = dispatch
    do_POST = dispatch
    do_PATCH = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch

    def do_CONNECT(self):
        if self.server.role == "origin" or not self.authenticated():
            return
        target = urllib.parse.urlsplit("//" + self.path)
        if (target.hostname not in {"localhost", "127.0.0.1"} or target.port != origin.server_port
                or target.username or target.password or target.query or target.fragment or target.path):
            return self.reject(403)
        with socket.create_connection(("127.0.0.1", origin.server_port), timeout=8) as upstream:
            self.send_response(200)
            self.end_headers()
            self.wfile.flush()
            forwarded = 0
            for _ in range(256):
                immediate = [s for s in [self.connection, upstream]
                             if isinstance(s, ssl.SSLSocket) and s.pending()]
                readable = immediate or select.select([self.connection, upstream], [], [], 8)[0]
                if not readable:
                    break
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        record(role=self.server.role, operation="connect_complete", bytes=forwarded)
                        self.close_connection = True
                        return
                    (upstream if source is self.connection else self.connection).sendall(data)
                    forwarded += len(data)
            record(role=self.server.role, operation="connect_bounded_end", bytes=forwarded)
        self.close_connection = True


def start(role, secure):
    startup_phase("binding_" + role)
    server = Server(("127.0.0.1", 0), Handler)
    if server.server_port == 18886:
        raise ValueError("shared default port prohibited")
    server.role, server.secure = role, secure
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


origin = start("origin", True)
proxy = start("http_proxy", False)
tls_proxy = start("https_proxy", True)
startup_phase("ready")
print(json.dumps({"ready": True, "loopback_only": True, "origin_port": origin.server_port,
                  "proxy_port": proxy.server_port, "tls_proxy_port": tls_proxy.server_port,
                  "python_platform": sysconfig.get_platform()}), flush=True)
threading.Event().wait()
