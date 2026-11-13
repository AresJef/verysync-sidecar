#!/usr/bin/env python3
"""Bounded test-only Global Discovery v3 service on private loopback HTTPS.

Protocol candidate: https://docs.syncthing.net/specs/globaldisco-v3.html
Actual VerySync interoperability is established by the native Rust caller.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import sys
import threading
import time
from socketserver import TCPServer
from urllib.parse import parse_qs, urlsplit

STARTED = time.monotonic()
STAGE = "python-startup"
OUTPUT = None


def stage(phase, error=None):
    global STAGE
    STAGE = phase
    if OUTPUT is None:
        return
    value = {"phase": phase, "elapsed_ms": int((time.monotonic() - STARTED) * 1000)}
    if error is not None:
        value["exception_type"] = type(error).__name__
        value["errno"] = getattr(error, "errno", None)
        value["ssl_reason"] = getattr(error, "reason", None)
    scratch = OUTPUT / "stage.tmp"
    scratch.write_text(json.dumps(value))
    scratch.replace(OUTPUT / "stage.json")


class LoopbackDiscoveryServer(ThreadingHTTPServer):
    def server_bind(self):
        if self.server_address[0] != "127.0.0.1":
            raise ValueError("private discovery must bind loopback")
        # HTTPServer.server_bind calls getfqdn even for literal loopback.
        # This fixture needs no reverse DNS or external name-service dependency.
        TCPServer.server_bind(self)
        self.server_name = "private-loopback"
        self.server_port = self.server_address[1]


def main():
    global OUTPUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-state", required=True, type=Path)
    parser.add_argument("--client-state", required=True, type=Path)
    parser.add_argument("--device", required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    OUTPUT = args.output
    stage("arguments-validated")
    selected = urlsplit(args.address)
    if selected.scheme != "tcp" or selected.hostname != "127.0.0.1" or selected.port in (None, 0, 18886):
        raise ValueError("only an explicit private receiver is admissible")
    observations = {"lookups": 0, "announcements": 0, "client_certificate_verified": 0,
                    "unexpected_requests": 0, "pin_parameter_not_transmitted": True,
                    "tls_errors": 0, "tls_error_reasons": []}
    guard = threading.Lock()
    expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert((args.client_state / "cert.pem").read_text())).digest()

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def log_message(self, *_):
            pass

        def reply(self, status, body=b""):
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.send_header("Reannounce-After", "60")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            query = parse_qs(urlsplit(self.path).query)
            valid = query.get("device") == [args.device]
            with guard:
                observations["pin_parameter_not_transmitted"] &= "id" not in query
                observations["lookups" if valid else "unexpected_requests"] += 1
            self.reply(200, json.dumps({"addresses": [args.address]}).encode()) if valid else self.reply(404)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 65536:
                self.reply(400)
                return
            value = json.loads(self.rfile.read(length) or b"{}")
            certificate = self.connection.getpeercert(binary_form=True)
            valid = certificate and hashlib.sha256(certificate).digest() == expected
            with guard:
                observations["announcements"] += 1
                observations["client_certificate_verified"] += int(bool(valid))
            self.reply(204 if valid and isinstance(value, dict) else 403)

    class Server(LoopbackDiscoveryServer):
        daemon_threads = True
        allow_reuse_address = False

        def get_request(self):
            try:
                return super().get_request()
            except ssl.SSLError as error:
                with guard:
                    observations["tls_errors"] += 1
                    if len(observations["tls_error_reasons"]) < 8:
                        observations["tls_error_reasons"].append(error.reason)
                raise

        def handle_error(self, *_):
            with guard:
                observations["unexpected_requests"] += 1

    stage("create-tls-context")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    stage("load-server-certificate")
    context.load_cert_chain(args.server_state / "cert.pem", args.server_state / "key.pem")
    stage("load-client-root")
    context.load_verify_locations(cafile=args.client_state / "cert.pem")
    context.verify_mode = ssl.CERT_OPTIONAL
    context.set_alpn_protocols(["http/1.1"])
    stage("create-loopback-server")
    with Server(("127.0.0.1", 0), Handler) as server:
        stage("wrap-listener-tls")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.socket.settimeout(3)
        if server.server_address[1] == 18886:
            raise RuntimeError("shared endpoint is forbidden")
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1})
        thread.start()
        stage("ready")
        ready = args.output / "ready.json"
        scratch = args.output / "ready.tmp"
        scratch.write_text(json.dumps({"loopback_https_port": server.server_address[1]}))
        scratch.replace(ready)
        sys.stdin.buffer.readline(16)
        server.shutdown()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("private discovery server did not stop")
    scratch = args.output / "result.tmp"
    scratch.write_text(json.dumps(observations, sort_keys=True))
    scratch.replace(args.output / "result.json")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        stage(STAGE, error)
        raise SystemExit(1) from None
