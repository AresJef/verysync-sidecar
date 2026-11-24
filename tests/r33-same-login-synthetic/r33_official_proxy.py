"""Keep the isolated account core's web traffic on the fixed official TLS service."""

import json
from pathlib import Path
import select
import socket
import socketserver
import ssl
import threading
import time


OFFICIAL_HOST = "my.verysync.com"
OFFICIAL_PORT = 443
CONNECT = f"{OFFICIAL_HOST}:{OFFICIAL_PORT}".encode("ascii")
DENIED = b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
MAX_TUNNELS = 16


class OfficialHandler(socketserver.StreamRequestHandler):
    rbufsize = 0

    def handle(self):
        self.request.settimeout(6)
        try:
            self.verified_tunnel()
        except (OSError, ValueError):
            self.server.count("failed")

    def verified_tunnel(self):
        first = self.rfile.readline(4097)
        if not first:
            return
        request = first.split()
        if (len(first) > 4096 or len(request) != 3 or request[:2] != [b"CONNECT", CONNECT]
                or request[2] not in (b"HTTP/1.0", b"HTTP/1.1")):
            self.server.count("unexpected_target")
            self.wfile.write(DENIED)
            return
        if not self.server.permit():
            self.wfile.write(DENIED)
            return

        for _ in range(24):
            header = self.rfile.readline(4097)
            if header == b"\r\n":
                break
            if not header or len(header) > 4096:
                raise ValueError("Unexpected header.")
        else:
            raise ValueError("Too many headers.")

        # Check the public service's certificate and DNS name independently,
        # then leave the engine's actual account protocol encrypted end to end.
        context = ssl.create_default_context()
        with socket.create_connection((OFFICIAL_HOST, OFFICIAL_PORT), timeout=6) as check:
            with context.wrap_socket(check, server_hostname=OFFICIAL_HOST) as tls:
                family, peer = tls.family, tls.getpeername()
        self.server.count("verified_public_tls")

        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        prefix = bytearray()
        while len(prefix) < 5:
            chunk = self.request.recv(5-len(prefix))
            if not chunk:
                return
            prefix.extend(chunk)
        if not prefix.startswith(b"\x16\x03"):
            raise ValueError("The private core did not start TLS.")
        with socket.socket(family, socket.SOCK_STREAM) as upstream:
            upstream.settimeout(6)
            upstream.connect(peer)
            upstream.sendall(prefix)
            self.copy_tls(upstream)

    def copy_tls(self, upstream):
        channels = (self.request, upstream)
        deadline = time.monotonic()+75
        while self.server.running():
            timeout = min(.4, deadline-time.monotonic())
            if timeout <= 0:
                break
            readable, _, _ = select.select(channels, [], [], timeout)
            for source in readable:
                chunk = source.recv(16384)
                if not chunk:
                    return
                target = upstream if source is self.request else self.request
                target.sendall(chunk)


class OfficialProxy(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self):
        super().__init__(("127.0.0.1", 0), OfficialHandler)
        self.lock = threading.Lock()
        self.active = False
        self.open = True
        self.stats = dict.fromkeys(("permitted","blocked","verified_public_tls","unexpected_target","failed"),0)
        self._thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval":.1}, daemon=True)
        self._thread.start()

    def count(self, event):
        with self.lock:
            self.stats[event] += 1

    def permit(self):
        with self.lock:
            accepted = self.active and self.open and self.stats["permitted"]<MAX_TUNNELS
            self.stats["permitted" if accepted else "blocked"] += 1
            return accepted

    def running(self):
        with self.lock:
            return self.open

    def activate(self):
        with self.lock:
            self.active = True

    def receipt(self):
        with self.lock:
            return self.stats.copy()

    def close(self):
        with self.lock:
            self.open = False
        self.shutdown()
        self.server_close()
        self._thread.join(timeout=1)


def native_sandbox(directory, private_state, proxy_port, recovery=False):
    """Apply the project-tested Mac network and filesystem boundary."""
    path = directory / "engine.sb"
    write_roots = (
        f"(subpath {json.dumps(str(private_state))}) "
        f"(subpath {json.dumps(str(directory))}) "
        '(literal "/dev/null") (literal "/dev/ptmx") '
        '(regex #"^/dev/ttys[0-9]+$")'
    )
    # Recovery may restart the same licensed identity to disarm jobs and sign out.
    # A persisted schedule cannot write either of its owned fixture trees then.
    readonly = (
        f"(deny file-write* (subpath {json.dumps(str(private_state / 'local-sync-cases'))}))\n"
        if recovery else ""
    )
    path.write_text(
        "(version 1)\n"
        "(allow default)\n"
        "(deny network-outbound (remote ip))\n"
        f'(allow network-outbound (remote tcp "localhost:{proxy_port}"))\n'
        "(deny network-inbound (local ip))\n"
        "(deny network-bind (local ip))\n"
        f"(deny file-write* (require-not (require-any {write_roots})))\n" + readonly,
        encoding="utf-8",
    )
    return path
