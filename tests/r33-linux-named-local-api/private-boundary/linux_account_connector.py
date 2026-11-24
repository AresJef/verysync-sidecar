"""Carry only the private native account proxy to an operator-owned Unix socket."""

from contextlib import suppress
from pathlib import Path
import os
import select
import socket
import socketserver
import stat
import struct
import threading
import time

from r33_official_proxy import OfficialProxy
from r33_protocol import peer_uid


class UnixOfficialProxy(OfficialProxy):
    """Apply the existing official-host and TLS checks on a local Unix socket."""

    address_family = socket.AF_UNIX

    def __init__(self, endpoint: Path, peer_allowed=None):
        self.endpoint = endpoint
        self.peer_allowed = peer_allowed
        super().__init__(str(endpoint))

    def verify_request(self, request, client_address):
        if self.peer_allowed is None:
            return True
        return self.peer_allowed(request)

    def close(self):
        super().close()
        self.endpoint.unlink(missing_ok=True)


def namespace_peer_allowed(stream, scope_inode, runtime_uid):
    """Admit the registered Linux runtime identity in its exact network scope."""
    fields = struct.Struct("=iII")
    try:
        raw = stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, fields.size)
        pid, uid, _ = fields.unpack(raw)
        if pid <= 0 or uid != runtime_uid:
            return False
        return os.stat(f"/proc/{pid}/ns/net").st_ino == scope_inode
    except (OSError, AttributeError, struct.error):
        return False


def relay(request, upstream, cancelled):
    streams = {request: upstream, upstream: request}
    end = time.monotonic() + 78
    while streams and not cancelled.is_set():
        left = end - time.monotonic()
        if left <= 0:
            break
        readers, _, _ = select.select(list(streams), [], [], min(0.20, left))
        for stream in readers:
            target = streams[stream]
            payload = stream.recv(16384)
            if payload:
                target.sendall(payload)
            else:
                del streams[stream]
                with suppress(OSError):
                    target.shutdown(socket.SHUT_WR)


class ConnectorRequest(socketserver.BaseRequestHandler):
    def handle(self):
        route = self.server
        if route.cancelled.is_set():
            return
        try:
            self.request.settimeout(5)
            route.verify_socket()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as authority:
                authority.settimeout(5)
                authority.connect(str(route.operator))
                if peer_uid(authority) != route.operator_uid:
                    raise PermissionError("The account route belongs to another operator.")
                route.verify_socket()
                if not route.cancelled.is_set():
                    relay(self.request, authority, route.cancelled)
        except (OSError, ValueError):
            # A transport failure leaves the native request unconfirmed.
            return


class NativeAccountConnector(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, operator: Path, operator_uid: int):
        self.operator = operator
        self.operator_uid = operator_uid
        self.cancelled = threading.Event()
        self.identity = self.socket_identity()
        super().__init__(("127.0.0.1", 0), ConnectorRequest)
        if self.server_address[1] == 18886:
            self.server_close()
            raise ValueError("The existing default port is outside the fixture.")
        self.thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": .1},
                                       daemon=True)
        self.thread.start()

    def socket_identity(self):
        detail = self.operator.lstat()
        if (not self.operator.is_absolute() or not stat.S_ISSOCK(detail.st_mode)
                or detail.st_uid != self.operator_uid or detail.st_mode & 0o007):
            raise PermissionError("The operator's account socket is unavailable.")
        return detail.st_dev, detail.st_ino

    def verify_socket(self):
        if self.socket_identity() != self.identity:
            raise PermissionError("The operator's account socket changed.")

    def close(self):
        self.cancelled.set()
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=2)
