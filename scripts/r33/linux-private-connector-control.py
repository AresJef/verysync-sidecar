"""Verify an operator-owned Unix connector from a disposable private network."""

import argparse
import contextlib
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time


CAP = 4096
EXPECTED = b"CONNECT example.invalid:443 HTTP/1.1\r\n\r\n"
UNEXPECTED = b"CONNECT other.invalid:443 HTTP/1.1\r\n\r\n"
OK = b"HTTP/1.1 200 Connection Established\r\n\r\n"
DENIED = b"HTTP/1.1 403 Forbidden\r\n\r\n"
SAMPLE = b"synthetic circuit witness"


def read_header(sock):
    encoded = bytearray()
    while not encoded.endswith(b"\r\n\r\n"):
        data = sock.recv(1)
        if not data or len(encoded) >= CAP:
            raise ValueError("The synthetic header is incomplete or too long.")
        encoded.extend(data)
    return bytes(encoded)


def relay(left, right, cancelled):
    active = {left: right, right: left}
    stop = time.monotonic() + 10
    while active and not cancelled.is_set() and time.monotonic() < stop:
        readers, _, _ = select.select(list(active), [], [], 0.25)
        for stream in readers:
            other = active[stream]
            data = stream.recv(16 * 1024)
            if data:
                other.sendall(data)
            else:
                del active[stream]
                with contextlib.suppress(OSError):
                    other.shutdown(socket.SHUT_WR)


def read_sample(sock):
    data = bytearray()
    while len(data) < len(SAMPLE):
        chunk = sock.recv(len(SAMPLE) - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


class MockAuthority(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(4)
        if read_header(self.request) != EXPECTED:
            self.server.denied += 1
            self.request.sendall(DENIED)
            return
        self.server.allowed += 1
        self.request.sendall(OK)
        if read_sample(self.request) == SAMPLE:
            self.request.sendall(SAMPLE)


class InnerForwarder(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(4)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as operator:
            operator.settimeout(4)
            operator.connect(str(self.server.operator))
            relay(self.request, operator, self.server.cancelled)


def case(port, request, expected):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as channel:
        channel.sendall(request)
        if read_header(channel) != expected:
            raise ValueError("The restricted connector returned an unexpected synthetic response.")
        if expected == OK:
            channel.sendall(SAMPLE)
            if read_sample(channel) != SAMPLE:
                raise ValueError("The byte flow through the private connector did not match.")


def namespace():
    return os.stat("/proc/self/ns/net").st_ino


def enter_worker(port, uid, gid, host_namespace, operator):
    if os.geteuid() != 0 or int(uid) <= 0 or namespace() == int(host_namespace):
        raise ValueError("The connector needs a private network and an ordinary worker identity.")
    subprocess.run(["/usr/sbin/ip", "link", "set", "lo", "up"], check=True, timeout=4)
    os.setgroups([])
    os.setgid(int(gid))
    os.setuid(int(uid))
    with socketserver.ThreadingTCPServer(("127.0.0.1", int(port)), InnerForwarder) as listener:
        listener.daemon_threads = True
        listener.operator = Path(operator)
        listener.cancelled = threading.Event()
        server = threading.Thread(target=listener.serve_forever, kwargs={"poll_interval":0.1})
        server.start()
        try:
            if {name for _, name in socket.if_nameindex()} != {"lo"}:
                raise ValueError("The connector worker has more than its own loopback.")
            case(int(port), UNEXPECTED, DENIED)
            case(int(port), EXPECTED, OK)
            print(json.dumps({"private_namespace":namespace(), "uid":os.geteuid(),
                              "allowed_request_and_bytes":True, "unexpected_request_denied":True}),
                  flush=True)
            if sys.stdin.readline().strip() != "STOP":
                raise ValueError("The caller did not send the expected connector stop.")
        finally:
            listener.cancelled.set()
            listener.shutdown()
            server.join(timeout=3)


def outside_read(marker, broker):
    if os.geteuid() != 0:
        raise ValueError("Use the separate synthetic observer identity.")
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    denied = []
    try:
        marker.open("rb").close()
    except PermissionError:
        denied.append("file")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(1)
            channel.connect(str(broker))
    except PermissionError:
        denied.append("socket")
    print(json.dumps({"denied":denied, "uid":os.geteuid()}), flush=True)


def run():
    if sys.platform != "linux" or os.geteuid() == 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("Run this test only as the ordinary user of a disposable Actions runner.")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="r33-connector-", dir="/tmp") as path:
        root = Path(path)
        route = root / "authority.sock"
        marker = root / "synthetic-state"
        marker.write_bytes(SAMPLE)
        with socketserver.UnixStreamServer(str(route), MockAuthority) as authority, socket.socket() as reserved:
            authority.allowed = authority.denied = 0
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
            current = namespace()
            serve = threading.Thread(target=authority.serve_forever, kwargs={"poll_interval":0.1})
            serve.start()
            try:
                script = str(Path(__file__).resolve())
                readback = subprocess.check_output(
                    ["/usr/bin/sudo", "-n", "/usr/bin/python3", "-B", script, "--outside", str(marker), str(route)],
                    text=True, timeout=5,
                )
                actual_outside = json.loads(readback)
                if actual_outside != {"denied":["file","socket"],"uid":65534}:
                    raise ValueError("The ordinary outside reader reached operator-owned files or sockets.")
                args = ["/usr/bin/sudo", "-n", "/usr/bin/unshare", "--net", "/usr/bin/python3", "-B",
                        script, "--worker", str(port), str(os.getuid()), str(os.getgid()), str(current), str(route)]
                child = subprocess.run(args, input="STOP\n", capture_output=True, text=True, timeout=22)
                if child.returncode:
                    print(child.stderr, file=sys.stderr)
                    raise ValueError("The private synthetic connector did not stop normally.")
                observed = json.loads(child.stdout)
                if (observed["private_namespace"] == current or observed["uid"] != os.getuid()
                        or authority.allowed != 1 or authority.denied != 1):
                    raise ValueError("The protected connector receipt is incomplete.")
            finally:
                authority.shutdown()
                serve.join(timeout=3)
        route.unlink()
        assert marker.read_bytes() == SAMPLE
        receipt = {"inside":observed, "outside":actual_outside, "allowed_mock_authorities":1,
                   "refused_mock_authorities":1, "native_credentials_used":False,
                   "external_contacts":0, "closed_unix_connector":not route.exists()}
    receipt["temporary_directory_removed"] = not root.exists()
    print("R33_PRIVATE_CONNECTOR " + json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", nargs=5)
    parser.add_argument("--outside", nargs=2, type=Path)
    options = parser.parse_args()
    if options.worker:
        enter_worker(*options.worker)
    elif options.outside:
        outside_read(*options.outside)
    else:
        run()
