"""Check a private loopback boundary on a disposable GitHub Linux runner."""

import argparse
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import subprocess
import sys
import threading


def net_namespace():
    return os.stat("/proc/self/ns/net").st_ino


def request(port):
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=1.5)
    try:
        client.request("GET", "/fixture")
        reply = client.getresponse()
        return reply.status, reply.read(128)
    finally:
        client.close()


def worker(port, uid, gid, host_namespace):
    if os.geteuid() != 0 or uid == 0 or net_namespace() == host_namespace:
        raise ValueError("Start this worker only in the disposable private network.")
    subprocess.run(["/usr/sbin/ip", "link", "set", "lo", "up"], check=True, timeout=4)
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise ValueError("The worker has interfaces beyond its private loopback.")
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    token = secrets.token_hex(12).encode("ascii")

    class Fixture(BaseHTTPRequestHandler):
        def do_GET(self):
            result = 200 if self.path == "/fixture" else 404
            payload = token if result == 200 else b""
            self.send_response(result)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format, *_args):
            pass

    with HTTPServer(("127.0.0.1", port), Fixture) as server:
        server.timeout = 2
        listener = threading.Thread(target=server.handle_request)
        listener.start()
        reply = request(port)
        listener.join(timeout=3)
        if listener.is_alive() or reply != (200, token):
            raise ValueError("The worker did not receive its own synthetic response.")
        print(json.dumps({"http": 200, "exact_payload": True, "pid": os.getpid(),
                          "namespace": net_namespace(), "ordinary_uid": os.geteuid(),
                          "interfaces": ["lo"]}), flush=True)
        if sys.stdin.readline().strip() != "STOP":
            raise ValueError("The caller did not send the expected fixture stop.")


def controller():
    if os.geteuid() == 0 or sys.platform != "linux" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("Use the ordinary user of a disposable standard Actions Linux runner.")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
        occupied.bind(("127.0.0.1", 0))
        port = occupied.getsockname()[1]
        before = net_namespace()
        args = [
            "/usr/bin/sudo", "-n", "/usr/bin/unshare", "--net", "/usr/bin/python3", "-B",
            str(Path(__file__).resolve()), "--worker", str(port), str(os.getuid()), str(os.getgid()),
            str(before),
        ]
        child = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 text=True, start_new_session=True)
        proof = {}
        forced = False
        try:
            ready, _, _ = select.select([child.stdout], [], [], 15)
            if not ready:
                raise TimeoutError("No private fixture readiness receipt.")
            proof = json.loads(child.stdout.readline())
            if (proof["namespace"] == before or proof["ordinary_uid"] != os.getuid()
                    or proof["http"] != 200 or proof["exact_payload"] is not True
                    or child.poll() is not None):
                raise ValueError("The independent private-network positive control did not verify.")
            try:
                request(port)
            except ConnectionRefusedError:
                proof["outside_same_uid_refused"] = True
            else:
                raise ValueError("The ordinary outside user reached the private fixture.")
            child.stdin.write("STOP\n")
            child.stdin.flush()
            child.communicate(timeout=8)
        finally:
            if child.poll() is None:
                forced = True
                subprocess.run(["/usr/bin/sudo", "-n", "/bin/kill", "-TERM", "--", f"-{child.pid}"],
                               timeout=5, check=False)
                child.wait(timeout=5)
        if forced or child.returncode != 0 or Path(f"/proc/{proof['pid']}").exists():
            raise ValueError("Normal owned fixture exit was not confirmed.")
        proof.update({"outside_namespace": before, "normal_owned_exit": True,
                      "host_port_reserved_but_never_listening": True,
                      "external_connections": 0, "kind": "synthetic-network-boundary"})
        print("R33_PRIVATE_LOOPBACK " + json.dumps(proof, sort_keys=True), flush=True)


if __name__ == "__main__":
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--worker", nargs=4, type=int)
    args = command.parse_args()
    if args.worker is None:
        controller()
    else:
        worker(*args.worker)
