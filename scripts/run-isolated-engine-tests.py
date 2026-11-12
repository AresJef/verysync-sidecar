#!/usr/bin/env python3
"""Run explicit engine tests with a bounded, nonforwarding private HTTP proxy."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import socketserver
import subprocess
import sys
import threading
from urllib.parse import urlsplit


class BlockedProxy(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self):
        super().__init__(("127.0.0.1", 0), BlockRequest)
        self.observed = {}
        self.errors = 0
        self.guard = threading.Lock()

    def handle_error(self, request, client_address):
        # No request headers, targets, environment or credential-bearing trace.
        with self.guard:
            self.errors += 1


class BlockRequest(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(1)
        first = self.rfile.readline(8193)
        if len(first) > 8192:
            return
        parts = first.decode("ascii", errors="replace").split()
        if len(parts) < 2:
            return
        method = parts[0] if parts[0] in {"CONNECT", "GET", "POST", "HEAD", "PUT", "DELETE"} else "other"
        try:
            host = urlsplit("//" + parts[1] if method == "CONNECT" else parts[1]).hostname
        except ValueError:
            host = None
        # Retain only a hostname and method, never credentials, queries or headers.
        key = (method, host if host and len(host) <= 253 else "unparsed")
        with self.server.guard:
            if key not in self.server.observed and len(self.server.observed) >= 63:
                key = ("other", "overflow")
            self.server.observed[key] = self.server.observed.get(key, 0) + 1
        self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--cargo", default=shutil.which("cargo"))
    parser.add_argument("--evidence-dir", required=True, type=Path)
    suite = parser.add_mutually_exclusive_group(required=True)
    suite.add_argument("--test-target", choices=["managed_lifetime", "managed_instance", "engine_control", "example_control", "events"])
    suite.add_argument("--mechanism", choices=["macos", "linux", "windows"])
    parser.add_argument("--test-filter")
    args = parser.parse_args()
    if args.test_target == "managed_lifetime" and sys.platform not in {"darwin", "linux", "win32"}:
        raise RuntimeError("owned-host acceptance requires native macOS, Linux or Windows")
    if args.mechanism and {"macos": "darwin", "linux": "linux", "windows": "win32"}[args.mechanism] != sys.platform:
        raise RuntimeError("mechanism investigation requires its actual native platform")
    if args.test_filter and not args.test_target:
        raise ValueError("a test filter requires an explicit Cargo test target")
    if not args.cargo or not Path(args.cargo).is_absolute():
        raise ValueError("an explicit resolved Cargo executable is required")
    binary = os.environ.get("VERYSYNC_TEST_BINARY")
    if not binary or not Path(binary).is_absolute():
        raise ValueError("an explicit private engine executable is required")
    if len(os.environ.get("VERYSYNC_TEST_BINARY_SHA256", "")) != 64:
        raise ValueError("the fixed executable SHA-256 is required")
    if not args.evidence_dir.is_absolute():
        raise ValueError("an absolute private evidence directory is required")
    args.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    with BlockedProxy() as proxy:
        server = threading.Thread(target=proxy.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        server.start()
        env = os.environ.copy()
        address = f"http://127.0.0.1:{proxy.server_address[1]}"
        proxy_names = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]
        bypass_names = ["NO_PROXY"]
        if os.name != "nt":
            proxy_names += [name.lower() for name in proxy_names]
            bypass_names += ["no_proxy"]
        for name in proxy_names:
            env[name] = address
        for name in bypass_names:
            env[name] = "127.0.0.1,localhost,::1"
        env["CARGO_NET_OFFLINE"] = "true"
        label = args.test_target or "mechanism-" + args.mechanism
        log_path = args.evidence_dir / (label.replace("_", "-") + ".log")
        try:
            if args.test_target:
                command = [args.cargo, f"+{args.toolchain}", "test", "--features", "engine-tests",
                           "--test", args.test_target, "--offline", "--locked"]
                if args.test_filter:
                    command += [args.test_filter]
                command += ["--", "--test-threads=1", "--nocapture"]
            else:
                command = [sys.executable, str(Path(__file__).with_name(f"run-{args.mechanism}-lifetime-probes.py")),
                           "--toolchain", args.toolchain, "--evidence-dir", str(args.evidence_dir / "mechanism")]
            with log_path.open("w", encoding="utf-8") as log:
                with subprocess.Popen(command, cwd=Path(__file__).resolve().parents[1],
                                      env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      text=True, encoding="utf-8", errors="replace") as process:
                    for line in process.stdout:
                        log.write(line)
                        log.flush()
                        print(line, end="", flush=True)
                    returncode = process.wait()
        finally:
            proxy.shutdown()
            server.join(timeout=5)
        with proxy.guard:
            observed = [{"method": method, "hostname": host, "count": count}
                        for (method, host), count in sorted(proxy.observed.items())]
            errors = proxy.errors
        report = {"scope": "test-only HTTP proxy observations; not an OS-wide no-egress proof",
                  "loopback_only": True, "forwarding_implemented": False,
                  "requests_blocked": observed, "handler_errors": errors,
                  "test_exit_code": returncode}
        (args.evidence_dir / "proxy-observations.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("Isolated engine HTTP proxy observations: " + json.dumps(report, sort_keys=True))
        return returncode


if __name__ == "__main__":
    raise SystemExit(main())
