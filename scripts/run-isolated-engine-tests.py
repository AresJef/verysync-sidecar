#!/usr/bin/env python3
"""Run engine tests with blocked HTTP egress and optional private discovery routing."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

DISCOVERY_HOSTS = frozenset({
    "discovery.verysync.cn", "discovery-v4.verysync.cn",
    "discovery-v4-1.verysync.cn", "discovery-v4-2.verysync.cn",
    "discovery-v4-3.verysync.cn", "discovery-v6.verysync.cn",
    "discovery-v6-1.verysync.cn",
})


class BlockedProxy(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, discovery_file=None, discovery_token=None, upgrade_metadata=False,
                 upgrade_archive=None):
        super().__init__(("127.0.0.1", 0), BlockRequest)
        self.observed = {}
        self.errors = 0
        self.discovery_file = discovery_file
        self.discovery_token = discovery_token
        self.forwarded = 0
        self.upgrade_metadata = upgrade_metadata
        self.upgrade_connections = 0
        self.upgrade_archive = upgrade_archive
        self.upgrade_archives_served = 0
        self.guard = threading.Lock()

    def private_discovery_port(self, method, target):
        if method != "CONNECT" or not self.discovery_file or not self.discovery_token:
            return None
        try:
            parsed = urlsplit("//" + target)
            if (parsed.hostname not in DISCOVERY_HOSTS or parsed.port != 443
                    or parsed.username or parsed.password or parsed.path
                    or parsed.query or parsed.fragment):
                return None
            with self.discovery_file.open("rb") as source:
                data = source.read(4097)
            if len(data) > 4096:
                return None
            record = json.loads(data)
            port = record.get("port")
            if (not secrets.compare_digest(str(record.get("token", "")), self.discovery_token)
                    or type(port) is not int or not 1 <= port <= 65535 or port == 18886):
                return None
            return port
        except (OSError, ValueError, TypeError, AttributeError):
            return None

    def upgrade_metadata_target(self, method, target):
        if not self.upgrade_metadata or method != "CONNECT":
            return None
        try:
            parsed = urlsplit("//" + target)
            if (parsed.hostname == "upgrades.verysync.cn" and parsed.port == 443
                    and not parsed.username and not parsed.password and not parsed.path
                    and not parsed.query and not parsed.fragment):
                return ("upgrades.verysync.cn", 443)
        except ValueError:
            pass
        return None

    def pinned_archive(self, method, target):
        if not self.upgrade_archive or method != "GET":
            return None
        try:
            parsed = urlsplit(target)
            archive, package = self.upgrade_archive
            if (parsed.scheme == "http" and parsed.hostname in {"dl.verysync.com", "dl-cn.verysync.com"}
                    and parsed.port in {None, 80} and not parsed.username and not parsed.password
                    and parsed.path == "/releases/v2.33.2/" + package["filename"]
                    and not parsed.query and not parsed.fragment):
                return archive, package
        except ValueError:
            pass
        return None

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
        port = self.server.private_discovery_port(method, parts[1])
        official = self.server.upgrade_metadata_target(method, parts[1])
        pinned = self.server.pinned_archive(method, parts[1])
        if pinned is not None:
            remaining = 16384
            while remaining > 0:
                header = self.rfile.readline(min(remaining + 1, 8193))
                remaining -= len(header)
                if header == b"\r\n":
                    break
                if not header or len(header) > 8192:
                    return
            else:
                return
            archive, package = pinned
            try:
                self.wfile.write(("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                                  "Content-Length: " + str(package["bytes"]) +
                                  "\r\nConnection: close\r\n\r\n").encode("ascii"))
                count = 0
                digest = hashlib.sha256()
                with archive.open("rb") as source:
                    while chunk := source.read(65536):
                        count += len(chunk)
                        if count > package["bytes"]:
                            raise ValueError("pinned test archive changed")
                        digest.update(chunk)
                        self.wfile.write(chunk)
                self.wfile.flush()
                if count != package["bytes"] or digest.hexdigest() != package["sha256"]:
                    raise ValueError("pinned test archive changed")
                with self.server.guard:
                    self.server.upgrade_archives_served += 1
            except (OSError, ValueError):
                return
            return
        if port is not None or official is not None:
            # Consume bounded CONNECT headers before switching to raw TLS bytes.
            remaining = 16384
            while remaining > 0:
                header = self.rfile.readline(min(remaining + 1, 8193))
                remaining -= len(header)
                if header == b"\r\n":
                    break
                if not header or len(header) > 8192:
                    return
            else:
                return
            # Discovery is routed only to its owned fixture. Upgrade metadata
            # is an explicit exception to one genuine TLS host; TLS stays end to
            # end and every other external host remains blocked.
            try:
                target = official or ("127.0.0.1", port)
                with socket.create_connection(target, timeout=10 if official else 2) as upstream:
                    self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    self.wfile.flush()
                    with self.server.guard:
                        if official:
                            self.server.upgrade_connections += 1
                        else:
                            self.server.forwarded += 1
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        readable, _, _ = select.select([self.request, upstream], [], [], 0.2)
                        for source in readable:
                            data = source.recv(65536)
                            if not data:
                                return
                            (upstream if source is self.request else self.request).sendall(data)
                return
            except (OSError, ValueError):
                return
        # Retain only a hostname and method, never credentials, queries or headers.
        key = (method, host if host and len(host) <= 253 else "unparsed")
        with self.server.guard:
            if key not in self.server.observed and len(self.server.observed) >= 63:
                key = ("other", "overflow")
            self.server.observed[key] = self.server.observed.get(key, 0) + 1
        self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")


def main():
    # Cargo/native diagnostics are decoded as UTF-8 below. Windows redirected
    # console defaults can be a legacy code page; preserve Unicode diagnostics
    # instead of raising while forwarding an otherwise valid test output line.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--cargo", default=shutil.which("cargo"))
    parser.add_argument("--evidence-dir", required=True, type=Path)
    suite = parser.add_mutually_exclusive_group(required=True)
    suite.add_argument("--test-target", choices=["managed_lifetime", "managed_instance", "engine_control", "example_control", "events", "operations", "sharing", "download_engine", "cache_engine", "p2p_isolation", "devices", "invitations", "network", "sync_observation", "p2p_three_nodes", "upgrade_engine", "files_engine", "file_transfer_engine", "file_history_engine", "maintenance_engine", "file_mutation_engine", "local_sync_engine", "local_sync_protocol_engine"])
    suite.add_argument("--mechanism", choices=["macos", "linux", "windows"])
    parser.add_argument("--test-filter")
    parser.add_argument("--allow-private-discovery", action="store_true",
                        help="route only allowlisted discovery CONNECTs to a nonce-selected loopback fixture")
    parser.add_argument("--allow-upgrade-metadata", action="store_true",
                        help="allow genuine end-to-end TLS only to upgrades.verysync.cn:443")
    parser.add_argument("--serve-pinned-upgrade-archive", action="store_true",
                        help="serve only the verified local v2.33.2 archive for its exact official HTTP URL")
    args = parser.parse_args()
    if args.test_target == "managed_lifetime" and sys.platform not in {"darwin", "linux", "win32"}:
        raise RuntimeError("owned-host acceptance requires native macOS, Linux or Windows")
    if args.mechanism and {"macos": "darwin", "linux": "linux", "windows": "win32"}[args.mechanism] != sys.platform:
        raise RuntimeError("mechanism investigation requires its actual native platform")
    if args.test_filter and not args.test_target:
        raise ValueError("a test filter requires an explicit Cargo test target")
    if args.allow_private_discovery and args.test_target != "network":
        raise ValueError("private discovery routing is restricted to the explicit network suite")
    if (args.allow_upgrade_metadata or args.serve_pinned_upgrade_archive) and args.test_target != "upgrade_engine":
        raise ValueError("upgrade routing is restricted to the explicit upgrade suite")
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
    discovery_file = args.evidence_dir / "private-discovery-target.json" if args.allow_private_discovery else None
    discovery_token = secrets.token_hex(32) if args.allow_private_discovery else None
    upgrade_archive = None
    if args.serve_pinned_upgrade_archive:
        archive = Path(os.environ["VERYSYNC_TEST_ARCHIVE"]).resolve(strict=True)
        manifest = json.loads((Path(__file__).resolve().parents[1] / "releases" /
                               "verysync-v2.33.2.json").read_text(encoding="utf-8"))
        matches = [p for p in manifest["packages"] if p["filename"] == archive.name]
        if len(matches) != 1:
            raise ValueError("pinned upgrade archive has no exact fixed catalog identity")
        package = matches[0]
        digest = hashlib.sha256()
        with archive.open("rb") as source:
            while chunk := source.read(65536):
                digest.update(chunk)
        if archive.stat().st_size != package["bytes"] or digest.hexdigest() != package["sha256"]:
            raise ValueError("pinned upgrade archive differs before testing")
        upgrade_archive = archive, package
    with BlockedProxy(discovery_file, discovery_token, args.allow_upgrade_metadata,
                      upgrade_archive) as proxy:
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
        # Short-lived external-versioner fixture only; the library installs no helper.
        env["VERYSYNC_TEST_PYTHON"] = str(Path(sys.executable).resolve(strict=True))
        # Never accept a target supplied by an unrelated parent environment.
        env.pop("VERYSYNC_TEST_DISCOVERY_FORWARD_TARGET_FILE", None)
        env.pop("VERYSYNC_TEST_DISCOVERY_FORWARD_TOKEN", None)
        if discovery_file:
            env["VERYSYNC_TEST_DISCOVERY_FORWARD_TARGET_FILE"] = str(discovery_file)
            env["VERYSYNC_TEST_DISCOVERY_FORWARD_TOKEN"] = discovery_token
        label = args.test_target or "mechanism-" + args.mechanism
        log_path = args.evidence_dir / (label.replace("_", "-") + ".log")
        try:
            if args.test_target:
                features = "engine-tests,download" if args.test_target in {"download_engine", "cache_engine", "file_transfer_engine", "maintenance_engine"} else "engine-tests"
                command = [args.cargo, f"+{args.toolchain}", "test", "--features", features,
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
                  "loopback_only": not args.allow_upgrade_metadata, "listener_loopback_only": True,
                  "forwarding_implemented": args.allow_private_discovery or args.allow_upgrade_metadata,
                  "external_forwarding_implemented": args.allow_upgrade_metadata,
                  "official_upgrade_metadata_host": "upgrades.verysync.cn:443" if args.allow_upgrade_metadata else None,
                  "official_upgrade_metadata_connections": proxy.upgrade_connections,
                  "pinned_upgrade_archives_served": proxy.upgrade_archives_served,
                  "private_discovery_forwarding_enabled": args.allow_private_discovery,
                  "private_connections_forwarded": proxy.forwarded,
                  "requests_blocked": observed, "handler_errors": errors,
                  "test_exit_code": returncode}
        (args.evidence_dir / "proxy-observations.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("Isolated engine HTTP proxy observations: " + json.dumps(report, sort_keys=True))
        return returncode


if __name__ == "__main__":
    raise SystemExit(main())
