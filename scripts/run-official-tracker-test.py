#!/usr/bin/env python3
"""Explicit specialist tracker test: genuine TLS, owned connection cut, private metadata."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import threading
from urllib.parse import urlsplit

HOSTS = frozenset({"control.verysync.cn", "control-v4.verysync.cn", "control-v6.verysync.cn"})
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("tracker_isolation_primitive", ROOT / "scripts/run-isolated-engine-tests.py")
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)


class TrackerRequest(BASE.BlockRequest):
    def setup(self):
        super().setup()
        with self.server.guard:
            self.server.requests.add(self.request)

    def finish(self):
        try:
            super().finish()
        finally:
            with self.server.guard:
                self.server.requests.discard(self.request)


class TrackerProxy(BASE.BlockedProxy):
    def __init__(self, control, token):
        super().__init__(upgrade_metadata=True)
        self.RequestHandlerClass = TrackerRequest
        self.control, self.token = control, token
        self.requests = set()
        self.fault = threading.Event()

    def upgrade_metadata_target(self, method, target):
        if self.fault.is_set() or method != "CONNECT":
            return None
        try:
            value = urlsplit("//" + target)
            if (value.hostname in HOSTS and value.port == 443 and not value.username
                    and not value.password and not value.path and not value.query and not value.fragment):
                return value.hostname, 443
        except ValueError:
            pass
        return None

    def activate_fault_if_requested(self):
        if self.fault.is_set() or self.control.is_symlink():
            return False
        try:
            with self.control.open("rb") as source:
                value = source.read(65)
        except OSError:
            return False
        if not secrets.compare_digest(value, self.token.encode("ascii")):
            return False
        self.fault.set()
        with self.guard:
            for connection in self.requests:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-official-tracker", action="store_true", required=True,
                        help="explicit authorization for native registration metadata to official services")
    parser.add_argument("--cargo", default=shutil.which("cargo"))
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.cargo or not Path(args.cargo).is_absolute() or not args.evidence_dir.is_absolute():
        raise ValueError("explicit absolute Cargo and evidence paths required")
    binary = Path(os.environ["VERYSYNC_TEST_BINARY"])
    expected = os.environ["VERYSYNC_TEST_BINARY_SHA256"]
    if not binary.is_absolute() or len(expected) != 64 or hashlib.sha256(binary.read_bytes()).hexdigest() != expected:
        raise ValueError("explicit private executable digest differs")
    args.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    control, token = args.evidence_dir / "owned-tracker-cut", secrets.token_hex(32)
    stop = threading.Event()
    with TrackerProxy(control, token) as proxy:
        server = threading.Thread(target=proxy.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        server.start()

        def monitor():
            while not stop.wait(0.05):
                proxy.activate_fault_if_requested()

        watcher = threading.Thread(target=monitor, daemon=True)
        watcher.start()
        env = os.environ.copy()
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
            env.pop(name, None)
            env.pop(name.lower(), None)
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            env[name] = f"http://127.0.0.1:{proxy.server_address[1]}"
        env["NO_PROXY"] = "127.0.0.1,localhost,::1"
        env.update({"CARGO_NET_OFFLINE": "true", "VERYSYNC_TEST_TRACKER": "explicit-official-network-test",
                    "VERYSYNC_TEST_TRACKER_CUT_FILE": str(control), "VERYSYNC_TEST_TRACKER_CUT_TOKEN": token})
        command = [args.cargo, "+" + args.toolchain, "test", "--offline", "--locked", "--features", "engine-tests",
                   "--test", "network", "tracker_observation_cases::native_tracker_registers_and_exposes_controlled_disconnect",
                   "--", "--test-threads=1", "--nocapture"]
        case_seen = summary_seen = False
        try:
            with (args.evidence_dir / "native-tracker.log").open("w", encoding="utf-8") as output:
                with subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                      encoding="utf-8", errors="replace") as process:
                    for line in process.stdout:
                        case_seen |= "native tracker registration and controlled disconnect: " in line
                        summary_seen |= "test result: ok. 1 passed; 0 failed; 0 ignored;" in line
                        output.write(line)
                        output.flush()
                        print(line, end="", flush=True)
                    result = process.wait()
        finally:
            stop.set()
            watcher.join(timeout=2)
            proxy.shutdown()
            server.join(timeout=2)
        report = {"explicit_official_tracker_network_opt_in": True,
                  "scope": "specialist child HTTP proxy; no OS-wide no-egress claim",
                  "allowed_official_https_hosts": sorted(HOSTS), "native_TLS_preserved": True,
                  "official_bootstrap_tls_connections": proxy.upgrade_connections,
                  "nonce_controlled_cut_activated": proxy.fault.is_set(),
                  "blocked_requests": [{"method": method, "hostname": host, "count": count}
                                       for (method, host), count in sorted(proxy.observed.items())],
                  "handler_errors": proxy.errors, "native_cargo_exit_code": result,
                  "strict_case_receipt_seen": case_seen, "one_actual_test_passed": summary_seen,
                  "default_isolation_wrapper_changed": False}
        (args.evidence_dir / "proxy-observations.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("Official tracker specialist proxy: " + json.dumps(report, sort_keys=True), flush=True)
        control.unlink(missing_ok=True)
        return result if result else (0 if case_seen and summary_seen and proxy.fault.is_set()
                                     and proxy.upgrade_connections > 0 and not proxy.errors else 1)


if __name__ == "__main__":
    raise SystemExit(main())
