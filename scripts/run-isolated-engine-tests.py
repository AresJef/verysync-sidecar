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
import struct
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

def windows_pe_machine(path):
    """Read the bounded PE signature and COFF machine; never execute the image.

    Format: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    """
    with path.open("rb") as source:
        header = source.read(64)
        if len(header) != 64 or header[:2] != b"MZ":
            raise ValueError("regular PE image required")
        offset = struct.unpack_from("<I", header, 0x3c)[0]
        if not 64 <= offset <= 1024 * 1024:
            raise ValueError("bounded PE header offset required")
        source.seek(offset)
        coff = source.read(6)
        if len(coff) != 6 or coff[:4] != b"PE\0\0":
            raise ValueError("exact PE signature required")
        return struct.unpack_from("<H", coff, 4)[0]


def windows_wow64_directory():
    import ctypes
    query = ctypes.WinDLL("kernel32", use_last_error=True).GetSystemWow64DirectoryW
    query.argtypes = [ctypes.POINTER(ctypes.c_wchar), ctypes.c_uint]
    query.restype = ctypes.c_uint
    capacity = 260
    for _ in range(2):
        buffer = ctypes.create_unicode_buffer(capacity)
        size = query(buffer, len(buffer))
        if not 0 < size < 32767:
            raise OSError("bounded x86 Windows system directory query failed")
        if size >= capacity:
            capacity = size+1
            continue
        value = buffer.value
        if not value or len(value.encode("utf-16-le", "surrogatepass"))//2 != size:
            raise OSError("x86 Windows system directory output is empty or incomplete")
        return Path(value)
    raise OSError("x86 Windows system directory output changed during bounded sizing")


def windows_socket_provider(executable):
    machine = windows_pe_machine(executable)
    if machine not in {0x014c, 0x8664, 0xaa64}:
        raise ValueError("verified Windows opener architecture required")
    runtime = Path(os.environ["SYSTEMROOT"]) / "System32" / "mswsock.dll"
    if machine == 0x014c and windows_pe_machine(runtime) != machine:
        # Query the actual x86 directory rather than copying the Python host's
        # 64-bit provider. Only the owned child adopts the private SystemRoot.
        runtime = windows_wow64_directory() / "mswsock.dll"
    if not runtime.is_absolute() or not runtime.is_file() or runtime.is_symlink():
        raise ValueError("exact native Windows socket provider required")
    if machine == 0x014c and windows_pe_machine(runtime) != machine:
        raise ValueError("x86 opener requires an actual x86 socket provider")
    return runtime, machine


def probe_windows_opener_runtime(executable, env, machine):
    target = {0x014c: ("x86", 32), 0x8664: ("x86_64", 64), 0xaa64: ("aarch64", 64)}[machine]
    probe = subprocess.run(
        [str(executable), "--verysync-test-loopback-runtime"],
        env=dict(env, VERYSYNC_TEST_OPENER_RUNTIME_PROBE="1"),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
    )
    if probe.returncode != 0:
        raise ValueError(f"owned Windows socket preflight failed: machine={hex(machine)}, "
                         f"exit={probe.returncode}, diagnostic={probe.stderr.decode('utf-8', errors='replace')[-512:]!r}")
    expected = {"owned_opener_runtime_probe": True, "target_arch": target[0],
                "pointer_bits": target[1], "loopback_bind": True}
    if json.loads(probe.stdout) != expected:
        raise ValueError("owned Windows socket preflight returned a mismatched target receipt")


def prepare_native_opener(cargo, toolchain, evidence_dir, env):
    """Capture explicit native desktop dispatch using a task-owned executable."""
    import importlib.util
    module_path = Path(__file__).with_name("prepare-test-examples.py")
    spec = importlib.util.spec_from_file_location("native_opener_artifacts", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    artifacts = module.build_artifacts(
        [cargo, f"+{toolchain}"],
        ["--example", "native_folder_opener", "--features", "engine-tests", "--offline",
         "--manifest-path", str(Path(__file__).resolve().parents[1] / "Cargo.toml")],
        env=env,
    )
    source = artifacts.get("native_folder_opener")
    if source is None or not source.is_absolute() or not source.is_file() or source.is_symlink():
        raise ValueError("Cargo did not identify the exact regular native opener fixture")
    directory = evidence_dir / "owned-native-opener"
    capture = directory / "captured"
    capture.mkdir(mode=0o700, parents=True, exist_ok=False)
    # The pinned Windows core's actual process-start trace dispatches rundll32,
    # rather than Explorer. Keep the owned capture ahead of the system command.
    name = "rundll32.exe" if os.name == "nt" else ("open" if sys.platform == "darwin" else "xdg-open")
    if os.name == "nt":
        system_root = directory / "windows-root"
        executable = system_root / "System32" / name
        executable.parent.mkdir(parents=True)
        # Winsock's registered provider expands SystemRoot too. Preserve that
        # native OS runtime in the private copy; never modify the OS directory.
        runtime, machine = windows_socket_provider(source)
        runtime_copy = executable.parent / runtime.name
        shutil.copy2(runtime, runtime_copy)
        if hashlib.sha256(runtime.read_bytes()).digest() != hashlib.sha256(runtime_copy.read_bytes()).digest():
            raise ValueError("owned native socket provider copy differs")
        # Only the exact dispatch test's separate child adopts this value.
        # Do not change SystemRoot for Cargo, the suite, or the caller.
        env["VERYSYNC_TEST_OPENER_SYSTEM_ROOT"] = str(system_root)
    else:
        executable = directory / name
    shutil.copy2(source, executable)
    if hashlib.sha256(executable.read_bytes()).digest() != hashlib.sha256(source.read_bytes()).digest():
        raise ValueError("owned native opener copy differs")
    receipt = {"fixture_only": True, "name": name, "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
    if os.name == "nt":
        print("Owned Windows socket provider candidate: " + json.dumps({
            "target_pe_machine": hex(machine),
            "socket_provider_pe_machine": hex(windows_pe_machine(runtime_copy)),
            "socket_provider_sha256": hashlib.sha256(runtime_copy.read_bytes()).hexdigest(),
            "owned_copy_byte_verified": True,
        }), flush=True)
        probe_windows_opener_runtime(executable, dict(env, SYSTEMROOT=str(system_root)), machine)
        receipt.update(target_pe_machine=hex(machine),
                       socket_provider_pe_machine=hex(windows_pe_machine(runtime_copy)),
                       target_runtime_preflight=True)
    env["PATH"] = str(executable.parent) + os.pathsep + env.get("PATH", "")
    env["VERYSYNC_TEST_OPENER_CAPTURE_DIR"] = str(capture)
    env["VERYSYNC_TEST_OPENER_EXECUTABLE"] = str(executable)
    return receipt

def mount_namespace_identity():
    return os.readlink("/proc/self/ns/mnt")


def isolate_linux_browser(command, evidence_dir, env):
    if env.get("GITHUB_ACTIONS") != "true" or env.get("RUNNER_OS") != "Linux" or os.getuid() == 0:
        raise ValueError("browser mount isolation requires an unprivileged isolated GitHub Linux VM")
    runner_temp = Path(env["RUNNER_TEMP"]).resolve(strict=True)
    if not evidence_dir.resolve(strict=True).is_relative_to(runner_temp):
        raise ValueError("browser fixture must be inside the explicit runner temporary root")
    invalid = evidence_dir / "owned-native-opener" / "invalid-native-browser"
    invalid.write_bytes(b"owned invalid browser executable; deliberately no executable header\n")
    invalid.chmod(0o755)
    env["VERYSYNC_TEST_BROWSER_ISOLATION"] = "linux-private-mount-fallback-v1"
    allowed = {"PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL",
               "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE", "CARGO_TERM_COLOR",
               "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
               "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
               "http_proxy", "https_proxy", "all_proxy", "no_proxy",
               "GITHUB_ACTIONS", "RUNNER_OS", "RUNNER_TEMP", "RUNNER_TRACKING_ID",
               "VERYSYNC_TEST_BINARY", "VERYSYNC_TEST_BINARY_SHA256",
               "VERYSYNC_TEST_OPENER_CAPTURE_DIR", "VERYSYNC_TEST_OPENER_EXECUTABLE",
               "VERYSYNC_TEST_BROWSER_HOLD", "VERYSYNC_TEST_BROWSER_ISOLATION", "BROWSER"}
    plan = {"uid": os.getuid(), "gid": os.getgid(), "groups": os.getgroups(), "caller_pid": os.getpid(),
            "parent_namespace": mount_namespace_identity(), "invalid_source": str(invalid),
            "command": command, "cwd": str(Path(__file__).resolve().parents[1]),
            "receipt": str(evidence_dir / "browser-mount-namespace.json"),
            "env": {key: value for key, value in env.items() if key in allowed}}
    payload = evidence_dir / "private-browser-mount-plan.json"
    with open(payload, "x", encoding="utf-8", opener=lambda p, f: os.open(p, f, 0o600)) as output:
        json.dump(plan, output)
    return ["sudo", "--non-interactive", "/usr/bin/unshare", "--mount", "--propagation", "private", "--fork",
            sys.executable, str(Path(__file__).with_name("browser-linux-namespace.py")), str(payload)]


def isolate_browser_command(command, evidence_dir, env):
    """Test-only pinned macOS native Chrome rejection and owned open fallback."""
    if sys.platform == "linux":
        return isolate_linux_browser(command, evidence_dir, env)
    if sys.platform != "darwin":
        raise ValueError("native browser selector isolation not verified on this platform")
    profile = evidence_dir / "browser-exec.sb"
    profile.write_text('''(version 1)
(allow default)
(deny process-exec (subpath "/Applications/Google Chrome.app")
 (subpath "/Applications/Google Chrome Canary.app")
 (subpath "/Applications/Chromium.app")
 (subpath "/Applications/Microsoft Edge.app")
 (literal "/usr/bin/google-chrome-stable")
 (literal "/usr/bin/google-chrome")
 (literal "/usr/bin/chromium")
 (literal "/usr/bin/chromium-browser"))
''', encoding="utf-8")
    env["VERYSYNC_TEST_BROWSER_ISOLATION"] = "macos-seatbelt-fallback-v1"
    return ["/usr/bin/sandbox-exec", "-f", str(profile)] + command

def finish_browser_actors(directory):
    """Observe only PIDs emitted by the exact owned browser actor fixture."""
    calls = list((directory / "captured").glob("*.argv"))
    actors = list((directory / "captured").glob("*.owned"))
    owned = {call.stem: call for call in calls + actors}
    if len(owned) > 16 or any(not pid.isdecimal() or not 1 < int(pid) <= 0xffffffff for pid in owned):
        raise ValueError("bounded exact owned actor PIDs required")
    must_exit = list((directory / "captured").glob("*.must-exit"))
    native_roots = list((directory / "captured").glob("*.native-root"))
    detached_actors = list((directory / "captured").glob("*.detached"))
    detached_openers = list((directory / "captured").glob("*.detached-opener"))
    required = {call.stem for call in must_exit + native_roots}
    detached = {call.stem for call in detached_actors + detached_openers}
    if len(required | detached) > 16 or any(
            not pid.isdecimal() or not 1 < int(pid) <= 0xffffffff for pid in required | detached):
        raise ValueError("exact native cancellation PIDs required")
    if (must_exit or detached) and len(native_roots) != 1:
        raise ValueError("one exact cancelled native root required")
    if detached and (len(detached_actors) != 1 or len(detached_openers) != 1 or required & detached):
        raise ValueError("exact separate native-detached opener and actor required")

    def alive(pid):
        result = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "stat="],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, timeout=2)
        if result.returncode not in (0, 1):
            raise OSError("owned browser exit observation unavailable")
        state = result.stdout.strip()
        return bool(state) and not state.startswith("Z")

    def observe_ended(pids):
        pending = {int(pid) for pid in pids}
        deadline = time.monotonic() + 3
        while pending and time.monotonic() < deadline:
            for pid in list(pending):
                if not alive(pid):
                    pending.remove(pid)
            if pending:
                time.sleep(0.01)
        if pending:
            raise RuntimeError("owned browser process still alive; preserve fixture")

    # Cancellation must already have ended these processes. Never turn a
    # missing SDK cleanup into a pass by sending our actor's normal stop first.
    observe_ended(required)
    # Linux's native opener can establish a separate process group. Observe
    # those exact fixture PIDs before sending any cleanup marker; GUI rollback
    # is not promised by the browser API. Never report their survival as exit.
    detached_alive = {pid: alive(pid) for pid in sorted(detached)}
    if detached:
        (directory / "captured" / "release-native-root").write_bytes(b"outer exact opener cleanup")
    for call in owned.values():
        if call.stem not in required:
            call.with_suffix(".stop").write_bytes(b"outer test-owned cleanup")
    observe_ended(set(owned) | detached)
    return {"captured_actor_count": len(calls), "journaled_actor_count": len(actors),
            "cancellation_actor_count": len(must_exit), "native_cancelled_root_count": len(native_roots),
            "cancellation_detached_actor_count": len(detached_actors),
            "cancellation_detached_opener_count": len(detached_openers),
            "cancellation_native_root_exit_before_outer_cleanup": True if native_roots else None,
            "cancellation_native_exit_before_outer_cleanup": not any(detached_alive.values()) if required else None,
            "cancellation_desktop_outlived_native_root": any(detached_alive.values()) if detached else None,
            "detached_pid_alive_before_outer_cleanup": detached_alive,
            "every_actor_native_exit_observed": True, "observer_outside_browser_sandbox": True}

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
        self.upgrade_tunnels = []
        self.upgrade_tunnels_omitted = 0
        self.started_at = time.monotonic()
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
            started = time.monotonic()
            tunnel = None
            outcome = "relay_deadline"
            if official:
                with self.server.guard:
                    if len(self.server.upgrade_tunnels) < 64:
                        tunnel = {"started_s": round(started - self.server.started_at, 3),
                                  "connected": False, "completed": False,
                                  "connect_s": None, "elapsed_s": None,
                                  "client_bytes": 0, "provider_bytes": 0,
                                  "outcome": "pending"}
                        self.server.upgrade_tunnels.append(tunnel)
                    else:
                        self.server.upgrade_tunnels_omitted += 1
            try:
                target = official or ("127.0.0.1", port)
                with socket.create_connection(target, timeout=10 if official else 2) as upstream:
                    if tunnel is not None:
                        with self.server.guard:
                            tunnel["connected"] = True
                            tunnel["connect_s"] = round(time.monotonic() - started, 3)
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
                                outcome = "client_eof" if source is self.request else "provider_eof"
                                return
                            if tunnel is not None:
                                with self.server.guard:
                                    field = "client_bytes" if source is self.request else "provider_bytes"
                                    tunnel[field] += len(data)
                            (upstream if source is self.request else self.request).sendall(data)
                return
            except (OSError, ValueError) as error:
                outcome = ("socket_timeout" if isinstance(error, TimeoutError) else
                           "connection_reset" if isinstance(error, ConnectionResetError) else
                           "broken_pipe" if isinstance(error, BrokenPipeError) else
                           "io_error")
                return
            finally:
                if tunnel is not None:
                    with self.server.guard:
                        tunnel["completed"] = True
                        tunnel["elapsed_s"] = round(time.monotonic() - started, 3)
                        tunnel["outcome"] = outcome
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
    parser.add_argument("--toolchain", required=True, help="Rust toolchain for building and running the selected suite")
    parser.add_argument("--cargo", default=shutil.which("cargo"), help="path to the Cargo executable")
    parser.add_argument("--evidence-dir", required=True, type=Path, help="directory for this suite's private test records")
    suite = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("--release", action="store_true", help="explicit optimized test build")
    suite.add_argument("--test-target", choices=["browser_engine", "managed_lifetime", "managed_instance", "engine_control", "example_control", "events", "operations", "sharing", "download_engine", "cache_engine", "p2p_isolation", "devices", "invitations", "network", "sync_observation", "p2p_three_nodes", "upgrade_engine", "files_engine", "file_transfer_engine", "disk_full_engine", "resource_usage_engine", "file_history_engine", "maintenance_engine", "file_mutation_engine", "local_sync_engine", "local_sync_protocol_engine", "local_sync_advanced_engine", "local_sync_runtime_engine", "local_sync_automation_engine", "local_sync_repair_engine", "local_sync_protocol_advanced_engine", "local_sync_configuration_engine", "configuration_engine", "authentication_engine", "ldap_trusted_ca_engine", "wallpaper_engine", "host_control_engine", "control_reliability_engine",
                                          "control_observation_engine", "control_preview_engine",
                                          "control_preflight_engine"])
    suite.add_argument("--managed-repair-regressions", action="store_true",
                       help="run the isolated managed lifecycle regressions")
    suite.add_argument("--mechanism", choices=["macos", "linux", "windows"])
    parser.add_argument("--blocked-upgrade-check", action="store_true",
                        help="run the dedicated CLI check with vendor metadata blocked")
    parser.add_argument("--upgrade-process-trace", type=Path,
                        help="collect independent process events for the two native upgrade recovery cases")
    parser.add_argument("--upgrade-consumer", type=Path,
                        help="separately unpacked crate consumer directory for the upgrade suite")
    parser.add_argument("--sdk-completion-consumer", type=Path,
                        help="separately unpacked crate consumer for the selected SDK workflow test")
    parser.add_argument("--test-filter", help="run only tests matching this name in the selected suite")
    parser.add_argument("--allow-private-discovery", action="store_true",
                        help="route only allowlisted discovery CONNECTs to a nonce-selected loopback fixture")
    parser.add_argument("--allow-upgrade-metadata", action="store_true",
                        help="allow genuine end-to-end TLS only to upgrades.verysync.cn:443")
    parser.add_argument("--serve-pinned-upgrade-archive", action="store_true",
                        help="serve only the verified local v2.33.2 archive for its exact official HTTP URL")
    parser.add_argument("--allow-wallpaper-source", action="store_true",
                        help="explicit wallpaper suite only: permit target Bing HTTPS through a child-only proxy bypass")
    args = parser.parse_args()
    if args.test_target == "managed_lifetime" and sys.platform not in {"darwin", "linux", "win32"}:
        raise RuntimeError("owned-host acceptance requires native macOS, Linux or Windows")
    if args.mechanism and {"macos": "darwin", "linux": "linux", "windows": "win32"}[args.mechanism] != sys.platform:
        raise RuntimeError("mechanism investigation requires its actual native platform")
    if args.test_filter and not args.test_target:
        raise ValueError("a test filter requires an explicit Cargo test target")
    if args.allow_private_discovery and args.test_target != "network":
        raise ValueError("private discovery routing is restricted to the explicit network suite")
    if args.blocked_upgrade_check and (
        args.test_target != "upgrade_engine"
        or args.test_filter != "stopped_cli_blocked_check"
        or args.allow_upgrade_metadata
        or args.serve_pinned_upgrade_archive
    ):
        raise ValueError("the blocked CLI check requires its dedicated selector and blocked metadata")
    if args.test_filter == "stopped_cli_blocked_check" and not args.blocked_upgrade_check:
        raise ValueError("use --blocked-upgrade-check to select the provider-blocked CLI case")
    if args.upgrade_process_trace and (
        args.test_target != "upgrade_engine"
        or args.test_filter not in {
            "native_same_attempt_observes",
            "native_business_install_reports_verified_target_after_lost_reply",
        }
        or not args.upgrade_consumer
        or os.environ.get("GITHUB_ACTIONS") != "true"
    ):
        raise ValueError("process tracing is scoped to the two packaged native upgrade recovery cases on GitHub")
    if args.upgrade_consumer and args.test_target != "upgrade_engine":
        raise ValueError("the independent upgrade consumer requires the upgrade suite")
    if args.sdk_completion_consumer and (
        args.upgrade_consumer or args.test_target not in {
            "authentication_engine", "devices", "engine_control", "file_transfer_engine",
            "local_sync_engine", "managed_instance",
        }
    ):
        raise ValueError("select one separately unpacked SDK consumer for a supported workflow test")
    if (args.allow_upgrade_metadata or args.serve_pinned_upgrade_archive) and args.test_target != "upgrade_engine":
        raise ValueError("upgrade routing is restricted to the explicit upgrade suite")
    if args.allow_wallpaper_source and args.test_target != "wallpaper_engine":
        raise ValueError("wallpaper source access is restricted to its explicit native suite")
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
            env[name] = "127.0.0.1,localhost,::1" + (",bing.com" if args.allow_wallpaper_source else "")
        env["CARGO_NET_OFFLINE"] = "true"
        env["VERYSYNC_TEST_WALLPAPER_SOURCE_ALLOWED"] = "1" if args.allow_wallpaper_source else "0"
        # Short-lived external-versioner fixture only; the library installs no helper.
        env["VERYSYNC_TEST_PYTHON"] = str(Path(sys.executable).resolve(strict=True))
        # Never accept a target supplied by an unrelated parent environment.
        env.pop("VERYSYNC_TEST_DISCOVERY_FORWARD_TARGET_FILE", None)
        env.pop("VERYSYNC_TEST_DISCOVERY_FORWARD_TOKEN", None)
        if discovery_file:
            env["VERYSYNC_TEST_DISCOVERY_FORWARD_TARGET_FILE"] = str(discovery_file)
            env["VERYSYNC_TEST_DISCOVERY_FORWARD_TOKEN"] = discovery_token
        if args.upgrade_process_trace:
            host = subprocess.check_output(
                ["rustc", f"+{args.toolchain}", "-vV"], text=True, timeout=30
            ).splitlines()
            host = next(row.split(": ", 1)[1] for row in host if row.startswith("host: "))
            runner = "CARGO_TARGET_" + host.replace("-", "_").upper() + "_RUNNER"
            witness = Path(__file__).with_name("trace-upgrade-recovery.py").resolve(strict=True)
            launcher = [str(Path(sys.executable).resolve(strict=True)), str(witness)]
            if any(any(character.isspace() for character in path) for path in launcher):
                raise ValueError("the private native tracing runner requires launcher paths without spaces")
            env[runner] = " ".join(launcher)
            env["VERYSYNC_S29_TRACE_DIR"] = str(args.upgrade_process_trace)
            if args.test_filter == "native_business_install_reports_verified_target_after_lost_reply":
                env["VERYSYNC_S30_TRACE"] = "1"
        opener = None
        for name in ("VERYSYNC_TEST_OPENER_CAPTURE_DIR", "VERYSYNC_TEST_OPENER_EXECUTABLE", "VERYSYNC_TEST_OPENER_SYSTEM_ROOT", "VERYSYNC_TEST_OPENER_OWNED_CHILD", "VERYSYNC_TEST_OPENER_RUNTIME_PROBE", "VERYSYNC_TEST_BROWSER_HOLD", "VERYSYNC_TEST_BROWSER_ACTOR", "VERYSYNC_TEST_BROWSER_ISOLATION"):
            env.pop(name, None)
        if args.test_target in {"engine_control", "browser_engine"}:
            opener = prepare_native_opener(args.cargo, args.toolchain, args.evidence_dir, env)
            (args.evidence_dir / "native-opener-fixture.json").write_text(json.dumps(opener), encoding="utf-8")
            if args.test_target == "browser_engine":
                env["BROWSER"] = env["VERYSYNC_TEST_OPENER_EXECUTABLE"]
                env["VERYSYNC_TEST_BROWSER_HOLD"] = "1"
        label = args.test_target
        if args.managed_repair_regressions:
            label = "managed-repair-regressions"
        elif args.mechanism:
            label = "mechanism-" + args.mechanism
        log_path = args.evidence_dir / (label.replace("_", "-") + ".log")
        try:
            if args.managed_repair_regressions:
                command = [args.cargo, f"+{args.toolchain}", "test", "--features", "engine-tests",
                           "--lib", "--offline", "--locked", "instance_regressions::deep_repair_",
                           "--", "--ignored", "--test-threads=1", "--nocapture"]
            elif args.test_target:
                features = "engine-tests,download" if args.test_target in {"download_engine", "cache_engine", "file_transfer_engine", "disk_full_engine", "resource_usage_engine", "maintenance_engine"} else "engine-tests"
                command = [args.cargo, f"+{args.toolchain}", "test", "--features", features,
                           "--test", args.test_target, "--offline", "--locked"]
                if args.release:
                    command += ["--release"]
                if args.test_filter:
                    command += [args.test_filter]
                command += ["--", "--test-threads=1", "--nocapture"]
                if args.blocked_upgrade_check:
                    command += ["--ignored"]
                if args.test_target == "browser_engine":
                    command = isolate_browser_command(command, args.evidence_dir, env)
            else:
                command = [sys.executable, str(Path(__file__).with_name(f"run-{args.mechanism}-lifetime-probes.py")),
                           "--toolchain", args.toolchain, "--evidence-dir", str(args.evidence_dir / "mechanism")]
            with log_path.open("w", encoding="utf-8") as log:
                cwd = args.upgrade_consumer or args.sdk_completion_consumer or Path(__file__).resolve().parents[1]
                with subprocess.Popen(command, cwd=cwd,
                                      env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      text=True, encoding="utf-8", errors="replace") as process:
                    for line in process.stdout:
                        log.write(line)
                        log.flush()
                        print(line, end="", flush=True)
                    returncode = process.wait()
        finally:
            try:
                if opener is not None:
                    owned_opener = args.evidence_dir / "owned-native-opener"
                    captures = sum(1 for _ in (owned_opener / "captured").glob("*.argv"))
                    if args.test_target == "browser_engine":
                        actor_report = finish_browser_actors(owned_opener)
                        (args.evidence_dir / "browser-actor-exits.json").write_text(json.dumps(actor_report), encoding="utf-8")
                        print("Isolated browser actor exits: " + json.dumps(actor_report), flush=True)
                    if owned_opener.exists():
                        shutil.rmtree(owned_opener)
                    opener["captured_calls"] = captures
                    opener["owned_capture_and_executable_removed"] = not owned_opener.exists()
                    (args.evidence_dir / "native-opener-fixture.json").write_text(json.dumps(opener), encoding="utf-8")
                    print("Isolated native opener observations: " + json.dumps({key: opener[key] for key in ("fixture_only", "name", "sha256", "captured_calls", "owned_capture_and_executable_removed", "target_pe_machine", "socket_provider_pe_machine", "target_runtime_preflight") if key in opener}, sort_keys=True), flush=True)
            finally:
                proxy.shutdown()
                server.join(timeout=5)
        with proxy.guard:
            observed = [{"method": method, "hostname": host, "count": count}
                        for (method, host), count in sorted(proxy.observed.items())]
            errors = proxy.errors
            upgrade_tunnels = [dict(record) for record in proxy.upgrade_tunnels]
            upgrade_tunnels_omitted = proxy.upgrade_tunnels_omitted
        report = {"scope": "test-only HTTP proxy observations; not an OS-wide no-egress proof",
                  "loopback_only": not args.allow_upgrade_metadata, "listener_loopback_only": True,
                  "forwarding_implemented": args.allow_private_discovery or args.allow_upgrade_metadata,
                  "external_forwarding_implemented": args.allow_upgrade_metadata,
                  "official_upgrade_metadata_host": "upgrades.verysync.cn:443" if args.allow_upgrade_metadata else None,
                  "official_upgrade_metadata_connections": proxy.upgrade_connections,
                  "official_upgrade_metadata_tunnels": upgrade_tunnels,
                  "official_upgrade_metadata_tunnels_omitted": upgrade_tunnels_omitted,
                  "pinned_upgrade_archives_served": proxy.upgrade_archives_served,
                  "private_discovery_forwarding_enabled": args.allow_private_discovery,
                  "private_connections_forwarded": proxy.forwarded,
                  "requests_blocked": observed, "handler_errors": errors,
                  "wallpaper_source_proxy_bypass_suffix": "bing.com" if args.allow_wallpaper_source else None,
                  "test_exit_code": returncode}
        (args.evidence_dir / "proxy-observations.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("Isolated engine HTTP proxy observations: " + json.dumps(report, sort_keys=True))
        return returncode


if __name__ == "__main__":
    raise SystemExit(main())
