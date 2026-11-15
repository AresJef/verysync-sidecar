"""Real loopback safety/credential controls for the explicit test-only proxy."""
import importlib.util
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch
from http.server import BaseHTTPRequestHandler

SOURCE = Path(__file__).resolve().parents[1] / "run-isolated-engine-tests.py"
SPEC = importlib.util.spec_from_file_location("isolated_engine_tests", SOURCE)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class ProxyContracts(unittest.TestCase):
    def test_unicode_output_survives_legacy_console_and_preserves_failed_exit(self):
        # Only the subprocess is synthetic. The real wrapper, UTF-8 log file,
        # console forwarding, private proxy and failure report all execute.
        output = "native synthetic filename: 二 %\n"
        console_bytes = io.BytesIO()
        console = io.TextIOWrapper(console_bytes, encoding="cp1252", newline="\r\n")
        process = MagicMock()
        process.__enter__.return_value = process
        process.stdout = iter([output])
        process.wait.return_value = 7
        with tempfile.TemporaryDirectory() as root:
            evidence = Path(root) / "evidence"
            binary = Path(root) / "synthetic-core-not-executed"
            binary.write_bytes(b"synthetic helper input; never executed")
            argv = [str(SOURCE), "--toolchain", "synthetic", "--cargo",
                    str(Path(sys.executable).resolve()), "--test-target",
                    "engine_control", "--evidence-dir", str(evidence)]
            def prepare_opener(*args):
                directory = evidence / "owned-native-opener"
                (directory / "captured").mkdir(parents=True)
                (directory / "synthetic-executable").write_bytes(b"synthetic fixture, not executed")
                (directory / "captured" / "1.argv").write_bytes(b"private-argv-value\0")
                return {"fixture_only": True, "name": "synthetic-executable", "sha256": "f" * 64, "private_argv": "private-argv-value"}
            with patch.object(HELPER.sys, "argv", argv), \
                    patch.object(HELPER.sys, "stdout", console), \
                    patch.dict(HELPER.os.environ, {"VERYSYNC_TEST_BINARY": str(binary),
                                                   "VERYSYNC_TEST_BINARY_SHA256": "0" * 64}), \
                    patch.object(HELPER.subprocess, "Popen", return_value=process), \
                    patch.object(HELPER, "prepare_native_opener", side_effect=prepare_opener):
                self.assertEqual(HELPER.main(), 7)
                console.flush()
                self.assertEqual(console_bytes.getvalue().decode("utf-8").splitlines()[0],
                                 output.rstrip("\n"))
                forwarded = console_bytes.getvalue().decode("utf-8")
                summary_line = next(line for line in forwarded.splitlines() if line.startswith("Isolated native opener observations: "))
                summary = json.loads(summary_line.split(": ", 1)[1])
                self.assertEqual(summary["captured_calls"], 1)
                self.assertTrue(summary["owned_capture_and_executable_removed"])
                self.assertNotIn("private-argv-value", forwarded)
                self.assertFalse((evidence / "owned-native-opener").exists())
            self.assertEqual((evidence / "engine-control.log").read_text(encoding="utf-8"), output)
            report = json.loads((evidence / "proxy-observations.json").read_text())
            self.assertEqual(report["test_exit_code"], 7)
            self.assertFalse(report["external_forwarding_implemented"])

    def test_upgrade_exceptions_require_exact_opt_in_hosts_ports_and_pinned_path(self):
        package = {"filename": "verysync-macos-arm64-v2.33.2.zip"}
        target = "upgrades.verysync.cn:443"
        archive_url = "http://dl.verysync.com/releases/v2.33.2/" + package["filename"]
        with HELPER.BlockedProxy() as blocked:
            self.assertIsNone(blocked.upgrade_metadata_target("CONNECT", target))
            self.assertIsNone(blocked.pinned_archive("GET", archive_url))
        with HELPER.BlockedProxy(upgrade_metadata=True, upgrade_archive=(Path("unused-test-input"), package)) as enabled:
            self.assertEqual(enabled.upgrade_metadata_target("CONNECT", target), ("upgrades.verysync.cn", 443))
            self.assertIsNotNone(enabled.pinned_archive("GET", archive_url))
            self.assertIsNone(enabled.upgrade_metadata_target("GET", target))
            self.assertIsNone(enabled.pinned_archive("POST", archive_url))
            for unsafe in ["upgrades.verysync.cn.attacker.invalid:443", "upgrades.verysync.cn:18886",
                           "user:secret@upgrades.verysync.cn:443", "upgrades.verysync.cn:443/path",
                           "upgrades.verysync.cn:443?secret=token", "upgrades.verysync.cn:443#fragment"]:
                self.assertIsNone(enabled.upgrade_metadata_target("CONNECT", unsafe))
            for unsafe in [archive_url + "?secret=token", archive_url + "#fragment",
                           archive_url.replace("dl.verysync.com", "dl.verysync.com.attacker.invalid"),
                           archive_url.replace("dl.verysync.com", "user:secret@dl.verysync.com"),
                           archive_url.replace("v2.33.2/", "v2.33.3/"),
                           archive_url.replace("dl.verysync.com", "dl.verysync.com:18886")]:
                self.assertIsNone(enabled.pinned_archive("GET", unsafe))

    def test_discovery_listener_does_not_call_reverse_dns(self):
        source = SOURCE.with_name("fixture-discovery-server.py")
        spec = importlib.util.spec_from_file_location("private_discovery_fixture", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch("socket.getfqdn", side_effect=AssertionError("reverse DNS must not run")):
            with module.LoopbackDiscoveryServer(("127.0.0.1", 0), BaseHTTPRequestHandler) as server:
                self.assertEqual(server.server_address[0], "127.0.0.1")
                self.assertGreater(server.server_address[1], 0)
                self.assertEqual(server.server_name, "private-loopback")

    def test_private_discovery_requires_exact_host_port_and_nonce(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "target.json"
            with HELPER.BlockedProxy(path, "synthetic-nonce") as proxy:
                target = "discovery.verysync.cn:443"
                self.assertIsNone(proxy.private_discovery_port("CONNECT", target))
                for record in [{"port": 12345, "token": "wrong"},
                               {"port": 18886, "token": "synthetic-nonce"},
                               {"port": True, "token": "synthetic-nonce"},
                               {"port": 0, "token": "synthetic-nonce"}]:
                    path.write_text(json.dumps(record))
                    self.assertIsNone(proxy.private_discovery_port("CONNECT", target))
                path.write_text(json.dumps({"port": 12345, "token": "synthetic-nonce"}))
                for rejected in ["discovery.verysync.cn:80", "discovery.verysync.cn.attacker.invalid:443",
                                 "127.0.0.1:443", "discovery.verysync.cn:443/path",
                                 "user:secret@discovery.verysync.cn:443"]:
                    self.assertIsNone(proxy.private_discovery_port("CONNECT", rejected))
                self.assertIsNone(proxy.private_discovery_port("GET", target))
                self.assertEqual(proxy.private_discovery_port("CONNECT", target), 12345)

    def test_allowed_discovery_connect_tunnels_only_to_selected_loopback_listener(self):
        with tempfile.TemporaryDirectory() as root, socket.socket() as upstream:
            upstream.bind(("127.0.0.1", 0))
            upstream.listen()
            upstream.settimeout(2)
            path = Path(root) / "target.json"
            path.write_text(json.dumps({"port": upstream.getsockname()[1], "token": "synthetic-nonce"}))
            with HELPER.BlockedProxy(path, "synthetic-nonce") as proxy:
                server = threading.Thread(target=proxy.serve_forever,
                                          kwargs={"poll_interval": 0.01}, daemon=True)
                server.start()
                try:
                    with socket.create_connection(proxy.server_address, timeout=2) as client:
                        client.sendall(b"CONNECT discovery.verysync.cn:443 HTTP/1.1\r\n\r\n")
                        self.assertTrue(client.recv(4096).startswith(b"HTTP/1.1 200"))
                        peer, address = upstream.accept()
                        with peer:
                            self.assertEqual(address[0], "127.0.0.1")
                            peer.settimeout(2)
                            client.sendall(b"synthetic-client-bytes")
                            self.assertEqual(peer.recv(4096), b"synthetic-client-bytes")
                            peer.sendall(b"synthetic-server-bytes")
                            self.assertEqual(client.recv(4096), b"synthetic-server-bytes")
                    with proxy.guard:
                        self.assertEqual(proxy.forwarded, 1)
                        self.assertEqual(proxy.observed, {})
                        self.assertEqual(proxy.errors, 0)
                finally:
                    proxy.shutdown()
                    server.join(timeout=2)
                    self.assertFalse(server.is_alive())

    def test_official_metadata_tunnel_records_only_bounded_timing_and_byte_counts(self):
        real_connect = socket.create_connection
        with socket.socket() as upstream, HELPER.BlockedProxy(upgrade_metadata=True) as proxy:
            upstream.bind(("127.0.0.1", 0))
            upstream.listen()
            upstream.settimeout(2)
            def connect(target, **kwargs):
                self.assertEqual(target, ("upgrades.verysync.cn", 443))
                self.assertEqual(kwargs, {"timeout": 10})
                return real_connect(upstream.getsockname(), timeout=2)
            server = threading.Thread(target=proxy.serve_forever,
                                      kwargs={"poll_interval": 0.01}, daemon=True)
            server.start()
            try:
                with patch.object(HELPER.socket, "create_connection", side_effect=connect):
                    with real_connect(proxy.server_address, timeout=2) as client:
                        client.sendall(b"CONNECT upgrades.verysync.cn:443 HTTP/1.1\r\n\r\n")
                        self.assertTrue(client.recv(4096).startswith(b"HTTP/1.1 200"))
                        peer, _ = upstream.accept()
                        with peer:
                            peer.settimeout(2)
                            sent = b"synthetic-private-client-record"
                            received = b"synthetic-private-provider-record"
                            client.sendall(sent)
                            self.assertEqual(peer.recv(4096), sent)
                            peer.sendall(received)
                            self.assertEqual(client.recv(4096), received)
                            client.shutdown(socket.SHUT_WR)
                            deadline = time.monotonic() + 2
                            while time.monotonic() < deadline:
                                with proxy.guard:
                                    records = [dict(r) for r in proxy.upgrade_tunnels]
                                if records and records[0]["completed"]:
                                    break
                                time.sleep(0.005)
                            self.assertEqual(len(records), 1)
                            record = records[0]
                            self.assertTrue(record["completed"])
                            self.assertTrue(record["connected"])
                            self.assertEqual(record["outcome"], "client_eof")
                            self.assertEqual(record["client_bytes"], len(sent))
                            self.assertEqual(record["provider_bytes"], len(received))
                            self.assertGreaterEqual(record["elapsed_s"], record["connect_s"])
                            serialized = json.dumps(record)
                            self.assertNotIn(sent.decode(), serialized)
                            self.assertNotIn(received.decode(), serialized)
                            self.assertEqual(proxy.errors, 0)
            finally:
                proxy.shutdown()
                server.join(timeout=2)
                self.assertFalse(server.is_alive())

    def test_official_metadata_connect_timeout_is_visible_without_headers_or_payload(self):
        real_connect = socket.create_connection
        with HELPER.BlockedProxy(upgrade_metadata=True) as proxy:
            server = threading.Thread(target=proxy.serve_forever,
                                      kwargs={"poll_interval": 0.01}, daemon=True)
            server.start()
            try:
                with patch.object(HELPER.socket, "create_connection", side_effect=TimeoutError):
                    with real_connect(proxy.server_address, timeout=2) as client:
                        client.sendall(b"CONNECT upgrades.verysync.cn:443 HTTP/1.1\r\nProxy-Authorization: synthetic-private-header\r\n\r\n")
                        self.assertEqual(client.recv(4096), b"")
                with proxy.guard:
                    records = [dict(r) for r in proxy.upgrade_tunnels]
                self.assertEqual(len(records), 1)
                self.assertTrue(records[0]["completed"])
                self.assertFalse(records[0]["connected"])
                self.assertEqual(records[0]["outcome"], "socket_timeout")
                self.assertEqual(records[0]["client_bytes"], 0)
                self.assertEqual(records[0]["provider_bytes"], 0)
                self.assertNotIn("synthetic-private-header", json.dumps(records))
                self.assertEqual(proxy.errors, 0)
            finally:
                proxy.shutdown()
                server.join(timeout=2)
                self.assertFalse(server.is_alive())

    def test_http_and_connect_are_blocked_without_forwarding_or_recording_credentials(self):
        with socket.socket() as canary, HELPER.BlockedProxy() as proxy:
            canary.bind(("127.0.0.1", 0))
            canary.listen()
            canary.settimeout(0.2)
            port = canary.getsockname()[1]
            server = threading.Thread(target=proxy.serve_forever,
                                      kwargs={"poll_interval": 0.01}, daemon=True)
            server.start()
            try:
                targets = [f"GET http://synthetic-user:synthetic-pass@127.0.0.1:{port}/private?token=synthetic-secret HTTP/1.1",
                           f"CONNECT 127.0.0.1:{port} HTTP/1.1"]
                for target in targets:
                    with socket.create_connection(proxy.server_address, timeout=2) as client:
                        client.sendall((target + "\r\nProxy-Authorization: synthetic-authorization\r\n\r\n").encode())
                        self.assertTrue(client.recv(4096).startswith(b"HTTP/1.1 403"))
                with self.assertRaises(socket.timeout):
                    canary.accept()
                with proxy.guard:
                    self.assertEqual(proxy.observed, {("GET", "127.0.0.1"): 1, ("CONNECT", "127.0.0.1"): 1})
                    text = json.dumps(list(proxy.observed))
                for secret in ["synthetic-user", "synthetic-pass", "synthetic-secret", "synthetic-authorization", "private"]:
                    self.assertNotIn(secret, text)
            finally:
                proxy.shutdown()
                server.join(timeout=2)
                self.assertFalse(server.is_alive())





class NativeOpenerContracts(unittest.TestCase):
    def test_exact_artifact_is_copied_into_owned_child_path_without_parent_environment_changes(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            source=root/"compiled opener fixture"
            source.write_bytes(b"synthetic regular artifact, not executed")
            evidence=root/"evidence"
            evidence.mkdir()
            env={"PATH":"original-child-path","CARGO_TARGET_DIR":"explicit-target"}
            original=HELPER.os.environ.copy()
            messages={"reason":"compiler-artifact","target":{"kind":["example"],"name":"native_folder_opener"},"executable":str(source)}
            result=SimpleNamespace(returncode=0,stdout=json.dumps(messages),stderr="")
            with patch.object(HELPER.subprocess,"run",return_value=result) as build:
                receipt=HELPER.prepare_native_opener("explicit-cargo","1.85.0",evidence,env)
            executable=Path(env["VERYSYNC_TEST_OPENER_EXECUTABLE"])
            self.assertEqual(executable.read_bytes(),source.read_bytes())
            self.assertEqual(Path(env["VERYSYNC_TEST_OPENER_CAPTURE_DIR"]).parent,executable.parent)
            self.assertEqual(env["PATH"],str(executable.parent)+HELPER.os.pathsep+"original-child-path")
            self.assertEqual(HELPER.os.environ.copy(),original)
            self.assertTrue(receipt["fixture_only"])
            self.assertIn("--manifest-path",build.call_args.args[0])
            self.assertIn("--offline",build.call_args.args[0])
            self.assertIs(build.call_args.kwargs["env"],env)

    def test_missing_compiled_helper_is_refused_before_capture_or_environment_changes(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temporary:
            evidence=Path(temporary)/"evidence"
            evidence.mkdir()
            env={"PATH":"kept"}
            result=SimpleNamespace(returncode=0,stdout="",stderr="")
            with patch.object(HELPER.subprocess,"run",return_value=result):
                with self.assertRaises(ValueError):
                    HELPER.prepare_native_opener("explicit-cargo","1.85.0",evidence,env)
            self.assertEqual(env,{"PATH":"kept"})
            self.assertEqual(list(evidence.iterdir()),[])



class WallpaperSourceContracts(unittest.TestCase):
    def test_source_permission_is_refused_outside_the_explicit_wallpaper_suite(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence=Path(temporary)/"not-created"
            argv=[str(SOURCE),"--toolchain","synthetic","--cargo",str(Path(sys.executable).resolve()),"--test-target","engine_control","--allow-wallpaper-source","--evidence-dir",str(evidence)]
            with patch.object(HELPER.sys,"argv",argv):
                with self.assertRaises(ValueError):
                    HELPER.main()
            self.assertFalse(evidence.exists())

    def test_wallpaper_bypass_and_permission_flag_only_reach_the_owned_child(self):
        process=MagicMock()
        process.__enter__.return_value=process
        process.stdout=iter([])
        process.wait.return_value=7
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            binary=root/"not-executed"
            binary.write_bytes(b"synthetic never-run core")
            evidence=root/"evidence"
            argv=[str(SOURCE),"--toolchain","synthetic","--cargo",str(Path(sys.executable).resolve()),"--test-target","wallpaper_engine","--allow-wallpaper-source","--evidence-dir",str(evidence)]
            with patch.object(HELPER.sys,"argv",argv), patch.dict(HELPER.os.environ,{"VERYSYNC_TEST_BINARY":str(binary),"VERYSYNC_TEST_BINARY_SHA256":"0"*64,"VERYSYNC_TEST_WALLPAPER_SOURCE_ALLOWED":"untrusted-parent"}), patch.object(HELPER.subprocess,"Popen",return_value=process) as run, patch.object(HELPER.sys,"stdout",io.StringIO()):
                self.assertEqual(HELPER.main(),7)
                child=run.call_args.kwargs["env"]
                self.assertEqual(child["NO_PROXY"],"127.0.0.1,localhost,::1,bing.com")
                self.assertEqual(child["VERYSYNC_TEST_WALLPAPER_SOURCE_ALLOWED"],"1")
                self.assertEqual(HELPER.os.environ["VERYSYNC_TEST_WALLPAPER_SOURCE_ALLOWED"],"untrusted-parent")
            report=json.loads((evidence/"proxy-observations.json").read_text())
            self.assertEqual(report["wallpaper_source_proxy_bypass_suffix"],"bing.com")
            self.assertFalse(report["external_forwarding_implemented"])
            self.assertEqual(report["test_exit_code"],7)


if __name__ == "__main__":
    unittest.main()
