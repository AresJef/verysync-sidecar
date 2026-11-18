"""The explicit tracker fixture restricts destinations and owns its fault injection."""
import importlib.util
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("official_tracker", ROOT / "scripts/run-official-tracker-test.py")
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class TrackerFixture(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.control = Path(self.directory.name) / "cut"
        self.proxy = FIXTURE.TrackerProxy(self.control, "a" * 64)
        self.addCleanup(self.proxy.server_close)

    def test_only_the_three_exact_official_tls_targets_are_forwardable(self):
        for host in FIXTURE.HOSTS:
            self.assertEqual(self.proxy.upgrade_metadata_target("CONNECT", host + ":443"), (host, 443))
        for target in ["example.com:443", "control.verysync.cn:80", "control.verysync.cn:444",
                       "control.verysync.cn.evil.example:443", "user@control.verysync.cn:443",
                       "control.verysync.cn:443/path", "control.verysync.cn:443?key=private",
                       "control.verysync.cn:443#fragment", "127.0.0.1:18886", "[::1]:18886"]:
            self.assertIsNone(self.proxy.upgrade_metadata_target("CONNECT", target))
        self.assertIsNone(self.proxy.upgrade_metadata_target("GET", "control.verysync.cn:443"))

    def test_wrong_or_oversized_nonce_cannot_cut_an_owned_connection(self):
        self.control.write_text("b" * 64)
        self.assertFalse(self.proxy.activate_fault_if_requested())
        self.control.write_text("a" * 4097)
        self.assertFalse(self.proxy.activate_fault_if_requested())
        self.assertFalse(self.proxy.fault.is_set())

    def test_runner_requires_explicit_opt_in_before_reading_program_or_creating_evidence(self):
        destination = Path(self.directory.name) / "not-created"
        result = subprocess.run([sys.executable, str(ROOT / "scripts/run-official-tracker-test.py"),
                                 "--toolchain", "1.85.0", "--evidence-dir", str(destination)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--allow-official-tracker", result.stderr)
        self.assertFalse(destination.exists())

    def test_authorized_cut_closes_only_registered_sockets_and_blocks_reconnection(self):
        owned, peer = socket.socketpair()
        unrelated, unrelated_peer = socket.socketpair()
        for connection in [owned, peer, unrelated, unrelated_peer]:
            self.addCleanup(connection.close)
        self.proxy.requests.add(owned)
        self.control.write_text("a" * 64)
        self.assertTrue(self.proxy.activate_fault_if_requested())
        peer.settimeout(1)
        self.assertEqual(peer.recv(1), b"")
        unrelated.sendall(b"x")
        self.assertEqual(unrelated_peer.recv(1), b"x")
        self.assertIsNone(self.proxy.upgrade_metadata_target("CONNECT", "control.verysync.cn:443"))
        self.assertTrue(self.proxy.fault.is_set())


if __name__ == "__main__":
    unittest.main()
