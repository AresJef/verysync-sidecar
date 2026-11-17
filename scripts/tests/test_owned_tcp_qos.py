"""Synthetic packet-header contracts are separate from actual CI effects."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("owned_qos", Path(__file__).resolve().parents[1] / "observe-owned-tcp-qos.py")
QOS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QOS)


class OwnedPacketContracts(unittest.TestCase):
    def test_non_ci_or_unelevated_observer_refuses_before_spawning_capture(self):
        for ci, uid in [("false", 0), ("true", 501)]:
            with patch.dict(QOS.os.environ, {"GITHUB_ACTIONS": ci}), patch.object(QOS.os, "geteuid", return_value=uid, create=True), patch.object(QOS.subprocess, "Popen") as spawn:
                with self.assertRaises(ValueError):
                    QOS.observe(32123)
                spawn.assert_not_called()

    def test_only_exact_loopback_target_and_supported_host_are_allowed(self):
        for host, interface in [("darwin", "lo0"), ("linux", "lo")]:
            command = QOS.capture_command(32123, host)
            self.assertEqual(command[command.index("-i")+1], interface)
            self.assertEqual(command[-1], "tcp and src host 127.0.0.1 and dst host 127.0.0.1 and dst port 32123")
            self.assertNotIn("-A", command)
            self.assertNotIn("-X", command)
        for port, host in [(0, "linux"), (18886, "darwin"), (65536, "linux"), (True, "linux"), (32123, "win32")]:
            with self.assertRaises(ValueError):
                QOS.capture_command(port, host)

    def test_actual_data_headers_retain_tos_ports_and_ignore_zero_data_acks(self):
        text = """12:00:00 IP (tos 0x12, ttl 64, id 1, proto TCP (6), length 100)
    127.0.0.1.45678 > 127.0.0.1.32123: Flags [P.], seq 1:49, ack 1, length 48
12:00:01 IP (tos 0x0, ttl 64, id 2, proto TCP (6), length 52)
    127.0.0.1.45678 > 127.0.0.1.32123: Flags [.], ack 49, length 0
"""
        self.assertEqual(QOS.data_headers(text, 32123), [{"tos": 18, "source_port": 45678,
            "destination_port": 32123, "tcp_payload_bytes": 48}])

    def test_missing_data_tos_or_wrong_endpoint_never_becomes_effect_evidence(self):
        for text in ["", "IP (tos 0x10)\n127.0.0.1.45678 > 127.0.0.1.32123: length 0",
                     "127.0.0.1.45678 > 127.0.0.1.32123: length 48",
                     "IP (tos 0x10)\n127.0.0.1.45678 > 127.0.0.1.32124: length 48"]:
            with self.assertRaises(ValueError):
                QOS.data_headers(text, 32123)


if __name__ == "__main__":
    unittest.main()
