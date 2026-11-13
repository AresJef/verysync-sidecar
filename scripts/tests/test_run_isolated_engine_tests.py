"""Real loopback safety/credential controls for the explicit test-only proxy."""
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler

SOURCE = Path(__file__).resolve().parents[1] / "run-isolated-engine-tests.py"
SPEC = importlib.util.spec_from_file_location("isolated_engine_tests", SOURCE)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class ProxyContracts(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
