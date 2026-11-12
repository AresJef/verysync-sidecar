"""Real loopback safety/credential controls for the explicit test-only proxy."""
import importlib.util
import json
from pathlib import Path
import socket
import threading
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "run-isolated-engine-tests.py"
SPEC = importlib.util.spec_from_file_location("isolated_engine_tests", SOURCE)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class ProxyContracts(unittest.TestCase):
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
