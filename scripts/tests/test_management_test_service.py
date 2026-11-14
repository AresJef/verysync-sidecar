"""Exercise the actual management fixture's binding code without peer packages."""
import ast
import http.server
import json
import os
from pathlib import Path
import socketserver
import stat
import tempfile
import time
import unittest
from unittest import mock


class ManagementBindingTests(unittest.TestCase):
    def test_explicit_loopback_binding_does_not_resolve_hostnames(self):
        source = Path(__file__).resolve().parents[1] / "management-test-service.py"
        parsed = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        server_class = next(
            node for node in parsed.body if isinstance(node, ast.ClassDef) and node.name == "Server"
        )
        namespace = {"http": http, "socketserver": socketserver}
        exec(compile(ast.Module(body=[server_class], type_ignores=[]), str(source), "exec"), namespace)
        with mock.patch("socket.getfqdn", side_effect=AssertionError("reverse DNS is prohibited")):
            with namespace["Server"](("127.0.0.1", 0), http.server.BaseHTTPRequestHandler) as server:
                self.assertEqual(server.server_address[0], "127.0.0.1")
                self.assertGreater(server.server_port, 0)
                self.assertNotEqual(server.server_port, 18886)
                self.assertEqual(server.server_name, "localhost")

    def test_startup_phase_replaces_private_bounded_state(self):
        source = Path(__file__).resolve().parents[1] / "management-test-service.py"
        parsed = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        function = next(
            node for node in parsed.body if isinstance(node, ast.FunctionDef) and node.name == "startup_phase"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            namespace = {"root": root, "os": os, "json": json, "time": time,
                         "startup_started": time.monotonic()}
            exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), namespace)
            for phase in ["loading_crypto", "ready"]:
                namespace["startup_phase"](phase)
                path = root / "management-startup.json"
                state = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(set(state), {"phase", "elapsed_millis"})
                self.assertEqual(state["phase"], phase)
                self.assertGreaterEqual(state["elapsed_millis"], 0)
                self.assertLess(path.stat().st_size, 1024)
                if os.name != "nt":
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertFalse((root / ".management-startup.tmp").exists())


if __name__ == "__main__":
    unittest.main()
