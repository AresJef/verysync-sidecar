"""Verify the exact firewall control on a fresh owned loopback port."""
import errno
import json
import os
from pathlib import Path
import secrets
import socket
import sys

from run_wan import cut_runner_link

assert os.environ.get("GITHUB_ACTIONS") == "true"
assert os.environ.get("RUNNER_OS") == "Linux"
result = {"only_owned_loopback": True, "exact_rule_removed": False, "recovery_verified": False}

with socket.socket() as server:
    server.bind(("127.0.0.1", 0))
    server.listen(3)
    server.settimeout(2)
    endpoint = server.getsockname()
    with socket.create_connection(endpoint, timeout=2) as original, server.accept()[0] as accepted:
        original.sendall(b"seed")
        assert accepted.recv(4) == b"seed"
        with cut_runner_link(*endpoint, secrets.token_hex(16)):
            try:
                with socket.create_connection(endpoint, timeout=2):
                    raise AssertionError("temporary rule failed to reject new connection")
            except OSError as exc:
                assert exc.errno in (errno.ECONNREFUSED, errno.ECONNRESET)
            accepted.settimeout(3)
            try:
                assert accepted.recv(1) == b""
            except ConnectionResetError:
                pass
            result["initial_socket_closed"] = result["new_connection_rejected"] = True
        result["exact_rule_removed"] = True
        with socket.create_connection(endpoint, timeout=2) as restored, server.accept()[0] as again:
            restored.sendall(b"back")
            assert again.recv(4) == b"back"
            result["recovery_verified"] = True
Path(sys.argv[1]).write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result))
