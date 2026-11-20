"""Verify the exact firewall control on a fresh owned loopback port."""
import errno
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
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
def inventory():
    def ip(*arguments):
        command = ["/usr/sbin/ip", "-j", *arguments]
        return json.loads(subprocess.run(command, capture_output=True, check=True, timeout=5).stdout)
    result = {"passive_only": True, "interface_addresses_disclosed": False}
    for family in (4, 6):
        result[f"default_ipv{family}_route"] = bool(ip(f"-{family}", "route", "show", "default"))
        native = [ipaddress.ip_address(entry["local"])
                  for iface in ip(f"-{family}", "address", "show", "up")
                  for entry in iface.get("addr_info", [])
                  if "local" in entry]
        result[f"assigned_global_ipv{family}"] = any(addr.is_global for addr in native)
        result[f"assigned_nonpublic_link_ipv{family}"] = any(
            not addr.is_global and not addr.is_loopback and not addr.is_link_local for addr in native)
    return result

result["runner_network_inventory"] = inventory()
Path(sys.argv[1]).write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result))
