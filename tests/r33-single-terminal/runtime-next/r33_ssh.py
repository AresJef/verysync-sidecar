"""Build one host-key-pinned OpenSSH channel for the owned test service."""

from dataclasses import dataclass
from pathlib import Path
import base64
import binascii
import hashlib
import ipaddress
import os
import re
import stat
import struct


REMOTE_ENTRY = (
    'exec /usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin '
    '/usr/bin/python3 -B "$HOME/.local/share/verysync-r33/r33_linux_worker.py" stdio'
)
HOST_ALIAS = "verysync-r33-designated-peer"
HOST_KEY_TYPES = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
                  "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
USER = re.compile(r"[a-z_][a-z0-9_.-]{0,31}\Z", re.ASCII)
DNS_COMPONENT = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z", re.ASCII)


class SSHConfigurationError(ValueError):
    pass


def validate_host(value):
    if type(value) is not str or not 0 < len(value) <= 253 or "%" in value:
        raise SSHConfigurationError("Enter a valid address or host name.")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not all(DNS_COMPONENT.fullmatch(piece) for piece in value.rstrip(".").split(".")):
            raise SSHConfigurationError("Enter a valid address or host name.")
        return value


def verify_host_key(public_key, fingerprint):
    if type(public_key) is not str or type(fingerprint) is not str or len(public_key) > 2048:
        raise SSHConfigurationError("A public key and its confirmed fingerprint are required.")
    atoms = public_key.split()
    if len(atoms) != 2 or atoms[0] not in HOST_KEY_TYPES:
        raise SSHConfigurationError("Enter the two fields of the server's public host key.")
    algorithm, contents = atoms
    try:
        wire = base64.b64decode(contents, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SSHConfigurationError("The server public key is invalid.") from exc
    prefix = struct.pack("!I", len(algorithm)) + algorithm.encode("ascii")
    if not wire.startswith(prefix) or len(wire) <= len(prefix):
        raise SSHConfigurationError("The server public key is invalid.")
    if base64.b64encode(wire).decode("ascii") != contents:
        raise SSHConfigurationError("The server public key is invalid.")
    actual = "SHA256:" + base64.b64encode(hashlib.sha256(wire).digest()).decode("ascii").rstrip("=")
    if actual != fingerprint:
        raise SSHConfigurationError("The SSH host key does not match the confirmed fingerprint.")
    return f"{algorithm} {contents}"


def private_identity(path):
    if not path.is_absolute() or path.is_symlink():
        raise SSHConfigurationError("Choose an absolute path to a private identity file.")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise SSHConfigurationError("The SSH identity must be private and owned by the operator.")
    return path


@dataclass(frozen=True)
class Destination:
    host: str
    port: int
    user: str
    public_key: str
    fingerprint: str

    @classmethod
    def parse(cls, data):
        allowed = {"host", "port", "user", "public_key", "fingerprint"}
        if type(data) is not dict or set(data) != allowed:
            raise SSHConfigurationError("The SSH destination has unexpected fields.")
        port, user = data["port"], data["user"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise SSHConfigurationError("Choose an existing valid SSH port.")
        if type(user) is not str or not USER.fullmatch(user) or user == "root":
            raise SSHConfigurationError("Choose the dedicated non-root SSH account.")
        return cls(validate_host(data["host"]), port, user,
                   verify_host_key(data["public_key"], data["fingerprint"]), data["fingerprint"])

    def command(self, runtime, identity=None, *, remote_entry=REMOTE_ENTRY):
        host_file = runtime/"pinned-host-key"
        with host_file.open("x", encoding="ascii") as stream:
            stream.write(f"{HOST_ALIAS} {self.public_key}\n")
        options = {
            "BatchMode": "yes" if identity else "no",
            "StrictHostKeyChecking": "yes",
            "UserKnownHostsFile": str(host_file),
            "GlobalKnownHostsFile": "/dev/null",
            "HostKeyAlias": HOST_ALIAS,
            "UpdateHostKeys": "no",
            "ControlMaster": "no",
            "ControlPersist": "no",
            "ControlPath": "none",
            "IdentityAgent": "none",
            "IdentitiesOnly": "yes",
            "ClearAllForwardings": "yes",
            "ForwardAgent": "no",
            "ForwardX11": "no",
            "PermitLocalCommand": "no",
            "ConnectTimeout": "8",
            "ConnectionAttempts": "1",
            "ServerAliveInterval": "8",
            "ServerAliveCountMax": "2",
            "NumberOfPasswordPrompts": "1",
            "PreferredAuthentications": "publickey" if identity else "password",
            "LogLevel": "ERROR",
            "KbdInteractiveAuthentication": "no",
        }
        command = ["/usr/bin/ssh", "-F", "/dev/null", "-T"]
        for key, value in options.items():
            command.extend(("-o", f"{key}={value}"))
        if identity:
            command.extend(("-i", str(private_identity(identity))))
        else:
            command.extend(("-o", "PubkeyAuthentication=no"))
        command.extend(("-p", str(self.port), "-l", self.user, "--", self.host, remote_entry))
        return command
