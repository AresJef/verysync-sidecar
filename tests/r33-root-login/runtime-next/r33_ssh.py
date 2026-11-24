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
import subprocess


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


def host_key_identity(public_key):
    if type(public_key) is not str or len(public_key) > 2048:
        raise SSHConfigurationError("A valid SSH public host key is required.")
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
    return f"{algorithm} {contents}", actual


def verify_host_key(public_key, fingerprint):
    key, actual = host_key_identity(public_key)
    if actual != fingerprint:
        raise SSHConfigurationError("The SSH host key does not match the confirmed fingerprint.")
    return key


def presented_host_keys(host, port):
    try:
        result = subprocess.run(
            ["/usr/bin/ssh-keyscan", "-T", "5", "-p", str(port),
             "-t", "ed25519,ecdsa,rsa", "--", host],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            encoding="ascii", errors="replace", timeout=8,
            env={"PATH":"/usr/bin:/bin","LANG":"C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SSHConfigurationError("The server's SSH host key could not be obtained.") from error
    for line in result.stdout[:16384].splitlines():
        fields = line.split()
        if len(fields) == 3:
            try:
                yield host_key_identity(" ".join(fields[1:]))
            except SSHConfigurationError:
                pass


def lookup_target(host, port):
    host = validate_host(host)
    if type(port) is not int or not 1 <= port <= 65535:
        raise SSHConfigurationError("Choose an existing valid SSH port.")
    return host


def discover_pinned_key(host, port, fingerprint):
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint):
        raise SSHConfigurationError("Enter the SHA256 host key fingerprint from the trusted console.")
    host = lookup_target(host, port)
    for key, actual in presented_host_keys(host, port):
        if actual == fingerprint:
            return key
    raise SSHConfigurationError("The server did not present the confirmed SSH host key.")


def saved_host_pin(host, port):
    canonical = lookup_target(host, port)
    candidates = set()
    authority_record = False
    # Keep OpenSSH's handling of hashed host names, aliases, and port-specific entries.
    for name in dict.fromkeys((host, canonical)):
        target = name if port == 22 else f"[{name}]:{port}"
        for source in (Path.home()/".ssh"/"known_hosts", Path.home()/".ssh"/"known_hosts2"):
            if not source.is_file():
                continue
            try:
                result = subprocess.run(
                    ["/usr/bin/ssh-keygen", "-F", target, "-f", str(source)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    encoding="ascii", errors="replace", timeout=4,
                    env={"PATH":"/usr/bin:/bin","LANG":"C"},
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise SSHConfigurationError("The saved SSH host keys could not be checked.") from error
            for line in result.stdout.splitlines():
                fields = line.split()
                if not fields or fields[0].startswith("#"):
                    continue
                if fields[0] == "@revoked":
                    raise SSHConfigurationError("The saved SSH identity for this target has been revoked.")
                if fields[0] == "@cert-authority":
                    authority_record = True
                if len(fields) < 3 or fields[0].startswith("@"):
                    continue
                try:
                    candidates.add(host_key_identity(" ".join(fields[1:3])))
                except SSHConfigurationError:
                    pass
    if authority_record and not candidates:
        raise SSHConfigurationError("This server uses a saved SSH certificate authority. A raw-key handoff is unavailable.")
    if len(candidates) < 2:
        return next(iter(candidates), None)
    for identity in presented_host_keys(canonical, port):
        if identity in candidates:
            return identity
    raise SSHConfigurationError("The server's SSH host key no longer matches the saved identities.")


def first_host_pin(host, port):
    canonical = lookup_target(host, port)
    choices = dict(presented_host_keys(canonical, port))
    for algorithm in ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"):
        for key, fingerprint in choices.items():
            if key.startswith(algorithm + " "):
                return key, fingerprint
    raise SSHConfigurationError("The SSH server did not present a supported host key. Check the address and port.")


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
    trust_source: str = "explicit-pin"

    @classmethod
    def parse(cls, data, *, allow_root=False):
        allowed = {"host", "port", "user", "public_key", "fingerprint"}
        if type(data) is not dict or not allowed <= set(data) <= allowed | {"trust_source"}:
            raise SSHConfigurationError("The SSH destination has unexpected fields.")
        port, user = data["port"], data["user"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise SSHConfigurationError("Choose an existing valid SSH port.")
        if type(user) is not str or not USER.fullmatch(user) or (user == "root" and not allow_root):
            raise SSHConfigurationError("This foreground scope does not accept the SSH login name.")
        source = data.get("trust_source", "explicit-pin")
        if source not in ("explicit-pin", "saved", "first-use"):
            raise SSHConfigurationError("The SSH identity approval mode is invalid.")
        return cls(validate_host(data["host"]), port, user,
                   verify_host_key(data["public_key"], data["fingerprint"]), data["fingerprint"],source)

    def command(self, runtime, identity=None, *, remote_entry=REMOTE_ENTRY):
        if self.user == "root" and (identity is not None or remote_entry == REMOTE_ENTRY):
            raise SSHConfigurationError("The root login requires the fixed password-only foreground bootstrap.")
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
