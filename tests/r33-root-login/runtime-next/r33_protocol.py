"""Framing, kernel peer identity and leases for the restricted R33 handoff."""

from dataclasses import dataclass
import ctypes
import json
import re
import socket
import struct
import sys
import time


FRAME_MAX = 4096
HEARTBEAT_SECONDS = 15
LEASE_SECONDS = 90
DENIED = {"ok": False, "code": "denied"}

LABEL = re.compile(r"[a-z][a-z0-9-]{0,39}\Z", re.ASCII)
RUN = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
REQUEST_ID = re.compile(r"[A-Za-z0-9]{16,32}\Z", re.ASCII)


class ProtocolError(ValueError):
    pass


class OperatorCancelled(Exception):
    """The operator stopped before a new private request was submitted."""


class BackendStartupError(Exception):
    """Startup submitted a request whose result needs to be reported."""

    def __init__(self, receipt):
        super().__init__("The private handoff could not confirm startup.")
        self.receipt = receipt


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ProtocolError("Duplicate field.")
        result[name] = value
    return result


def reject_constant(_value):
    raise ProtocolError("Invalid numeric value.")


def decode_frame(line):
    if not line or not line.endswith(b"\n") or len(line) > FRAME_MAX:
        raise ProtocolError("Invalid frame.")
    try:
        obj = json.loads(line.decode("utf-8"), object_pairs_hook=unique_object,
                         parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ProtocolError("Invalid JSON.") from exc
    if type(obj) is not dict:
        raise ProtocolError("Expected an object.")
    return obj


def encode_frame(obj):
    try:
        line = json.dumps(obj, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii") + b"\n"
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProtocolError("Invalid response.") from exc
    if len(line) > FRAME_MAX:
        raise ProtocolError("Frame exceeds the limit.")
    return line


@dataclass(frozen=True)
class Request:
    run: str
    target: str
    operation: str
    request: str

    @classmethod
    def parse(cls, value):
        if set(value) != {"run", "target", "operation", "request"}:
            raise ProtocolError("Unexpected request fields.")
        for key, shape in (("run", RUN), ("target", LABEL), ("operation", LABEL),
                           ("request", REQUEST_ID)):
            if type(value[key]) is not str or not shape.fullmatch(value[key]):
                raise ProtocolError("Invalid request field.")
        return cls(**value)


def peer_identity(connection):
    """Use the Unix socket's authenticated operating-system identity."""
    if not connection or connection.family != socket.AF_UNIX:
        raise OSError("A Unix peer credential is required.")
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        method = libc.getpeereid
        method.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint),
                           ctypes.POINTER(ctypes.c_uint)]
        method.restype = ctypes.c_int
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        if method(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            raise OSError(ctypes.get_errno(), "Could not read peer credentials.")
        return uid.value, gid.value
    if sys.platform.startswith("linux"):
        shape = struct.Struct("iII")
        creds = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, shape.size)
        return tuple(shape.unpack(creds)[1:])
    raise OSError("Peer credentials are unavailable on this platform.")


def peer_uid(connection):
    return peer_identity(connection)[0]


class Lease:
    def __init__(self, lifetime=LEASE_SECONDS, now=None):
        when = time.monotonic() if now is None else now
        self.lifetime = lifetime
        self.last_renewed = when
        self.deadline = when + lifetime
        self.revoked_at = None
        self.reason = None

    def permits(self, when):
        if self.revoked_at is None and when >= self.deadline:
            self.revoke(self.deadline, "expired")
        return self.revoked_at is None

    def renew(self, when):
        if not self.permits(when):
            return False
        self.last_renewed = when
        self.deadline = when + self.lifetime
        return True

    def revoke(self, when, reason):
        if self.revoked_at is not None:
            return False
        self.revoked_at, self.reason = when, reason
        return True
