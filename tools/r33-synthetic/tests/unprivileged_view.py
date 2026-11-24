"""Inspect this synthetic grant with the OS identity actually supplied by sudo."""

import errno
import json
import os
from pathlib import Path
import socket
import sys
import uuid


def cannot_read(path):
    try:
        Path(path).read_bytes()
    except PermissionError:
        return True
    return False


def cannot_open_private_socket(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as private:
        try:
            private.connect(path)
        except PermissionError:
            return True
    return False


def query(socket_path, run, target, operation):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(2)
        stream.connect(socket_path)
        command = {"run":run,"target":target,"operation":operation,"request":uuid.uuid4().hex}
        try:
            stream.sendall((json.dumps(command)+"\n").encode("ascii"))
        except OSError as error:
            if error.errno != errno.EPIPE:
                raise
        with stream.makefile("rb") as replies:
            return json.loads(replies.readline())


if __name__ == "__main__":
    endpoint, run, key, cookie, backend = sys.argv[1:]
    allowed = query(endpoint, run, "pro", "observe")
    rejected = query(endpoint, run, "linux", "observe")
    wrong_run = query(endpoint, "0"*32, "pro", "observe")
    stop = query(endpoint, run, "handoff", "stop")
    print(json.dumps({
        "actual_uid":os.getuid(), "allowed":allowed,
        "wrong_scope_denied":rejected=={"ok":False,"code":"denied"},
        "wrong_run_denied":wrong_run=={"ok":False,"code":"denied"},
        "operator_stop_denied":stop=={"ok":False,"code":"denied"},
        "synthetic_key_read_denied":cannot_read(key), "synthetic_cookie_read_denied":cannot_read(cookie),
        "private_service_connect_denied":cannot_open_private_socket(backend),
    }))
