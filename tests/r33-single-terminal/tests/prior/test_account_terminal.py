"""Exercise hidden input, revocation and restart independently of a real account."""

import asyncio
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import socket
import subprocess
import sys
import tempfile
import time

from r33_accounts import private_call
from test_terminal import TMP, Terminal, connect, request


@contextmanager
def provider(folder):
    fixture = Path(__file__).with_name("fake_vendor.py")
    with subprocess.Popen([sys.executable, "-B", str(fixture), str(folder)],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          stdin=subprocess.DEVNULL) as service:
        try:
            assert select.select([service.stdout], [], [], 4)[0]
            assert service.stdout.readline() == b"ACCOUNT_FIXTURE_READY\n"
            yield service
        finally:
            if service.poll() is None:
                service.terminate()
                assert service.wait(4) == 0


def verify_argv(markers, pids):
    argv = subprocess.check_output(
        ["/bin/ps" if sys.platform == "darwin" else "/usr/bin/ps", "-ww",
         "-p", ",".join(map(str, pids)), "-o", "command="])
    assert not any(marker in argv for marker in markers)


def verify_files(markers, paths):
    assert not any(marker in path.read_bytes() for path in paths for marker in markers)


def make_fixture(root):
    directory = root/"provider"
    storage = root/"back"
    directory.mkdir()
    storage.mkdir()
    username = f"r33-fixture-user-{secrets.token_hex(13)}"
    password = f"r33-fixture-pass-{secrets.token_hex(19)}"
    (directory/"expect.json").write_text(json.dumps({
        "username": hashlib.sha256(username.encode()).hexdigest(),
        "password": hashlib.sha256(password.encode()).hexdigest(),
    }))
    target = directory/"account.sock"
    profile = root/"profile.json"
    profile.write_text(json.dumps({
        "pro":{"allow":["observe"], "connection":{"socket":str(target),"recovery":str(storage)}}
    }))
    return directory, storage, target, profile, username.encode(), password.encode()


def start(profile, journal):
    return Terminal(["start","--synthetic","--profile",str(profile),"--evidence",str(journal),
                     "--minutes","5","--executor-uid",str(os.getuid())])


def inspect(target, token):
    return asyncio.run(private_call(target, {"kind":"inspect", "session":token}))


def terminal_exchange(root, mode):
    folder, storage, target, profile, username, password = make_fixture(root)
    journal = root/"broker.jsonl"
    with provider(folder) as service:
        user = start(profile, journal)
        try:
            user.feed(b"START\n")
            user.prompt(b"VerySync account (hidden) ")
            user.feed(username+b"\n")
            user.prompt(b"VerySync password (hidden) ")
            verify_argv((username, password), (user.pid, service.pid))
            assert username not in user.observed and password not in user.observed
            if mode == "interrupt-input":
                began = time.monotonic()
                user.feed(b"\x03")
                end = user.response(b"R33_STOPPED ", 4)
                assert end["local"] == "revoked" and end["pro"]["state"] == "not-enabled"
                assert user.wait(2) in (0,1)
                assert not (folder/"login.json").exists(), "Credential entry was cancelled before login."
                assert not any((item/"session").exists() for item in storage.iterdir())
                assert time.monotonic()-began < 2.0
                return {"scenario":mode, "hidden_fields":2, "provider_login_requests_effect":0,
                        "known_terminal":end, "local_transport_no_login":True}
            user.feed(password+b"\n")
            ready = user.response(b"R33_READY ")
            assert username not in user.observed and password not in user.observed
            run, broker = ready["run"], Path(ready["socket"])
            token_file = storage/run/"session"
            token = token_file.read_text()
            markers = (username, password, token.encode())
            verify_argv(markers, (user.pid, service.pid))

            with connect(broker) as agent:
                assert request(agent, run, "pro", "observe") == {"ok": True, "signed_in": True}
            assert inspect(target,token) == {"ok":True}
            assert token_file.stat().st_mode & 0o077 == 0
            if mode == "offline":
                service.terminate()
                assert service.wait(4) == 0
                assert not target.exists()
            user.feed(b"\x03")
            end = user.response(b"R33_STOPPED ", 12)
            assert user.wait(5) == 0
            assert end["local"] == "revoked" and not broker.exists()
            assert end["pro"]["state"] == ("pending-confirmation" if mode == "offline" else
                                            "synthetic-session-closed"), end
            assert token_file.is_file() == (mode == "offline")
            assert not any(marker in user.observed for marker in markers)
            verify_files(markers, (profile, journal))
        finally:
            user.close()
    recovery = None
    with provider(folder):
        if mode == "offline":
            assert inspect(target, token) == {"ok":True}, "The previous session actually survived the outage."
            recovery_user = Terminal(["recover","--synthetic","--target","pro",
                                      "--profile",str(profile),"--run",run])
            try:
                recovery_user.feed(b"RECOVER\n")
                recovered = recovery_user.response(b"R33_RECOVERY ", 6)
                assert recovered["pro"]["state"] == "synthetic-session-closed"
                assert recovery_user.wait(5) == 0
                recovery = recovered
            finally:
                recovery_user.close()
        assert inspect(target, token) == {"ok":False,"code":"signed-out"}
        assert not token_file.exists()
    with provider(folder):
        assert inspect(target, token) == {"ok":False,"code":"signed-out"}
    verify_files(markers, (profile, journal, folder/"expect.json"))
    assert not (folder/"login.json").exists() and not target.exists()
    return {"scenario": mode, "run":run, "terminal":end, "recovery":recovery,
            "actual_active_before_revocation":True,"old_token_denied_after_restart":True,
            "private_token_removed_after_confirmed_revocation":True,
            "counts_in_allowed_view_argv_pty_and_journal":[0,0,0],
            "provider_socket_absent":True}


def main(mode, output):
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="r33-h5-",dir=TMP) as work:
        root = Path(work).resolve()
        result = terminal_exchange(root, mode)
    result["fixture_directory_absent"] = not root.exists()
    output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main(sys.argv[1], Path(sys.argv[2]))
