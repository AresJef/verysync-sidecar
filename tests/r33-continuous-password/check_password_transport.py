"""Exercise the exact combined bootstrap over a single disposable password login."""

import asyncio
import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import signal
import socket
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from zipfile import ZipFile, ZipInfo

from r33_linux_qualification_bootstrap import ROLE_FILES
from r33_linux_qualification_session import LinuxForeground, LinuxQualification
from r33_ssh import host_key_identity

HERE = Path(__file__).resolve()
ROLE_PROGRAM = b'''
import json, os, sys

fixed = b"fixture bytes, no native executable"
if "--run" in sys.argv:
    engine = sys.argv[sys.argv.index("--engine") + 1]
    run = sys.argv[sys.argv.index("--run") + 1]
    expires = int(sys.argv[sys.argv.index("--expires") + 1])
    role = "live"
    ready = "local-api-foreground-ready"
else:
    _, operation, directory, run, raw = sys.argv
    engine = directory + "/verysync-v2.33.2"
    expires = int(raw)
    role = "native-target"
    ready = "native-gateway-foreground-ready"
assert open(engine, "rb").read() == fixed

def publish(event, **values):
    print(json.dumps({"event": event, "run": run, **values}, separators=(",",":")), flush=True)

publish(ready, deadline=expires, role_pid=os.getpid())
for line in sys.stdin:
    request = json.loads(line)
    assert request["run"] == run
    if request["kind"] == "renew":
        continue
    if request["kind"] == "stop":
        publish("local-api-foreground-stopped")
        publish("local-api-cleanup", private_state_removed=True)
        break
    assert request["kind"] == "execute"
    publish("operation-observed", request=request["request"],
            native={"role": role, "role_pid": os.getpid()})
'''


class FixtureGateway(LinuxQualification):
    ready_event = "native-gateway-foreground-ready"
    live_scope = "native-target"


async def through_password(root, spec):
    run = secrets.token_hex(16)
    source = root / "synthetic-stage.zip"
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    expires = int(time.time()) + 45
    foreground, _ = await LinuxForeground.open(
        spec, root, HERE.with_name("r33_linux_qualification_bootstrap.py"), source, digest, run, expires,
    )
    stop = asyncio.Event()
    pids = []
    try:
        # The exact root bootstrap reads both children from the prepared ZIP.
        for worker in (LinuxQualification, FixtureGateway):
            child, ready = await foreground.begin(worker, stop)
            pids.append(ready["role_pid"])
            reply = await child.execute("inspect")
            assert reply == {"role": worker.live_scope, "role_pid": pids[-1]}
            assert child.child is foreground.session.child
            ended = await child.stop()
            assert ended["cleanup"]["private_state_removed"]
            assert foreground.session.child.returncode is None
        assert len(set(pids)) == 2
        print("Both staged roles used the same SSH connection.", flush=True)
        if input().strip() != "STOP":
            raise ValueError("Expected the fixture stop signal.")
    finally:
        cleanup = await foreground.stop()
    assert cleanup["ssh_exit"] == 0 and cleanup["staging"]["temporary_programs_removed"]
    print("R33_SYNTHETIC_PASSWORD_STOPPED", flush=True)


def write_bundle(target):
    files = {"verysync-v2.33.2": b"fixture bytes, no native executable"}
    for _, (folder, names) in ROLE_FILES.items():
        for name in names - {"verysync-v2.33.2"}:
            files[f"{folder}/{name}"] = (
                ROLE_PROGRAM if name in {"run_local_api_scope.py", "r33_gateway_target.py"} else b"fixture"
            )
    with ZipFile(target, "x") as archive:
        for name, contents in sorted(files.items()):
            member = ZipInfo(name)
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(member, contents)


def drive_terminal(root, spec, password):
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execv(sys.executable, [sys.executable, "-B", str(HERE), "--fixture", str(root), json.dumps(spec)])
    history = bytearray()
    reaped = False

    def wait_for(marker):
        deadline = time.monotonic() + 12
        while marker not in history:
            if not select.select([descriptor], [], [], max(0, deadline - time.monotonic()))[0]:
                raise ValueError(f"Missing the fixture terminal marker {marker!r}.")
            try:
                block = os.read(descriptor, 4096)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                block = b""
            if not block:
                safe = bytes(history).replace(password, b"[redacted]")
                raise ValueError(f"Fixture stopped before {marker!r}: {safe[-1600:]!r}.")
            history.extend(block)

    try:
        wait_for(b"'s password:")
        os.write(descriptor, password + b"\n")
        wait_for(b"Both staged roles used the same SSH connection.")
        os.write(descriptor, b"STOP\n")
        wait_for(b"R33_SYNTHETIC_PASSWORD_STOPPED")
        _, status = os.waitpid(pid, 0)
        reaped = True
        assert os.waitstatus_to_exitcode(status) == 0
        assert history.count(b"'s password:") == 1
        assert password not in history
    finally:
        if not reaped:
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
        os.close(descriptor)


def check(root):
    if (sys.platform != "linux" or os.getuid() != 0 or not Path("/.dockerenv").is_file()
            or os.environ.get("R33_FOREGROUND_PASSWORD_TEST") != "isolated-linux-container"):
        raise ValueError("Run only in the disposable Linux test container.")
    contents_before = set(Path("/tmp").glob("r33-la-staging-*"))
    password = secrets.token_hex(20).encode("ascii")
    subprocess.run(["/usr/sbin/chpasswd"], input=b"root:" + password + b"\n", check=True, timeout=5)
    Path("/run/sshd").mkdir(exist_ok=True)
    host = root / "fixture-host"
    subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host)],
                   check=True, timeout=5)
    public, fingerprint = host_key_identity(" ".join(host.with_suffix(".pub").read_text().split()[:2]))
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    configuration = root / "sshd_config"
    configuration.write_text("\n".join((
        "AddressFamily inet", "ListenAddress 127.0.0.1", f"Port {port}", f"HostKey {host}",
        f"PidFile {root / 'sshd.pid'}", "UsePAM no", "PasswordAuthentication yes",
        "PermitRootLogin yes", "KbdInteractiveAuthentication no", "PubkeyAuthentication no",
        "AuthenticationMethods password", "DisableForwarding yes", "PermitTTY no",
        "LogLevel VERBOSE", "LoginGraceTime 12", "AllowUsers root",
    )) + "\n")
    write_bundle(root / "synthetic-stage.zip")
    log_path = root / "sshd.log"
    with log_path.open("wb") as log:
        daemon = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(configuration)],
                                  stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while b"Server listening on 127.0.0.1 " not in log_path.read_bytes():
                if daemon.poll() is not None or time.monotonic() >= deadline:
                    raise ValueError("The isolated SSH service did not start.")
                time.sleep(0.04)
            drive_terminal(root, {"host": "127.0.0.1", "port": port, "user": "root",
                                  "public_key": public, "fingerprint": fingerprint}, password)
        finally:
            daemon.terminate()
            daemon.wait(timeout=6)
    accepted = len(re.findall(rb"Accepted password for root from 127\.0\.0\.1 port ", log_path.read_bytes()))
    assert accepted == 1
    assert set(Path("/tmp").glob("r33-la-staging-*")) == contents_before
    return {"fixture": "Linux AMD64 disposable container", "open_ssh_password_authentications": accepted,
            "password_prompts": 1, "password_echoes": 0, "both_roles_used_one_connection": True,
            "remote_staging_removed": True, "ssh_daemon_stopped": True,
            "official_account_calls": 0, "native_engine_used": False}


if __name__ == "__main__":
    os.umask(0o077)
    if sys.argv[1:2] == ["--fixture"]:
        asyncio.run(through_password(Path(sys.argv[2]), json.loads(sys.argv[3])))
    else:
        with TemporaryDirectory(prefix="r33-password-fixture-") as directory:
            result = check(Path(directory))
        assert not Path(directory).exists()
        print(json.dumps(result | {"fixture_root_removed": True}, sort_keys=True))
