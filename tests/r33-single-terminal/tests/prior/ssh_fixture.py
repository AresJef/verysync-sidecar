"""Isolated OpenSSH fixture shared by the R33 transport and terminal tests."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import pwd
import shlex
import socket
import subprocess
import sys
import time

from r33_ssh import Destination


SSHD = "/usr/sbin/sshd"


def available_port():
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        return reserve.getsockname()[1]


def generate_pair(path):
    subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    return " ".join(path.with_suffix(".pub").read_text().split()[:2])


def fingerprint(path):
    return subprocess.check_output(["/usr/bin/ssh-keygen", "-lf", str(path.with_suffix(".pub"))],
                                   text=True).split()[1]


@contextmanager
def daemon(root, paused=None):
    root.mkdir(mode=0o700)
    port = available_port()
    ssh_root = root/"sessions"
    ssh_root.mkdir(mode=0o700)
    key = root/"client"
    host = root/"host"
    wrong = root/"wrong"
    user = pwd.getpwuid(os.getuid()).pw_name
    assert user != "root"
    (root/"authorized").write_text("restrict "+generate_pair(key)+"\n")
    (root/"authorized").chmod(0o600)
    host_public = generate_pair(host)
    wrong_public = generate_pair(wrong)
    script = Path(__file__).resolve().parents[1]/"r33_linux_worker.py"
    if paused is None:
        forced = shlex.join([sys.executable, "-B", str(script), "stdio", "--root", str(ssh_root)])
    else:
        shim=script.parent/"tests/hold_ssh_reply.py"
        forced=shlex.join(["/usr/bin/env", f"PYTHONPATH={script.parent}",
                           sys.executable,"-B",str(shim),str(script.parent),str(ssh_root),str(paused)])
    config = root/"sshd.conf"
    config.write_text("\n".join((
        "AddressFamily inet", "ListenAddress 127.0.0.1", f"Port {port}", f"HostKey {host}",
        f"PidFile {root/'sshd.pid'}", f"AuthorizedKeysFile {root/'authorized'}", f"AllowUsers {user}",
        # StrictModes rejects the temporary-root ancestry. This server uses only
        # its own owner-verified 0700 fixture directory and generated files.
        "StrictModes no", "UsePAM no", "PasswordAuthentication no", "KbdInteractiveAuthentication no",
        "AuthenticationMethods publickey", "PermitRootLogin no", "DisableForwarding yes",
        "LogLevel VERBOSE", "LoginGraceTime 12", f"ForceCommand {forced}",
    ))+"\n")
    validated = subprocess.run([SSHD,"-t","-f",str(config)], text=True, capture_output=True)
    if validated.returncode:
        raise RuntimeError(validated.stderr.replace(str(root), "<fixture>"))
    with (root/"sshd.log").open("wb") as server_log:
        server = subprocess.Popen([SSHD,"-D","-e","-f",str(config)], stdin=subprocess.DEVNULL,
                                  stdout=server_log, stderr=server_log, start_new_session=True)
        try:
            for _ in range(40):
                if server.poll() is not None:
                    raise RuntimeError("The isolated SSH service exited before listening.")
                try:
                    with socket.create_connection(("127.0.0.1",port),.15):
                        break
                except OSError:
                    time.sleep(.08)
            else:
                raise RuntimeError("The isolated SSH service did not start.")
            primary = {"host": "127.0.0.1", "port": port, "user": user,
                       "public_key": host_public, "fingerprint": fingerprint(host)}
            mismatch = primary | {"public_key": wrong_public, "fingerprint": fingerprint(wrong)}
            yield Destination.parse(primary), Destination.parse(mismatch), key, ssh_root
        except Exception:
            detail = (root/"sshd.log").read_text(errors="replace").replace(str(root),"<fixture>")
            print(detail[-2600:],file=sys.stderr)
            raise
        finally:
            if server.poll() is None:
                server.terminate()
            server.wait(timeout=6)
