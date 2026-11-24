"""Exercise the password-only root login in a disposable Linux container."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch


TESTS = Path(__file__).resolve().parent
RUNTIME = TESTS.parent / "runtime-next"
sys.path[:0] = [str(RUNTIME), str(TESTS / "prior")]

from r33_protocol import DENIED
from r33_ssh import SSHConfigurationError, discover_pinned_key
from r33_single import LINUX_ALLOWED, linux_destination
import test_terminal
from test_terminal import Terminal, connect, request


test_terminal.BUNDLE = RUNTIME


@contextmanager
def disposable_sshd(directory, password):
    if (not Path("/.dockerenv").is_file() or os.getuid() != 0
            or os.environ.get("R33_DISPOSABLE_ROOT_PROBE") != "local-synthetic-container"):
        raise RuntimeError("Use the dedicated disposable Linux container for this probe.")
    Path("/run/sshd").mkdir(exist_ok=True)
    subprocess.run(["/usr/sbin/chpasswd"], input=b"root:" + password + b"\n", check=True)
    host = directory / "host"
    subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host)], check=True)
    fingerprint = subprocess.check_output(["/usr/bin/ssh-keygen", "-lf", str(host) + ".pub"],
                                          text=True).split()[1]
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config = directory / "sshd"
    config.write_text("\n".join((
        "AddressFamily inet", "ListenAddress 127.0.0.1", f"Port {port}", f"HostKey {host}",
        f"PidFile {directory / 'pid'}", "UsePAM no", "PasswordAuthentication yes", "PermitRootLogin yes",
        "KbdInteractiveAuthentication no", "PubkeyAuthentication no", "AuthenticationMethods password",
        "DisableForwarding yes", "PermitTTY no", "LogLevel VERBOSE", "AllowUsers root",
    )) + "\n")
    subprocess.run(["/usr/sbin/sshd", "-t", "-f", str(config)], check=True)
    transcript = directory / "sshd.log"
    with transcript.open("wb") as stream:
        server = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
                                  stdout=stream, stderr=stream, stdin=subprocess.DEVNULL)
        try:
            stop = time.monotonic() + 6
            while not (directory / "pid").is_file():
                assert server.poll() is None and time.monotonic() < stop
                time.sleep(0.03)
            try:
                discover_pinned_key("127.0.0.1", port, "SHA256:" + "A" * 43)
            except SSHConfigurationError:
                pass
            else:
                raise AssertionError("An incorrect trust fingerprint was accepted.")
            key = discover_pinned_key("127.0.0.1", port, fingerprint)
            yield {"host":"127.0.0.1","port":port,"user":"root","public_key":key,
                   "fingerprint":fingerprint}, transcript
        finally:
            server.terminate()
            server.wait(timeout=7)


def peer_processes(directory):
    needle = os.fsencode(directory) + b"/"
    for process in Path("/proc").glob("[0-9]*"):
        try:
            arguments = (process / "cmdline").read_bytes().split(b"\x00")
            if b"guard" in arguments and any(item.startswith(needle) for item in arguments):
                status = dict(row.split(":",1) for row in (process / "status").read_text().splitlines()
                              if ":" in row)
                yield status
        except (FileNotFoundError, PermissionError):
            continue


@contextmanager
def local_operator(base):
    account = pwd.getpwnam("daemon")
    uid, gid = account.pw_uid, account.pw_gid
    assert uid > 0 and gid > 0
    base.mkdir(mode=0o700)
    os.chown(base,uid,gid)
    groups = os.getgroups()
    home = os.environ.get("HOME")
    os.setgroups([])
    os.setresgid(gid,gid,0)
    os.setresuid(uid,uid,0)
    os.environ["HOME"] = str(base)
    try:
        yield
    finally:
        os.setresuid(0,0,0)
        os.setresgid(0,0,0)
        os.setgroups(groups)
        if home is None:
            os.environ.pop("HOME",None)
        else:
            os.environ["HOME"] = home


def exercise(base,destination,password,mode):
    assert os.getuid()>0
    host, port = destination["host"], destination["port"]
    if mode == "STOP":
        trust = base/".ssh"
        trust.mkdir(mode=0o700)
        saved = trust/"known_hosts"
        saved.write_text(f"[{host}]:{port} {destination['public_key']}\n")
        subprocess.run(["/usr/bin/ssh-keygen","-q","-H","-f",str(saved)],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        assert saved.read_text().startswith("|1|")
    with patch("builtins.input",side_effect=[host,str(port),"root"]) as prompts:
        selected = linux_destination()
    source = "saved" if mode == "STOP" else "first-use"
    assert prompts.call_count == 3 and selected == destination | {"trust_source":source}
    profile = base / "profile.json"
    profile.write_text(json.dumps({"linux":{"connection":selected,"allow":sorted(LINUX_ALLOWED)}}))
    tape = base / "tape.jsonl"
    user = Terminal(["start","--synthetic","--executor-uid",str(os.getuid()),"--profile",str(profile),
                     "--evidence",str(tape),"--expires-at",str(int(time.time()) + 150)])
    try:
        user.prompt(b"Type START to grant these operations.",timeout=12)
        user.feed(b"START\n")
        user.prompt(b"password:",timeout=12)
        user.feed(password + b"\n")
        ready = user.response(b"R33_READY ",12)
        run, endpoint = ready["run"], Path(ready["socket"])
        worker = Path("/tmp") / ("r33-root-" + run)
        nobody = pwd.getpwnam("nobody")
        with connect(endpoint) as active:
            def call(operation):
                return request(active,run,"linux",operation)
            status = call("observe")
            assert status["standby"] and status["native_test_listeners"] == 0
            assert [status["worker_uid"],status["worker_gid"]] == [nobody.pw_uid,nobody.pw_gid]
            identity, = peer_processes(worker)
            assert list(map(int,identity["Uid"].split())) == [nobody.pw_uid] * 4
            assert list(map(int,identity["Gid"].split())) == [nobody.pw_gid] * 4
            assert not identity["Groups"].split()
            assert (worker.stat().st_uid,worker.stat().st_mode & 0o777) == (nobody.pw_uid,0o700)
            if mode == "STOP":
                due = time.monotonic() + 40
                while status["renewals"] < 2 and time.monotonic() < due:
                    time.sleep(.4)
                    status = call("observe")
                assert status["renewals"] >= 2 and status["standby"]
            samples = []
            for _ in range(2):
                assert call("start-observer")["running"]
                assert call("observe")["tasks"] == 1
                time.sleep(.45)
                result = call("finish-observer")
                assert result.get("standby") and result["normal_task_exit"], result
                size = result["sample_bytes"]
                assert size > 0 and size % 5 == 0
                assert result["sample_sha256"] == hashlib.sha256(b"tick\n" * (size//5)).hexdigest()
                assert call("observe")["standby"]
                samples.append(result["sample_bytes"])
            assert call("start-observer")["running"]
            time.sleep(.45)
            begin = time.monotonic()
            user.feed(b"STOP\n" if mode == "STOP" else b"\x03")
            while request(active,run,"handoff","status")["local"] == "active":
                assert time.monotonic() - begin < 1
                time.sleep(.01)
            assert call("write-sample") == DENIED
            observed_ms = round((time.monotonic()-begin)*1000,3)
        assert observed_ms <= 1000
        stopped = user.response(b"R33_STOPPED ",14)
        assert stopped["linux"] == {"state":"stopped","writes":0,"owned_worker_directory_removed":True}
        assert user.wait(8) == 0
        cutoff = time.monotonic() + 4
        while worker.exists() and time.monotonic() < cutoff:
            time.sleep(.05)
        assert not worker.exists() and not endpoint.parent.exists() and not list(peer_processes(worker))
        exposed = [user.observed,tape.read_bytes()]
        assert all(password not in evidence for evidence in exposed)
        assert user.observed.count(b"password:") == 1
        return {"mode":mode,"ssh_password_prompts":1,"root_authentications":1,
                "worker_uid":nobody.pw_uid,"worker_gid":nobody.pw_gid,
                "same_connection_cycles":2,"renewals_observed":status["renewals"],
                "sample_lengths":samples,"old_request_refused_ms":observed_ms,
                "zero_worker_and_owned_directory":True,"non_secret_logs":True,
                "isolated_container":True,"incorrect_host_fingerprint_refused":True,
                "visible_linux_values":3,"trust_source":source}
    except Exception:
        no_secret = user.observed.replace(password,b"[redacted]")
        print("R33_ROOT_FIXTURE_TERMINAL " + json.dumps(no_secret[-1500:].decode(errors="replace")),
              flush=True)
        raise
    finally:
        user.close()


def probe(mode):
    with tempfile.TemporaryDirectory(prefix="r33-root-probe-", dir="/tmp") as work:
        base = Path(work)
        unrelated = base / "outside"
        unrelated.write_bytes(b"independent synthetic sentinel")
        password = ("synthetic-root-" + secrets.token_hex(24)).encode()
        with disposable_sshd(base,password) as (destination, transcript):
            base.chmod(0o711)
            client = base / "client"
            with local_operator(client):
                report = exercise(client,destination,password,mode)
            ssh_log = transcript.read_bytes()
            assert password not in ssh_log
            assert ssh_log.count(b"Accepted password for root") == 1
            assert unrelated.read_bytes() == b"independent synthetic sentinel"
            return report


if __name__ == "__main__":
    os.umask(0o077)
    for mode in ("STOP","Ctrl+C"):
        print("R33_ROOT_SSH " + json.dumps(probe(mode),sort_keys=True),flush=True)
