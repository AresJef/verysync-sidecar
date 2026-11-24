"""Check the detached root-authenticated lease after unexpected connection loss."""

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import sys
import tempfile
import time
from unittest.mock import patch

from test_root_password import disposable_sshd, local_operator, peer_processes, Terminal, connect, request
from r33_single import LINUX_ALLOWED, linux_destination


def disconnect(terminal, mode):
    if mode == "foreground-kill":
        command = (Path("/proc")/str(terminal.pid)/"cmdline").read_bytes().split(b"\0")
        assert any(arg.endswith(b"/runtime-next/r33_handoff.py") for arg in command)
        os.kill(terminal.pid, signal.SIGKILL)
        return
    children = Path(f"/proc/{terminal.pid}/task/{terminal.pid}/children").read_text().split()
    ssh = [int(pid) for pid in children if os.readlink(f"/proc/{pid}/exe") == "/usr/bin/ssh"]
    assert len(ssh) == 1, children
    os.kill(ssh[0], signal.SIGKILL)


def start(client, destination, password, mode):
    with patch("builtins.input", side_effect=[destination["host"], str(destination["port"]), "root"]):
        linux = linux_destination()
    profile = client/"profile.json"
    profile.write_text(json.dumps({"linux":{"connection":linux,"allow":sorted(LINUX_ALLOWED)}}))
    journal = client/"journal.jsonl"
    terminal = Terminal(["start","--synthetic","--executor-uid",str(os.getuid()),"--profile",str(profile),
                         "--evidence",str(journal),"--expires-at",str(int(time.time())+180)])
    try:
        terminal.prompt(b"Type START to grant these operations.",timeout=12)
        terminal.feed(b"START\n")
        terminal.prompt(b"'s password:",timeout=12)
        terminal.feed(password+b"\n")
        ready = terminal.response(b"R33_READY ",12)
        run, endpoint = ready["run"], Path(ready["socket"])
        assert re.fullmatch("[a-f0-9]{32}",run)
        assert re.fullmatch(r"/tmp/r33-client-[a-z0-9_]{8}/b\.sock",str(endpoint))
        with connect(endpoint) as broker:
            deadline = time.monotonic()+28
            peer = request(broker,run,"linux","observe")
            while peer["renewals"] < 1:
                assert time.monotonic() < deadline
                time.sleep(.3)
                peer = request(broker,run,"linux","observe")
            assert peer["standby"] and peer["worker_uid"] > 0
            assert request(broker,run,"linux","start-observer")["running"]
            time.sleep(.45)
            assert request(broker,run,"linux","observe")["tasks"] == 1
        assert password not in terminal.observed and password not in journal.read_bytes()
        disconnect(terminal,mode)
        return terminal,run,endpoint
    except BaseException:
        terminal.close()
        raise


def observe_expiry(worker, run):
    directory = worker/"s"/run
    receipt = directory/"receipt.json"
    sample = directory/"observer-sample"
    before = sample.read_bytes()
    assert before
    end = time.monotonic()+98
    while not receipt.exists() and time.monotonic() < end:
        time.sleep(.15)
    observed = json.loads(receipt.read_text())
    assert observed["state"] == "revoked" and observed["reason"] == "expired"
    assert observed["tasks"] == 0 and observed["normal_task_exit"] and observed["renewals"] >= 1
    elapsed = observed["stopped"]-observed["renewed"]
    assert 0 < elapsed <= 95, elapsed
    after = sample.read_bytes()
    time.sleep(.42)
    assert after == sample.read_bytes() and after.startswith(before)
    assert after == b"tick\n"*(len(after)//5)
    deadline = time.monotonic()+5
    while list(peer_processes(worker)) and time.monotonic() < deadline:
        time.sleep(.1)
    assert not list(peer_processes(worker))
    return {"seconds_from_last_renewal":round(elapsed,3),
            "remote_reason":observed["reason"],"normal_task_exit":True,
            "sample_writes_stopped":True,"remote_guard_exited":True,
            "sample_bytes":len(after),"sample_sha256":hashlib.sha256(after).hexdigest()}


def main(mode):
    if mode not in {"ssh-loss","foreground-kill"}:
        raise ValueError("Choose one deliberate withdrawal fixture.")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="r33-root-loss-", dir="/tmp") as work:
        root = Path(work)
        outside = root/"outside"
        outside.write_bytes(b"kept")
        secret = ("synthetic-root-"+secrets.token_hex(24)).encode()
        with disposable_sshd(root,secret) as (destination,sshd_log):
            root.chmod(0o711)
            client = root/"client"
            with local_operator(client):
                terminal,run,endpoint = start(client,destination,secret,mode)
            try:
                report = observe_expiry(Path("/tmp")/("r33-root-"+run),run)
                if mode == "ssh-loss":
                    terminal.feed(b"STOP\n")
                    stopped = terminal.response(b"R33_STOPPED ",12)
                    assert stopped["local"] == "revoked"
                else:
                    assert terminal.wait(8) == -signal.SIGKILL
                assert outside.read_bytes() == b"kept"
                assert sshd_log.read_bytes().count(b"Accepted password for root") == 1
                assert secret not in sshd_log.read_bytes() and secret not in terminal.observed
                shutil.rmtree(Path("/tmp")/("r33-root-"+run))
                if endpoint.parent.exists():
                    shutil.rmtree(endpoint.parent)
                print("R33_ROOT_LEASE_LOSS "+json.dumps(report | {"mode":mode,
                      "expired_fixture_collected_in_container":True},sort_keys=True),flush=True)
            finally:
                terminal.close()


if __name__ == "__main__":
    main(sys.argv[1])
