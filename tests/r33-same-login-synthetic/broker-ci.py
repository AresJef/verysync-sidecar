"""Exercise a real local same-UID handoff using only synthetic credentials."""

import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


HERE = Path(__file__).resolve().parent
PYTHON = ["/usr/bin/python3","-B"]
TMP = Path("/private/tmp")
EXAMPLE_USER = b"r33-synthetic-operator"
EXAMPLE_PASSWORD = b"r33-synthetic-only-password"
REJECT = {"ok":False,"code":"denied"}


class TerminalView:
    def __init__(self, fd):
        self.fd, self.observed = fd, b""

    def find(self, prefix, timeout=12):
        deadline=time.monotonic()+timeout
        while prefix not in self.observed or b"\n" not in self.observed.split(prefix,1)[1]:
            if not select.select([self.fd],[],[],max(0,deadline-time.monotonic()))[0]:
                raise TimeoutError(prefix.decode())
            try:
                chunk=os.read(self.fd,8192)
            except OSError as err:
                if err.errno!=errno.EIO:
                    raise
                chunk=b""
            if not chunk:
                raise RuntimeError("The synthetic terminal closed near "+prefix.decode())
            self.observed+=chunk
        return self.observed.split(prefix,1)[1].split(b"\n",1)[0].strip()

    def prompt(self, fragment):
        deadline = time.monotonic()+8
        while fragment not in self.observed:
            if not select.select([self.fd],[],[],max(0,deadline-time.monotonic()))[0]:
                raise TimeoutError(fragment.decode())
            self.observed+=os.read(self.fd,8192)


def send(socket_path, run, target, action):
    from uuid import uuid4
    payload = json.dumps({"run":run,"target":target,"operation":action,"request":uuid4().hex})+"\n"
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(4)
        client.connect(str(socket_path))
        with client.makefile("rb") as data:
            client.sendall(payload.encode())
            return json.loads(data.readline(4096))


def owner(working, uid, gid):
    os.setgroups([gid])
    os.setgid(gid)
    os.setuid(uid)
    assert os.getuid()==uid and os.getegid()==gid
    scratch=working/"f"
    scratch.mkdir()
    stored=working/"t"
    stored.mkdir()
    (scratch/"expect.json").write_text(json.dumps({
        "username":hashlib.sha256(EXAMPLE_USER).hexdigest(),
        "password":hashlib.sha256(EXAMPLE_PASSWORD).hexdigest(),
    }))
    profile=working/"profile"
    profile.write_text(json.dumps({"pro":{"allow":["observe"],"connection":{
        "socket":str(scratch/"account.sock"),"recovery":str(stored)
    }}}))
    provider=subprocess.Popen(PYTHON+[str(HERE/"fake_vendor.py"),str(scratch)],
                              stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL,start_new_session=True)
    try:
        assert select.select([provider.stdout],[],[],5)[0]
        assert provider.stdout.readline()==b"ACCOUNT_FIXTURE_READY\n"
        fixed=["--executor-uid",str(uid),"--group-private",str(working)]
        proof=working/"isolation.json"
        subprocess.run(PYTHON+[str(HERE/"r33_isolation.py"),"operator","--record",str(proof)]+fixed,
                       check=True,timeout=20)
        reconciliation=json.loads(proof.read_text())
        assert reconciliation["operator_uid"]==reconciliation["executor_uid"]==uid
        assert reconciliation["operator_group"]!=reconciliation["executor_group"]
        journal=working/"broker.jsonl"
        signal.signal(signal.SIGINT,signal.SIG_IGN)
        child=subprocess.run(PYTHON+[str(HERE/"r33_handoff.py"),"start","--synthetic","--minutes","1",
                                    "--profile",str(profile),"--evidence",str(journal)]+fixed,
                             timeout=35,check=False)
        assert child.returncode==0
        assert not (scratch/"login.json").exists() and not list(stored.iterdir())
        assert b"synthetic-session-closed" in journal.read_bytes()
        assert EXAMPLE_USER not in journal.read_bytes() and EXAMPLE_PASSWORD not in journal.read_bytes()
        print("FULL_GROUP_FLOW_CLEANED",flush=True)
    finally:
        if provider.poll() is None:
            provider.terminate()
        assert provider.wait(6)==0


def root():
    spec=importlib.util.spec_from_file_location("group_launch",HERE/"group-launch.py")
    core=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(core)
    uid=int(os.environ["SUDO_UID"])
    gid=core.next_group()
    base=Path(tempfile.mkdtemp(prefix="r33-session-",dir=TMP))
    box=base/"owner"
    try:
        box.mkdir()
        os.chown(base,0,gid)
        os.chown(box,uid,gid)
        base.chmod(0o710)
        with core.private_terminal(uid,gid):
            child=os.fork()
            if child==0:
                try:
                    owner(box,uid,gid)
                except BaseException as error:
                    print("Synthetic owner interrupted",type(error).__name__,flush=True)
                    os._exit(4)
                os._exit(0)
            with core.owned_signals(child):
                assert os.waitstatus_to_exitcode(os.waitpid(child,0)[1])==0
    finally:
        shutil.rmtree(base)
    print("FULL_FIXTURE_REMOVED",flush=True)


def flow():
    child,fd=pty.fork()
    if child==0:
        command=["/usr/bin/sudo","--non-interactive","--",*PYTHON,
                 str(HERE/"broker-ci.py"),"--sudo-synthetic-owner"]
        os.execv(command[0],command)
    result=TerminalView(fd)
    child_waited = False
    try:
        challenge=result.find(b"R33_ISOLATION ").decode("ascii")
        tested=subprocess.run(PYTHON+[str(HERE/"r33_isolation.py"),"executor","--challenge",challenge],
                              capture_output=True,text=True,check=True,timeout=7)
        verified=json.loads(tested.stdout.split("R33_ISOLATION_RESULT ",1)[-1])
        assert all(verified[field] for field in ("ok","matches_os_identity","file_denied","write_denied","socket_denied"))
        result.prompt(b"Type START to grant these operations.")
        os.write(fd,b"START\n")
        result.prompt(b"VerySync account (hidden) ")
        os.write(fd,EXAMPLE_USER+b"\n")
        result.prompt(b"VerySync password (hidden) ")
        os.write(fd,EXAMPLE_PASSWORD+b"\n")
        ready=json.loads(result.find(b"R33_READY "))
        endpoint,run=ready["socket"],ready["run"]
        assert send(endpoint,run,"pro","observe")=={"ok":True,"signed_in":True}
        assert send(endpoint,run,"pro","withdraw")==REJECT
        assert send(endpoint,run,"handoff","stop")==REJECT
        cy_start=time.monotonic()
        os.write(fd,b"\x03")
        point=json.loads(result.find(b"R33_STOPPED ",timeout=8))
        assert point["local"]=="revoked" and point["pro"]["state"]=="synthetic-session-closed"
        result.find(b"FULL_FIXTURE_REMOVED",timeout=6)
        _, exit_status=os.waitpid(child,0)
        child_waited=True
        assert os.waitstatus_to_exitcode(exit_status)==0
        assert EXAMPLE_USER not in result.observed and EXAMPLE_PASSWORD not in result.observed
        assert not Path(challenge).exists() and not Path(endpoint).exists()
        print(json.dumps({"engine":"synthetic-credential-provider","arch":os.uname().machine,
                          "outside_uid":os.getuid(),"facade":verified,"same_uid_status_observed":True,
                          "outside_withdraw_and_stop_denied":True,"ctrl_c_stopped":True,
                          "terminal_stop_and_logout_seconds":round(time.monotonic()-cy_start,4),
                          "no_terminal_credentials_echoed":True,"private_state_cleanup":True,
                          "public_broker_cleanup":True}),flush=True)
    finally:
        if not child_waited:
            try:
                os.kill(child,signal.SIGTERM)
                os.waitpid(child,0)
            except ProcessLookupError:
                pass
        os.close(fd)


if __name__=="__main__":
    os.umask(0o077)
    if sys.argv[1:]==["--sudo-synthetic-owner"]:
        root()
    else:
        flow()
