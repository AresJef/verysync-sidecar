"""Exercise no-TTY, partial input, expiry and offline logout on the frozen launcher."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
RUNTIME=ROOT/"runtime-next"
sys.path.insert(0,str(RUNTIME))
sys.path.insert(0,str(Path(__file__).parent/"prior"))

from r33_ssh import Destination, SSHConfigurationError
from ssh_fixture import fingerprint, generate_pair
from test_account_terminal import inspect, make_fixture, provider
import test_terminal
from test_terminal import TMP, Terminal, connect, request

test_terminal.BUNDLE=RUNTIME


def scenario(root, mode):
    root.mkdir()
    folder,storage,target,profile,user,secret=make_fixture(root)
    journal=root/"journal"
    flags=["start","--synthetic","--executor-uid",str(os.getuid()),"--profile",str(profile),
           "--evidence",str(journal),"--expires-at",str(int(time.time())+(5 if mode=="expiry" else 80))]
    if mode=="no-tty":
        attempt=subprocess.run([sys.executable,"-B",str(RUNTIME/"r33_handoff.py"),*flags],
                               stdin=subprocess.DEVNULL,capture_output=True,timeout=5)
        assert attempt.returncode==2 and b"Start the handoff in a private operator terminal" in attempt.stderr
        assert not journal.exists()
        return {"credentials_prompted":False,"journal_created":False}
    with provider(folder) as backend:
        process=Terminal(flags)
        try:
            process.prompt(b"Type START to grant these operations.")
            process.feed(b"START\n")
            process.prompt(b"VerySync account (hidden) ")
            process.feed(user+b"\n")
            process.prompt(b"VerySync password (hidden) ")
            if mode=="partial":
                process.feed(b"\x03")
                result=process.response(b"R33_STOPPED ",8)
                assert result["cause"]=="SIGINT" and result["pro"]["state"]=="not-enabled"
                assert process.wait(5) in (0,1) and not (folder/"login.json").exists()
                assert user not in process.observed and user not in journal.read_bytes()
                return {"login_commits":0,"actual_signal":"SIGINT","end":result}
            process.feed(secret+b"\n")
            ready=process.response(b"R33_READY ")
            token=(storage/ready["run"]/"session").read_text()
            with connect(Path(ready["socket"])) as client:
                assert request(client,ready["run"],"pro","observe")["account"]=="logged-in"
            if mode=="offline":
                assert inspect(target,token)=={"ok":True}
                backend.terminate()
                assert backend.wait(timeout=5)==0
                process.feed(b"STOP\n")
            result=process.response(b"R33_STOPPED ",10)
            assert process.wait(8)==0 and not Path(ready["socket"]).exists()
            if mode=="expiry":
                assert result["cause"]=="authorization-expired" and inspect(target,token)=={"ok":False,"code":"signed-out"}
                assert result["pro"]=={"state":"synthetic-session-closed"}
                return {"end":result,"old_session_denied":True}
            assert result["cause"]=="operator-quit" and result["pro"]=={"state":"pending-confirmation"}
            assert all(value not in process.observed and value not in journal.read_bytes()
                       for value in (user,secret,token.encode()))
        finally:
            process.close()
    with provider(folder):
        assert inspect(target,token)=={"ok":True}
        recovery=Terminal(["recover","--unified","--synthetic","--profile",str(profile),
                           "--target","pro","--run",ready["run"]])
        try:
            recovery.feed(b"RECOVER\n")
            observed=recovery.response(b"R33_RECOVERY ")
            assert observed["local"]=="no-new-grant"
            assert observed["pro"]=={"state":"synthetic-session-closed"} and recovery.wait()==0
            assert inspect(target,token)=={"ok":False,"code":"signed-out"}
        finally:
            recovery.close()
    return {"immediate":result,"later_recovery":observed,"old_session_denied":True}


def controls():
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="r33-controls-",dir=TMP) as folder:
        root=Path(folder).resolve()
        first,second=root/"first",root/"second"
        public=generate_pair(first)
        generate_pair(second)
        data={"host":"127.0.0.1","user":"fixture","port":22,
              "public_key":public,"fingerprint":fingerprint(second)}
        try:
            Destination.parse(data)
        except SSHConfigurationError:
            mismatched=True
        else:
            raise AssertionError("A different host key passed the confirmed fingerprint check.")
        results={mode:scenario(root/mode,mode) for mode in ("no-tty","partial","expiry","offline")}
    results["different_confirmed_host_key_refused_before_ssh"]=mismatched
    results["owned_control_root_removed"]=not root.exists()
    print("R33_SINGLE_CONTROLS "+json.dumps(results,sort_keys=True),flush=True)


if __name__=="__main__":
    controls()

