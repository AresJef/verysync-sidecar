"""Use actual hidden OpenSSH password entry on an ephemeral hosted Linux VM."""

import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from r33_ssh import Destination
from ssh_fixture import available_port, fingerprint, generate_pair
from test_terminal import BUNDLE, Terminal, connect, request
from test_terminal_active import until


def sudo(*command, input=None, capture_output=False):
    return subprocess.run(["/usr/bin/sudo","-n",*command],check=True,timeout=8,input=input,
                          capture_output=capture_output)


def root_process_is_ours(pid, parameter):
    try:
        value = Path(f"/proc/{pid}/cmdline").read_bytes()
        return b"sshd" in value[:80] and str(parameter).encode() in value
    except (FileNotFoundError,PermissionError):
        return False


def check(root):
    root.chmod(0o755)
    fixture="r33"+secrets.token_hex(4)
    try:
        pwd.getpwnam(fixture)
    except KeyError:
        pass
    else:
        raise AssertionError("The disposable login already exists.")
    home=root/"peer"
    home.mkdir()
    sudo("/usr/sbin/useradd","--no-create-home","--home-dir",str(home),"--shell","/bin/sh",fixture)
    try:
        return exercise(root,home,fixture)
    finally:
        sudo("/usr/sbin/userdel",fixture)
        try:
            pwd.getpwnam(fixture)
        except KeyError:
            pass
        else:
            raise AssertionError("The fixture login survived its cleanup.")
        sudo("/bin/chown","-R",str(os.getuid()),str(home))
        home.chmod(0o700)


def exercise(root,home,fixture):
    gid=pwd.getpwnam(fixture).pw_gid
    worker=root/"worker"
    worker.mkdir(mode=0o755)
    worker.chmod(0o755)
    for name in ("r33_linux_worker.py","r33_protocol.py"):
        script=worker/name
        shutil.copyfile(BUNDLE/name,script)
        script.chmod(0o444)
    sudo("/bin/chown",f"{fixture}:{gid}",str(home))
    sudo("/bin/chmod","0700",str(home))
    password=("r33-test-ssh-"+secrets.token_hex(21)).encode("ascii")
    sudo("/usr/sbin/chpasswd",input=fixture.encode()+b":"+password+b"\n")
    state=home/"session"
    host=root/"host-key"
    public_key=generate_pair(host)
    port=available_port()
    config=root/"isolated-sshd.conf"
    pidfile=root/"isolated-sshd.pid"
    fixed=shlex.join(["/usr/bin/python3","-B",str(worker/"r33_linux_worker.py"),"stdio","--root",str(state)])
    config.write_text("\n".join((
        "AddressFamily inet","ListenAddress 127.0.0.1",f"Port {port}",f"HostKey {host}",
        f"PidFile {pidfile}","UsePAM no","PasswordAuthentication yes","PermitRootLogin no",
        "KbdInteractiveAuthentication no","PubkeyAuthentication no","AuthenticationMethods password",
        "DisableForwarding yes", "PermitTTY no","LogLevel VERBOSE",f"AllowUsers {fixture}",f"ForceCommand {fixed}",
    ))+"\n")
    sudo("/usr/sbin/sshd","-t","-f",str(config))
    with (root/"sshd.out").open("wb") as log:
        sshd=subprocess.Popen(["/usr/bin/sudo","-n","/usr/sbin/sshd","-D","-e","-f",str(config)],
                              stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        try:
            until(pidfile.is_file,timeout=5)
            pid=int(pidfile.read_text())
            assert root_process_is_ours(pid,config)
            return terminal(root,state,fixture,port,public_key,fingerprint(host),password)
        finally:
            if not pidfile.is_file():
                sshd.wait(5)
            else:
                pid=int(pidfile.read_text())
                if root_process_is_ours(pid,config):
                    sudo("/bin/kill","-TERM",str(pid))
                sshd.wait(6)


def terminal(root,state,fixture,port,key,fingerprint,password):
    profile=root/"profile.json"
    data={"host":"127.0.0.1","port":port,"user":fixture,"public_key":key,"fingerprint":fingerprint}
    Destination.parse(data)
    profile.write_text(json.dumps({"linux":{"connection":data,"allow":["observe","start-observer","write-sample"]}}))
    journal=root/"journal.jsonl"
    user=Terminal(["start","--synthetic","--executor-uid",str(os.getuid()),
                   "--minutes","2","--profile",str(profile),"--evidence",str(journal)])
    try:
        user.feed(b"START\n")
        user.prompt(b"assword:",timeout=8)
        user.feed(password+b"\n")
        ready=user.response(b"R33_READY ",12)
        run=ready["run"]
        with connect(Path(ready["socket"])) as client:
            assert request(client,run,"linux","observe")["writes"]==0
            assert request(client,run,"linux","start-observer")["running"]
            assert request(client,run,"linux","write-sample")["committed"]
        user.feed(b"\x03")
        end=user.response(b"R33_STOPPED ",12)
        assert user.wait(6)==0 and end["linux"]=={"state":"stopped","writes":1}
        assert password not in user.observed and password not in journal.read_bytes()
        assert password not in (root/"sshd.out").read_bytes()
        persisted=sudo("/bin/cat",str(state/run/"receipt.json"),capture_output=True).stdout
        verified=json.loads(persisted)
        assert verified["state"]=="revoked" and verified["tasks"]==0 and verified["writes"]==1
        return {"linux_native_password_prompt":True,
                "count_in_terminal_journal_sshd_log":0, "isolated_state":verified,
                "terminal":end,"actual_pid_tree_cleanup":True}
    finally:
        user.close()


def main():
    # No system account may be created on a developer machine or a self-hosted runner.
    if not (sys.platform=="linux" and os.environ.get("GITHUB_ACTIONS")=="true"
            and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted"
            and os.environ.get("GITHUB_REPOSITORY")=="AresJef/verysync-sidecar"):
        raise SystemExit("Use only the designated disposable GitHub-hosted Linux runner.")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="r33-pw-",dir="/tmp") as raw:
        root=Path(raw).resolve()
        result=check(root)
    result["owned_temporary_paths_removed"]=not root.exists()
    print(json.dumps(result),flush=True)


if __name__=="__main__":
    main()
