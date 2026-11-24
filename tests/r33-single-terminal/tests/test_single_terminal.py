"""Prove one password-SSH connection, ordered case effects and real terminal withdrawal."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT/"runtime-next"
sys.path.insert(0,str(RUNTIME))
sys.path.insert(0,str(Path(__file__).resolve().parent/"prior"))

from r33_cases import TWO_CORE_SCOPES
from r33_protocol import DENIED
from r33_remote_peer import bundle
from r33_single import LINUX_ALLOWED
from ssh_fixture import available_port, fingerprint, generate_pair
from test_account_terminal import make_fixture, provider, verify_argv
from test_linux_password import root_process_is_ours, sudo, terminate_only_fixture_uid
import test_terminal
from test_terminal import Terminal, connect, request
from test_terminal_active import until, write

test_terminal.BUNDLE = RUNTIME
TTL = 95


@contextmanager
def ssh_target(root):
    root.chmod(0o711)
    account = "r33" + secrets.token_hex(4)
    home = root/"peer"
    home.mkdir()
    sudo("/usr/sbin/useradd","--no-create-home","--home-dir",str(home),"--shell","/bin/sh",account)
    info = pwd.getpwnam(account)
    password = ("r33-ssh-fixture-"+secrets.token_hex(21)).encode()
    try:
        sudo("/usr/sbin/chpasswd",input=account.encode()+b":"+password+b"\n")
        sudo("/bin/chown",f"{info.pw_uid}:{info.pw_gid}",str(home))
        gates = root/"gates"
        gates.mkdir(mode=0o700)
        # A host test observer and this disposable account can both synchronize
        # the deliberately held test response. Gates contain only test IDs.
        sudo("/bin/chown",f"{os.getuid()}:{info.pw_gid}",str(gates))
        gates.chmod(0o770)
        scripts = root/"fixture"
        scripts.mkdir()
        for file in (Path(__file__).with_name("relay_once.py"),RUNTIME/"r33_protocol.py"):
            installed = scripts/file.name
            shutil.copyfile(file,installed)
            installed.chmod(0o444)
        command = scripts/"expected.txt"
        remote_command, peer_sha, _ = bundle(RUNTIME)
        command.write_text(remote_command)
        command.chmod(0o444)
        scripts.chmod(0o755)
        host = root/"host"
        public_key = generate_pair(host)
        bad_key = root/"bad-host"
        generate_pair(bad_key)
        port = available_port()
        config, pidfile = root/"sshd.conf",root/"sshd.pid"
        control = shlex.join(["/usr/bin/python3","-B",str(scripts/"relay_once.py"),str(command),str(gates)])
        config.write_text("\n".join((
            "AddressFamily inet","ListenAddress 127.0.0.1",f"Port {port}",f"HostKey {host}",
            f"PidFile {pidfile}","UsePAM no","PasswordAuthentication yes","PermitRootLogin no",
            "KbdInteractiveAuthentication no","PubkeyAuthentication no","AuthenticationMethods password",
            "DisableForwarding yes","PermitTTY no","LogLevel VERBOSE",f"AllowUsers {account}",f"ForceCommand {control}",
        ))+"\n")
        sudo("/usr/sbin/sshd","-t","-f",str(config))
        with (root/"sshd.log").open("wb") as transcript:
            server = subprocess.Popen(["/usr/bin/sudo","-n","/usr/sbin/sshd","-D","-e","-f",str(config)],
                                      stdin=subprocess.DEVNULL,stdout=transcript,stderr=transcript)
            try:
                until(pidfile.is_file,timeout=5)
                assert root_process_is_ours(int(pidfile.read_text()),config)
                actual = {"host":"127.0.0.1","port":port,"user":account,
                          "public_key":public_key,"fingerprint":fingerprint(host)}
                yield actual, password, home, gates, peer_sha, fingerprint(bad_key)
            finally:
                if pidfile.is_file():
                    pid = int(pidfile.read_text())
                    if root_process_is_ours(pid,config):
                        sudo("/bin/kill","-TERM",str(pid))
                server.wait(8)
    finally:
        terminate_only_fixture_uid(info.pw_uid)
        sudo("/usr/sbin/userdel",account)
        sudo("/bin/chown","-R",str(os.getuid()),str(home))
        try:
            pwd.getpwnam(account)
        except KeyError:
            pass
        else:
            raise AssertionError("The one-use SSH test identity still exists.")


def terminal(root,destination,credentials, *, seconds=280):
    address, ssh_password = destination
    folder, storage, _, profile, username, password = credentials
    document = json.loads(profile.read_text())
    document["pro"]["allow"] += ["refresh-paid",*TWO_CORE_SCOPES["pro-cases"]]
    document["linux"] = {"allow":sorted(LINUX_ALLOWED),"connection":address}
    profile.write_text(json.dumps(document))
    journal = root/"journal"
    args = ["start","--synthetic","--executor-uid",str(os.getuid()),"--profile",str(profile),
            "--evidence",str(journal),"--expires-at",str(int(time.time())+seconds)]
    user = Terminal(args)
    try:
        user.prompt(b"Type START to grant these operations.")
        user.feed(b"START\n")
        user.prompt(b"VerySync account (hidden) ")
        user.feed(username+b"\n")
        user.prompt(b"VerySync password (hidden) ")
        user.feed(password+b"\n")
        user.prompt(b"password:",timeout=9)
        user.feed(ssh_password+b"\n")
        ready = user.response(b"R33_READY ",12)
        run = ready["run"]
        token = (storage/run/"session").read_bytes()
        markers = (username,password,ssh_password,token)
        verify_argv(markers, (user.pid,))
        assert all(secret not in user.observed for secret in markers)
        assert all(secret not in journal.read_bytes() for secret in markers)
        return user, Path(ready["socket"]), run, journal, markers
    except BaseException:
        user.close()
        raise


def cases(endpoint,run,storage):
    with connect(endpoint) as client:
        assert request(client,run,"pro","observe") == {"ok":True,"account":"logged-in","synthetic":True}
        assert request(client,run,"pro","refresh-paid")["refresh_count"]==1
        assert request(client,run,"pro","refresh-paid")==DENIED
        for forbidden in ("enterprise-execute","claim-trial","local-api-write"):
            assert request(client,run,"pro",forbidden)==DENIED
        observed = {}
        for group, operations in (
            ("watch", ["schedule-watch-"+step for step in ("prepare","seed","observe","finish")]),
            ("selection", [action for action in TWO_CORE_SCOPES["pro-cases"] if action.startswith("selection-")]),
            ("audit", [action for action in TWO_CORE_SCOPES["pro-cases"] if action.startswith("audit-")]),
        ):
            assert request(client,run,"pro",operations[0])["ok"]
            attempted = "audit-reset" if group!="audit" else "selection-prepare"
            assert request(client,run,"pro",attempted)==DENIED
            for operation in operations[1:]:
                result = request(client,run,"pro",operation)
                assert result["ok"], (operation,result)
                if "sha256" in result:
                    actual = (storage/run/("case-"+result["fixture"])).read_bytes()
                    assert result["sha256"]==hashlib.sha256(actual).hexdigest() and result["bytes"]==len(actual)
                    observed[group]=result
                if operation.endswith("-finish"):
                    assert result["owned_sample_removed"]
            assert not list((storage/run).glob("case-*"))
        return observed


def cycle_linux(endpoint,run,peer_sha):
    with connect(endpoint) as client:
        def observation():
            return request(client,run,"linux","observe")
        start = observation()
        assert start["standby"] and not start["tasks"] and start["native_test_listeners"]==0
        assert start["peer_payload_sha256"]==peer_sha
        next_probe = until(lambda: (value if (value:=observation())["renewals"]>=2 else None),timeout=36)
        assert next_probe["standby"] and next_probe["native_test_listeners"]==0
        cycles = []
        for _ in range(2):
            assert request(client,run,"linux","start-observer")["running"]
            assert not observation()["standby"]
            time.sleep(.45)
            result = request(client,run,"linux","finish-observer")
            actual = b"tick\n"*(result["sample_bytes"]//5)
            assert result["normal_task_exit"] and result["sample_sha256"]==hashlib.sha256(actual).hexdigest()
            assert observation()["standby"] and observation()["tasks"]==0
            cycles.append(result)
        return {"two_renewals_in_standby":next_probe,"cycles":cycles}


def unexpected_targets(client, run):
    assert request(client,run,"linux","shell")==DENIED
    assert request(client,"0"*32,"linux","start-observer")==DENIED


def run_stop(root,destination,credentials,mode,home,gates,peer_sha):
    state = home/".local/share/verysync-r33/single"
    user, endpoint, run, journal, markers = terminal(root,destination,credentials)
    try:
        scenarios = cases(endpoint,run,credentials[1])
        linux = cycle_linux(endpoint,run,peer_sha) if mode=="STOP" else None
        with connect(endpoint) as previous:
            unexpected_targets(previous,run)
            if mode=="STOP":
                report = {"scores":{"licensed":"0.00","fixture_only":True},"remaining":["live-entitlements"]}
                (root/"stage-result.json").write_text(json.dumps(report))
                assert request(previous,run,"handoff","seal")["business_queue_sealed"]
                assert request(previous,run,"linux","write-sample")==DENIED
                assert request(previous,run,"linux","observe")["ok"]
                now = time.monotonic()
                user.feed(b"STOP\n")
                until(lambda:request(previous,run,"handoff","status")["local"]=="revoked",timeout=.9)
                first_denial = time.monotonic()-now
                with connect(endpoint) as fresh:
                    assert request(fresh,run,"pro","audit-prepare")==DENIED
                    assert request(fresh,run,"handoff","stop")["local"]=="revoked"
                held = None
            else:
                assert request(previous,run,"linux","start-observer")["running"]
                (gates/"pause").touch()
                committed, queued = secrets.token_hex(16),secrets.token_hex(16)
                with ThreadPoolExecutor(max_workers=2) as actor:
                    delayed = actor.submit(write,endpoint,run,committed)
                    until((gates/"held").is_file)
                    assert (gates/"held").read_text()==committed
                    waiting = actor.submit(write,endpoint,run,queued)
                    until(lambda: any(row.get("request")==queued and row["event"]=="queued"
                                      for row in map(json.loads,journal.read_text().splitlines())))
                    now = time.monotonic()
                    user.feed(b"\x03")
                    assert waiting.result(timeout=.9)==DENIED
                    first_denial = time.monotonic()-now
                    assert request(previous,run,"linux","write-sample")==DENIED
                    with connect(endpoint) as fresh:
                        assert request(fresh,run,"linux","write-sample")==DENIED
                    (gates/"release").touch()
                    assert delayed.result(timeout=5)=={"ok":False,"code":"result-pending"}
                held = {"ack_received_before_stop":False,"queued_commits":0,"previous_request":committed}
        result = user.response(b"R33_STOPPED ",15)
        assert user.wait(5)==0 and not endpoint.exists()
        assert result["cause"]==("operator-quit" if mode=="STOP" else "SIGINT")
        assert result["pro"]=={"state":"synthetic-session-closed"}
        assert result["linux"]["state"]=="stopped" and result["linux"]["owned_worker_directory_removed"]
        assert result["linux"]["writes"]==(0 if mode=="STOP" else 1)
        exists = subprocess.run(["/usr/bin/sudo","-n","/usr/bin/test","-e",str(state/run)],timeout=4)
        assert exists.returncode==1
        rows = [json.loads(line) for line in journal.read_text().splitlines()]
        original_authentications = (root.parent/"ssh"/"sshd.log").read_bytes().count(b"Accepted password")
        assert original_authentications==1
        if held:
            observed = [row for row in rows if row["event"]=="write-readback" and row.get("request")==held["previous_request"]]
            assert len(observed)==1 and observed[0]["verified"] and observed[0]["sample_present"]
            held["one_readback"] = True
        assert first_denial<1
        assert user.observed.count(b"Type START to grant these operations.")==1
        assert user.observed.count(b"VerySync account (hidden) ")==1
        assert user.observed.count(b"VerySync password (hidden) ")==1
        assert user.observed.count(b"password:")==1
        assert all(secret not in user.observed and secret not in journal.read_bytes()
                   and secret not in (root.parent/"ssh"/"sshd.log").read_bytes() for secret in markers)
        return {"terminal":result,"one_start":True,"one_synthetic_login":True,"one_openssh_authentication":True,
                "same_run_case_effects":scenarios,"standby":linux,"first_denial_seconds":first_denial,
                "no_secret_in_argv_terminal_receipts_or_sshd_log":True,"held_write":held}
    finally:
        (gates/"release").touch(exist_ok=True)
        user.close()


def loss(root,destination,credentials,home,kind):
    user, endpoint, run, journal, markers = terminal(root,destination,credentials)
    path=home/".local/share/verysync-r33/single"/run/"receipt.json"

    def observed():
        entry=subprocess.run(["/usr/bin/sudo","-n","/bin/cat",str(path)],
                             capture_output=True,timeout=4)
        if entry.returncode==0:
            value=json.loads(entry.stdout)
            if value["state"]=="revoked" and value["tasks"]==0:
                return value
        return None

    try:
        with connect(endpoint) as client:
            assert request(client,run,"linux","start-observer")["running"]
            assert request(client,run,"linux","observe")["tasks"]==1
            if kind=="ssh-loss":
                lines=subprocess.check_output(["/usr/bin/ps","--ppid",str(user.pid),"-o","pid=,args="],
                                              text=True)
                children=[int(line.split()[0]) for line in lines.splitlines()
                          if "/usr/bin/ssh " in line and "HostKeyAlias=verysync-r33-designated-peer" in line]
                assert len(children)==1
                os.kill(children[0],signal.SIGKILL)
                assert request(client,run,"pro","observe")["account"]=="logged-in"
            else:
                os.kill(user.pid,signal.SIGKILL)
                assert user.wait(3)==-signal.SIGKILL
        lasted=until(observed,timeout=TTL+2)
        elapsed=lasted["stopped"]-lasted["renewed"]
        assert 89 <= elapsed <= TTL and lasted["normal_task_exit"]
        if kind=="ssh-loss":
            user.feed(b"STOP\n")
            receipt=user.response(b"R33_STOPPED ",12)
            assert receipt["pro"]["state"]=="synthetic-session-closed" and user.wait(5)==0
        else:
            receipt={"state":"foreground-killed"}
            profile=root/"profile.json"
            recovery=Terminal(["recover","--synthetic","--unified","--target","pro","--profile",
                               str(profile),"--run",run])
            try:
                recovery.feed(b"RECOVER\n")
                found=recovery.response(b"R33_RECOVERY ",6)
                assert found["pro"]["state"]=="synthetic-session-closed" and recovery.wait()==0
            finally:
                recovery.close()
        return {"fault":kind,"time_from_last_renewal":elapsed,"remote_cleanup":lasted,"terminal":receipt}
    finally:
        user.close()
        if endpoint.exists() and kind=="foreground-kill":
            # The killed synthetic process cannot remove its public socket directory.
            shutil.rmtree(endpoint.parent)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",choices=("STOP","interrupt","ssh-loss","foreground-kill"),required=True)
    args=parser.parse_args()
    if not (os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted"
            and os.environ.get("GITHUB_REPOSITORY")=="AresJef/verysync-sidecar"
            and os.environ.get("GITHUB_ACTIONS")=="true" and sys.platform=="linux"):
        raise SystemExit("Use the designated disposable standard Linux runner.")
    os.umask(0o077)
    privilege=Path("/run/sshd")
    created=not privilege.exists()
    if created:
        sudo("/usr/bin/install","-d","-m","0755",str(privilege))
    try:
        with tempfile.TemporaryDirectory(prefix="r33-one-") as folder:
            root=Path(folder).resolve()
            local,ssh=root/"local",root/"ssh"
            local.mkdir()
            ssh.mkdir()
            credentials=make_fixture(local)
            with ssh_target(ssh) as (address,password,home,gates,peer_sha,bad):
                with provider(credentials[0]):
                    if args.mode in ("STOP","interrupt"):
                        outcome=run_stop(local,(address,password),credentials,args.mode,home,gates,peer_sha)
                    else:
                        outcome=loss(local,(address,password),credentials,home,args.mode)
    finally:
        if created:
            sudo("/usr/bin/rmdir",str(privilege))
    outcome["mode"]=args.mode
    outcome["owned_test_user_and_temporary_roots_removed"]=not root.exists()
    print("R33_SINGLE_TERMINAL "+json.dumps(outcome,sort_keys=True),flush=True)


if __name__=="__main__":
    main()

