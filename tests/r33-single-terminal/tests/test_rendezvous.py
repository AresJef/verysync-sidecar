"""Observe the synthetic group challenge and private management gate without copying a receipt."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import pty
import secrets
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime-next"))
sys.path.insert(0,str(Path(__file__).parent/"prior"))

from r33_isolation import agent, public_challenge
from r33_protocol import DENIED, decode_frame, encode_frame
from r33_rendezvous import TMP, await_notice, native_probe, watch
from test_terminal import Terminal, connect, request


class ProtectedTerminal(Terminal):
    def __init__(self, exchange, config):
        self.buffer = b""
        self.observed = b""
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            fixture = Path(__file__).with_name("root-terminal.py")
            command=["/usr/bin/sudo","-n","/usr/bin/python3","-B",str(fixture),str(exchange),str(config)]
            os.execv(command[0],command)
        self.exit=None


def check_native(exchange):
    stop=time.monotonic()+55
    challenge=await_notice(exchange,"challenge",stop)
    proof=public_challenge(Path(challenge["challenge"]))
    assert agent(Path(challenge["challenge"]))==0
    native=await_notice(exchange,"native",stop)
    native_probe(native,proof)
    return proof["run"]


def run_native(exchange, config, engine, driver, source):
    config.write_text(json.dumps({"scope":{"gid":os.getegid()},
                                 "native":{"engine":str(engine),"driver":str(driver),
                                           "suite_digest":hashlib.sha256(source.read_bytes()).hexdigest()}}))
    tty=ProtectedTerminal(exchange,config)
    try:
        vault=Path(tty.response(b"R33_PROTECTED_VAULT ")["private"])
        with ThreadPoolExecutor(max_workers=1) as observer:
            proof=observer.submit(check_native,exchange)
            tty.prompt(b"Dedicated Linux address",timeout=20)
            tty.feed(b"\n")
            tty.prompt(b"Type START to grant these operations.",timeout=8)
            tty.feed(b"START\n")
            run=proof.result(timeout=40)
        tty.prompt(b"VerySync account (hidden) ",timeout=12)
        running=Path(vault/"kit/official-v2.33.2")
        ps=("/bin/ps","-ww","-ax","-o","comm=")
        assert str(running) in {line.strip() for line in subprocess.check_output(ps,text=True).splitlines()}
        tty.feed(b"\x03")
        terminal=tty.response(b"R33_STOPPED ",18)
        assert terminal["run"]==run and terminal["cause"]=="SIGINT" and terminal["local"]=="revoked"
        native=terminal["pro"]
        assert native["state"]=="stopped-before-login" and native["normal_owned_exit"]
        assert native["official_network"]["permitted"]==0
        assert tty.wait(12) in (0,1) and not vault.exists()
        assert str(running) not in {line.strip() for line in subprocess.check_output(ps,text=True).splitlines()}
        assert not (exchange/"ready.json").exists()
    finally:
        tty.close()
    print("R33_REAL_NATIVE_PREFLIGHT "+json.dumps({"fixed_native":"v2.33.2",
                "crate_sha256":"1d1e7d0d3ef4ac4dcf063b8e4d3ac336bd823fd056e5aae84c5dbaaf24d6cbfe",
                "native_archive_sha256":hashlib.sha256(engine.read_bytes()).hexdigest(),
                "driver_sha256":hashlib.sha256(driver.read_bytes()).hexdigest(),
                "direct_native_management_refused_from_same_uid":True,
                "stopped_at_first_hidden_prompt":True,"owned_paths_removed":True,
                "terminal":terminal},sort_keys=True),flush=True)


def run(args):

    if (os.environ.get("RUNNER_ENVIRONMENT")!="github-hosted"
            or os.environ.get("GITHUB_REPOSITORY")!="AresJef/verysync-sidecar"
            or os.environ.get("GITHUB_ACTIONS")!="true"):
        raise SystemExit("Use this group test on the designated disposable hosted runner.")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="r33-exchange-",dir=TMP) as endpoint:
        exchange=Path(endpoint).resolve()
        config=exchange/"synthetic-config.json"
        if args.native:
            return run_native(exchange, config, *args.native)
        username=("r33-first-"+secrets.token_hex(16)).encode()
        password=("r33-second-"+secrets.token_hex(20)).encode()
        config.write_text(json.dumps({"expected":{"username":hashlib.sha256(username).hexdigest(),
                                                 "password":hashlib.sha256(password).hexdigest()},
                                      "scope":{"gid":os.getegid()}}))
        tty=ProtectedTerminal(exchange,config)
        try:
            vault=Path(tty.response(b"R33_PROTECTED_VAULT ")["private"])
            with ThreadPoolExecutor(max_workers=1) as observer:
                sent = await_notice(exchange,"challenge",time.monotonic()+10)
                candidate = public_challenge(Path(sent["challenge"]))
                with connect(Path(candidate["broker"])) as wrong:
                    probe = {"run": "0"*32,"private_file_unreadable":True,
                             "private_socket_denied":True,"private_write_denied":True}
                    assert probe["run"] != sent["run"]
                    wrong.sendall(encode_frame(probe))
                    with wrong.makefile("rb") as access:
                        assert decode_frame(access.readline()) == DENIED
                assert not (exchange/"native.json").exists()
                ready=observer.submit(watch,exchange,35,True)
                try:
                    tty.prompt(b"Type START to grant these operations.",timeout=14)
                except (AssertionError,OSError) as exc:
                    if ready.done():
                        self_error=ready.exception()
                    else:
                        self_error=None
                    message=tty.observed.decode(errors="replace").splitlines()[-9:]
                    raise AssertionError(f"Protected terminal startup failed. Observer: {self_error}; "
                                         f"no-secret terminal: {message}") from exc
                assert b"R33_ISOLATION " not in tty.observed
                assert (exchange/"native.json").exists()
                tty.feed(b"START\n")
                tty.prompt(b"VerySync account (hidden) ")
                tty.feed(username+b"\n")
                tty.prompt(b"VerySync password (hidden) ")
                tty.feed(password+b"\n")
                bound=ready.result(timeout=12)
                run=bound["run"]
                assert bound["status"]["local"]=="active"
                for path in (vault/"kit/profile.json",vault/"recovery"/run/"session"):
                    try:
                        path.read_bytes()
                    except PermissionError:
                        pass
                    else:
                        raise AssertionError("The delegated process could read a protected file.")
                with connect(Path(bound["socket"])) as client:
                    assert request(client,run,"pro","observe")["account"]=="logged-in"
                    assert request(client,run,"handoff","stop")=={"ok":False,"code":"denied"}
                    assert request(client,run,"handoff","seal")["business_queue_sealed"]
                remaining=time.monotonic()+10
                tty.feed(b"STOP\n")
                stop=await_notice(exchange,"stopped",remaining)
                assert stop["run"]==run and stop["pro"]["state"]=="synthetic-session-closed"
                printed=tty.response(b"R33_STOPPED ",10)
                assert printed==stop
                status=tty.wait(12)
                detail={"exit":status,"vault_still_present":vault.exists(),
                        "socket_still_present":Path(bound["socket"]).exists()}
                assert detail=={"exit":0,"vault_still_present":False,"socket_still_present":False}, detail
        finally:
            tty.close()
        assert all(credential not in tty.observed for credential in (username,password))
        assert all(credential not in notice.read_bytes() for credential in (username,password)
                   for notice in exchange.glob("*.json"))
        print("R33_SINGLE_ISOLATION "+json.dumps({
            "system":sys.platform,"run":run,"automatic_fake_challenge":True,"unbound_challenge_refused":True,
            "automatic_private_management_socket_denial":True,"automatic_ready_and_stop":True,
            "session_file_access_denied":True,"account_values_absent_in_notifications":True,
            "same_uid_different_group":True,"operator_only_stop":True,"owned_paths_removed":True,
            "terminal":stop},sort_keys=True),flush=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native",nargs=3,type=Path,metavar=("ENGINE","DRIVER","SOURCE"))
    run(parser.parse_args())

