"""Observe the synthetic group challenge and private management gate without copying a receipt."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import pty
import secrets
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime-next"))
sys.path.insert(0,str(Path(__file__).parent/"prior"))

from r33_rendezvous import TMP, await_notice, watch
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


def run():
    if (os.environ.get("RUNNER_ENVIRONMENT")!="github-hosted"
            or os.environ.get("GITHUB_REPOSITORY")!="AresJef/verysync-sidecar"
            or os.environ.get("GITHUB_ACTIONS")!="true"):
        raise SystemExit("Use this group test on the designated disposable hosted runner.")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="r33-exchange-",dir=TMP) as endpoint:
        exchange=Path(endpoint).resolve()
        config=exchange/"synthetic-config.json"
        username=("r33-first-"+secrets.token_hex(16)).encode()
        password=("r33-second-"+secrets.token_hex(20)).encode()
        config.write_text(json.dumps({"expected":{"username":hashlib.sha256(username).hexdigest(),
                                                 "password":hashlib.sha256(password).hexdigest()},
                                      "scope":{"gid":os.getegid()}}))
        tty=ProtectedTerminal(exchange,config)
        try:
            vault=Path(tty.response(b"R33_PROTECTED_VAULT ")["private"])
            with ThreadPoolExecutor(max_workers=1) as observer:
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
            "system":sys.platform,"run":run,"automatic_fake_challenge":True,
            "automatic_private_management_socket_denial":True,"automatic_ready_and_stop":True,
            "session_file_access_denied":True,"account_values_absent_in_notifications":True,
            "same_uid_different_group":True,"operator_only_stop":True,"owned_paths_removed":True,
            "terminal":stop},sort_keys=True),flush=True)


if __name__=="__main__":
    run()

