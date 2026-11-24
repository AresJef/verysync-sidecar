"""Measure revocation at the real foreground terminal and the SSH peer."""

import errno
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from r33_protocol import decode_frame, encode_frame
from ssh_fixture import daemon


BUNDLE = Path(__file__).resolve().parents[1]
TMP = Path("/private/tmp") if sys.platform == "darwin" else Path("/tmp")


class Terminal:
    def __init__(self, arguments):
        self.buffer = b""
        self.observed = b""
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execv(sys.executable,[sys.executable,"-B",str(BUNDLE/"r33_handoff.py"),*arguments])
        self.exit = None

    def response(self, prefix, timeout=10):
        end = time.monotonic()+timeout
        while time.monotonic() < end:
            try:
                offset = self.buffer.index(prefix)
            except ValueError:
                offset = None
            if offset is not None:
                finish = self.buffer.find(b"\n", offset)
                if finish != -1:
                    result=self.buffer[offset+len(prefix):finish].strip()
                    self.buffer=self.buffer[finish+1:]
                    return json.loads(result)
            if not select.select([self.fd],[],[],max(0,end-time.monotonic()))[0]:
                break
            try:
                data=os.read(self.fd,4096)
            except OSError as trouble:
                if trouble.errno != errno.EIO:
                    raise
                data=b""
            if not data:
                break
            self.buffer += data
            self.observed += data
        # This contains only operator confirmations with echo and output codes.
        # Credential-bearing terminal buffers are never saved by the harness.
        raise AssertionError(f"Missing terminal receipt {prefix!r}. Bytes waiting: {len(self.buffer)}.")

    def prompt(self, marker, timeout=6):
        end = time.monotonic() + timeout
        while marker not in self.buffer:
            if not select.select([self.fd], [], [], max(0, end-time.monotonic()))[0]:
                raise AssertionError("The private terminal prompt was not received.")
            chunk = os.read(self.fd, 4096)
            if not chunk:
                raise AssertionError("The foreground process closed the terminal early.")
            self.buffer += chunk
            self.observed += chunk

    def feed(self, data):
        os.write(self.fd,data)

    def wait(self, timeout=8):
        end=time.monotonic()+timeout
        while time.monotonic()<end and self.exit is None:
            result,status=os.waitpid(self.pid,os.WNOHANG)
            if result:
                self.exit=os.waitstatus_to_exitcode(status)
                break
            time.sleep(.03)
        return self.exit

    def close(self):
        if self.wait(.1) is None:
            os.kill(self.pid,signal.SIGTERM)
            if self.wait(20) is None:
                os.kill(self.pid,signal.SIGKILL)
                self.wait(5)
        os.close(self.fd)


def connect(path):
    conn=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    conn.settimeout(3)
    try:
        conn.connect(str(path))
    except BaseException:
        conn.close()
        raise
    return conn


def request(conn, run, target, operation):
    value={"run":run,"target":target,"operation":operation,"request":uuid.uuid4().hex}
    with conn.makefile("rb") as response:
        conn.sendall(encode_frame(value))
        return decode_frame(response.readline(4096))


def profile_file(path, target, key):
    doc={"linux":{"connection":target.__dict__|{"identity":str(key)},
                  "allow":["observe","write-sample","start-observer"]}}
    with path.open("x") as stream:
        json.dump(doc,stream)


def replay_idle(output):
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="r33-pty-",dir=TMP) as work:
        home=Path(work).resolve()
        untouched=home/"sentinel.txt"
        untouched.write_bytes(b"unrelated synthetic file\n")
        with daemon(home/"ssh") as (destination, _mismatch, key, remote):
            config=home/"operator-profile.json"
            profile_file(config,destination,key)
            evidence=home/"broker.jsonl"
            user=Terminal(["start","--synthetic","--executor-uid",str(os.getuid()),
                           "--minutes","2","--profile",str(config),"--evidence",str(evidence)])
            try:
                user.feed(b"START\n")
                owner=user.response(b"R33_READY ",12)
                run=owner["run"]
                endpoint=Path(owner["socket"])
                with connect(endpoint) as old_client:
                    initial=request(old_client,run,"linux","observe")
                    assert initial["ok"] and initial["writes"]==0
                    assert request(old_client,run,"not-this-peer","observe")["ok"] is False
                    assert request(old_client,run,"linux","ungranted")["ok"] is False
                    assert request(old_client,"0"*32,"linux","write-sample")["ok"] is False
                    begin=time.monotonic()
                    user.feed(b"\x03")
                    while True:
                        snapshot=request(old_client,run,"handoff","status")
                        if snapshot["local"]=="revoked":
                            break
                        assert time.monotonic()-begin<.85, snapshot
                        time.sleep(.005)
                    assert request(old_client,run,"linux","write-sample")["ok"] is False
                    previous=time.monotonic()-begin
                with connect(endpoint) as newcomer:
                    assert request(newcomer,run,"linux","write-sample")["ok"] is False
                    newest=time.monotonic()-begin
                assert newest<=1.0 and previous<=1.0
                terminal=user.response(b"R33_STOPPED ",15)
                assert terminal["local"]=="revoked"
                assert terminal["linux"]=={"state":"stopped","writes":0}, terminal
                assert user.wait()==0
                assert not endpoint.exists()
                native=json.loads((remote/run/"receipt.json").read_text())
                assert native["state"]=="revoked" and native["tasks"]==native["writes"]==0
                fixture=remote/run/"g.sock"
                end=time.monotonic()+5
                while fixture.exists() and time.monotonic()<end:
                    time.sleep(.05)
                assert not fixture.exists()
                assert untouched.read_bytes()==b"unrelated synthetic file\n"
                records=[json.loads(row) for row in evidence.read_text().splitlines()]
                assert next(x for x in records if x["event"]=="local-revoked")["reason"]=="SIGINT"
                outcome={"pty_ctrl_c":True,"old_client_denied_sec":previous,"new_client_denied_sec":newest,
                         "wrong_target_grant_and_operation_denied":True,"terminal":terminal,
                         "owned_peer_socket_absent":True,"unrelated_file_retained":True,
                         "events":records}
            finally:
                user.close()
    output.write_text(json.dumps(outcome,indent=2)+"\n")
    print(json.dumps({k:v for k,v in outcome.items() if k!="events"}))


if __name__=="__main__":
    replay_idle(Path(sys.argv[1]))
