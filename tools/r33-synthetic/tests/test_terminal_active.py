"""Use a held remote ACK to measure queued versus committed operations."""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

from r33_protocol import encode_frame,decode_frame
from ssh_fixture import daemon
from test_terminal import TMP, Terminal, connect, profile_file, request


def until(read, timeout=5):
    limit=time.monotonic()+timeout
    while time.monotonic()<limit:
        answer=read()
        if answer:
            return answer
        time.sleep(.012)
    raise AssertionError("A required synthetic effect was never observed.")


def write(endpoint,run,identifier):
    value={"run":run,"target":"linux","operation":"write-sample","request":identifier}
    with connect(endpoint) as channel:
        channel.settimeout(12)
        channel.sendall(encode_frame(value))
        with channel.makefile("rb") as stream:
            return decode_frame(stream.readline())


def replay(output):
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="r33-h3-",dir=TMP) as work:
        root=Path(work).resolve()
        gates=root/"gates"
        gates.mkdir()
        sentinel=root/"unrelated"
        sentinel.write_bytes(b"unrelated synthetic data")
        independent=subprocess.Popen(["/bin/sleep","30"],start_new_session=True)
        try:
            with daemon(root/"ssh",gates) as (peer, _wrong, key, remote):
                profile=root/"profile.json"
                profile_file(profile,peer,key)
                journal=root/"broker.jsonl"
                user=Terminal(["start","--synthetic","--executor-uid",str(os.getuid()),
                               "--minutes","3","--profile",str(profile),"--evidence",str(journal)])
                try:
                    user.feed(b"START\n")
                    active=user.response(b"R33_READY ")
                    run=active["run"]
                    endpoint=Path(active["socket"])
                    with connect(endpoint) as client:
                        assert request(client,run,"linux","start-observer")["running"]
                        assert request(client,run,"linux","write-sample")["committed"]
                        until(lambda:(remote/run/"observer-sample").exists())
                        (gates/"pause-next").touch()
                        in_flight, queued=uuid.uuid4().hex,uuid.uuid4().hex
                        with ThreadPoolExecutor(max_workers=2) as race:
                            lost=race.submit(write,endpoint,run,in_flight)
                            assert until(lambda:(gates/"ack-held").is_file())
                            assert (gates/"ack-held").read_text()==in_flight
                            assert (remote/run/f"sample-{in_flight}").read_bytes()==b"R33 synthetic sample\n"
                            waiting=race.submit(write,endpoint,run,queued)
                            until(lambda:any(x["event"]=="queued" and x.get("request")==queued
                                             for x in map(json.loads,journal.read_text().splitlines())))
                            now=time.monotonic()
                            user.feed(b"\x03")
                            assert waiting.result(timeout=.8)["ok"] is False
                            assert request(client,run,"handoff","stop")["local"]=="revoked"
                            (gates/"release").touch()
                            assert lost.result(timeout=4)=={"ok":False,"code":"result-pending"}
                            elapsed=time.monotonic()-now
                    terminal=user.response(b"R33_STOPPED ",15)
                    assert terminal["linux"]=={"state":"stopped","writes":2},terminal
                    assert user.wait()==0
                    data=json.loads((remote/run/"receipt.json").read_text())
                    assert data["tasks"]==0 and data["readbacks"]==1 and data["writes"]==2
                    observer=remote/run/"observer-sample"
                    length=observer.stat().st_size
                    time.sleep(.37)
                    assert observer.stat().st_size==length
                    assert not (remote/run/f"sample-{queued}").exists()
                    rows=list(map(json.loads,journal.read_text().splitlines()))
                    assert sum(x["event"]=="local-revoked" for x in rows)==1
                    initiated=[x["request"] for x in rows if x["event"]=="write-submitted"]
                    recovered=[x for x in rows if x["event"]=="write-readback"]
                    assert len(initiated)==2 and in_flight in initiated and queued not in initiated
                    assert len(recovered)==1 and recovered[0]["request"]==in_flight
                    assert recovered[0]["verified"] and recovered[0]["sample_present"]
                    assert independent.poll() is None and sentinel.read_bytes()==b"unrelated synthetic data"
                    outcome={"pre_ack_stop":True,"new_write_count":0,"queued_write_count":0,"committed_writes":2,
                             "durable_readbacks":len(recovered),"owned_observer_stopped":True,
                             "owned_observer_no_later_output":True,
                             "other_process_and_file_retained":True,"elapsed_sec":elapsed,"events":rows}
                finally:
                    (gates/"release").touch(exist_ok=True)
                    user.close()
        finally:
            independent.terminate()
            independent.wait(timeout=4)
    output.write_text(json.dumps(outcome,indent=2)+"\n")
    print(json.dumps({k:v for k,v in outcome.items() if k!="events"}))


if __name__=="__main__":
    replay(Path(sys.argv[1]))
