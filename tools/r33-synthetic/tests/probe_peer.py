"""Verify the fixed peer path with an actual short-lived OpenSSH service."""

import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time
import uuid

from r33_protocol import decode_frame, encode_frame
from ssh_fixture import daemon


def send(peer, value):
    peer.stdin.write(encode_frame(value))
    peer.stdin.flush()
    ready, _, _ = select.select([peer.stdout],[],[],5)
    assert ready, "The SSH peer returned no receipt."
    line = peer.stdout.readline()
    if not line:
        reason = peer.stderr.read(1200).decode(errors="replace")
        raise RuntimeError("The SSH peer closed: "+reason)
    return decode_frame(line)


root_prefix=Path("/private/tmp") if Path("/private/tmp").is_dir() else Path("/tmp")
with tempfile.TemporaryDirectory(prefix="r33t-",dir=root_prefix) as workspace:
    os.umask(0o077)
    state = Path(workspace).resolve()
    with daemon(state/"ssh") as (destination, mismatch, key, remote):
        def channel(bound):
            client = state/uuid.uuid4().hex[:5]
            client.mkdir()
            return bound.command(client,key)

        refus = subprocess.run(channel(mismatch),input=encode_frame({"kind":"start","run":uuid.uuid4().hex}),
                               capture_output=True,timeout=10)
        assert refus.returncode==255 and b"Host key verification failed" in refus.stderr, refus.stderr[-400:]
        assert list(remote.iterdir())==[]
        run = uuid.uuid4().hex
        with subprocess.Popen(channel(destination),stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as conn:
            first = send(conn, {"kind":"start","run":run})
            assert first["state"]=="active" and first["writes"]==0
            identifier=uuid.uuid4().hex
            result = send(conn, {"kind":"execute","id":identifier,"operation":"write-sample"})
            assert result["committed"] and (remote/run/f"sample-{identifier}").is_file()
            result=send(conn,{"kind":"stop"})
            assert result["state"]=="revoked" and result["writes"]==1 and result["tasks"]==0
            assert send(conn,{"kind":"execute","id":uuid.uuid4().hex,"operation":"write-sample"})["ok"] is False
            assert send(conn,{"kind":"readback","id":identifier})["observed"]["length"]==21
            assert send(conn,{"kind":"readback","id":identifier})["ok"] is False
            conn.stdin.close()
            assert conn.wait(timeout=8)==0
        trigger=remote/run/"g.sock"
        until=time.monotonic()+6
        while trigger.exists() and time.monotonic()<until:
            time.sleep(.05)
        assert not trigger.exists()
    print(json.dumps({"synthetic":True,"wrong_host_rejected_before_service":True,"actual_owned_ssh":True,
                      "committed_writes":1,"repeat_readback_rejected":True,"actual_peer_socket_exit":True}))
