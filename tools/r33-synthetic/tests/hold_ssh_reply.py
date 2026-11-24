"""Hold one synthetic reply after the real SSH peer has acted."""

import os
from pathlib import Path
import subprocess
import sys
import time

from r33_protocol import FRAME_MAX, decode_frame


def relay(bundle, state, gates):
    peer = subprocess.Popen(
        [sys.executable,"-B",str(bundle/"r33_linux_worker.py"),"stdio","--root",str(state)],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
    )
    try:
        while line := sys.stdin.buffer.readline(FRAME_MAX+1):
            data=decode_frame(line)
            peer.stdin.write(line)
            peer.stdin.flush()
            reply=peer.stdout.readline(FRAME_MAX+1)
            if not reply:
                break
            if data.get("operation")=="write-sample" and (gates/"pause-next").is_file():
                committed=decode_frame(reply)
                assert committed["committed"]
                (gates/"pause-next").unlink()
                (gates/"ack-held").write_text(data["id"],encoding="ascii")
                end=time.monotonic()+6
                while not (gates/"release").exists():
                    assert time.monotonic()<end
                    time.sleep(.015)
            sys.stdout.buffer.write(reply)
            sys.stdout.buffer.flush()
    finally:
        peer.stdin.close()
        peer.wait(timeout=7)


if __name__=="__main__":
    os.umask(0o077)
    relay(*(Path(arg) for arg in sys.argv[1:]))
