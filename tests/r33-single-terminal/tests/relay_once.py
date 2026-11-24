"""Hold a single synthetic write acknowledgement on the disposable password SSH server."""

import os
from pathlib import Path
import struct
import subprocess
import sys
import time


def read_exact(stream, size):
    result = bytearray()
    while len(result) < size:
        value = stream.read(size-len(result))
        if not value:
            raise EOFError("Synthetic peer input ended early.")
        result.extend(value)
    return result


def run(command_file, fixtures):
    from r33_protocol import FRAME_MAX, decode_frame
    approved = command_file.read_text()
    if os.environ.get("SSH_ORIGINAL_COMMAND") != approved:
        raise ValueError("The one-time peer received an unexpected SSH command.")
    with subprocess.Popen(["/bin/sh","-c",approved],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                          stderr=None) as peer:
        try:
            raw = sys.stdin.buffer
            header = read_exact(raw,4)
            size, = struct.unpack("!I",header)
            if not 0 < size <= 65536:
                raise ValueError("The one-time peer inventory is invalid.")
            peer.stdin.write(header + read_exact(raw,size))
            peer.stdin.flush()
            while line := raw.readline(FRAME_MAX+1):
                item = decode_frame(line)
                peer.stdin.write(line)
                peer.stdin.flush()
                result = peer.stdout.readline(FRAME_MAX+1)
                if not result:
                    break
                if item.get("operation") == "write-sample" and (fixtures/"pause").exists():
                    assert decode_frame(result)["committed"]
                    (fixtures/"pause").unlink()
                    (fixtures/"held").write_text(item["id"])
                    stop = time.monotonic()+5
                    while not (fixtures/"release").is_file() and time.monotonic()<stop:
                        time.sleep(.015)
                sys.stdout.buffer.write(result)
                sys.stdout.buffer.flush()
        finally:
            peer.stdin.close()


if __name__ == "__main__":
    # The path belongs to the disposable fixture account.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    run(Path(sys.argv[1]), Path(sys.argv[2]))

