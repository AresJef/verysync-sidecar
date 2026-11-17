#!/usr/bin/env python3
"""Bounded CI-only loopback TCP headers; the native core remains unprivileged."""
import argparse
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import tempfile
import time


def capture_command(port, host_platform):
    if type(port) is not int or not 1 <= port <= 65535 or port == 18886:
        raise ValueError("explicit non-user test port required")
    if host_platform not in {"darwin", "linux"}:
        raise ValueError("explicit supported disposable CI host required")
    program = "/usr/sbin/tcpdump" if host_platform == "darwin" else "/usr/bin/tcpdump"
    interface = "lo0" if host_platform == "darwin" else "lo"
    return [program, "-nn", "-l", "-v", "-s", "80", "-i", interface, "-c", "256",
            f"tcp and src host 127.0.0.1 and dst host 127.0.0.1 and dst port {port}"]


def data_headers(text, port):
    result, current_tos = [], None
    for line in text.splitlines():
        tos = re.search(r"\btos 0x([0-9a-fA-F]+)\b", line)
        if tos:
            current_tos = int(tos[1], 16)
        packet = re.search(r"\b127\.0\.0\.1\.(\d+) > 127\.0\.0\.1\.(\d+):.*\blength (\d+)\s*$", line)
        if packet:
            if current_tos is None or not 0 <= current_tos <= 255 or int(packet[2]) != port:
                raise ValueError("incomplete or mismatched owned packet header")
            if int(packet[3]) > 0:
                result.append({"tos": current_tos, "source_port": int(packet[1]),
                               "destination_port": port, "tcp_payload_bytes": int(packet[3])})
            current_tos = None
    if not result:
        raise ValueError("no actual owned TCP data headers observed")
    return result


def observe(port):
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.geteuid() != 0:
        raise ValueError("only the explicit privileged observer in a disposable CI job may capture")
    command = capture_command(port, sys.platform)
    if not Path(command[0]).is_file():
        raise ValueError("the runner's native tcpdump is unavailable")
    with tempfile.TemporaryFile() as headers, tempfile.TemporaryFile() as diagnostic:
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=headers, stderr=diagnostic)
        started = time.monotonic()
        try:
            while True:
                message = os.pread(diagnostic.fileno(), 65537, 0)
                if len(message) > 65536:
                    raise ValueError("capture diagnostic bound exceeded")
                if b"listening on" in message:
                    break
                if child.poll() is not None or time.monotonic()-started >= 5:
                    raise RuntimeError("owned loopback capture did not become ready within 5s")
                time.sleep(.025)
            print(json.dumps({"ready": True, "port": port, "loopback_only": True}), flush=True)
            # EOF also releases the exact owned observer when the test fails.
            readable, _, _ = select.select([sys.stdin], [], [], max(0, 30-(time.monotonic()-started)))
            if not readable:
                raise TimeoutError("original 30s owned capture bound reached")
            os.read(sys.stdin.fileno(), 1)
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
                    raise RuntimeError("owned capture required forced cleanup")
        if child.returncode != 0:
            raise RuntimeError("owned capture did not exit normally")
        headers.seek(0)
        raw = headers.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ValueError("owned packet header bound exceeded")
        print(json.dumps({"normal_capture_exit": True, "packets": data_headers(raw.decode("utf-8"), port)}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    observe(parser.parse_args().port)
