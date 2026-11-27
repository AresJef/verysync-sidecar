#!/usr/bin/env python3
"""Count requests from the standalone recovery process on its owned CI listener."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import time


READS = {
    b"/rest/system/version": "version",
    b"/rest/system/status": "identity",
    b"/rest/config/gui": "gui",
}
EXPECTED = Counter({"version": 2, "identity": 3, "gui": 1})
MAX_PACKETS = 128
SNAP_LENGTH = 4096


def capture_command(platform, port):
    if type(port) is not int or not 1 <= port <= 65535 or port == 18886:
        raise ValueError("explicit isolated listener port required")
    if platform == "darwin":
        executable, interface = "/usr/sbin/tcpdump", "lo0"
    elif platform == "linux":
        executable, interface = "/usr/bin/tcpdump", "lo"
    else:
        raise ValueError("capture supports the disposable Unix runners")
    packet_filter = f"tcp and src host 127.0.0.1 and dst host 127.0.0.1 and dst port {port}"
    return [executable, "-nn", "-p", "-i", interface, "--immediate-mode", "-U",
            "-c", str(MAX_PACKETS), "-s", str(SNAP_LENGTH), "-w", "-", packet_filter]


def tcp_payload(frame, link_type, capture_order, port):
    offset = {0: 4, 1: 14, 108: 4, 113: 16, 276: 20}.get(link_type)
    if offset is None:
        raise ValueError("unsupported isolated loopback link type")
    address = b"\x7f\x00\x00\x01"
    ip = frame[offset:]
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6 or ip[12:20] != address * 2:
        raise ValueError("capture contains a packet outside the owned loopback filter")
    ip_size = (ip[0] & 0x0f) * 4
    ip_length, fragment = struct.unpack_from("!HxxH", ip, 2)
    if ip_size < 20 or ip_length < ip_size + 20 or ip_length > len(ip) or fragment & 0x3fff:
        raise ValueError("truncated or fragmented IPv4 frame")
    tcp = ip[ip_size:ip_length]
    source, target, sequence = struct.unpack_from("!HHI", tcp)
    tcp_size = (tcp[12] >> 4) * 4
    if target != port or tcp_size < 20 or tcp_size > len(tcp):
        raise ValueError("invalid isolated TCP frame")
    if len(tcp) == tcp_size:
        return source, None
    if tcp[13] & 2:
        sequence += 1  # Account for SYN only if a native frame also carries data.
    return source, (sequence, capture_order, tcp[tcp_size:])


def extract_streams(blob, port):
    endian = {
        b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",
    }.get(blob[:4])
    if len(blob) < 24 or endian is None:
        raise ValueError("standard pcap capture header required")
    _, _, _, _, snap, link = struct.unpack_from(endian + "HHIIII", blob, 4)
    if not 64 <= snap <= SNAP_LENGTH:
        raise ValueError("unexpected isolated capture length")
    position, packets, flows = 24, 0, {}
    while position < len(blob):
        if packets >= MAX_PACKETS - 1 or len(blob) - position < 16:
            raise ValueError("capture truncated or reached its packet bound")
        _, _, stored, original = struct.unpack_from(endian + "IIII", blob, position)
        position += 16
        if stored != original or stored > snap or stored > len(blob) - position:
            raise ValueError("isolated capture omitted packet bytes")
        source, segment = tcp_payload(blob[position:position + stored], link, packets, port)
        if segment is not None:
            flows.setdefault(source, []).append(segment)
        position += stored
        packets += 1
    if not flows:
        raise ValueError("no request bytes from the standalone recovery process")
    return packets, flows


def combine(segments):
    # TCP sequence numbers wrap on four-byte boundaries. Normalize around
    # the first observed index, where this short stream spans only a few KiB.
    reference = min(segments, key=lambda item: item[1])[0]
    offsets = sorted((((sequence - reference + (1 << 31)) % (1 << 32)) - (1 << 31),
                      data) for sequence, _, data in segments)
    start = offsets[0][0]
    stream = bytearray()
    for offset, data in offsets:
        offset -= start
        if offset > len(stream):
            raise ValueError("isolated capture contains a gap in the request stream")
        overlap = min(len(stream) - offset, len(data))
        if stream[offset:offset + overlap] != data[:overlap]:
            raise ValueError("isolated capture contains conflicting request bytes")
        stream.extend(data[overlap:])
    return bytes(stream)


def read_requests(stream):
    routes = []
    while stream:
        header, end, stream = stream.partition(b"\r\n\r\n")
        if not end:
            raise ValueError("isolated capture contains an incomplete HTTP request")
        first, _, headers = header.partition(b"\r\n")
        fields = first.split(b" ")
        if len(fields) != 3 or fields[0] != b"GET" or fields[1] not in READS or fields[2] != b"HTTP/1.1":
            raise ValueError("standalone recovery used a route or method outside the read-only contract")
        credential_count = 0
        for header_line in headers.split(b"\r\n"):
            name, separator, value = header_line.partition(b":")
            if not separator:
                raise ValueError("standalone recovery sent an incomplete HTTP header")
            name = name.strip().lower()
            if name == b"x-api-key" and value.strip():
                credential_count += 1
            if name == b"transfer-encoding" or (name == b"content-length" and value.strip() != b"0"):
                raise ValueError("standalone recovery sent an unexpected request body")
        if credential_count != 1:
            raise ValueError("standalone recovery did not send exactly one credential header")
        routes.append(READS[fields[1]])
    return routes


def analyze(blob, port):
    packets, flows = extract_streams(blob, port)
    reads = Counter()
    for segments in flows.values():
        reads.update(read_requests(combine(segments)))
    if reads != EXPECTED:
        raise ValueError("standalone recovery did not issue the six expected read requests")
    return {"packet_count": packets, "streams": len(flows), "reads": dict(reads),
            "modifications": 0, "all_routes_allowlisted": True,
            "kernel_dropped_packets": 0, "normal_capture_exit": True}


def observe(port):
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.geteuid() != 0:
        raise ValueError("only the explicit observer on a disposable GitHub runner may capture")
    command = capture_command(sys.platform, port)
    if not Path(command[0]).is_file():
        raise ValueError("runner's native loopback observer is unavailable")
    # TemporaryFile is closed before exit and never appears in published evidence.
    with tempfile.TemporaryFile() as wire, tempfile.TemporaryFile() as diagnostic:
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=wire, stderr=diagnostic)
        started = time.monotonic()
        try:
            while True:
                if b"listening on" in os.pread(diagnostic.fileno(), 4096, 0):
                    break
                if child.poll() is not None or time.monotonic() - started >= 5:
                    raise ValueError("isolated loopback observer did not become ready")
                time.sleep(.025)
            print(json.dumps({"ready": True, "loopback_and_owned_port_only": True}), flush=True)
            readable, _, _ = select.select([sys.stdin], [], [], max(0, 30 - (time.monotonic() - started)))
            if not readable or not os.read(sys.stdin.fileno(), 1):
                raise ValueError("standalone recovery did not signal completion within the capture window")
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
                    raise ValueError("owned loopback observer required forced cleanup")
        if child.returncode != 0:
            raise ValueError("owned loopback observer did not exit normally")
        status = os.pread(diagnostic.fileno(), 4096, 0)
        dropped = re.search(rb"(\d+) packets dropped by kernel", status)
        if dropped is None or dropped[1] != b"0":
            raise ValueError("owned loopback observer did not confirm zero kernel drops")
        wire.seek(0)
        limit = 24 + MAX_PACKETS * (16 + SNAP_LENGTH)
        observation = wire.read(limit + 1)
        if len(observation) > limit:
            raise ValueError("isolated capture exceeded its byte bound")
        print(json.dumps(analyze(observation, port), sort_keys=True), flush=True)


def calibrate():
    # Exercise a synthetic TCP stream independently of how the application
    # produces it. Neither the credential nor frame bytes are public output.
    def request(method, route):
        return method + b" " + route + b" HTTP/1.1\r\nX-API-Key: private-fake-key\r\n\r\n"

    fixture_port = 42341

    def framed(data):
        frames = bytearray(
            b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, SNAP_LENGTH, 0)
        )
        for offset, piece in [(0, data[:28]), (28, data[28:]), (0, data[:28])]:
            ip = struct.pack("!BBHHHBBH", 0x45, 0, 40 + len(piece), 0, 0, 64, 6, 0)
            tcp = struct.pack("!HHIIBBHHH", 25123, fixture_port, 200 + offset, 0, 80, 24, 0, 0, 0)
            frame = b"\x02\x00\x00\x00" + ip + b"\x7f\x00\x00\x01" * 2 + tcp + piece
            frames.extend(struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame)
        return bytes(frames)

    routes = [
        b"/rest/system/version", b"/rest/system/status", b"/rest/system/status",
        b"/rest/config/gui", b"/rest/system/version", b"/rest/system/status",
    ]
    correct = b"".join(request(b"GET", route) for route in routes)
    result = analyze(framed(correct), fixture_port)
    assert result["reads"] == EXPECTED and result["packet_count"] == 3
    for wrong in [request(b"PATCH", b"/rest/config/gui"),
                  request(b"GET", b"/rest/svc/folder/secret"),
                  request(b"GET", b"/rest/system/status")]:
        try:
            analyze(framed(correct + wrong), fixture_port)
        except ValueError:
            pass
        else:
            raise ValueError("loopback witness accepted an injected extra request")
    print(json.dumps({"synthetic_capture_calibrated": True, "negative_controls": 3}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--port", type=int)
    mode.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        calibrate()
    else:
        observe(arguments.port)
