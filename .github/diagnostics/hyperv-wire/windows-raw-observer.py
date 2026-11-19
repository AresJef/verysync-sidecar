"""Qualify a receive-only Winsock observer with explicitly owned loopback TCP flows."""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import platform
import runpy
import socket
import sys
from threading import Event
import time

from qos_payload import SIZE, sample
from qos_send import per_socket_qos

TCP_DATA = runpy.run_path(str(Path(__file__).with_name("receive-headers.py")))["tcp_data"]
# This Mstcpip.h enumeration value selects IP-level capture with hardware promiscuous mode off.
RCVALL_IPLEVEL = 3


def capture(raw, family, address, ports, finished):
    counts = Counter()
    indicated = 0
    headerless = 0
    end = time.monotonic() + 6
    while time.monotonic() < end:
        try:
            data = raw.recv(65535)
        except TimeoutError:
            if finished.is_set():
                break
            continue
        header = TCP_DATA(data, family, address, address, ports[1])
        if header is not None and header[0] == ports[0]:
            counts[header[1]] += 1
            indicated += header[2]
        elif family == 6 and len(data) >= 20:
            observed_ports = (int.from_bytes(data[:2], "big"), int.from_bytes(data[2:4], "big"))
            header_size = (data[12] >> 4) * 4
            if observed_ports == ports and 20 <= header_size < len(data):
                headerless += 1
    return counts, indicated, headerless


def read_sample(peer):
    digest = sha256()
    seen = 0
    while block := peer.recv(32 * 1024):
        seen += len(block)
        if seen > SIZE:
            raise ValueError("owned TCP sample exceeded its expected length")
        digest.update(block)
    return seen, digest.hexdigest()


def run_flow(family, requested):
    af, proto, address = ((socket.AF_INET, socket.IPPROTO_IP, "127.0.0.1") if family == 4
                          else (socket.AF_INET6, socket.IPPROTO_IPV6, "::1"))
    body = sample(family, requested)
    with socket.socket(af, socket.SOCK_STREAM) as listen, socket.socket(af, socket.SOCK_STREAM) as sender:
        listen.settimeout(6)
        listen.bind((address, 0))
        listen.listen(1)
        sender.settimeout(6)
        sender.bind((address, 0))
        sender.connect(listen.getsockname())
        port_pair = sender.getsockname()[1], listen.getsockname()[1]
        peer, origin = listen.accept()
        with peer, ThreadPoolExecutor(max_workers=2) as pool:
            assert origin[:2] == (address, port_pair[0])
            peer.settimeout(6)
            finished = Event()
            raw = None
            enabled = False
            disabled = False
            capture_job = None
            stage = "socket"
            winerror = None
            try:
                try:
                    raw = socket.socket(af, socket.SOCK_RAW, proto)
                    stage = "bind"
                    raw.bind((address, 0))
                    raw.settimeout(0.25)
                    stage = "ioctl"
                    raw.ioctl(socket.SIO_RCVALL, RCVALL_IPLEVEL)
                    enabled = True
                    stage = "receive"
                    capture_job = pool.submit(capture, raw, family, ipaddress.ip_address(address).packed,
                                              port_pair, finished)
                except OSError as exc:
                    winerror = exc.winerror
                transfer = pool.submit(read_sample, peer)
                with per_socket_qos(sender, requested) as configured:
                    sender.sendall(body)
                    sender.shutdown(socket.SHUT_WR)
                    size, digest = transfer.result()
                    assert size == len(body) and digest == sha256(body).hexdigest()
                finished.set()
                fields, indicated, headerless = (capture_job.result() if capture_job
                                                  else (Counter(), 0, 0))
            finally:
                finished.set()
                if raw is not None:
                    try:
                        if enabled:
                            raw.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                            disabled = True
                    finally:
                        raw.close()
    masked = {octet & 0xFC for octet in fields}
    return {
        "family": family, "requested": requested, "stage": stage, "winerror": winerror,
        "real_tcp_data_size": size, "data_sha256": digest,
        "connected_socket_control": configured, "bound_loopback": address,
        "source_port": port_pair[0], "destination_port": port_pair[1],
        "actual_ip_header_octets": dict(fields), "indicated_tcp_payload": indicated,
        "matching_headerless_ipv6_tcp_records": headerless,
        "owned_raw_socket_closed": True, "enabled": enabled, "disabled": disabled,
        "eligible": enabled and disabled and indicated >= size and masked == {requested}
                    and configured.get("winerror") == 0,
    }


def main():
    if (sys.platform != "win32" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("OWNED_WINDOWS_RAW_OBSERVER") != "true"):
        raise SystemExit("The observer is limited to explicitly selected hosted Windows jobs.")
    expected = os.environ["RUNNER_ARCH"].lower()
    machine = platform.machine().lower()
    expected_machine = {"x64": "amd64", "arm64": "arm64"}[expected]
    if machine != expected_machine:
        raise SystemExit(f"The Python observer must match the native runner architecture, found {machine}.")
    outcomes = []
    for family in (4, 6):
        for requested in (0, 16, 32):
            result = run_flow(family, requested)
            outcomes.append(result)
            print("OWNED_WINSOCK_OBSERVER " + json.dumps(result), flush=True)
    eligible = {str(family): all(r["eligible"] for r in outcomes if r["family"] == family)
                for family in (4, 6)}
    print("OWNED_WINSOCK_OBSERVER_RESULT " + json.dumps({
        "architecture": machine, "eligible": eligible, "observer_qualification_only": True,
    }), flush=True)
    raise SystemExit(0 if all(eligible.values()) else 1)


if __name__ == "__main__":
    main()
