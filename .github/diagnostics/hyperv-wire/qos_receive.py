"""Match independent Linux raw IP observations to a calibrated TCP payload."""

from collections import Counter
import hashlib
import ipaddress
import json
import os
import select
import socket
import struct
import sys
import time

from qos_payload import CLASSES, PEERS, PORT, SIZE, sample
from receive_headers import tcp_data


def listen(af, target):
    net = socket.socket(af, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    if af == socket.AF_INET6:
        net.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    try:
        deadline = time.monotonic() + 12
        while True:
            try:
                net.bind((target, PORT))
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.15)
        net.listen(1)
        net.settimeout(45)
        return net
    except BaseException:
        net.close()
        raise


def receive_and_capture(net, packet, family, source, target, source_port):
    classes = Counter()
    content = bytearray()
    tcp_bytes = 0
    watched = [packet, net]
    deadline = time.monotonic() + 12
    while (left := deadline - time.monotonic()) > 0:
        ready = select.select(watched, [], [], left)[0]
        if packet in ready:
            header, address = packet.recvfrom(128)
            if address[0] == "peer" and address[2] == socket.PACKET_HOST:
                data = tcp_data(header, family, source.packed, target.packed, PORT)
                if data is not None and data[0] == source_port:
                    classes[data[1] & 0xFC] += 1
                    tcp_bytes += data[2]
        if net in ready:
            chunk = net.recv(64 * 1024)
            content.extend(chunk)
            if len(content) > SIZE:
                raise ValueError("Calibration payload exceeded its exact length")
            if not chunk:
                watched.remove(net)
                deadline = time.monotonic() + 0.25
    if net in watched:
        raise TimeoutError("Calibration payload connection did not finish")
    # Linux SOL_PACKET/PACKET_STATISTICS records drops before the parser runs.
    _, drops = struct.unpack("=II", packet.getsockopt(263, 6, 8))
    return content, classes, tcp_bytes, drops


def receive_all():
    if sys.platform != "linux" or os.geteuid() != 0 or os.environ.get("OWNED_HYPERV_QOS_CONTROL") != "true":
        raise RuntimeError("Use only the disposable Linux receive guest")
    for family, af, source, target in PEERS:
        with listen(af, target) as listener:
            for traffic_class in CLASSES:
                with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3)) as packet:
                    packet.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
                    packet.bind(("peer", 3))
                    net, address = listener.accept()
                    with net:
                        net.settimeout(12)
                        if address[0] != source or net.getsockname()[:2] != (target, PORT):
                            raise ValueError("The flow did not originate on the private link")
                        # A queued TCP connection can be established before the per-flow observer binds.
                        net.sendall(b"\x01")
                        content, classes, tcp_bytes, drops = receive_and_capture(
                            net, packet, family, ipaddress.ip_address(source),
                            ipaddress.ip_address(target), address[1],
                        )
                        if content != sample(family, traffic_class):
                            raise ValueError("Unexpected calibration payload")
                        digest = hashlib.sha256(content).digest()
                        net.sendall(digest)
                    print("QOS_RECEIVED " + json.dumps({
                        "family": family, "class": traffic_class, "source_port": address[1],
                        "target_port": PORT, "bytes": len(content), "sha256": digest.hex(),
                        "classes": dict(classes), "tcp_payload_bytes": tcp_bytes, "kernel_drops": drops,
                    }), flush=True)
                    if not classes or tcp_bytes < SIZE or drops:
                        raise ValueError("Incomplete independent packet observation")
    print("QOS_CONTROL_LINUX_FINISH cases=6", flush=True)


if __name__ == "__main__":
    receive_all()
