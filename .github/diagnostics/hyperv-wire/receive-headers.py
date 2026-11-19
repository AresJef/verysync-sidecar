"""Read the inbound IP and TCP headers of an explicit test peer on its own link."""
from collections import Counter
import ipaddress
import json
import os
import select
import socket
import struct
import sys
import time


def tcp_data(layer3, family, source, target, port):
    # A packet socket may deliver only part of the datagram. The IP and TCP
    # header lengths describe the indicated TCP data without retaining it.
    if not layer3 or layer3[0] >> 4 != family:
        return None
    if family == 4:
        if len(layer3) < 20 or layer3[9] != socket.IPPROTO_TCP:
            return None
        if layer3[12:16] != source or layer3[16:20] != target:
            return None
        ip_size = (layer3[0] & 15) * 4
        fragments = int.from_bytes(layer3[6:8], "big") & 0x3fff
        if fragments or ip_size < 20:
            return None
        tcp_size = int.from_bytes(layer3[2:4], "big") - ip_size
        class_octet = layer3[1]
        remaining_hops = layer3[8]
    else:
        if len(layer3) < 40 or layer3[6] != socket.IPPROTO_TCP:
            return None
        if layer3[8:24] != source or layer3[24:40] != target:
            return None
        ip_size = 40
        tcp_size = int.from_bytes(layer3[4:6], "big")
        class_octet = ((layer3[0] & 15) << 4) | (layer3[1] >> 4)
        remaining_hops = layer3[7]
    if len(layer3) < ip_size + 20 or tcp_size < 20:
        return None
    tcp = layer3[ip_size:]
    if int.from_bytes(tcp[2:4], "big") != port:
        return None
    tcp_header = (tcp[12] >> 4) * 4
    if not 20 <= tcp_header <= len(tcp):
        return None
    payload = tcp_size - tcp_header
    if payload <= 0:
        return None
    return int.from_bytes(tcp[:2], "big"), class_octet, payload, remaining_hops


def datagrams_until_stop(packet, stop, deadline):
    while (remaining := deadline - time.monotonic()) > 0:
        ready, _, _ = select.select([stop, packet], [], [], remaining)
        if stop in ready:
            # The engine can finish writing before this observer is scheduled.
            # Drain ready datagrams without waiting for any additional traffic.
            packet.setblocking(False)
            while time.monotonic() < deadline:
                try:
                    yield packet.recvfrom(128)
                except BlockingIOError:
                    return
            break
        if packet in ready:
            yield packet.recvfrom(128)
    raise TimeoutError("the owned receive observer exceeded its 30-second bound")


def main():
    if sys.platform != "linux" or os.geteuid() != 0 or os.environ.get("RUNNER_DISPOSABLE_RX") != "true":
        raise ValueError("run only inside the authorized disposable receiver fixture")
    family = int(sys.argv[1])
    source = ipaddress.ip_address(sys.argv[2])
    target = ipaddress.ip_address(sys.argv[3])
    port = int(sys.argv[4])
    if (family not in (4, 6) or source.version != family or target.version != family
            or source == target or source.is_loopback or target.is_loopback
            or not 1 <= port <= 65535 or port == 18886):
        raise ValueError("an explicit nonloopback test flow is required")
    eth_all = 3
    packet_host = 0
    so_rcvbufforce = 33
    sol_packet = 263
    packet_statistics = 6
    burst_bytes = 2 * 1024 * 1024
    counts = Counter()
    sizes = Counter()
    with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(eth_all)) as packet:
        # The isolated guest can size this socket for the whole burst despite
        # the narrower system default. Linux accounts twice the requested size.
        packet.setsockopt(socket.SOL_SOCKET, so_rcvbufforce, burst_bytes)
        buffer_bytes = packet.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        if buffer_bytes < 2 * burst_bytes:
            raise RuntimeError("the isolated packet socket did not reserve the expected buffer")
        packet.bind(("peer", eth_all))
        print("RECEIVER_HEADERS_READY", flush=True)
        deadline = time.monotonic() + 30
        for data, address in datagrams_until_stop(packet, sys.stdin, deadline):
            if address[0] != "peer" or address[2] != packet_host:
                continue
            item = tcp_data(data, family, source.packed, target.packed, port)
            if item is not None:
                source_port, traffic_class, size, remaining_hops = item
                key = (source_port, traffic_class, remaining_hops)
                counts[key] += 1
                sizes[key] += size
                if len(counts) > 64:
                    raise RuntimeError("unexpected number of distinct test flow headers")
        offered, drops = struct.unpack("=II", packet.getsockopt(sol_packet, packet_statistics, 8))
        print("RECEIVER_CAPTURE_ACCOUNTING " + json.dumps({
            "family": family, "socket_buffer_bytes": buffer_bytes,
            "offered_packets": offered, "kernel_drops": drops,
        }), file=sys.stderr, flush=True)
        if drops:
            raise RuntimeError("the kernel dropped packets on the isolated capture socket")
    rows = [
        {"source_port": key[0], "class_octet": key[1], "remaining_hops": key[2],
         "tcp_payload_bytes": sizes[key], "packets": count}
        for key, count in sorted(counts.items())
    ]
    print("RECEIVER_HEADERS " + json.dumps(rows, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
