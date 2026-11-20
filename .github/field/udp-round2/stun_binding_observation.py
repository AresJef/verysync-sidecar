"""One allowed public STUN Binding request, with no application attributes."""
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import sys


HOST = "stun.cloudflare.com"
PORT = 3478
COOKIE = 0x2112A442


def encode_binding(txid):
    return struct.pack("!HHI12s", 0x0001, 0, COOKIE, txid)


def mapped_address(packet, transaction):
    if len(packet) < 20:
        raise ValueError("malformed STUN header")
    kind, size, cookie, reply_id = struct.unpack_from("!HHI12s", packet)
    if (kind, size, cookie, reply_id) != (0x0101, len(packet) - 20, COOKIE, transaction) or size % 4:
        raise ValueError("STUN response did not match request")
    offset = 20
    while offset < len(packet):
        if offset + 4 > len(packet):
            raise ValueError("truncated STUN attribute header")
        tag, length = struct.unpack_from("!HH", packet, offset)
        start = offset + 4
        end = start + length
        if end > len(packet):
            raise ValueError("truncated STUN attribute")
        if tag == 0x0020 and length == 8:
            reserved, family, port, packed_ip = struct.unpack_from("!BBHI", packet, start)
            if reserved == 0 and family == 1:
                return ipaddress.IPv4Address(packed_ip ^ COOKIE), port ^ (COOKIE >> 16)
        offset = (end + 3) & ~3
    raise ValueError("STUN IPv4 mapping absent")


def observe():
    result = {"observed_at": datetime.now().astimezone().isoformat(timespec="seconds"),
              "server": HOST, "transport": "IPv4/UDP", "server_port": PORT,
              "datagrams_sent": 0, "datagram_size": 20, "attributes_sent": 0,
              "addresses_preserved": False, "manual_mapping_requested": False,
              "authenticated_peer_connection": False}
    try:
        destination = socket.getaddrinfo(HOST, PORT, socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)[0][4]
        if not ipaddress.IPv4Address(destination[0]).is_global:
            result["outcome"] = "dns_candidate_nonpublic"
            return result
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(4)
            probe.connect(destination)
            source_ip, source_port = probe.getsockname()
            transaction = secrets.token_bytes(12)
            sent = probe.send(encode_binding(transaction))
            assert sent == 20
            result["datagrams_sent"] = 1
            mapped, observed_port = mapped_address(probe.recv(1500), transaction)
            source = ipaddress.IPv4Address(source_ip)
            result.update(outcome="binding_reply_verified", source_address_global=source.is_global,
                          mapping_address_global=mapped.is_global, address_translated=mapped != source,
                          port_translated=observed_port != source_port)
    except (OSError, ValueError) as exc:
        result["outcome"] = type(exc).__name__
        if isinstance(exc, OSError):
            result["errno"] = exc.errno
    return result


if __name__ == "__main__":
    os.umask(0o077)
    result = observe()
    with Path(sys.argv[1]).open("x", encoding="utf-8") as sink:
        json.dump(result, sink, indent=2)
        sink.write("\n")
    print(json.dumps(result))
