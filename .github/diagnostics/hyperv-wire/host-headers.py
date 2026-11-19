"""Summarize owned outbound port fields from a bounded Packet Monitor pcapng."""

from collections import Counter
import ipaddress
import json
from pathlib import Path
import runpy
import struct
import sys

tcp_data = runpy.run_path(str(Path(__file__).with_name("receive-headers.py")))["tcp_data"]
ADDRESSES = {
    4: tuple(ipaddress.ip_address(ip).packed for ip in ("192.0.2.1", "192.0.2.2")),
    6: tuple(ipaddress.ip_address(ip).packed for ip in ("2001:db8:73f:43::1", "2001:db8:73f:43::2")),
}
PORT = 47529


def interface_name(options, endian):
    offset = 0
    while offset + 4 <= len(options):
        kind, size = struct.unpack_from(endian + "HH", options, offset)
        offset += 4
        if kind == 0:
            break
        value = options[offset: offset + size]
        if len(value) != size:
            raise ValueError("Invalid interface option length")
        if kind == 2:
            return value.decode("utf-8", "replace")
        offset += (size + 3) & ~3
    return ""


def ip_payload(frame, link):
    if link in (101, 228, 229):
        return frame
    if link != 1 or len(frame) < 14:
        return b""
    ethertype = int.from_bytes(frame[12:14], "big")
    offset = 14
    while ethertype in (0x8100, 0x88A8) and len(frame) >= offset + 4:
        ethertype = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
    return frame[offset:] if ethertype in (0x0800, 0x86DD) else b""


def summarize(data):
    if not 0 < len(data) <= 20 * 1024 * 1024:
        raise ValueError("A bounded capture is required")
    endian = None
    offset = 0
    interfaces = []
    counts = Counter()
    unsupported = Counter()
    while offset < len(data):
        if len(data) - offset < 12:
            raise ValueError("Truncated PCAPNG block")
        if data[offset:offset + 4] == b"\x0a\x0d\x0d\x0a":
            if endian is not None:
                raise ValueError("Multiple capture sections")
            magic = data[offset + 8:offset + 12]
            endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}[magic]
        if endian is None:
            raise ValueError("Capture byte order is missing")
        kind, length = struct.unpack_from(endian + "II", data, offset)
        if not 12 <= length <= 65536 or length % 4 or offset + length > len(data):
            raise ValueError("Invalid PCAPNG block length")
        if struct.unpack_from(endian + "I", data, offset + length - 4)[0] != length:
            raise ValueError("Capture length trailer mismatch")
        payload = data[offset + 8:offset + length - 4]
        if kind == 1:
            link, _, snap = struct.unpack_from(endian + "HHI", payload)
            interfaces.append({"link": link, "name": interface_name(payload[8:], endian), "snap": snap})
        elif kind == 6:
            index, _, _, captured, original = struct.unpack_from(endian + "IIIII", payload)
            if index >= len(interfaces) or captured > original or captured > 160 or captured > len(payload) - 20:
                raise ValueError("Invalid captured packet bounds")
            link = interfaces[index]["link"]
            if link not in (1, 101, 228, 229):
                unsupported[link] += 1
            layer3 = ip_payload(payload[20:20 + captured], link)
            if layer3 and (family := layer3[0] >> 4) in ADDRESSES:
                result = tcp_data(layer3, family, *ADDRESSES[family], PORT)
                if result is not None:
                    port, value, _, _ = result
                    counts[index, family, port, value & 0xFC] += 1
        elif kind in (2, 3):
            raise ValueError("Unsupported packet block")
        offset += length
    rows = [{"interface": i, "family": f, "source_port": p, "class": c, "packets": n}
            for (i, f, p, c), n in sorted(counts.items())]
    return {"interfaces": interfaces, "flows": rows, "unsupported_link_types": dict(unsupported)}


if __name__ == "__main__":
    data = summarize(Path(sys.argv[1]).read_bytes())
    print("OWNED_WINDOWS_TRACE " + json.dumps(data, separators=(",", ":")), flush=True)
