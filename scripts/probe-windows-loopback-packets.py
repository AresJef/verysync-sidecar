#!/usr/bin/env python3
"""Bounded owned-loopback observer feasibility; zero VerySync feature acceptance."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import time

MAX_BYTES = 20 * 1024 * 1024


def no_filters(text):
    lines = [line.strip().lower() for line in text.splitlines() if line.strip()]
    lines = [line for line in lines if line not in {'packet filters:', 'filters:'}]
    return lines in [['none'], ['no filters'], ['no filters.'], ['no filters configured.']]


def owned_filter_id(text, name):
    rows = []
    for line in text.splitlines():
        value = line.strip()
        if not value or value == 'Packet Filters:' or re.fullmatch(r'[- ]+', value):
            continue
        if re.match(r'#\s+Name\s+', value):
            continue
        if re.fullmatch(r'\d{1,5}', value):
            continue
        match = re.fullmatch(r'(\d+)\s+(\S+)\s+TCP\s+.+', value)
        if not match:
            raise ValueError('unverified filter table layout')
        rows.append(match.groups())
    if len(rows) != 1 or rows[0][1] != name:
        raise ValueError('entire filter table is not exclusively owned')
    return rows[0][0]


def summarize(data, source_port, destination_port, version):
    if not 0 < len(data) <= MAX_BYTES:
        raise ValueError('bounded nonempty pcapng required')
    offset, endian, interfaces = 0, None, []
    classes, foreign, blocks = {}, 0, 0
    while offset < len(data):
        if len(data) - offset < 12:
            raise ValueError('truncated pcapng block')
        if data[offset:offset + 4] == b'\x0a\x0d\x0d\x0a':
            magic = data[offset + 8:offset + 12]
            endian = '<' if magic == b'\x4d\x3c\x2b\x1a' else '>' if magic == b'\x1a\x2b\x3c\x4d' else None
            interfaces = []
        if endian is None:
            raise ValueError('pcapng byte order absent')
        kind, length = struct.unpack_from(endian + 'II', data, offset)
        if length < 12 or length > 65536 or length % 4 or offset + length > len(data):
            raise ValueError('invalid pcapng block length')
        if struct.unpack_from(endian + 'I', data, offset + length - 4)[0] != length:
            raise ValueError('pcapng length trailer mismatch')
        body = data[offset + 8:offset + length - 4]
        blocks += 1
        if blocks > 100000:
            raise ValueError('pcapng block bound exceeded')
        if kind == 0x0a0d0d0a:
            if length < 28 or struct.unpack_from(endian + 'H', body, 4)[0] != 1:
                raise ValueError('unsupported pcapng section')
        elif kind == 1:
            if len(body) < 8 or len(interfaces) >= 128:
                raise ValueError('invalid pcapng interface')
            link, _, snap = struct.unpack_from(endian + 'HHI', body)
            interfaces.append((link, snap))
        elif kind == 6:
            if len(body) < 20:
                raise ValueError('truncated enhanced packet')
            interface, _, _, captured, original = struct.unpack_from(endian + 'IIIII', body)
            if interface >= len(interfaces) or captured > original or captured > 160 or 20 + captured > len(body):
                raise ValueError('packet/header bounds invalid')
            link, snap = interfaces[interface]
            if snap and captured > snap:
                raise ValueError('interface snapshot bound exceeded')
            packet = body[20:20 + captured]
            if link == 1:
                if len(packet) < 14:
                    raise ValueError('truncated Ethernet header')
                ethertype = struct.unpack_from('!H', packet, 12)[0]
                if ethertype not in {0x0800, 0x86dd}:
                    offset += length
                    continue
                packet = packet[14:]
            elif link not in {101, 228, 229}:
                raise ValueError('unverified capture link type')
            if not packet:
                raise ValueError('missing IP header')
            family = packet[0] >> 4
            if family == 4:
                if len(packet) < 20:
                    raise ValueError('truncated IPv4 header')
                ip_length = (packet[0] & 15) * 4
                total = struct.unpack_from('!H', packet, 2)[0]
                protocol, traffic = packet[9], packet[1]
                loopback = packet[12:16] == packet[16:20] == b'\x7f\0\0\x01'
                fragmented = struct.unpack_from('!H', packet, 6)[0] & 0x3fff
                if ip_length < 20 or fragmented:
                    raise ValueError('unsupported IPv4 layout')
            elif family == 6:
                if len(packet) < 40:
                    raise ValueError('truncated IPv6 header')
                ip_length = 40
                total = 40 + struct.unpack_from('!H', packet, 4)[0]
                protocol, traffic = packet[6], ((packet[0] & 15) << 4) | (packet[1] >> 4)
                loopback = packet[8:24] == packet[24:40] == b'\0' * 15 + b'\x01'
            else:
                raise ValueError('unverified IP layout')
            if protocol != 6 or len(packet) < ip_length + 20:
                raise ValueError('complete direct TCP header required')
            source, destination = struct.unpack_from('!HH', packet, ip_length)
            tcp_length = (packet[ip_length + 12] >> 4) * 4
            if tcp_length < 20 or len(packet) < ip_length + tcp_length or total < ip_length + tcp_length:
                raise ValueError('invalid TCP data/header length')
            owned = loopback and family == version and (source, destination) == (source_port, destination_port)
            reverse = loopback and family == version and (source, destination) == (destination_port, source_port)
            if not owned and not reverse:
                foreign += 1
            if owned and total > ip_length + tcp_length:
                key = str(traffic)
                classes[key] = classes.get(key, 0) + 1
        elif kind in {2, 3}:
            raise ValueError('unverified packet block container')
        offset += length
    return {'owned_data_headers': sum(classes.values()), 'traffic_classes': classes,
            'foreign_tcp_headers': foreign, 'blocks': blocks, 'raw_packet_contents_logged': False}


def run_phase(tool, root, version, records):
    def command(*args):
        result = subprocess.run([str(tool), *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=15, text=True, encoding='utf-8', errors='replace')
        records.append({'arguments': list(args), 'exit_code': result.returncode, 'output': result.stdout[:12000]})
        if result.returncode:
            raise RuntimeError('packet monitor command failed: ' + args[0])
        return result.stdout
    if command('status').strip() != 'Packet Monitor is not running.':
        raise RuntimeError('initial capture session is not confirmed inactive')
    filters = command('filter', 'list')
    if not no_filters(filters):
        return {'version': version, 'status': 'INCONCLUSIVE_FILTER_FORMAT_OR_EXISTING_FILTERS',
                'preflight_filter_output': filters[:12000], 'capture_started': False, 'records': records}
    command('filter', 'remove', 'help')
    family, address = (socket.AF_INET, '127.0.0.1') if version == 4 else (socket.AF_INET6, '::1')
    name = 'vs' + secrets.token_hex(4)
    identifier, started, start_requested, filter_added = None, False, False, False
    etl = root / (name + '.etl')
    pcap = root / (name + '.pcapng')
    with socket.socket(family, socket.SOCK_STREAM) as server, socket.socket(family, socket.SOCK_STREAM) as client:
        server.bind((address, 0))
        server.listen(1)
        server.settimeout(3)
        client.bind((address, 0))
        client.settimeout(3)
        source, destination = client.getsockname()[1], server.getsockname()[1]
        if 18886 in {source, destination} or source == destination:
            raise RuntimeError('protected or ambiguous synthetic flow port')
        try:
            command('filter', 'add', name, '-i', address, '-t', 'TCP', '-p', str(source), str(destination))
            filter_added = True
            identifier = owned_filter_id(command('filter', 'list'), name)
            start_requested = True
            command('start', '--capture', '--comp', 'all', '--pkt-size', '128', '--file-size', '16',
                    '--log-mode', 'circular', '--file-name', str(etl))
            started = True
            client.connect((address, destination))
            accepted, _ = server.accept()
            payload = bytes(range(256)) * 32
            received = hashlib.sha256()
            deadline = time.monotonic() + 10
            with accepted:
                accepted.settimeout(3)
                for _ in range(128):
                    if time.monotonic() >= deadline:
                        raise RuntimeError('synthetic flow deadline exceeded')
                    client.sendall(payload)
                    count = 0
                    while count < len(payload):
                        chunk = accepted.recv(len(payload) - count)
                        if not chunk:
                            raise RuntimeError('incomplete synthetic data')
                        received.update(chunk)
                        count += len(chunk)
                    time.sleep(0.01)
            if received.digest() != hashlib.sha256(payload * 128).digest():
                raise RuntimeError('synthetic byte identity failed')
        finally:
            safe_to_remove_filter = not start_requested
            try:
                if start_requested:
                    status = command('status')
                    if status.strip() == 'Packet Monitor is not running.':
                        safe_to_remove_filter = True
                    else:
                        if not started and etl.name.lower() not in status.lower():
                            raise RuntimeError('unconfirmed start outcome; refusing to stop an unknown monitor')
                        command('stop')
                        if command('status').strip() != 'Packet Monitor is not running.':
                            raise RuntimeError('owned monitor did not stop')
                        safe_to_remove_filter = True
            finally:
                if filter_added:
                    if not safe_to_remove_filter:
                        raise RuntimeError('unconfirmed capture; retaining the owned filter to avoid broadening capture')
                    if identifier is None:
                        raise RuntimeError('owned filter identifier unknown; refusing a blanket removal')
                    # The native CLI ignores a supplied ID and removes the whole
                    # table. Reconfirm that the entire table is exactly ours.
                    if owned_filter_id(command('filter', 'list'), name) != identifier:
                        raise RuntimeError('owned filter table identity changed')
                    command('filter', 'remove')
                    if not no_filters(command('filter', 'list')):
                        raise RuntimeError('owned filter cleanup not confirmed')
        command('etl2pcap', str(etl), '--out', str(pcap))
        if pcap.stat().st_size > MAX_BYTES or etl.stat().st_size > MAX_BYTES:
            raise RuntimeError('capture file bound exceeded')
        summary = summarize(pcap.read_bytes(), source, destination, version)
        return {'version': version, 'source_port': source, 'destination_port': destination,
                'synthetic_bytes_verified': 1048576, 'capture_started': True,
                'capture_and_named_filter_cleanup_confirmed': True, 'summary': summary,
                'status': 'HEADERS_OBSERVED' if summary['owned_data_headers'] and not summary['foreign_tcp_headers'] else 'INCONCLUSIVE_NO_OWNED_HEADERS',
                'records': records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--github-actions-owned-loopback', action='store_true', required=True)
    args = parser.parse_args()
    if not args.github_actions_owned_loopback or sys.platform != 'win32' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('explicit fresh Windows Actions VM required')
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError('observer requires the disposable VM administrator token')
    tool = Path(os.environ['SystemRoot']) / 'System32' / 'pktmon.exe'
    if not tool.is_absolute() or not tool.is_file() or tool.is_symlink():
        raise RuntimeError('explicit in-box packet monitor required')
    rows = []
    with tempfile.TemporaryDirectory(prefix='vs-owned-packets-') as directory:
        for version in [4, 6]:
            records = []
            try:
                row = run_phase(tool, Path(directory), version, records)
            except Exception as error:
                row = {'version': version, 'status': 'INCONCLUSIVE_DIAGNOSTIC_ERROR', 'error': str(error), 'records': records}
            rows.append(row)
    print('Windows owned loopback header feasibility: ' + json.dumps({
        'diagnostic_only': True, 'VerySync_native_cases': 0, 'native_packet_class_accepted': False,
        'only_generated_owned_loopback_flows': True, 'raw_capture_files_removed': True, 'phases': rows,
    }, sort_keys=True), flush=True)
    return 0 if all(row['status'] == 'HEADERS_OBSERVED' for row in rows) else 2


if __name__ == '__main__':
    raise SystemExit(main())
