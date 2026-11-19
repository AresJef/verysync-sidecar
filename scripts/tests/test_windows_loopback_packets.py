"""Generated packet inputs cannot become evidence for unrelated flows or incomplete headers."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('loopback_packets', ROOT / 'scripts/probe-windows-loopback-packets.py')
PARSER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PARSER)


def capture(version=4, traffic_class=32, source=32123, destination=32124, payload=8, endian='<'):
    tcp = struct.pack('!HHIIBBHHH', source, destination, 0, 0, 0x50, 0x18, 1, 0, 0)
    if version == 4:
        ip = bytes([0x45, traffic_class]) + struct.pack('!HHHBBH4s4s', 40 + payload, 0, 0, 64, 6, 0,
            socket.inet_pton(socket.AF_INET, '127.0.0.1'), socket.inet_pton(socket.AF_INET, '127.0.0.1'))
    else:
        ip = struct.pack('!IHBB16s16s', (6 << 28) | (traffic_class << 20), 20 + payload, 6, 64,
            socket.inet_pton(socket.AF_INET6, '::1'), socket.inet_pton(socket.AF_INET6, '::1'))
    packet = b'\0' * 12 + struct.pack('!H', 0x0800 if version == 4 else 0x86dd) + ip + tcp + b'x' * payload
    def block(kind, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack(endian + 'II', kind, len(body) + 12) + body + struct.pack(endian + 'I', len(body) + 12)
    return (block(0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, -1))
            + block(1, struct.pack(endian + 'HHI', 1, 0, 160))
            + block(6, struct.pack(endian + 'IIIII', 0, 0, 1, len(packet), len(packet)) + packet))


class PacketHeaders(unittest.TestCase):
    def test_actual_generated_ipv4_ipv6_and_both_endian_sections(self):
        for version in [4, 6]:
            for endian in ['<', '>']:
                result = PARSER.summarize(capture(version=version, endian=endian), 32123, 32124, version)
                self.assertEqual(result['owned_data_headers'], 1)
                self.assertEqual(result['traffic_classes'], {'32': 1})

    def test_reverse_wrong_port_and_ack_only_do_not_count(self):
        for data in [capture(source=32124, destination=32123), capture(source=32125), capture(payload=0)]:
            self.assertEqual(PARSER.summarize(data, 32123, 32124, 4)['owned_data_headers'], 0)

    def test_truncated_or_bad_block_lengths_are_refused(self):
        data = capture()
        for bad in [data[:-1], data[:12], b'x' * 64, data[:-4] + b'\0' * 4]:
            with self.assertRaises(ValueError):
                PARSER.summarize(bad, 32123, 32124, 4)

    def test_empty_filter_state_and_exact_named_id_are_required(self):
        self.assertTrue(PARSER.no_filters('Packet Filters:\nNone\n'))
        self.assertFalse(PARSER.no_filters('Packet Filters:\n1 existing TCP\n'))
        self.assertFalse(PARSER.no_filters('unknown'))
        self.assertEqual(PARSER.owned_filter_id('Packet Filters:\n1 vs1234 TCP 127.0.0.1 32123\n 32124\n', 'vs1234'), '1')
        with self.assertRaises(ValueError):
            PARSER.owned_filter_id('1 other TCP 127.0.0.1 32123\n', 'vs1234')
        with self.assertRaises(ValueError):
            PARSER.owned_filter_id('1 vs1234 TCP 127.0.0.1 32123\n2 unrelated TCP 10.0.0.1 80\n', 'vs1234')

    def test_unknown_link_or_oversized_snapshot_cannot_produce_headers(self):
        unknown = bytearray(capture())
        struct.pack_into('<H', unknown, 36, 147)
        for data in [bytes(unknown), capture(payload=256)]:
            with self.assertRaises(ValueError):
                PARSER.summarize(data, 32123, 32124, 4)

    def test_existing_filter_or_unknown_empty_format_prevents_every_mutation(self):
        for filters in ['1 existing TCP\n', 'unknown native filter layout']:
            replies = [SimpleNamespace(returncode=0, stdout='Packet Monitor is not running.'),
                       SimpleNamespace(returncode=0, stdout=filters)]
            with patch.object(PARSER.subprocess, 'run', side_effect=replies) as command:
                row = PARSER.run_phase(Path('/owned/pktmon.exe'), Path('/owned'), 4, [])
            self.assertFalse(row['capture_started'])
            self.assertEqual([c.args[0][1:] for c in command.call_args_list], [['status'], ['filter', 'list']])

    def test_active_session_is_not_stopped_or_modified(self):
        with patch.object(PARSER.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='already running')) as command:
            with self.assertRaises(RuntimeError):
                PARSER.run_phase(Path('/owned/pktmon.exe'), Path('/owned'), 4, [])
        self.assertEqual(command.call_count, 1)

    def test_uncertain_start_never_stops_unknown_capture_or_removes_its_filter(self):
        server, client = MagicMock(), MagicMock()
        for stream, port in [(server, 32124), (client, 32123)]:
            stream.__enter__.return_value = stream
            stream.getsockname.return_value = ('127.0.0.1', port)
        state = {'starting': False}
        def result(argv, **kwargs):
            args = argv[1:]
            if args[0] == 'start':
                state['starting'] = True
                raise PARSER.subprocess.TimeoutExpired(argv, 15)
            output = ''
            if args == ['status']:
                output = 'unknown active capture' if state['starting'] else 'Packet Monitor is not running.'
            elif args == ['filter', 'list']:
                output = '1 vsabcd1234 TCP 127.0.0.1 32123' if command.call_count > 3 else 'Packet Filters:\nNone'
            return SimpleNamespace(returncode=0, stdout=output)
        with patch.object(PARSER.socket, 'socket', side_effect=[server, client]), \
                patch.object(PARSER.secrets, 'token_hex', return_value='abcd1234'), \
                patch.object(PARSER.subprocess, 'run', side_effect=result) as command:
            with self.assertRaisesRegex(RuntimeError, 'retaining the owned filter'):
                PARSER.run_phase(Path('/owned/pktmon.exe'), Path('/owned'), 4, [])
        calls = [c.args[0][1:] for c in command.call_args_list]
        self.assertNotIn(['stop'], calls)
        self.assertNotIn(['filter', 'remove', '1'], calls)


if __name__ == '__main__':
    unittest.main()
