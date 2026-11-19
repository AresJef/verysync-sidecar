"""Release capture must count packets queued when its owner signals completion."""

from contextlib import redirect_stdout
import importlib.util
import io
import ipaddress
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch


CAPTURE_PATH = Path(__file__).resolve().with_name("receive-headers.py")
SPEC = importlib.util.spec_from_file_location("wire_receive_headers", CAPTURE_PATH)
CAPTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPTURE)


class PacketSocket:
    """Present a real, ready datagram socket as the private receiver link."""

    def __init__(self, receiver):
        self.receiver = receiver

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def bind(self, address):
        if address != ("peer", 3):
            raise ValueError("unexpected packet fixture binding")

    def fileno(self):
        return self.receiver.fileno()

    def setblocking(self, value):
        self.receiver.setblocking(value)

    def recvfrom(self, bound):
        return self.receiver.recv(bound), ("peer", 0, 0)


def private_test_segment(source_port, traffic_class):
    packet = bytearray(41)
    packet[0] = 0x45
    packet[1] = traffic_class
    packet[2:4] = len(packet).to_bytes(2, "big")
    packet[8] = 64
    packet[9] = socket.IPPROTO_TCP
    packet[12:16] = ipaddress.IPv4Address("192.0.2.1").packed
    packet[16:20] = ipaddress.IPv4Address("192.0.2.2").packed
    packet[20:22] = source_port.to_bytes(2, "big")
    packet[22:24] = (47529).to_bytes(2, "big")
    packet[32] = 0x50
    packet[40] = 1
    return packet


class ReceiverHeaderTests(unittest.TestCase):
    def test_reads_pending_headers_before_honoring_completion(self):
        producer, receiver = socket.socketpair(type=socket.SOCK_DGRAM)
        finish, stop = socket.socketpair()
        with producer, receiver, finish, stop:
            producer.sendall(private_test_segment(31001, 16))
            producer.sendall(private_test_segment(31002, 32))
            finish.close()
            transcript = io.StringIO()
            with (
                patch.object(CAPTURE.socket, "AF_PACKET", 17, create=True),
                patch.object(CAPTURE.socket, "socket", return_value=PacketSocket(receiver)),
                patch.object(CAPTURE.os, "geteuid", return_value=0, create=True),
                patch.dict(CAPTURE.os.environ, {"RUNNER_DISPOSABLE_RX": "true"}),
                patch.object(sys, "platform", "linux"),
                patch.object(sys, "stdin", stop),
                patch.object(sys, "argv", ["receive-headers.py", "4", "192.0.2.1", "192.0.2.2", "47529"]),
                redirect_stdout(transcript),
            ):
                CAPTURE.main()

        ready, data = transcript.getvalue().splitlines()
        self.assertEqual(ready, "RECEIVER_HEADERS_READY")
        self.assertTrue(data.startswith("RECEIVER_HEADERS "))
        headers = json.loads(data.removeprefix("RECEIVER_HEADERS "))
        self.assertEqual(
            [(h["source_port"], h["class_octet"], h["tcp_payload_bytes"]) for h in headers],
            [(31001, 16, 1), (31002, 32, 1)],
        )
